"""
netns-jail: run a process in its own network namespace jail.
"""
import argparse
import atexit
import os
import shutil
import signal
import subprocess
import sys
import uuid
from typing import List, Optional


# ---------------------------------------------------------------------------
# Tool path resolution
# ---------------------------------------------------------------------------
def _require(tool: str) -> str:
    """Resolve a tool via PATH, raising a clear error if not found."""
    path = shutil.which(tool)
    if path is None:
        raise RuntimeError(f"Required tool not found in PATH: {tool!r}")
    return path


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
class Forward:
    """A unix-domain socket -> TCP forward into the jail."""

    def __init__(self, unix_socket: str, host: str, port: int):
        self.unix_socket = unix_socket
        self.host = host
        self.port = port

    @classmethod
    def parse(cls, spec: str) -> "Forward":
        """Parse 'unix.sock:host:port'."""
        parts = spec.rsplit(":", 2)
        if len(parts) != 3:
            raise ValueError(
                f"Invalid --forward spec {spec!r}, expected SOCK:HOST:PORT"
            )
        sock, host, port_str = parts
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Port must be an integer, got {port_str!r}")
        return cls(unix_socket=sock, host=host, port=port)

    def __str__(self) -> str:
        return f"{self.unix_socket}:{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_debug = False


def _log(cmd: List[str]) -> None:
    if _debug:
        print(f"+ {' '.join(cmd)}", file=sys.stderr)


def _run(cmd: List[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    _log(cmd)
    return subprocess.run(cmd, check=check, **kwargs)


def _sudo(cmd: List[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return _run([_require("sudo")] + cmd, check=check, **kwargs)


def _calling_user() -> str:
    """Return the non-root user who invoked us (handles sudo elevation)."""
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or os.getlogin()


def _default_iface() -> str:
    """Return the name of the default route interface."""
    result = subprocess.run(
        [_require("ip"), "route", "show", "default"],
        capture_output=True, text=True, check=True,
    )
    parts = result.stdout.split()
    if "dev" not in parts:
        raise RuntimeError("Cannot determine default network interface")
    return parts[parts.index("dev") + 1]


# ---------------------------------------------------------------------------
# Jail
# ---------------------------------------------------------------------------
class NetnsJail:
    """Manages the lifecycle of a single network-namespace jail."""

    def __init__(self, nat: bool = False, forwards: Optional[List[Forward]] = None):
        uid = uuid.uuid4()
        user_slug = _calling_user()[:5]
        self.name = f"nj-{user_slug}-{uid}"
        self.nat = nat
        self.forwards: List[Forward] = forwards or []

        # Derive a unique /30 subnet from uuid bytes to avoid collisions
        b = uid.bytes
        self._gw_ip   = f"10.{b[0]}.{b[1]}.1"
        self._jail_ip = f"10.{b[0]}.{b[1]}.2"
        self._cidr    = f"10.{b[0]}.{b[1]}.0/30"

        # Veth interface names must be <= 15 chars
        short = uid.hex[:8]
        self.veth_host = f"vh{short}"
        self.veth_jail = f"vj{short}"

        self._socat_procs: List[subprocess.Popen] = []
        self._nat_iface: Optional[str] = None
        self._cleaned_up = False

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def setup(self) -> None:
        ip = _require("ip")
        _sudo([ip, "netns", "add", self.name])
        _sudo([ip, "netns", "exec", self.name, ip, "link", "set", "lo", "up"])
        if self.nat:
            self._setup_nat()

    def _setup_nat(self) -> None:
        ip       = _require("ip")
        iptables = _require("iptables")
        sysctl   = _require("sysctl")
        self._nat_iface = _default_iface()
        dev = self._nat_iface

        # veth pair: one end in host namespace, one inside the jail
        _sudo([ip, "link", "add", self.veth_host,
               "type", "veth", "peer", "name", self.veth_jail])
        _sudo([ip, "link", "set", self.veth_jail, "netns", self.name])

        # Configure host end
        _sudo([ip, "addr", "add", f"{self._gw_ip}/30", "dev", self.veth_host])
        _sudo([ip, "link", "set", self.veth_host, "up"])

        # Configure jail end
        _sudo([ip, "netns", "exec", self.name,
               ip, "addr", "add", f"{self._jail_ip}/30", "dev", self.veth_jail])
        _sudo([ip, "netns", "exec", self.name,
               ip, "link", "set", self.veth_jail, "up"])
        _sudo([ip, "netns", "exec", self.name,
               ip, "route", "add", "default", "via", self._gw_ip])

        # NAT masquerade
        _sudo([sysctl, "-qw", "net.ipv4.ip_forward=1"])
        _sudo([iptables, "-t", "nat", "-A", "POSTROUTING",
               "-s", self._cidr, "-o", dev, "-j", "MASQUERADE"])
        _sudo([iptables, "-A", "FORWARD",
               "-i", self.veth_host, "-o", dev, "-j", "ACCEPT"])
        _sudo([iptables, "-A", "FORWARD",
               "-i", dev, "-o", self.veth_host,
               "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------
    def start_forwards(self) -> None:
        """For each --forward spec, run a socat inside the jail's netns.

        socat listens on the unix socket (which lives on the host filesystem,
        shared with the jail since netns does not isolate filesystems) and
        connects to the TCP address inside the jail. This avoids socat's
        experimental `netns=` option, which isn't available in older versions.
        """
        sudo  = _require("sudo")
        ip    = _require("ip")
        socat = _require("socat")

        for fwd in self.forwards:
            if os.path.exists(fwd.unix_socket):
                os.unlink(fwd.unix_socket)

            # Make the socket owned by the calling user so they can connect
            # to it without sudo. The `,user=` option on UNIX-LISTEN chowns
            # after bind.
            user = _calling_user()
            socat_cmd = [
                sudo, ip, "netns", "exec", self.name,
                socat,
                "-d0",  # only log fatal errors; suppresses the SIGTERM warning on cleanup
                f"UNIX-LISTEN:{fwd.unix_socket},fork,reuseaddr,user={user}",
                f"TCP:{fwd.host}:{fwd.port}",
            ]
            _log(socat_cmd)
            proc = subprocess.Popen(
                socat_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            self._socat_procs.append(proc)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------
    def run(self, cmd: List[str]) -> int:
        user = _calling_user()
        full_cmd = [
            _require("sudo"), _require("ip"),
            "netns", "exec", self.name,
            _require("sudo"), "-u", user, "--",
        ] + cmd
        return subprocess.run(full_cmd).returncode

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True

        for proc in self._socat_procs:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        for fwd in self.forwards:
            if os.path.exists(fwd.unix_socket):
                try:
                    os.unlink(fwd.unix_socket)
                except OSError:
                    pass

        if self.nat:
            self._cleanup_nat()

        _sudo([_require("ip"), "netns", "del", self.name], check=False)

    def _cleanup_nat(self) -> None:
        ip       = _require("ip")
        iptables = _require("iptables")
        dev = self._nat_iface
        if dev:
            _sudo([iptables, "-t", "nat", "-D", "POSTROUTING",
                   "-s", self._cidr, "-o", dev, "-j", "MASQUERADE"], check=False)
            _sudo([iptables, "-D", "FORWARD",
                   "-i", self.veth_host, "-o", dev, "-j", "ACCEPT"], check=False)
            _sudo([iptables, "-D", "FORWARD",
                   "-i", dev, "-o", self.veth_host,
                   "-m", "state", "--state", "RELATED,ESTABLISHED",
                   "-j", "ACCEPT"], check=False)
        _sudo([ip, "link", "del", self.veth_host], check=False)


# ---------------------------------------------------------------------------
# Sudoers generation
# ---------------------------------------------------------------------------
def print_sudoers(nat: bool, forwards: List[Forward]) -> None:
    try:
        user = _calling_user()
    except Exception:
        user = "%user%"
    ip    = _require("ip")
    sudo  = _require("sudo")
    socat    = _require("socat") if forwards else None
    iptables = _require("iptables") if nat else None
    sysctl   = _require("sysctl") if nat else None

    flags = ("--nat " if nat else "") + " ".join(f"--forward {f}" for f in forwards)
    lines = [
        "# netns-jail sudoers rules",
        f"# Generated by: netns-jail --sudoers {flags}".rstrip(),
        "# Install with: netns-jail --sudoers | sudo tee /etc/sudoers.d/netns-jail",
        "",
        "# Preserve SUDO_USER so netns-jail can drop back to the calling user",
        "Defaults env_keep += SUDO_USER",
        "",
        "# Core namespace operations",
        f"{user} ALL=(root) NOPASSWD: {ip} netns add nj-{user[:5]}-*",
        f"{user} ALL=(root) NOPASSWD: {ip} netns del nj-{user[:5]}-*",
        f"{user} ALL=(root) NOPASSWD: {ip} netns exec nj-{user[:5]}-* {sudo} -u {user} -- *",
        f"{user} ALL=(root) NOPASSWD: {sudo} -u {user} -- *",
    ]
    if nat:
        lines += [
            "",
            "# NAT / veth setup",
            f"{user} ALL=(root) NOPASSWD: {ip} link add * type veth peer name *",
            f"{user} ALL=(root) NOPASSWD: {ip} link set * netns netns-jail-*",
            f"{user} ALL=(root) NOPASSWD: {ip} link set * up",
            f"{user} ALL=(root) NOPASSWD: {ip} link del *",
            f"{user} ALL=(root) NOPASSWD: {ip} addr add * dev *",
            f"{user} ALL=(root) NOPASSWD: {ip} route add *",
            f"{user} ALL=(root) NOPASSWD: {sysctl} -qw net.ipv4.ip_forward=1",
            f"{user} ALL=(root) NOPASSWD: {iptables} -t nat -A POSTROUTING *",
            f"{user} ALL=(root) NOPASSWD: {iptables} -t nat -D POSTROUTING *",
            f"{user} ALL=(root) NOPASSWD: {iptables} -A FORWARD *",
            f"{user} ALL=(root) NOPASSWD: {iptables} -D FORWARD *",
        ]
    if forwards:
        lines += [
            "",
            "# Unix socket forwarding (socat runs inside the jail's netns)",
            f"{user} ALL=(root) NOPASSWD: {ip} netns exec nj-{user[:5]}-* {socat} UNIX-LISTEN:* TCP:*",
        ]
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netns-jail",
        description="Run a process in its own network namespace jail.",
        epilog=(
            "Examples:\n"
            "  netns-jail -- nc -l 1000\n"
            "  netns-jail --nat -- nc -l 1000\n"
            "  netns-jail --nat --forward /tmp/foo.sock:localhost:1000 -- nc -l 1000\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print each command before running it.",
    )
    parser.add_argument(
        "--nat", action="store_true",
        help="Give the jail outbound internet access via NAT "
             "(no access to host loopback)",
    )
    parser.add_argument(
        "--forward", action="append", default=[], metavar="SOCK:HOST:PORT",
        help="Forward a unix domain socket into the jail's TCP port. "
             "May be repeated.",
    )
    parser.add_argument(
        "--sudoers", action="store_true",
        help="Print sudoers rules for this configuration and exit. "
             "Usage: netns-jail --sudoers [flags] | sudo tee /etc/sudoers.d/netns-jail",
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER,
        help="Command to run inside the jail (after --)",
    )
    args = parser.parse_args()

    global _debug
    _debug = args.debug

    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd

    forwards = []
    for spec in args.forward:
        try:
            forwards.append(Forward.parse(spec))
        except ValueError as e:
            parser.error(str(e))

    if args.sudoers:
        print_sudoers(args.nat, forwards)
        return

    if not cmd:
        parser.error("No command specified. Use -- <command>")

    jail = NetnsJail(nat=args.nat, forwards=forwards)

    def _on_signal(signum, frame):
        jail.cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    atexit.register(jail.cleanup)

    try:
        jail.setup()
        jail.start_forwards()
        rc = jail.run(cmd)
    except Exception as e:
        print(f"netns-jail: {e}", file=sys.stderr)
        jail.cleanup()
        sys.exit(1)

    sys.exit(rc)


if __name__ == "__main__":
    main()