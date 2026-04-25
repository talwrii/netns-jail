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
import time
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

    def __init__(self, nat: bool = False, forwards: Optional[List[Forward]] = None,
                 dns: bool = False):
        uid = uuid.uuid4()
        user_slug = _calling_user()[:5]
        self.name = f"nj-{user_slug}-{uid}"
        self.nat = nat
        self.dns = dns
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

        # DNS tunnel uses a dedicated unix datagram socket per jail.
        self._dns_sock = f"/tmp/netns-jail-{uid.hex[:8]}-dns.sock"
        # Unprivileged port we redirect :53 traffic to inside the jail.
        self._dns_redirect_port = 5354
        # Where the host-side forwarder sends queries. systemd-resolved's stub
        # resolver is the common default on Ubuntu/Debian.
        self._dns_upstream_host = "127.0.0.53"
        self._dns_upstream_port = 53

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def setup(self) -> None:
        ip = _require("ip")
        _sudo([ip, "netns", "add", self.name])
        _sudo([ip, "netns", "exec", self.name, ip, "link", "set", "lo", "up"])
        if self.nat:
            self._setup_nat()
        if self.dns:
            if not self.nat:
                # DNS tunnel doesn't need NAT to reach the unix socket (the
                # socket is on shared filesystem), but the host-side socat
                # needs to actually reach a resolver — which is an outbound
                # network call. If you really wanted DNS without NAT, the
                # outside socat would still work. So we allow it.
                pass
            self._setup_dns()

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

    def _setup_dns(self) -> None:
        """Tunnel jail DNS queries over a unix datagram socket.

        Inside the jail: iptables redirects :53 UDP traffic to an unprivileged
        port where `netns-jail --dns-to-sock` listens. Each datagram is
        forwarded to a unix datagram socket on the shared filesystem.

        On the host: `netns-jail --sock-to-dns` reads from that unix socket
        and forwards to the host's real DNS resolver.

        We invoke ourselves (sys.argv[0]) as the forwarder so there's only one
        binary to install.
        """
        ip       = _require("ip")
        iptables = _require("iptables")
        sysctl   = _require("sysctl")
        user     = _calling_user()
        self_bin = os.path.abspath(sys.argv[0])

        # DNAT to 127.0.0.1 requires route_localnet=1 — without it, the kernel
        # drops packets whose post-NAT destination is in 127.0.0.0/8 when they
        # weren't already loopback-bound.
        _sudo([ip, "netns", "exec", self.name,
               sysctl, "-qw", "net.ipv4.conf.all.route_localnet=1"])

        # iptables rule lives inside the netns and vanishes when the netns is
        # deleted — no cleanup needed.
        # Use DNAT (not REDIRECT) so both destination address and port are
        # rewritten. REDIRECT would only change the port, leaving e.g.
        # 127.0.0.53:53 as 127.0.0.53:5354 — which nothing listens on.
        _sudo([ip, "netns", "exec", self.name,
               iptables, "-t", "nat", "-A", "OUTPUT",
               "-p", "udp", "--dport", "53",
               "-j", "DNAT",
               "--to-destination", f"127.0.0.1:{self._dns_redirect_port}"])

        # Host-side first so the unix socket exists when the jail-side starts.
        if os.path.exists(self._dns_sock):
            os.unlink(self._dns_sock)

        outside_cmd = [
            self_bin, "--sock-to-dns",
            self._dns_sock,
            # Special token — sock-to-dns reads /etc/resolv.conf
            "resolv.conf",
        ]
        _log(outside_cmd)
        self._socat_procs.append(subprocess.Popen(
            outside_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL))

        # Wait briefly for the socket to appear before starting the jail side.
        for _ in range(50):
            if os.path.exists(self._dns_sock):
                break
            time.sleep(0.02)

        # Jail-side: runs as the calling user inside the netns.
        inside_cmd = [
            _require("sudo"), ip, "netns", "exec", self.name,
            _require("sudo"), "-u", user, "--",
            self_bin, "--dns-to-sock",
            f"127.0.0.1:{self._dns_redirect_port}",
            self._dns_sock,
        ]
        _log(inside_cmd)
        self._socat_procs.append(subprocess.Popen(
            inside_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL))

        # Wait for dns-to-sock to actually be listening on 127.0.0.1:5354
        # inside the jail, otherwise the user's command can race ahead and
        # send DNS queries that get ICMP-unreachable replies.
        ss = shutil.which("ss")
        if ss is not None:
            for _ in range(100):
                r = subprocess.run(
                    [_require("sudo"), ip, "netns", "exec", self.name,
                     ss, "-nlu", "-H"],
                    capture_output=True, text=True,
                )
                if f":{self._dns_redirect_port}" in r.stdout:
                    break
                time.sleep(0.02)

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
        if self.dns:
            self._cleanup_dns()

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

    def _cleanup_dns(self) -> None:
        if os.path.exists(self._dns_sock):
            try:
                os.unlink(self._dns_sock)
            except OSError:
                pass


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
            "",
            "# Per-namespace /etc/resolv.conf",
            f"{user} ALL=(root) NOPASSWD: /bin/mkdir -p /etc/netns/nj-{user[:5]}-*",
            f"{user} ALL=(root) NOPASSWD: /bin/sh -c printf*/etc/netns/nj-{user[:5]}-*/resolv.conf",
            f"{user} ALL=(root) NOPASSWD: /bin/rm -rf /etc/netns/nj-{user[:5]}-*",
        ]
    if forwards:
        lines += [
            "",
            "# Unix socket forwarding (socat runs inside the jail's netns)",
            f"{user} ALL=(root) NOPASSWD: {ip} netns exec nj-{user[:5]}-* {socat} UNIX-LISTEN:* TCP:*",
        ]
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# DNS forwarders (used by --dns-to-sock / --sock-to-dns modes)
# ---------------------------------------------------------------------------
def _parse_host_port(spec: str):
    if ":" not in spec:
        raise SystemExit(f"expected HOST:PORT, got {spec!r}")
    host, _, port = spec.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit(f"port must be an integer, got {port!r}")


def _dns_to_sock(listen_spec: str, unix_path: str) -> None:
    """Run a UDP-listener -> unix-datagram-client forwarder forever."""
    import socket as _socket
    import tempfile

    host, port = _parse_host_port(listen_spec)

    udp = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    udp.bind((host, port))
    print(f"[dns-to-sock] listening on {host}:{port} -> {unix_path}",
          file=sys.stderr)

    unix = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    return_path = tempfile.mktemp(
        prefix=f"netns-jail-dns-to-sock-{os.getpid()}-", suffix=".sock")
    unix.bind(return_path)
    try:
        while True:
            try:
                query, client = udp.recvfrom(65535)
            except KeyboardInterrupt:
                break
            try:
                unix.sendto(query, unix_path)
            except OSError as e:
                print(f"[dns-to-sock] sendto({unix_path}) failed: {e}",
                      file=sys.stderr)
                continue
            try:
                reply, _ = unix.recvfrom(65535)
            except OSError as e:
                print(f"[dns-to-sock] recvfrom unix failed: {e}",
                      file=sys.stderr)
                continue
            udp.sendto(reply, client)
    finally:
        try:
            os.unlink(return_path)
        except OSError:
            pass


def _read_resolv_conf_nameserver(path: str = "/etc/resolv.conf"):
    """Return (host, port) of the first 'nameserver' entry in resolv.conf.

    Port defaults to 53. Returns None if no nameserver found or file unreadable.
    """
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ns = parts[1]
                    # Handle rare "ip#port" or "ip:port" forms
                    if "#" in ns:
                        ip_str, _, port_str = ns.partition("#")
                        return ip_str, int(port_str)
                    return ns, 53
    except OSError:
        pass
    return None


def _sock_to_dns(unix_path: str, upstream_spec: str) -> None:
    """Run a unix-datagram-listener -> UDP-client forwarder forever.

    If upstream_spec is the special string 'resolv.conf', read
    /etc/resolv.conf and use the first nameserver.
    """
    import socket as _socket

    if upstream_spec == "resolv.conf":
        ns = _read_resolv_conf_nameserver()
        if ns is None:
            raise SystemExit("[sock-to-dns] could not find a nameserver in "
                             "/etc/resolv.conf")
        upstream_host, upstream_port = ns
    else:
        upstream_host, upstream_port = _parse_host_port(upstream_spec)

    if os.path.exists(unix_path):
        os.unlink(unix_path)
    unix = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    unix.bind(unix_path)
    os.chmod(unix_path, 0o666)
    print(f"[sock-to-dns] listening on {unix_path} -> "
          f"{upstream_host}:{upstream_port}", file=sys.stderr)

    upstream = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    upstream.settimeout(5.0)

    try:
        while True:
            try:
                query, peer = unix.recvfrom(65535)
            except KeyboardInterrupt:
                break
            if not peer:
                print(f"[sock-to-dns] skipping anonymous peer "
                      f"({len(query)} bytes)", file=sys.stderr)
                continue
            try:
                upstream.sendto(query, (upstream_host, upstream_port))
            except OSError as e:
                print(f"[sock-to-dns] sendto upstream failed: {e}",
                      file=sys.stderr)
                continue
            try:
                reply, _ = upstream.recvfrom(65535)
            except OSError as e:
                print(f"[sock-to-dns] recvfrom upstream failed: {e}",
                      file=sys.stderr)
                continue
            try:
                unix.sendto(reply, peer)
            except OSError as e:
                print(f"[sock-to-dns] sendto peer {peer} failed: {e}",
                      file=sys.stderr)
    finally:
        try:
            os.unlink(unix_path)
        except OSError:
            pass


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
        "--dns", action="store_true",
        help="Tunnel DNS queries from jail :53 to the host's resolver via a "
             "unix datagram socket. Useful with --nat.",
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
        "--dns-to-sock", nargs=2, metavar=("HOST:PORT", "UNIX-SOCK"),
        help="Forwarder mode: listen on UDP HOST:PORT, forward each datagram "
             "to the unix datagram socket UNIX-SOCK. Used internally by --dns, "
             "also usable standalone.",
    )
    parser.add_argument(
        "--sock-to-dns", nargs=2, metavar=("UNIX-SOCK", "HOST:PORT"),
        help="Forwarder mode: listen on unix datagram socket UNIX-SOCK, forward "
             "each datagram to UDP HOST:PORT. Pass 'resolv.conf' instead of "
             "HOST:PORT to use the first nameserver from /etc/resolv.conf. "
             "Used internally by --dns, also usable standalone.",
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER,
        help="Command to run inside the jail (after --)",
    )
    args = parser.parse_args()

    global _debug
    _debug = args.debug

    # Forwarder modes: don't touch the namespace at all, just run the proxy.
    if args.dns_to_sock:
        listen, sock = args.dns_to_sock
        _dns_to_sock(listen, sock)
        return
    if args.sock_to_dns:
        sock, upstream = args.sock_to_dns
        _sock_to_dns(sock, upstream)
        return

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

    jail = NetnsJail(nat=args.nat, forwards=forwards, dns=args.dns)

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