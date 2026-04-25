# netns jail
Run a process in its own network jail. Provide some convenience functions for limited access.

This is unreviewed AI-generated code. However, I use it.

## Motivation
I have spent too much time on multiuser linux servers, but I really dislike running privileged services on open, unsecured ports on local host. However, some services just work like this and I am not able to patch all of them to support auth or another mechanism.

Thus can be solved with containerisation like docker or podman, but thus can become quiet heavy weight and start using a lot of disk.

`netns-jail` provides *limited* isolation, by just wrapping the network stack (netns), while also handling nat and tunnelling, and limited privilege escalation via Saudi.


##  Alterantives and prior work
You can do this yourself with `netns` or use something like `docker` for complete containerisation. There are likely other 
containerisation solutions.

`iptables` has some crazy modules that allow you to limit port access to certain users but this rather magical and difficult to debug.

## Installation
`pipx install netns-jail`

## Usage
Run something listening on localhost inside the jail
`netns-jail --forward /tmp/test.sock:localhost:1024  -- nc -l 1024`

Connect to it form outside using the socket.
`nc -U /tmp/test.sock`

If you want to be able to connect to the internet and use dns use --nat and --dns respectively like so:

`netns-jail --dns --nat curl https://www.google.com/`

If you run with --sudoers netns will create a set of sudo rules to allow netns-jail to run without prompting for a password, if you add these rules to sudoers.

