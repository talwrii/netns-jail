# netns jail
Run a process in its own network jail. Provide some convenience functions for limited access.

This is unreviewed AI-generated code. However, I use it.

## Motivation
I might be a bit oldschool, but I really dislike open sockets, unsecured sockets on localhost which allow privileged access to things. However, some services work like this and I am not about to go and match them all. The reason I describe this as oldskool is that you may choose to have one user per machine and use docker containerisation such that everyprocess having access to your localhost running all sorts of powerful things is not an issue.

This is a little jail which gives a process its own little network stack using linuxes `netns` containment. It can then optioally tunnel in secure connections using unix domain sockets.


##  Alterntives and prior work
You can do this yourself with `netns` or use something like `docker` for complete containerisation. For some use cases I explicitly want a shared filesystem for libraries and file access. There are likely other jail systems.

`iptables` has some crazy modules that allow you to limit port access to certain users but this rather crazy and hard to debug.

## Installation
pipx install netns-jail

## Usage
Run something listening on localhost inside the jail
`netns-jail --forward /tmp/test.sock:localhost:1024  -- nc -l 1024`

Connect to it form outside using the socket.
`nc -U /tmp/test.sock`

If you want to be able to connect to the internet and use dns use --nat and --dns respectively like so:

`netns-jail --dns --nat curl https://www.google.com/`


