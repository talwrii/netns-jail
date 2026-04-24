# netns jail
Run a process in its own network jail. Provide some convenience functions related to limited access.

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
netns-jail  -- nc -l 1000

Forward outgoing traffic through your default route interfaces (does not give access to loopback)
netns-jail --nat  -- nc -l 1000

netns-jail --nat --forward unix-domain.sock:localhost:1000  -- nc -l 1000
