# mcquery

`mcquery` is a trivial utility for multicast control testing.
Developed to simplify IGMP and MLD queriers debugging without
need to tamper with linux bridge driver. Furthermore it may
serve as sample code source for multicast sockets handling.

Inspired by and borrowed some of the design decision from
Joachim Wiberg's `mcjoin` tool (https://github.com/troglobit/mcjoin).

Utility is expected to be used by developers or testing engineers
debugging multicast issues or developing multicast features. In
consequence utility was designed to run only linux (or anything
POSIX compliant) without thought about exotic or irrelevant OSes,
i.e. Windows.

## building

```
$ make
```
