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

## features

* Send IGMP and/or MLD queries to network.
* Listen for IGMP or MLD packets in network.
* Support IGMP v1/v2/v3 and MLD v1/v2 protocols.
* Support RAW AF_PACKET or AF_INET* socket modes.
* Support bound to interface or unbound listen.

## building

```
$ make
```

### defines

* `USE_COOKED_SOCKET` -- uses DGRAM instead of RAW type for AF_PACKET sockets.
* `DEBUG` -- enables DEBUG log level (enabled by default).

## running

Running without arguments acts as sender and emits IGMPv2 and MLDv1 packets
with default parameters to first eligible network interface over RAW packet
socket.

```
$ mcquery -h

Usage: mcquery [-i INTERFACE] [-u] [-n] [-l|-s] [igmp[:<version>[,<key>:<value>...]]] [mld[:<version>[,<key>:<value>...]]]

Options:
  -h, --help               Show this help text
  -v, --verbose            Perform verbose operation
  -s, --submit             Send multicast query (default)
  -l, --listen             Listen for multicast queries/reports
  -i, --interface <name>   Interface to use for sending/receiving multicast
  -u, --unbound            Do not bind to interface
  -n, --noraw              Use IP socket instead fo RAW socket

Parameters:
  * igmp:<version>         IGMP version, allowed values: 1, 2, 3, default: 2
  * mld:<version>          MLD version, allowed values: 1, 2, default: 1
  * rt|respond:<time>      Maximal response time, default: 10 seconds
  * gr|group:<address>     Specific group to query, default: no group
  * rs|suppress:<state>    Router suppresion, allowed values 'y', 'n', default: n
  * qr|robust:<value>      Querier robustness value, default: 2
  * qi|interval:<value>    Querier interval value, default: 125 sec
```

To send IGMP/MLD queries `-s|--submig` is optional. This mode has option
modifier `-i|--interface` to specify where to send queries to. When not
specified, first eligible interface is used.

To receive IGMP/MLD packets `-l|--listen` should be specified. This mode
has an option modifiers `-i|--interface` to specify where to bind socket
to or `-u|--unbound` to skip binding to socket. When non provided, first
eligible interface is used. Binding to interface is default option as it
gives more deterministic behaviour.

Last arguments specifies type of packets to emit or to listen to. They can
either be `igmp` or `mld`. When non provided, both IGMP and MLD assumed.
For send mode further colon and comma separated key-value pairs can modify
sending packets parameters.

### listen for IGMP and MLD

```
# ./mcquery -l
[N] RECV IGMPv2 Query     from 0.0.0.0                    to 224.0.0.1          on eth0            from 28:76:10:0B:EC:2A
[N] RECV MLD Done         from fe80::3ce8:8774:ec1:965f   to ff02::2            on eth0            from 70:85:C2:40:C5:61
[N] RECV IGMP Leave       from 192.168.100.48             to 224.0.0.2          on eth0            from 70:85:C2:40:C5:61
[N] RECV MLDv2 Query      from fe80::2a76:10ff:fe09:9d5a  to ff02::1            on eth0            from 28:76:10:09:9D:5A
[N] RECV MLDv1 Report     from fe80::216:3eff:fedd:977d   to ff02::1:ffdd:977d  on eth0            from 00:16:3E:DD:97:7D
[N] RECV IGMPv2 Query     from 0.0.0.0                    to 224.0.0.1          on eth0            from 28:76:10:14:EF:FC
```

More less the same can be captured using:

```
# tcpdump -nneli eth0 multicast and not broadcast
```

### send IGMP and MLD

```
# ./mcquery -i eth0 igmp mld
```

### send IGMP with custom params

```
# ./mcquery -i eth0 igmp:3,respond:5,group:239.1.2.3,robust:4,interval:100
```
