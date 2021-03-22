[![Crate release version](https://flat.badgen.net/crates/v/passcod-noodle)](https://crates.io/crates/passcod-noodle)
[![Crate license: Apache 2.0 or MIT](https://flat.badgen.net/badge/license/Apache%202.0%20or%20MIT)][copyright]
![MSRV: latest stable](https://flat.badgen.net/badge/MSRV/latest%20stable/orange)
[![Uses Caretaker Maintainership](https://flat.badgen.net/badge/Caretaker/Maintainership%20👥%20/purple)][caretaker]

# Noodle

_AKA "someone stop Félix from naming things, please, this is terrible."_

- Go directly to the [usage summary](#obtain).
- [Dual-licensed][copyright] with Apache 2.0 and MIT.
- Uses [Caretaker Maintainership][caretaker].

[caretaker]: ./CARETAKERS.md
[copyright]: ./COPYRIGHT

## Introduction

Noodle as in pool noodle, because it floats and IPs and... geddit?

The idea is based on [MetalLB](https://metallb.universe.tf/concepts/layer2/).

Basically, we emit [RFC5944 "gratuitous" ARP announcements](https://tools.ietf.org/html/rfc5944#section-4.6).

Instead of the usual ARP request-reply "who has 1.2.3.4?" "I do" cycle, we send
"I have 1.2.3.4" and we add 1.2.3.4 to the network interface we do that from,
so the network stack handles traffic sent to it properly.

Noodle is the little daemon that does the ARP announcements like that.

But Noodle also listens for ARP on the interface. If it sees ARP on the
interface for the same IP it's announcing, but with a different MAC address, it
stops and exits!

When it stops, if it's being managed by an active orchestrator or supervisor,
it will get restarted. And if it's not, but for some reason wasn't shut down
when the orchestrator or supervisor went down, it wont come back up.

In any case, an active Noodle will keep spraying its ARP over the subnet
every N seconds, so well behaved devices like routers and VMs will keep
their ARP tables updated with the MAC of whatever device Noodle is on.

Essentially it's like MetalLB but we use the network itself as an additional
consensus layer, and the main consensus is via whatever orchestrator you use.
You can also disable the ARP watcher and/or only send a number of ARPs and then
quit, so you can build the orchestration a little more granularly yourself if
you want. It's up to you!

BTW this was written for use with Nomad but doesn't in any way depend on Nomad.

## Good times

### In a graceful move situation

Orchestrator will boot Noodle on the other Node, and then either the
orchestrator or the new ARP will kill the old Noodle. ARP tables will be
updated subnet-wide and most importantly at the router, and the IP will
essentially have "floated" over to the new node in short order.

The orchestrator, when configured properly, can also keep the old service
running for a bit before killing it even while starting the new one, so traffic
will move over as smoothly as it can (long connections may still get broken).

### In a failover situation

The old node will be dead. Traffic goes nowhere. Devices on the subnet
and the router still have the old MAC in the ARP tables.

Orchestrator notices a node is down, and reschedules its workload on the alive
nodes. Noodle starts, blathers ARP announcements over the network, tables get
updated, and traffic starts flowing again.

### In a split brain situation

Orchestrator worker node gets separated from the orchestrator's servers, or
talks to only one server and _it_ is separated from the others. In either case,
that node's orchestrator worker agent will:

- appear dead to the rest of the cluster, which will reschedule work as
  in the above, and
- notice that it's dead or doesn't have consensus, and _ideally_ will
  kill itself.

Proceeds mostly the same as failover, but may proceed as crash:

### In an orchestrator crash situation

Orchestrator crashes, leaving the underlying containers or applications
running. Rest of the cluster notices the node is dead and reschedules. The new
Noodle yells its announce, the old Noodle notices ARP that is not coming from
itself, and exits. Traffic moves over to the new node.

## Bad times

### Partial split brain where the old node still thinks it's meant to be up

Old orchestrator appears dead to the rest of the cluster, which reschedules.

Old Noodle notices ARP, and kills itself.

Old orchestrator restarts its Noodle.

New Noodle notices ARP, and kills itself.

New orchestrator restarts its Noodle.

Round and round it goes, traffic is mightily confused, routers might
take a hit.

### In a Noodle crash situation

Noodle crashes in the middle of its loops and doesn't clean up the IP on
its interface. Linux responds to ARP requests with solicited "it's me!"
while other Noodle is screaming out "it's me it's me it's me" announces.

Traffic and routers get confused.

_This is always a bug and should be reported._

### Operator accidentally scales the Noodle service for one floating IP to 2 or more instances

Proceeds like partial split brain except both nodes are technically legitimate.

## Alternatives

- Native Cloud Provider Floating IP: absolutely use that if available.

- Tunnels: requires router access to set up and tunnel endpoint at the
  service, can be connected to twice concurrently and then what. Adds a
  moving piece. But is much quieter on the network, cleaner
  traffic-wise, maybe clearer to netops.

- BGP: requires router access to set up, and complicated daemon on every
  node, plus management of said daemons' config. Does offer true IP-level
  load-balancing instead of just directing traffic to one host. BGP can
  be a pain and also may interfere with netops.

- DNS: externalises the problem, very slow to update even with TTL=0 because of
  client behaviour. Some traffic just never dies.

- Single VM acts as load-balancer and is never rebooted: not really an
  option, this is what we're trying to get away from.

- Transferring the entire NIC at the VM hypervisor level between machines
  instead of doing the ARP dance: certainly an option, relies on having
  hypervisor API access, needs some kind of centralised control to avoid
  split brain and conflicts. Implies downtime during the switching.

- Just changing the hypervisor MAC of the interfaces: same as previous,
  plus adds even more downtime as MACs can't conflict across VMs and
  it needs to find a free "transfer" mac or shut the old NIC down.

- Changing the ARP table of the router directly with the router's
  administrative API: doesn't yell so much into the void, but requires access
  to router, and some kind of synchronisation to avoid conflicting commands.

- VRRP, Tree Spanning, OSPF, bonding, etc: cool tech, may work, requires
  netops. May not handle intra-subnet traffic, only via router.

## Obtain

Only works on Linux.

Currently only ARP (supporting IPv4) is implemented.

### From binary release

The [release tab on GitHub](https://github.com/passcod/noodle/releases).

Builds are available for:

- x86-64, both gnu and musl
- AArch64, both gnu and musl
- Arm7 HF, both gnu and musl

It's trivial to add more, so please ask.

### ~~With cargo binstall~~

⚠  Not available yet, depends on [netlink#149](https://github.com/little-dude/netlink/issues/149)

```
cargo binstall passcod-noodle
```

### ~~From source~~

⚠  Not available yet, depends on [netlink#149](https://github.com/little-dude/netlink/issues/149)

```
cargo install passcod-noodle
```

You can also compile from the repo as usual.

## Use

Requires sudo or the correct capability (TBC).

Minimal command:

```
noodle --ip 10.9.8.7/24 --interface ens123
```

Mandatory options:

- `--ip IP/SUBNET`: the floating IP to announce.
- `--interface NAME`: which interface to announce ARP on.

Other options:

- `--mac ADDRESS`: override the MAC address IP is announced for (default=read from interface)
- `--target ADDRESS`: override the MAC address packets are sent to (default=broadcast)
- `--log LEVEL`: specify the log level (default=info). All logs are JSON.
- `--interval DURATION` in seconds (default=10): how often to announce.
- `--delay DURATION` in seconds (default=0): delay the first announce.
- `--watch-delay DURATION` in seconds (default=0): delay before watching for competings.
- `--jitter DURATION` in seconds (default=1): add jitter to each interval up to this value.
- `--arp-reply`: use ARP reply instead of ARP request as announcement type
- `--unmanaged-ip`: leave the interface alone (don't add/remove the ip)
- `--watch BEHAVIOUR`: control the competing announcement watcher:
  * `fail` (default): exit with status 1 if we see an announcement for this
    IP by another MAC address
  * `quit`: exit with status 0 instead
  * `log`: don't exit, only log it
  * `no`: don't watch
- `--watch-immediately`: don't wait until the first announce is sent to start watching.
- `--count N` (default=0/disabled): only announce this many times.
- `--once`: shorthand for `--count 1  --delay 0  --jitter 0  --watch no`.

Info switches:

- `--help`: print the help.
- `--readme`: print this readme.
- `--source`: print the source (Cargo.toml and main.rs).
- `--version`: print the version number.
