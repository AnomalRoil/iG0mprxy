# ig0mprxy

Is a basic IGMP proxy in Go to forward IGMP (multicast) packets from one interface to the other.

I had the issue on my Vyos router that igmproxy itself didn't seem to work to forward multicast packets across interfaces, and it was easier to do it in Go rather than trying to fix igmproxy or my kernel.

This is currently hardcoded to make tv7 from Init7 work.
It uses port 5000 for now.

TODO:
- [] support the igmproxy config files?

# Usage

```
./ig0mprxy eth0 eth1
```

