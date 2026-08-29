# conntrackd runtime configuration

The `conntrack-tools` package owns the strict `conntrackd.*` runtime module.
The daemon is disabled unless an operator-controlled supplemental module sets
`conntrackd.enable = true`.

Statistics mode records local kernel connection tracking events:

```nix
{
  conntrackd = {
    enable = true;
    mode = "stats";
    logConnections = true;
  };
}
```

FTFW synchronization mode replicates state over a dedicated UDP link:

```nix
{
  conntrackd = {
    enable = true;
    mode = "sync";
    sync = {
      interface = "eth1";
      localAddress = "192.0.2.10";
      peerAddress = "192.0.2.11";
      port = 3780;
    };
  };
}
```

The signed package declaration confines configuration to
`/etc/aos/packages/conntrackd/conntrackd.conf`, grants only the network
administration capabilities required for kernel conntrack access, and keeps
runtime sockets and logs in systemd-managed directories.
