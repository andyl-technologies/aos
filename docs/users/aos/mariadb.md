# Configure MariaDB

Install `mariadb`, then configure its package-owned `mariadb.*` interface from
`host.nix` or a supplemental runtime module:

```nix
{
  aos.apm.desiredPackages = ["mariadb"];

  mariadb = {
    enable = true;
    bindAddress = "127.0.0.1";
    maxConnections = 250;
  };
}
```

The package writes a validated option file at
`/etc/aos/packages/mariadb/my.cnf`. Database state remains in
`/var/lib/aos-pkg-mariadb`; logs and the Unix socket use systemd-managed
directories. Initial system tables are created before the main service starts,
and MariaDB's `upgrade=AUTO` gate completes internal upgrades before the server
accepts clients.

## Credentials

TLS and bootstrap SQL use opaque references. Secret bytes are delivered only
through systemd's credential directory and never enter Nix evaluation:

```nix
{
  mariadb = {
    enable = true;
    tls = {
      enable = true;
      certificate.ref = "system-credential:mariadb-certificate";
      privateKey.ref = "system-credential:mariadb-private-key";
      ca.ref = "system-credential:mariadb-client-ca";
    };
    bootstrap = {
      adminSql.ref = "system-credential:mariadb-admin-bootstrap-sql";
      replicationSql.ref = "system-credential:mariadb-replication-bootstrap-sql";
    };
  };
}
```

Bootstrap credentials contain idempotent SQL statements, not Nix strings. They
are assembled into a mode-0600 volatile file immediately before startup and
removed after MariaDB reports readiness. This supports administrator and
replication-account rotation without putting passwords in the store or process
arguments. Restrict the network listener with `aos.firewall` when binding
beyond loopback.
