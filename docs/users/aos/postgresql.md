# Configure PostgreSQL

Install `postgresql`, then configure its package-owned `postgresql.*`
interface in `host.nix` or in a supplemental runtime module:

```nix
{
  aos.apm.desiredPackages = ["postgresql"];

  postgresql = {
    enable = true;
    clusterName = "application-db";
    listen = {
      addresses = ["127.0.0.1"];
      port = 5432;
    };
    bootstrap.password.ref = "system-credential:postgres-bootstrap";
    resources = {
      maxConnections = 200;
      sharedBuffers = "512MB";
    };
  };
}
```

The package renders `/etc/postgresql/postgresql.conf` and
`/etc/postgresql/pg_hba.conf`. The database cluster is initialized once in
`/var/lib/aos-pkg-postgresql/data` and remains there across package and
configuration generations. Desired configuration changes conservatively
restart the service because PostgreSQL cannot apply every server parameter by
reload; an explicit `systemctl reload postgresql.service` validates and reloads
reloadable changes.

`postgresql.settings` covers non-secret server parameters that do not yet have
a dedicated option. Dedicated settings such as `port`, `shared_buffers`, and
TLS paths cannot be overridden through that map. Values containing secret
material must never be placed in `settings`.

## Authentication and TLS

Host authentication is an ordered, typed rule list. The default accepts local
peer authentication and SCRAM authentication from loopback:

```nix
{
  postgresql.authentication.rules = [
    {
      type = "local";
      databases = ["all"];
      users = ["all"];
      method = "peer";
    }
    {
      type = "hostssl";
      databases = ["application"];
      users = ["application"];
      address = "10.20.0.0/16";
      method = "scram-sha-256";
    }
  ];
}
```

TLS and bootstrap secrets use opaque references. Secret bytes are delivered
through systemd credentials and never enter Nix evaluation:

```nix
{
  postgresql = {
    enable = true;
    bootstrap.password.ref = "system-credential:postgres-bootstrap";
    tls = {
      enable = true;
      certificate.ref = "system-credential:postgres-certificate";
      privateKey.ref = "system-credential:postgres-private-key";
      ca.ref = "system-credential:postgres-client-ca";
    };
  };
}
```

The bootstrap password is mounted only into the ordered
`postgresql-init.service` and consumed by `initdb` only when the state directory
does not contain a cluster. It is never mounted into the long-running
`postgresql.service`. Binding beyond loopback also requires an explicit host
firewall policy.

## Streaming replication

A primary enables replication-capable WAL by selecting the `primary` topology
and adding an appropriate `pg_hba` rule. Role creation remains an explicit
database administration operation:

```nix
{
  postgresql = {
    enable = true;
    topology = "primary";
    bootstrap.password.ref = "system-credential:postgres-bootstrap";
    replication = {
      walLevel = "replica";
      maxWalSenders = 10;
      maxReplicationSlots = 10;
    };
  };
}
```

A new standby obtains its initial cluster with `pg_basebackup`:

```nix
{
  postgresql = {
    enable = true;
    topology = "standby";
    replication = {
      primary = {
        host = "postgres-primary.internal";
        port = 5432;
      };
      user = "replicator";
      slot = "standby_1";
      passfile.ref = "desired-toml:postgres-replication-passfile";
    };
  };
}
```

The replication credential contains a complete libpq passfile entry, for
example `host:port:replication:user:password`, with mode 0600 supplied by the
credential resolver. Initialization and base backup are staged under the exact
service-owned `.data-initializing` sibling and atomically renamed into place.
An interrupted staging attempt is cleaned on retry. A final `data` directory
that is nonempty but lacks `PG_VERSION` is never deleted automatically; the
service fails closed so an operator can inspect it.
