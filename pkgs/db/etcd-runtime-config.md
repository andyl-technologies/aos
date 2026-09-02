# etcd runtime configuration

The `etcd` package owns the `etcd.*` option root and the singleton
`etcd.service`. Configuration is rendered as native JSON at
`/etc/aos/packages/etcd/etcd.json`; changes and enablement transitions restart
the service because etcd does not reload its configuration in place.

Client and peer TLS material is represented only by opaque AOS credential
references. At activation it is delivered to the service's volatile,
mode-restricted systemd credential directory. Secret bytes never enter a Nix
expression, generated `/etc` file, package manifest, or store path.

The initial cluster token identifies a cluster and is not an authentication
secret. User and role provisioning is intentionally outside this module:
etcd's authentication API is transactional runtime state, and attempting to
encode an initial root password in declarative configuration creates unsafe
partial-bootstrap recovery cases. Operators should provision authentication
through a separately authenticated, idempotent controller after endpoint
health is established.

Other packages do not receive a contribution surface under `etcd.*`. Cluster
membership, listeners, TLS policy, and storage limits remain owner/operator
authority because changing them can replace consensus membership or expose the
database.
