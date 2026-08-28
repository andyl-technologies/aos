# Kerberos KDC runtime configuration

The `krb5` package owns the strict `krb5Kdc.*` runtime module. It can run the
MIT Kerberos key distribution center and, when requested, `kadmind` without
placing the database master password in a Nix store path or generation
manifest.

```nix
{
  krb5Kdc = {
    enable = true;
    enableAdminServer = true;
    realm = "EXAMPLE.COM";
    kdcServers = ["kdc.example.com"];
    adminServer = "kdc.example.com";
    masterPassword.ref = "system-credential:krb5-master-password";
    acl = ["*/admin@EXAMPLE.COM *"];
  };
}
```

The master password is delivered only to the one-shot database initializer.
The initialized principal database and stash remain in package-owned persistent
state. KDC and administration logs use systemd-managed storage, and the signed
expose declaration grants only low-port binding plus the documented network
ports.
