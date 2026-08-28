# OpenLDAP

The `openldap` package exposes a disabled-by-default directory server. Install
the package system-wide and enable it from a supplemental runtime module:

```nix
{
  openldap = {
    enable = true;
    suffix = "dc=example,dc=org";
    rootDn = "cn=admin,dc=example,dc=org";
    rootPassword.ref = "system-credential:ldap-admin-password";
  };
}
```

TLS certificate, private-key, and CA inputs are opaque credential references.
The administrator password is combined with the public signed configuration
only in a mode-0600 runtime file under `/run`; it never enters Nix evaluation or
the store. Directory data persists below `/var/lib/aos-pkg-openldap`.
