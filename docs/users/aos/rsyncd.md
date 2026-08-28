# Rsync daemon

Install `rsync` into the system package profile, then enable the package-owned
daemon from a supplemental runtime module:

```nix
{
  rsyncd = {
    enable = true;
    modules.backups = {
      comment = "Backups";
      readOnly = false;
      authUsers = ["backup"];
    };
    secrets.ref = "system-credential:rsyncd-secrets";
  };
}
```

Each module is rooted at `/var/lib/aos-pkg-rsyncd/exports/<name>`. Authentication
uses an opaque credential containing rsync `user:password` lines; secret bytes
are delivered through systemd credentials and never enter the generated config
or Nix store.
