# Control access to an AOS host

AOS separates account identity, remote authentication, configuration authority,
and recovery authorization. Configure each explicitly and retain an independent
recovery path while changing how operators reach a machine.

This guide covers interactive and remote access. Network addressing and
firewall policy are documented in [Configure networking](networking.md), secret
material in [Manage secrets on AOS](secrets.md), and recovery authorization in
[Recover an AOS host](recovery.md).

## Create named operator accounts

Prefer named accounts over shared root access. Assign stable numeric IDs where
persistent ownership or fleet consistency requires them:

```nix
{pkgs, ...}: {
  aos.users.groups.operator = {
    gid = 1000;
    members = ["operator"];
  };

  aos.users.users.operator = {
    uid = 1000;
    group = "operator";
    home = "/var/lib/operator";
    shell = "${pkgs.bash}/bin/bash";
    description = "Host operator";
    extraGroups = ["adm"];
  };

  environment.etc."ssh/authorized_keys/operator" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME operator@example.com\n";
    mode = "0600";
  };
}
```

Group membership is authorization. Review access implied by `adm`, device,
container, virtualization, storage, and service-specific groups before adding
an operator. Do not use a broad group merely to repair one file-permission
problem.

Public SSH keys may be built into an image or supplied by authenticated
configuration. Private keys must remain outside the repository and Nix store.

## Restrict SSH authentication

The SSH service defaults to key authentication, prohibits root password login,
disables password and keyboard-interactive authentication, and limits attempts.
Keep those defaults unless the replacement path has been tested on the exact
image:

```nix
{
  aos.services.ssh = {
    enable = true;
    port = 22;
    permitRootLogin = "no";
    passwordAuthentication = false;
    kbdInteractiveAuthentication = false;
    maxAuthTries = 3;
  };
}
```

Opening the SSH port and authorizing an identity are different changes. The SSH
module contributes its configured listener to the firewall, but a reachable
port does not grant an account access without a valid authentication path.

Keep a tested console or recovery route while changing SSH keys, users, OIDC
policy, DNS, time synchronization, or firewall rules. An atomically valid
configuration can still make a host unreachable.

## Use OIDC-backed SSH deliberately

`opkssh` can add OIDC-backed key lookup alongside the configured authorized-key
file:

```nix
{
  aos.services.opkssh = {
    enable = true;

    providers = [{
      issuer = "https://id.example.com";
      clientId = "aos-ssh";
      expirationPolicy = "12h";
    }];

    authRules = [{
      principal = "operator";
      identity = "platform@example.com";
      issuer = "https://id.example.com";
    }];

    denyUsers = ["root"];
  };
}
```

This configures `opkssh verify` as sshd's `AuthorizedKeysCommand`. Before
removing a static break-glass key, test:

- identity-provider reachability from the target network;
- token issuance and audience policy;
- clock synchronization and expiration behavior;
- mapping from external identity to the intended local principal;
- explicit denial of root and other protected accounts; and
- behavior during identity-provider or network failure.

OIDC changes the authentication source; it does not change the local account's
Unix permissions or group authority.

## Treat cloud identities as input, not grants

Native cloud metadata may contain public SSH keys or identity facts. AOS
normalizes them as typed evaluation inputs but does not automatically authorize
them. A trusted module must explicitly map an accepted fact to an account's
authorized-key entry.

This separation matters when the deployment uses platform-trusted `host.nix`:
access to the metadata channel is configuration authority. Deployments that do
not trust that channel should use signed configuration and a transport capable
of carrying its detached signature. See [Understand and operate
`host.nix`](host-nix.md#choose-the-trust-policy).

## Keep console and recovery authority distinct

Normal initrds have no interactive root-login fallback: the root password is
locked and upstream emergency and rescue logins are masked. Do not add a shared
image password. A credential present in every image authenticates nobody.

The signed recovery environment can boot without granting access to persistent
state. Reading or changing `/var`, opening a maintenance shell, or restoring an
inactive slot requires the per-machine off-host recovery key. Secure Boot
authenticates the recovery program; the recovery key authorizes the operator.

See [Recover an AOS host](recovery.md) before relying on recovery as the only
break-glass path.

## Verify effective access policy

After activation, inspect the running configuration rather than only the Nix
source:

```sh
getent passwd operator
id operator
sshd -T
systemctl status sshd.service
journalctl -u sshd.service -b
```

Test from the real operator network with the intended identity. Confirm that
authorized access succeeds and that password, root, expired OIDC, and unknown-
identity paths fail as designed.

When access fails, distinguish account creation, key material, identity-
provider behavior, listener state, routing, and firewall policy. See
[Troubleshoot an AOS host](troubleshooting.md#ssh-is-unreachable) for the
failure-oriented checklist.
