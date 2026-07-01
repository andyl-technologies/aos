##! systems/server-rfc0011.nix — server with on-host config evaluation enabled.
##!
##! The RFC-0011 provisioning path (`aos metadata` fetch + `systemd-repart` disks
##! + `aos-config-seed` files) is now the default for every system (Ignition has
##! been removed), so this variant differs from `systems/server.nix` only by
##! enabling `aos.config.evalAtBoot`: the in-image base library
##! (`aos.config.evalAtBoot.baseLib`, assembled by the system discovery in
##! `default.nix` via `mkBaseLib`) plus `aos-eval.service`, which recomputes a
##! config generation on-host from the verified `host.nix`. With no `host.nix`
##! present the service is a clean no-op and the box stays on the baked gen-0
##! toplevel.
{...}: {
  aos.profiles.server.enable = true;
  aos.profiles.debug.enable = true;
  aos.profiles.debug.autologin = true;

  # On-host config evaluation. `baseLib` is wired by the system discovery in
  # default.nix; the service is `ConditionPathExists`-guarded on host.nix.
  aos.config.evalAtBoot.enable = true;
}
