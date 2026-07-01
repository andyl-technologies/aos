##! systems/server-rfc0011.nix — RFC-0011 new-path server (no Ignition)
##!
##! Same as `systems/server.nix`, provisioned by the RFC-0011 path: the
##! `aos metadata` agent fetches the operator `host.nix`, the `systemd-repart`
##! substrate carves the disk, and (once the in-image base library is built)
##! on-host `config-eval` renders generations. The neutral boot infrastructure
##! orders against these backends via the provisioning-backend indirection in
##! modules/services/boot-substrate.nix.
##!
##! `aos.config.evalAtBoot` is enabled: the in-image base library
##! (`aos.config.evalAtBoot.baseLib`) is assembled by the system discovery in
##! `default.nix` (`mkBaseLib`), and `aos-eval.service` recomputes a config
##! generation on-host from the verified `host.nix`. With no `host.nix` present
##! the service is a clean no-op and the box stays on the baked gen-0 toplevel.
{...}: {
  aos.profiles.server.enable = true;
  aos.profiles.debug.enable = true;
  aos.profiles.debug.autologin = true;

  # The RFC-0011 provisioning path.
  aos.provisioning.repart.enable = true;
  aos.provisioning.metadataAgent.enable = true;

  # On-host config evaluation. `baseLib` is wired by the system discovery in
  # default.nix; the service is `ConditionPathExists`-guarded on host.nix.
  aos.config.evalAtBoot.enable = true;
}
