##! systems/server-rfc0011.nix — RFC-0011 new-path server (no Ignition)
##!
##! Same as `systems/server.nix` but provisioned by the RFC-0011 path instead of
##! Ignition: the `aos metadata` agent fetches the operator `host.nix`, the
##! `systemd-repart` substrate carves the disk, and (once the in-image base
##! library is built) on-host `config-eval` renders generations. Ignition stands
##! down (`aos.provisioning.ignition.enable = false`), so the neutral boot
##! infrastructure orders against the new backends via the provisioning-backend
##! indirection in modules/services/ignition.nix.
##!
##! `aos.config.evalAtBoot` stays off here until the base-lib builder lands; the
##! box boots on the baked gen-0 toplevel and the metadata agent stashes (but
##! does not yet apply) the operator host.nix.
{...}: {
  aos.profiles.server.enable = true;
  aos.profiles.debug.enable = true;
  aos.profiles.debug.autologin = true;

  # The RFC-0011 provisioning path.
  aos.provisioning.ignition.enable = false;
  aos.provisioning.repart.enable = true;
  aos.metadata.enable = true;
}
