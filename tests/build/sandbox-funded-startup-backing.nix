# Checks selected setup recipes against the genuine finite receiver budgets.
{
  lib,
  pkgs,
  systems,
}: let
  system = import ../fleet/_sandbox-funded-system.nix {inherit lib pkgs systems;};
  cfg = system.config;
  receivers = [
    {
      unit = "aos-sandbox-source-signerd";
      allocation = "sourceSignerReceiving";
    }
    {
      unit = "aos-sandbox-ownershipd";
      allocation = "ownershipReceiving";
    }
    {
      unit = "aos-sandbox-mountd";
      allocation = "mountReceiving";
    }
    {
      unit = "aos-netd";
      allocation = "networkReceiving";
    }
  ];
  canPrepare = receiver: let
    settings = cfg.systemd.services.${receiver.unit}.serviceConfig;
    budget = cfg.aos.sandbox.resourceBank.parentEnclosure.${receiver.allocation};
    # These capacities are debited before credential/device filesystem setup.
    deviceBytes =
      if settings.PrivateDevices or false
      then 4 * 1048576
      else 0;
    deviceEntries =
      if settings.PrivateDevices or false
      then 65536
      else 0;
    # Keep the arithmetic tied to these actual recipes. A disconnected
    # private tmp, tmpfs home or extra temporary filesystem needs new pricing.
    fixedTmpfsRecipe =
      (settings.PrivateTmp or false)
      == true
      && (settings.PrivateVarTmp or settings.PrivateTmp or false) == true
      && (settings.ProtectHome or false) == true
      && builtins.elem (settings.TemporaryFileSystem or null) [null "" []];
  in
    fixedTmpfsRecipe
    && budget.tmpfs-bytes
    >= 1048576 + deviceBytes
    && budget.memory-bytes >= budget.tmpfs-bytes
    && budget.metadata-entries > 1024 + deviceEntries
    && budget.mounts > 1;
in
  assert lib.all canPrepare receivers;
  # Node capacity stays fixed; the native parent compiler checks that every
  # receiver and the remaining logging provision fit the original F/Components.
  assert cfg.aos.sandbox.resourceBank.policy.capacity.tmpfs-bytes == 1073741824;
    pkgs.runCommand "sandbox-funded-startup-backing-check" {} ''
      test -s ${cfg.aos.sandbox.resourceBank._parentImage}/enclosure.bin
      touch "$out"
    ''
