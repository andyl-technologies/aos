##! Typed execution scopes and their closed wire representation.
{lib}: let
  option = type: description: lib.mkOption {inherit type description;};
  text = description: option lib.types.str description;
  optionalText = description: (option (lib.types.nullOr lib.types.str) description) // {default = null;};
  strings = description: (option (lib.types.listOf lib.types.str) description) // {default = [];};
  natural = lib.types.addCheck lib.types.int (value: value >= 0);
  closed = options:
    lib.types.submodule {
      inherit options;
      config._module.strict = true;
    };
  defaultObject = type: description: (option type description) // {default = {};};
  platform = lib.types.enum ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

  cpu = closed {
    vendors = strings "Accepted CPU vendors; empty leaves vendor unconstrained.";
    models = strings "Accepted CPU family/model identities.";
    skus = strings "Accepted exact CPU SKUs; unknown observations cannot match.";
    features = strings "CPU features required by the artifact and functions.";
  };
  physical = closed {
    board = optionalText "Board or system identity constraint.";
    chipset = optionalText "Chipset or SoC identity constraint.";
  };
  qemu = closed {
    machine = text "QEMU machine family.";
    machine_version = optionalText "Versioned QEMU machine identity.";
    version = optionalText "QEMU build/version identity.";
    accelerator = option (lib.types.enum ["tcg" "kvm"]) "Execution accelerator, independent of architecture.";
    cpu_model = optionalText "QEMU guest CPU model.";
  };
  cloud = closed {
    provider = text "Cloud provider.";
    service = text "Provider service.";
    sku = text "Exact instance SKU.";
    region = optionalText "Region constraint.";
  };
  container = closed {
    runtime = option (lib.types.enum ["containerd-runc"]) "Container runtime implementation.";
    version = optionalText "Runtime build/version identity.";
    cgroup = optionalText "Cgroup mode.";
    network = optionalText "Network implementation/configuration identity.";
    volume = optionalText "Persistent volume implementation/configuration identity.";
  };
  backend = lib.types.submodule ({config, ...}: {
    options = {
      kind = option (lib.types.enum ["physical" "qemu" "cloud" "container"]) "Execution backend.";
      physical = (option (lib.types.nullOr physical) "Physical backend constraints.") // {default = null;};
      qemu = (option (lib.types.nullOr qemu) "QEMU backend constraints.") // {default = null;};
      cloud = (option (lib.types.nullOr cloud) "Cloud backend constraints.") // {default = null;};
      container = (option (lib.types.nullOr container) "Container backend constraints.") // {default = null;};
      export = (option lib.types.attrs "Closed backend wire value.") // {readOnly = true;};
    };
    config = {
      _module.strict = true;
      export = let
        kinds = ["physical" "qemu" "cloud" "container"];
        selected = builtins.filter (kind: config.${kind} != null) kinds;
      in
        if selected != [config.kind]
        then throw "An environment layer must configure exactly its selected backend."
        else {kind = config.kind;} // config.${config.kind};
    };
  });
  layer = closed {
    platform = (option (lib.types.nullOr platform) "Required layer platform; only outer hosts may be unconstrained.") // {default = null;};
    backend = option backend "Typed backend constraints for this layer.";
    cpu = defaultObject cpu "CPU compatibility scope for this layer.";
  };
  security = closed (builtins.listToAttrs (map (name: {
    inherit name;
    value = (option lib.types.bool "Requires ${name} in the observed boot state.") // {default = false;};
  }) ["secure_boot" "measured_boot" "verity" "encrypted_state" "persistent_firmware"]));
  resources = closed (builtins.listToAttrs (map (name: {
    inherit name;
    value = (option natural "Minimum subject ${name}.") // {default = 0;};
  }) ["cpus" "memory_mib" "disk_mib"]));
  device = closed {
    driver = text "Required bound Linux driver.";
    bus = optionalText "Required device bus.";
    vendor = optionalText "Required vendor/implementer identity.";
    product = optionalText "Required product/device identity.";
    revision = optionalText "Required device revision.";
    stage = option (lib.types.enum ["initrd" "runtime" "recovery"]) "Stage requiring the driver and firmware.";
    firmware = strings "Required firmware paths at that stage.";
  };
in {
  profile = closed {
    layers = option (lib.types.listOf layer) "Ordered outer-host-to-subject execution topology.";
    boot = option (lib.types.enum ["systemd-boot-uki" "linux-container" "native"]) "Boot implementation; no implicit fallback is admitted.";
    security = defaultObject security "Required boot-security properties.";
    resources = defaultObject resources "Minimum resources of the subject.";
    devices = (option (lib.types.listOf device) "Required device/driver bindings.") // {default = [];};
    kernel_options = (option (lib.types.attrsOf lib.types.str) "Required resolved kernel configuration values.") // {default = {};};
  };
  export = profile:
    profile
    // {
      layers = map (layer: layer // {backend = layer.backend.export;}) profile.layers;
    };
}
