##! Canonical native one-time storage transaction contracts.
{lib}: let
  field = type: description: lib.mkOption {inherit type description;};
  defaulted = type: default: description: lib.mkOption {inherit type default description;};
  record = options: lib.types.submodule {inherit options;};
  text = lib.types.str;
  nullableText = lib.types.nullOr text;
  target = lib.types.taggedUnion "kind" {
    root-disk = record {kind = field (lib.types.enum ["root-disk"]) "Select the disk containing the root filesystem.";};
    device = record {
      kind = field (lib.types.enum ["device"]) "Select an explicit stable disk identity.";
      path = field text "Stable /dev/disk/by-id device path.";
    };
  };
  partition = record {
    target = field target "Exact partition target device selection.";
    label = field text "GPT partition label.";
    partition_type = field text "Validated GPT type or supported repart type.";
    size_min = field text "Minimum partition size.";
    size_max = defaulted nullableText null "Maximum partition size, when bounded.";
    weight = field lib.types.int "Allocation weight.";
    format = defaulted nullableText null "Optional initial filesystem format.";
    encryption = defaulted nullableText null "Declared encryption, or the measured-boot policy default.";
    uuid = defaulted nullableText null "Deterministic partition UUID.";
    grow = field lib.types.bool "Consume remaining available space.";
    grow_fs = field lib.types.bool "Allow filesystem growth.";
    priority = field lib.types.int "Deterministic placement priority.";
  };
  array = record {
    level = field text "Validated Linux MD RAID level.";
    members = field (lib.types.listOf text) "Logical partition names composing the array.";
    format = defaulted nullableText null "Initial array filesystem format.";
    encryption = defaulted nullableText null "Declared encryption, or the measured-boot policy default.";
  };
in {
  request = record {
    name = field text "Logical one-time transaction name.";
    enabled = defaulted lib.types.bool true "Enable initial provisioning.";
    root_device = field text "Root partition used to discover the containing disk.";
    measured_boot = field lib.types.bool "Enforce measured-boot storage policy.";
    policy = defaulted (record {
      initialize = defaulted (lib.types.enum ["if-unprovisioned"]) "if-unprovisioned" "Initialize only an absent durable layout.";
      committed_divergence = defaulted (lib.types.enum ["require-factory-reset"]) "require-factory-reset" "Require explicit factory reset after committed drift.";
    }) {} "One-time initialization and divergence policy.";
    prerequisites = defaulted (lib.types.listOf (lib.types.deferred text)) [] "Checked prerequisite resource identities.";
  };
  plan = record {
    schema = field (lib.types.enum ["aos.storage.provisioning-plan/v1"]) "Canonical plan schema.";
    source = field (lib.types.enum ["operator" "fallback"]) "Configuration source committed by the durable marker.";
    marker_uuid = field text "Exact durable provisioning marker UUID.";
    measured_boot = field lib.types.bool "Measured-boot policy used to validate this plan.";
    arrays = defaulted (lib.types.attrsOf array) {} "Canonical validated MD array definitions.";
    partitions = field (lib.types.attrsOf partition) "Canonical validated partition definitions.";
  };
  marker = record {
    schema = field (lib.types.enum ["aos.storage.provisioning-marker-observation/v1"]) "Durable marker observation schema.";
    state = field (lib.types.enum ["absent" "completed" "pending" "indeterminate"]) "Observed transaction state.";
    source = defaulted (lib.types.nullOr (lib.types.enum ["operator" "fallback"])) null "Committed configuration source.";
    marker_uuid = defaulted nullableText null "Committed durable marker UUID.";
  };
  tools = record {
    systemd_repart = field text "Exact retained repart executable.";
    blkid = field text "Exact retained filesystem inspection executable.";
    lsblk = field text "Exact retained block-device inspection executable.";
    sfdisk = field text "Exact retained GPT marker relabeling executable.";
    udevadm = field text "Exact retained device synchronization executable.";
    mdadm = field text "Exact retained MD array management executable.";
    mkfs_ext4 = field text "Exact retained ext4 formatting executable.";
    mkfs_xfs = field text "Exact retained XFS formatting executable.";
  };
}
