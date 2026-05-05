# SPDX-License-Identifier: Apache-2.0
#
# Ignition config schema, transcribed from the upstream Go types.
#   Upstream path: config/v3_6/types/schema.go
#   Upstream repo: https://github.com/coreos/ignition
#   Upstream rev:  e3742b68017dc5d4561594b46751a08b013dedf1
#
# Portions © 2018 Red Hat, Inc. and the Ignition contributors.
# Used under the Apache 2.0 license; see the upstream LICENSE file for
# the full text.
#
# The v3.5 and v3.6 struct definitions are byte-identical — this file
# covers both. The default `version` is "3.5.0" to match the AOS
# ignition package (2.25.1), which accepts config versions up to 3.5
# inclusive. Callers targeting a future binary that understands v3.6
# can override with `lib.formats.ignition { ...; version = "3.6.0"; }`.
#
# Translation rules — applied mechanically from the Go struct tags:
#
#   Go `*T` (pointer)             → `types.nullOr T`, default null
#   Go `[]T` with omitempty       → `types.listOf T`, default []
#   Non-pointer, non-omitempty    → required (mkOption, no default)
#   Embedded non-pointer struct   → `types.nullOr <submodule>`, default null
#   Composite embed (Node + …)    → flattened into one submodule with
#                                   every embedded field declared directly
#
# Every submodule sets `strict = true`, so keys outside this schema
# throw at eval time. Ignition's Go JSON decoder does not reject
# unknown fields on its own, so eval-time strictness is the only line
# of defence before a config reaches the initrd.
#
# `allowStorageHardware = false` omits `storage.{disks,filesystems,
# raid,luks}` from the Storage submodule — combined with strict-mode
# this produces a readable "option 'storage.disks' is not declared"
# error at each forbidden def site. That flag is how the VM test
# harness rejects partitioning fields it does not own.
{
  lib,
  pkgs,
  version ? "3.5.0",
  allowStorageHardware ? true,
}: let
  inherit (lib) types mkOption;

  # Shortcut: every submodule in this schema is strict.
  strictSubmodule = opts:
    types.submodule {
      strict = true;
      options = opts;
    };

  # Field-shape shortcuts — named for the Go-side spelling so the
  # struct translations below read like the original `schema.go`.
  nullStr = mkOption {
    type = types.nullOr types.str;
    default = null;
  };
  nullInt = mkOption {
    type = types.nullOr types.int;
    default = null;
  };
  nullBool = mkOption {
    type = types.nullOr types.bool;
    default = null;
  };
  listOfStr = mkOption {
    type = types.listOf types.str;
    default = [];
  };
  nullSubmodule = sub:
    mkOption {
      type = types.nullOr sub;
      default = null;
    };
  listOfSubmodule = sub:
    mkOption {
      type = types.listOf sub;
      default = [];
    };

  # ── Leaf types ───────────────────────────────────────────────────────

  # type Verification struct { Hash *string }
  verificationType = strictSubmodule {
    hash = nullStr;
  };

  # type HTTPHeader struct { Name string; Value *string }
  httpHeaderType = strictSubmodule {
    name = mkOption {type = types.str;};
    value = nullStr;
  };

  # type Resource struct { Compression *string; HTTPHeaders []HTTPHeader;
  #                        Source *string; Verification Verification }
  # `Verification` is an embedded non-pointer → nullOr submodule.
  resourceType = strictSubmodule {
    compression = nullStr;
    httpHeaders = listOfSubmodule httpHeaderType;
    source = nullStr;
    verification = nullSubmodule verificationType;
  };

  # type NodeGroup struct { ID *int; Name *string }
  nodeGroupType = strictSubmodule {
    id = nullInt;
    name = nullStr;
  };

  # type NodeUser struct { ID *int; Name *string }
  nodeUserType = strictSubmodule {
    id = nullInt;
    name = nullStr;
  };

  # ── Filesystem nodes ─────────────────────────────────────────────────
  # Directory / File / Link all embed Node (path, overwrite, user,
  # group) plus their own embed struct. We flatten everything into one
  # submodule per node kind — each Go embed contributes its fields
  # directly so callers don't have to walk nested attrpaths that don't
  # appear in the JSON output.

  # type Node struct { Group NodeGroup; Overwrite *bool; Path string; User NodeUser }
  nodeFields = {
    group = nullSubmodule nodeGroupType;
    overwrite = nullBool;
    path = mkOption {type = types.str;};
    user = nullSubmodule nodeUserType;
  };

  # type Directory struct { Node; DirectoryEmbedded1 { Mode *int } }
  directoryType = strictSubmodule (nodeFields
    // {
      mode = nullInt;
    });

  # type File struct { Node; FileEmbedded1 { Append []Resource; Contents Resource; Mode *int } }
  fileType = strictSubmodule (nodeFields
    // {
      append = listOfSubmodule resourceType;
      contents = nullSubmodule resourceType;
      mode = nullInt;
    });

  # type Link struct { Node; LinkEmbedded1 { Hard *bool; Target *string } }
  linkType = strictSubmodule (nodeFields
    // {
      hard = nullBool;
      target = nullStr;
    });

  # ── Disks / RAID / LUKS / Filesystems ────────────────────────────────

  # type Partition struct { GUID; Label; Number int; Resize; ShouldExist;
  #                         SizeMiB; StartMiB; TypeGUID; WipePartitionEntry }
  # Note: `Number int` (not pointer) with omitempty. Modelled as nullOr
  # int so the null-prune step in `generate` can omit it when unset.
  partitionType = strictSubmodule {
    guid = nullStr;
    label = nullStr;
    number = nullInt;
    resize = nullBool;
    shouldExist = nullBool;
    sizeMiB = nullInt;
    startMiB = nullInt;
    typeGuid = nullStr;
    wipePartitionEntry = nullBool;
  };

  # type Disk struct { Device string; Partitions []Partition; WipeTable *bool }
  diskType = strictSubmodule {
    device = mkOption {type = types.str;};
    partitions = listOfSubmodule partitionType;
    wipeTable = nullBool;
  };

  # type Filesystem struct { Device string; Format; Label; MountOptions;
  #                          Options; Path; UUID; WipeFilesystem }
  filesystemType = strictSubmodule {
    device = mkOption {type = types.str;};
    format = nullStr;
    label = nullStr;
    mountOptions = listOfStr;
    options = listOfStr;
    path = nullStr;
    uuid = nullStr;
    wipeFilesystem = nullBool;
  };

  # type Raid struct { Devices []Device; Level; Name string; Options; Spares }
  raidType = strictSubmodule {
    devices = listOfStr;
    level = nullStr;
    name = mkOption {type = types.str;};
    options = listOfStr;
    spares = nullInt;
  };

  # type ClevisCustom struct { Config; NeedsNetwork; Pin }
  clevisCustomType = strictSubmodule {
    config = nullStr;
    needsNetwork = nullBool;
    pin = nullStr;
  };

  # type Tang struct { Advertisement; Thumbprint; URL string }
  # URL is non-pointer string with omitempty — model as nullOr str so
  # prune omits the empty-string case (also what Go's encoder does).
  tangType = strictSubmodule {
    advertisement = nullStr;
    thumbprint = nullStr;
    url = nullStr;
  };

  # type Clevis struct { Custom ClevisCustom; Tang []Tang; Threshold *int; Tpm2 *bool }
  clevisType = strictSubmodule {
    custom = nullSubmodule clevisCustomType;
    tang = listOfSubmodule tangType;
    threshold = nullInt;
    tpm2 = nullBool;
  };

  # type Cex struct { Enabled *bool }
  cexType = strictSubmodule {
    enabled = nullBool;
  };

  # type Luks struct { Cex; Clevis; Device *string; Discard; KeyFile Resource;
  #                    Label; Name string; OpenOptions; Options; UUID; WipeVolume }
  luksType = strictSubmodule {
    cex = nullSubmodule cexType;
    clevis = nullSubmodule clevisType;
    device = nullStr;
    discard = nullBool;
    keyFile = nullSubmodule resourceType;
    label = nullStr;
    name = mkOption {type = types.str;};
    openOptions = listOfStr;
    options = listOfStr;
    uuid = nullStr;
    wipeVolume = nullBool;
  };

  # ── Storage (varies on allowStorageHardware) ─────────────────────────

  # Always-available storage options.
  storageBaseFields = {
    directories = listOfSubmodule directoryType;
    files = listOfSubmodule fileType;
    links = listOfSubmodule linkType;
  };

  # Storage options that are omitted when allowStorageHardware = false.
  # Under that setting those paths are UNDECLARED, so strict-mode
  # throws at eval time if a caller writes to them. This is the lever
  # the VM test harness pulls: production/standalone callers get the
  # full schema; test configs get a subset that rejects partitioning.
  storageHardwareFields = {
    disks = listOfSubmodule diskType;
    filesystems = listOfSubmodule filesystemType;
    luks = listOfSubmodule luksType;
    raid = listOfSubmodule raidType;
  };

  storageType = strictSubmodule (
    storageBaseFields
    // lib.optionalAttrs allowStorageHardware storageHardwareFields
  );

  # ── systemd ──────────────────────────────────────────────────────────

  # type Dropin struct { Contents *string; Name string }
  dropinType = strictSubmodule {
    contents = nullStr;
    name = mkOption {type = types.str;};
  };

  # type Unit struct { Contents; Dropins []Dropin; Enabled; Mask; Name string }
  unitType = strictSubmodule {
    contents = nullStr;
    dropins = listOfSubmodule dropinType;
    enabled = nullBool;
    mask = nullBool;
    name = mkOption {type = types.str;};
  };

  # type Systemd struct { Units []Unit }
  systemdType = strictSubmodule {
    units = listOfSubmodule unitType;
  };

  # ── passwd ───────────────────────────────────────────────────────────

  # type PasswdGroup struct { Gid; Name string; PasswordHash; ShouldExist; System }
  passwdGroupType = strictSubmodule {
    gid = nullInt;
    name = mkOption {type = types.str;};
    passwordHash = nullStr;
    shouldExist = nullBool;
    system = nullBool;
  };

  # type PasswdUser struct { Gecos; Groups; HomeDir; Name string; NoCreateHome;
  #                          NoLogInit; NoUserGroup; PasswordHash; PrimaryGroup;
  #                          SSHAuthorizedKeys; Shell; ShouldExist; System; UID }
  passwdUserType = strictSubmodule {
    gecos = nullStr;
    groups = listOfStr;
    homeDir = nullStr;
    name = mkOption {type = types.str;};
    noCreateHome = nullBool;
    noLogInit = nullBool;
    noUserGroup = nullBool;
    passwordHash = nullStr;
    primaryGroup = nullStr;
    sshAuthorizedKeys = listOfStr;
    shell = nullStr;
    shouldExist = nullBool;
    system = nullBool;
    uid = nullInt;
  };

  # type Passwd struct { Groups []PasswdGroup; Users []PasswdUser }
  passwdType = strictSubmodule {
    groups = listOfSubmodule passwdGroupType;
    users = listOfSubmodule passwdUserType;
  };

  # ── kernelArguments ──────────────────────────────────────────────────

  # type KernelArguments struct { ShouldExist []KernelArgument; ShouldNotExist []KernelArgument }
  kernelArgumentsType = strictSubmodule {
    shouldExist = listOfStr;
    shouldNotExist = listOfStr;
  };

  # ── ignition metadata ────────────────────────────────────────────────

  # type IgnitionConfig struct { Merge []Resource; Replace Resource }
  ignitionConfigType = strictSubmodule {
    merge = listOfSubmodule resourceType;
    replace = nullSubmodule resourceType;
  };

  # type Proxy struct { HTTPProxy *string; HTTPSProxy *string; NoProxy []NoProxyItem }
  proxyType = strictSubmodule {
    httpProxy = nullStr;
    httpsProxy = nullStr;
    noProxy = listOfStr;
  };

  # type TLS struct { CertificateAuthorities []Resource }
  tlsType = strictSubmodule {
    certificateAuthorities = listOfSubmodule resourceType;
  };

  # type Security struct { TLS TLS }
  securityType = strictSubmodule {
    tls = nullSubmodule tlsType;
  };

  # type Timeouts struct { HTTPResponseHeaders *int; HTTPTotal *int }
  timeoutsType = strictSubmodule {
    httpResponseHeaders = nullInt;
    httpTotal = nullInt;
  };

  # type Ignition struct { Config IgnitionConfig; Proxy; Security; Timeouts; Version string }
  # Version is required; default to the factory's `version` arg so
  # callers can omit it in the common case.
  ignitionMetaType = strictSubmodule {
    config = nullSubmodule ignitionConfigType;
    proxy = nullSubmodule proxyType;
    security = nullSubmodule securityType;
    timeouts = nullSubmodule timeoutsType;
    version = mkOption {
      type = types.str;
      default = version;
    };
  };

  # ── root Config ──────────────────────────────────────────────────────

  # type Config struct { Ignition (required); KernelArguments; Passwd; Storage; Systemd }
  configType = strictSubmodule {
    ignition = mkOption {
      type = ignitionMetaType;
      default = {};
    };
    kernelArguments = nullSubmodule kernelArgumentsType;
    passwd = nullSubmodule passwdType;
    storage = nullSubmodule storageType;
    systemd = nullSubmodule systemdType;
  };

  # ── Serialisation: null/empty pruning ────────────────────────────────
  #
  # Recursively drops:
  #   - null values
  #   - empty lists and empty attrsets
  #   - the `_module` key at every level — it is engine-internal state
  #     populated by the synthetic internal module in `lib/modules.nix`
  #     (declares `_module.{args,freeformType,strict}`), surfaces on
  #     every submodule's evaluated result, and must not appear in the
  #     serialised Ignition JSON.
  #
  # Matches Go's zero-value omitempty behaviour closely enough that
  # `ignition-validate` accepts the output — explicit `null`s and all-
  # default empty objects are treated by Ignition's struct decoder as
  # equivalent to absence, but emitting them as literal JSON `null`s
  # confuses casual inspection of the config and risks tripping
  # stricter downstream validators. The outer attrset is returned
  # verbatim (unpruned at the root), so even an all-default Config
  # still serialises to a JSON object.
  prune = v:
    if builtins.isAttrs v
    then let
      kept = builtins.concatMap (
        name: let
          pv = prune v.${name};
        in
          if name == "_module" || pv == null
          then []
          else [
            {
              inherit name;
              value = pv;
            }
          ]
      ) (builtins.attrNames v);
      result = builtins.listToAttrs kept;
    in
      if result == {}
      then null
      else result
    else if builtins.isList v
    then let
      kept = builtins.filter (x: x != null) (builtins.map prune v);
    in
      if kept == []
      then null
      else kept
    else v;

  # `version` is required at the schema level (Ignition's
  # `Config.Ignition.Version` is a non-pointer `string`). The factory's
  # `version` arg gives every consumer a valid default — but the
  # `ignitionMetaType` submodule only fires that default when an
  # `ignition` definition reaches it. Callers that hand `generate` a
  # value built via raw `//` (not through the submodule, e.g.
  # `modules/roles/default.nix:168` composing `extras // { systemd = …; }`)
  # would otherwise produce a JSON with no `ignition` field at all, and
  # `ignition-validate` would reject it with "invalid config version
  # (couldn't parse)". Inject the default here so every JSON `generate`
  # emits is at minimum `{"ignition":{"version":"<version>"},...}`.
  pruneRoot = v: let
    p = prune v;
    base =
      if p == null
      then {}
      else p;
    ignition = base.ignition or {};
  in
    base
    // {
      ignition =
        ignition
        // {
          version = ignition.version or version;
        };
    };
in {
  type = configType;

  # Re-exported so the ignition-flavoured systemd lib at
  # `lib/modules/ignition/systemd.nix` can reuse the format's
  # submodule type for `dropins[]` without carrying a parallel
  # declaration whose shape would have to be kept in lock-step.
  inherit dropinType;

  # `generate name value` produces a derivation that materialises the
  # Ignition JSON and validates it with `ignition-validate`. Validation
  # at build time catches semantic errors (impossible partition sizing,
  # malformed GUIDs, unsupported resource URLs) that the eval-time
  # type check cannot.
  generate = name: value:
    pkgs.mkDerivation {
      pname = "format-ignition-${name}";
      inherit version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.ignition
      ];
      content = builtins.toJSON (pruneRoot value);
      passAsFile = ["content"];
      OUTPUT_NAME = name;
      phases = [
        {
          name = "emit-and-validate";
          script = ''
            cp "$contentPath" "$out/$OUTPUT_NAME"
            ignition-validate "$out/$OUTPUT_NAME"
          '';
        }
      ];
    };
}
