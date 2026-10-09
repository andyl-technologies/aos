##! Image-selected manager and fixed-service subdivisions of Components.
##!
##! M covers the whole original init.scope, including generators and remnants;
##! F covers only the named services below /aoscomponents.slice. PID1 installs
##! and verifies CPU, memory and PID controls before continuing generators.
##! Neither these DATA bytes nor a zero accounting field grants or denies an
##! effect. Other services and effects retain their existing owners and gates.
##! Earlier manager/image work and preexisting remnant page charges are not
##! retroactively controlled or paid by this frontier. NOFILE observations do
##! not establish privileged-remnant FD containment or full physical fit.
{
  config,
  lib,
  pkgs,
  ...
}: let
  bank = config.aos.sandbox.resourceBank;
  cfg = bank.parentEnclosure;
  # Provenance traversal inspects inactive payloads; the outer mkIf still
  # discards these definitions. Selected profiles retain their exact values.
  selectedValue = value: if cfg == null then null else value;
  dimensions = bank._dimensionOrder;
  unsigned = lib.types.addCheck lib.types.int (value: value >= 0);
  positive = lib.types.addCheck lib.types.int (value: value > 0);
  vectorType = lib.types.attrsOf unsigned;
  journalType = lib.types.submodule {
    options = lib.genAttrs ["systemMaxUse" "systemMaxFileSize" "runtimeMaxUse" "runtimeMaxFileSize"] (name:
      lib.mkOption {
        type = positive;
        description = "Configured ${name} retention target in bytes; rotation is not a hard disk quota.";
      });
  };

  # This is a finite role table, not a prefix-based capability or permission to
  # create services. The always-present journal helper is part of its roster.
  serviceNames =
    ["aos-journald-runtime-prep" "systemd-journald"]
    ++ lib.optional config.aos.sandbox.sourceSignerService.enable "aos-sandbox-source-signerd"
    ++ lib.optional config.aos.sandbox.sourceSignerView.enable "aos-sandbox-source-signer-view"
    ++ lib.optional config.aos.sandbox.cacheSignerService.enable "aos-sandbox-cache-signerd"
    ++ lib.optional config.aos.sandbox.cacheSignerView.enable "aos-sandbox-cache-signer-views"
    ++ lib.optionals config.aos.sandbox.policyAuthority.enable [
      "aos-sandbox-cache-journal-view"
      "aos-sandbox-policy-cache-recovery"
    ]
    ++ lib.optionals config.aos.security.audit.enable ["auditd" "audit-rules"];
  members = builtins.sort builtins.lessThan (
    ["aoscomponents.slice"] ++ builtins.map (name: "${name}.service") serviceNames
  );
  unitEntries = config.system.build.systemdEtcEntries;
  bodies = config.system.build.systemdUnitBodies;
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  leafOwnership = systemdLib.unitsToOwnership bodies config.system.build.systemdUnitOwners;
  entryPaths = builtins.attrNames unitEntries;
  dropinsFor = name:
    builtins.filter (path: lib.hasPrefix "systemd/system/${name}.d/" path) entryPaths;
  memberInventory = builtins.map (name: {
    inherit name;
    dropins = builtins.map (lib.removePrefix "systemd/system/") (dropinsFor name);
  }) members;

  # Register the existing package leaf through the same inventory resolver as
  # other package units. A drop-in alone does not put journald's base fragment
  # in systemdSystemUnits; no copied upstream definition or new derivation is
  # introduced by this purpose-local metadata on the same package outPath.
  journalInventory = config.systemd.package.systemdUnitInventory
    or (config.systemd.package.passthru.systemdUnitInventory or {});
  journalLeaf = "lib/systemd/system/systemd-journald.service";
  journalLeaves = [journalLeaf "etc/systemd/system/systemd-journald.service"];
  journalEntries = journalInventory.system or [];
  journalAlreadyInventoried = builtins.any (entry:
    (builtins.isString entry && builtins.elem entry journalLeaves)
    || (builtins.isAttrs entry && builtins.elem (entry.path or null) journalLeaves))
  journalEntries;
  journalPackage = config.systemd.package // {
    systemdUnitInventory = journalInventory // {
      system = journalEntries ++ lib.optional (!journalAlreadyInventoried) journalLeaf;
    };
  };

  manifest = pkgs.runCommand "aos-resource-parent-enclosure-v1" {
    nativeBuildInputs = [pkgs.python3 pkgs.coreutils];
    contractJson = builtins.toJSON cfg;
    policyJson = builtins.toJSON bank.policy;
    dimensionJson = builtins.toJSON dimensions;
    memberJson = builtins.toJSON memberInventory;
    auditEnabled = if config.aos.security.audit.enable then "yes" else "no";
  } ''
    set -eu
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 -B - "$out/enclosure.bin" \
      "${bank._imagePolicy}/bootstrap.bin" "${config.system.build.systemdSystemUnits}" <<'PY'
    import hashlib
    import json
    import os
    import struct
    import sys
    from pathlib import Path

    contract = json.loads(os.environ["contractJson"])
    policy = json.loads(os.environ["policyJson"])
    dimensions = json.loads(os.environ["dimensionJson"])
    members = json.loads(os.environ["memberJson"])
    maximum = (1 << 64) - 1
    if len(dimensions) != 22 or len(set(dimensions)) != 22:
        raise ValueError("parent enclosure requires the canonical complete dimension registry")

    def vector(values):
        if set(values) != set(dimensions):
            raise ValueError("parent accounting must explicitly contain every dimension")
        result = [values[name] for name in dimensions]
        if any(type(value) is not int or value < 0 or value > maximum for value in result):
            raise ValueError("parent accounting must be a finite unsigned vector")
        return result

    manager = vector(contract["manager"])
    fixed = vector(contract["fixedServices"])
    residual = vector(policy["components"])
    for name in ("hostService", "hostControl", "rootReceiving"):
        if policy.get(name) is not None:
            part = vector(policy[name])
            residual = [left - right for left, right in zip(residual, part)]
    if any(left + right > available for left, right, available in zip(manager, fixed, residual)):
        raise ValueError("M and F exceed the already committed Components baseline")

    nofiles = [contract["managerOpenFilesPerProcess"], contract["fixedOpenFilesPerProcess"]]
    for values, nofile in zip((manager, fixed), nofiles):
        if any(values[index] == 0 for index in (0, 1, 2, 3, 21)):
            raise ValueError("parent service accounting is incomplete")
        if values[0] % 1000 != 0 or values[0] > maximum // 10:
            raise ValueError("100ms CPU quota must convert exactly without overflow")
        if values[1] % 4096 != 0 or values[1] > (1 << 63) - 1 or values[2] > (1 << 63) - 1:
            raise ValueError("memory and PID controls must fit finite native bounds")
        if type(nofile) is not int or nofile <= 0 or nofile > (1 << 32) - 1:
            raise ValueError("per-process NOFILE must fit its finite native limit")
        if values[2] * nofile > values[3]:
            raise ValueError("aggregate FD provision does not cover tasks times per-process NOFILE")

    # Categories describe accounting, not effect authority: 1 is the three
    # hard native controls; 2 is a conservative positive provision; 0 is zero
    # baseline provision, never proof that a live effect cannot occur.
    def dispositions(values):
        return bytes(1 if index < 3 else (2 if value else 0)
                     for index, value in enumerate(values))

    # These targets are configured retention only. Active files, queue/kernel
    # memory, existing excess and imported daemon configuration are not proven
    # bounded here. Include an extra-file rotation provision, not a proven
    # retained-byte ceiling or filesystem quota.
    journal = contract["journal"]
    audit = contract["audit"]
    persistent = journal["systemMaxUse"] + journal["systemMaxFileSize"]
    runtime = journal["runtimeMaxUse"] + journal["runtimeMaxFileSize"]
    audit_rotation = (audit["maxLogFileMiB"] * (audit["numLogs"] + 1) * 1048576
                      if os.environ["auditEnabled"] == "yes" else 0)
    if fixed[6] < persistent + audit_rotation or fixed[7] < runtime:
        raise ValueError("F does not cover the configured journal/audit rotation provision")
    if fixed[1] < fixed[7]:
        raise ValueError("tmpfs accounting must also fit the fixed memory envelope")

    names = [member["name"] for member in members]
    if not 1 <= len(names) <= 16 or names != sorted(set(names)) or "aoscomponents.slice" not in names:
        raise ValueError("parent membership must be a bounded canonical fixed table")
    bootstrap = Path(sys.argv[2]).read_bytes()
    body = b"AOSRPE01" + hashlib.sha256(bootstrap).digest()
    body += struct.pack(">44Q", *(manager + fixed))
    body += struct.pack(">2Q", *nofiles)
    body += dispositions(manager) + dispositions(fixed) + struct.pack(">H", len(members))
    unit_root = Path(sys.argv[3])

    def field(value, width):
        encoded = value.encode("ascii")
        if not encoded or len(encoded) >= width or b"\0" in encoded:
            raise ValueError("parent name/path exceeds its fixed field")
        return encoded + bytes(width - len(encoded))

    def leaf(path):
        # Read the sole materializer's final bytes, including substituted job
        # scripts. Pure body text contains placeholders and is not this hash.
        with (unit_root / path).open("rb") as source:
            content = source.read(65537)
        if len(content) > 65536:
            raise ValueError("parent unit leaf exceeds its bounded acquisition")
        return field(path, 256) + hashlib.sha256(content).digest()

    for member in members:
        name = member["name"]
        dropins = member["dropins"]
        if dropins != sorted(set(dropins)) or len(dropins) > 4:
            raise ValueError("parent drop-in inventory exceeds its canonical bound")
        body += field(name, 64) + leaf(name) + struct.pack(">H", len(dropins))
        for path in dropins:
            prefix = name + ".d/"
            basename = path[len(prefix):] if path.startswith(prefix) else ""
            if not basename or "/" in basename or basename in (".", "..") or not basename.endswith(".conf"):
                raise ValueError("parent drop-in is not an exact unit-local image leaf")
            body += leaf(path)
        body += bytes((4 - len(dropins)) * 288)
    encoded = body + hashlib.sha256(body).digest()
    if len(encoded) != 486 + 1506 * len(members):
        raise ValueError("parent enclosure fixed wire geometry changed")
    Path(sys.argv[1]).write_bytes(encoded)
    PY
    chmod 0444 "$out/enclosure.bin"
  '';
in {
  options.aos.sandbox.resourceBank = {
    parentEnclosure = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          manager = lib.mkOption {
            type = vectorType;
            description = "Finite M accounting for the whole original init.scope, not PID1 alone.";
          };
          fixedServices = lib.mkOption {
            type = vectorType;
            description = "Finite F accounting for the named singleton service roster, not all node services.";
          };
          managerOpenFilesPerProcess = lib.mkOption {
            type = positive;
            description = "Checked PID1 NOFILE setting used for conservative task-times-limit accounting; not privileged-remnant FD confinement.";
          };
          fixedOpenFilesPerProcess = lib.mkOption {
            type = positive;
            description = "Selected fixed-service per-process NOFILE ceiling, conservatively multiplied by F tasks.";
          };
          journal = lib.mkOption {
            type = journalType;
            description = "Explicit persistent and runtime journal rotation targets; actual retained disk capacity remains a separate obligation.";
          };
          audit = lib.mkOption {
            type = lib.types.submodule {
              options = lib.genAttrs ["maxLogFileMiB" "numLogs" "maximumRules" "maximumRuleBytes" "maximumBacklog"] (name:
                lib.mkOption {
                  type = positive;
                  description = "Explicit configured audit ${name} bound; not a new reservation or daemon-consumption proof.";
                });
            };
            description = "Configured audit input and rotation bounds, including the kernel queue's separate ownership.";
          };
        };
      });
      default = null;
      description = "Optional original-image M/F control contract inside already committed Components; it grants no Source or Root receiving authority.";
    };
    _parentImage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      internal = true;
      readOnly = true;
      description = "Immutable parent control/accounting DATA consumed by original PID1 enrollment.";
    };
  };

  config = lib.mkIf (cfg != null) {
    assertions = [
      {
        assertion = bank.policy != null;
        message = "Parent enclosure requires the existing original resource bootstrap policy.";
      }
      {
        assertion = builtins.length members <= 16
          && builtins.all (name: bodies ? ${name} && bodies.${name}.enable && bodies.${name}.aliases == []) members
          && builtins.all (name: unitEntries ? ${"systemd/system/${name}"}
            && leafOwnership ? ${"systemd/system/${name}"}) members;
        message = "Parent roster requires every real enabled image base, including journald's package inventory.";
      }
      {
        assertion = builtins.all (name: builtins.length (dropinsFor name) <= 4
          && builtins.all (path: leafOwnership ? ${path}) (dropinsFor name)) members;
        message = "Parent roster has too many exact image drop-ins.";
      }
    ];

    aos.sandbox.resourceBank._parentImage = manifest;
    environment.etc."aos/resource-parent-enclosure-v1" = {
      source = "${manifest}/enclosure.bin";
      mode = "0444";
    };
    # Selection is independent of successful manifest acquisition: a missing
    # selected manifest cannot silently fall back to the ordinary null path.
    environment.etc."aos/resource-parent-enclosure-required-v1" = {
      text = "AOSRPE01";
      mode = "0444";
    };

    systemd.packages = [journalPackage];
    systemd.slices.aoscomponents = {
      description = "Image-selected fixed Components services";
      sliceConfig = {
        CPUAccounting = true;
        CPUQuotaPeriodSec = "100ms";
        CPUQuota = selectedValue "${toString (cfg.fixedServices.cpu-micros-per-period / 1000)}%";
        MemoryMax = selectedValue cfg.fixedServices.memory-bytes;
        MemorySwapMax = 0;
        TasksMax = selectedValue cfg.fixedServices.pids;
      };
    };
    systemd.services = lib.genAttrs serviceNames (_: {
      serviceConfig = {
        Slice = lib.mkForce "aoscomponents.slice";
        CPUAccounting = true;
        CPUQuotaPeriodSec = lib.mkForce "100ms";
        CPUQuota = lib.mkForce (selectedValue "${toString (cfg.fixedServices.cpu-micros-per-period / 1000)}%");
        MemoryMax = lib.mkForce (selectedValue cfg.fixedServices.memory-bytes);
        MemorySwapMax = lib.mkForce 0;
        TasksMax = lib.mkForce (selectedValue cfg.fixedServices.pids);
        LimitNOFILE = lib.mkForce (selectedValue cfg.fixedOpenFilesPerProcess);
      };
    });

    aos.journald = {
      maxUse = lib.mkForce (selectedValue (toString cfg.journal.systemMaxUse));
      systemMaxFileSize = lib.mkForce (selectedValue (toString cfg.journal.systemMaxFileSize));
      runtimeMaxUse = lib.mkForce (selectedValue cfg.journal.runtimeMaxUse);
      runtimeMaxFileSize = lib.mkForce (selectedValue cfg.journal.runtimeMaxFileSize);
    };
    # Definition collection inspects this leaf before filtering the outer mkIf.
    aos.security.audit.bounds = if cfg == null then null else cfg.audit;
  };
}
