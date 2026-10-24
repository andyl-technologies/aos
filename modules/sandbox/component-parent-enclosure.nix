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
  retainedServiceDefinitions = builtins.path {
    path = ./_retained-service-definitions.nix;
    name = "aos-retained-service-definitions.nix";
  };
  # Provenance traversal inspects inactive payloads; the outer mkIf still
  # discards these definitions. Selected profiles retain their exact values.
  selectedValue = value:
    if cfg == null
    then null
    else value;
  dimensions = bank._dimensionOrder;
  bootPreparation =
    config.aos.sandbox.runtimeDeploymentPublisher.enable
    && config.aos.sandbox.runtimeDeploymentPublisher.bootPreparation;
  confinedViewPreparation =
    config.aos.sandbox.policyAuthority.enable
    && config.aos.security.selinux.enable
    && config.aos.security.selinux.bootMode == "immutable-stage0";
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
    ++ lib.optional config.aos.sandbox.ownershipAuthority.enable "aos-sandbox-ownershipd"
    ++ lib.optional config.aos.sandbox.sourceSignerView.enable "aos-sandbox-source-signer-view"
    ++ lib.optional config.aos.sandbox.cacheSignerService.enable "aos-sandbox-cache-signerd"
    ++ lib.optional config.aos.sandbox.cacheSignerView.enable "aos-sandbox-cache-signer-views"
    ++ lib.optional config.aos.sandbox.mountBroker.enable "aos-sandbox-mountd"
    ++ lib.optional config.aos.sandbox.networkBroker.enable "aos-netd"
    ++ lib.optionals config.aos.sandbox.policyAuthority.enable [
      "aos-sandbox-cache-journal-view"
      "aos-sandbox-policy-cache-recovery"
    ]
    ++ lib.optional confinedViewPreparation "aos-sandbox-view-roots"
    ++ lib.optionals config.aos.security.audit.enable ["auditd" "audit-rules"];
  members = builtins.sort builtins.lessThan (
    ["aoscomponents.slice"]
    ++ builtins.map (name: "${name}.service") serviceNames
    ++ lib.optional bootPreparation "aos-sandbox-runtime-publisher.service"
  );
  unitEntries = config.system.build.systemdEtcEntries;
  bodies = config.system.build.systemdUnitBodies;
  nativeAuditNames = lib.optionalAttrs config.aos.security.audit.enable {
    "audit.auditd" = "auditd";
    "audit.audit-rules" = "audit-rules";
  };
  nativeAuditUnits = lib.mapAttrs' (key: name: let
    input = config.system.build.systemdBootstrapServices.${key};
  in
    lib.nameValuePair "${name}.service" {
      valid =
        input.enabled
        && input.service == name
        && input.manager_identity == null
        && (input.instantiation == null || input.instantiation.kind == "singleton");
      owner = config.system.build.systemdBootstrapServiceOwners.${key};
    })
  nativeAuditNames;
  # These are owners of actual final leaves, not a synthetic package inventory.
  leafOwnership =
    config.system.build.systemdEtcEntryOwners
    // lib.mapAttrs' (name: unit:
      lib.nameValuePair "systemd/system/${name}" unit.owner)
    nativeAuditUnits
    // lib.mapAttrs' (name: owner:
      lib.nameValuePair "systemd/system/${name}" owner)
    config.system.build.systemdPackagedUnitOwners;
  entryPaths = builtins.attrNames unitEntries;
  dropinsFor = name:
    builtins.filter (path: lib.hasPrefix "systemd/system/${name}.d/" path) entryPaths;
  memberInventory =
    builtins.map (name: {
      inherit name;
      dropins = builtins.map (lib.removePrefix "systemd/system/") (dropinsFor name);
    })
    members;

  manifest =
    pkgs.runCommand "aos-resource-parent-enclosure-v5" {
      nativeBuildInputs = [pkgs.python3 pkgs.coreutils];
      contractJson = builtins.toJSON cfg;
      policyJson = builtins.toJSON bank.policy;
      dimensionJson = builtins.toJSON dimensions;
      memberJson = builtins.toJSON memberInventory;
      sourceProfileValidator = ../../pkgs/system/_source-protected-profile.py;
      sourceProfileExec =
        if config.aos.sandbox.sourceSignerService.enable
        then "${config.aos.sandbox.sourceSignerService.package}/bin/aos-sandbox-source-signerd ${toString config.aos.sandbox.controller.uid} ${toString config.aos.sandbox.controller.gid} ${toString config.aos.sandbox.sourceSignerView.uid} ${toString config.aos.sandbox.sourceSignerView.gid}"
        else "";
      cacheProfileExec =
        if config.aos.sandbox.cacheSignerService.enable
        then "${config.aos.sandbox.cacheSignerService.package}/bin/aos-sandbox-cache-signerd ${toString config.aos.sandbox.controller.uid} ${toString config.aos.sandbox.controller.gid} ${toString config.aos.sandbox.cacheSignerView.uid} ${toString config.aos.sandbox.cacheSignerView.gid}"
        else "";
      auditEnabled =
        if config.aos.security.audit.enable
        then "yes"
        else "no";
      bootPreparationSelected =
        if bootPreparation
        then "yes"
        else "no";
      hostExecutionReceivingJson = builtins.toJSON config.aos.sandbox.hostBroker.executionReceiving;
    } ''
      set -eu
      ${pkgs.python3}/bin/python3 -B ${../../pkgs/system/tests/source-protected-profile.py} "$sourceProfileValidator"
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 -B - "$out/enclosure.bin" \
        "${bank._imagePolicy}/bootstrap.bin" "${config.system.build.managerConfiguration}/systemd-units" <<'PY'
      import hashlib
      import importlib.util
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
      source = vector(contract["sourceSignerReceiving"]) if contract["sourceSignerReceiving"] is not None else [0] * 22
      sender = vector(contract["sourceSignerSender"]) if contract["sourceSignerSender"] is not None else [0] * 22
      controller_sender = vector(contract["controllerSuccessorSender"]) if contract["controllerSuccessorSender"] is not None else [0] * 22
      ownership = vector(contract["ownershipReceiving"]) if contract["ownershipReceiving"] is not None else [0] * 22
      ownership_sender = vector(contract["ownershipSender"]) if contract["ownershipSender"] is not None else [0] * 22
      cache = vector(contract["cacheSignerReceiving"]) if contract["cacheSignerReceiving"] is not None else [0] * 22
      cache_sender = vector(contract["cacheSignerSender"]) if contract["cacheSignerSender"] is not None else [0] * 22
      mount = vector(contract["mountReceiving"]) if contract["mountReceiving"] is not None else [0] * 22
      mount_sender = vector(contract["mountSender"]) if contract["mountSender"] is not None else [0] * 22
      network = vector(contract["networkReceiving"]) if contract["networkReceiving"] is not None else [0] * 22
      network_sender = vector(contract["networkSender"]) if contract["networkSender"] is not None else [0] * 22
      boot_receiving = vector(contract["hostBootPreparationReceiving"]) if contract["hostBootPreparationReceiving"] is not None else [0] * 22
      boot_sender = vector(contract["hostBootPreparationSender"]) if contract["hostBootPreparationSender"] is not None else [0] * 22
      boot_selected = os.environ["bootPreparationSelected"] == "yes"
      if boot_selected != any(boot_receiving) or boot_selected != any(boot_sender):
          raise ValueError("Host boot preparation requires both genuine M/HostService subdivisions")
      if boot_selected:
          if policy.get("hostService") is None:
              raise ValueError("Host boot preparation requires the existing HostService allocation")
          host_service = vector(policy["hostService"])
          host_receiving = json.loads(os.environ["hostExecutionReceivingJson"])
          if host_receiving is None:
              raise ValueError("Host boot preparation requires the genuine selected Host baseline receiving ledger")
          siblings = ([host_receiving[name] for name in ("prepare", "accept", "launch")]
                      if host_receiving is not None else [])
          if any(sum(parts) > whole for parts, whole in zip(zip(boot_receiving, *siblings), host_service)):
              raise ValueError("Host boot preparation and execution receivers exceed the same HostService")
          complement = [whole - sum(parts) for parts, whole in zip(zip(boot_receiving, *siblings), host_service)]
          if any(complement[index] == 0 for index in (1, 2, 3)):
              raise ValueError("Host boot preparation must retain the real Host service baseline complement")
          for amount in (boot_receiving, boot_sender):
              if any(amount[index] == 0 for index in (0, 1, 2, 3)) or amount[21] != 1:
                  raise ValueError("Host boot preparation requires one finite complete sender/receiver interval")
      mount_present = any(member["name"] == "aos-sandbox-mountd.service" for member in members)
      network_present = any(member["name"] == "aos-netd.service" for member in members)
      for label, present, receiving, sending in [
          ("Mount", mount_present, mount, mount_sender),
          ("Network", network_present, network, network_sender),
      ]:
          if present != any(receiving) or present != any(sending):
              raise ValueError(f"{label} F/M slices must match the actual enabled fixed service")
          if present and (sending[0] == 0 or sending[1] == 0 or sending[3] == 0 or sending[21] != 1):
              raise ValueError(f"{label} sender requires one finite original interval")
      cache_present = any(member["name"] == "aos-sandbox-cache-signerd.service" for member in members)
      if cache_present != any(cache) or cache_present != any(cache_sender):
          raise ValueError("Cache slices must match the actual enabled Cache signer service")
      ownership_present = any(member["name"] == "aos-sandbox-ownershipd.service" for member in members)
      if ownership_present != any(ownership) or ownership_present != any(ownership_sender):
          raise ValueError("Ownership slices must match the actual enabled Ownership service")
      source_present = any(member["name"] == "aos-sandbox-source-signerd.service" for member in members)
      if source_present != any(source) or source_present != any(sender):
          raise ValueError("Source slice and sender must match the actual enabled Source service")
      profiles = []
      if source_present or cache_present:
          spec = importlib.util.spec_from_file_location("source_protected_profile", os.environ["sourceProfileValidator"])
          module = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(module)
          if source_present:
              profiles.append(module.SourceProtectedProfileV1(os.environ["sourceProfileExec"]))
          if cache_present:
              profiles.append(module.CacheProtectedProfileV1(os.environ["cacheProfileExec"]))
      residual = vector(policy["components"])
      for name in ("hostService", "hostControl", "rootReceiving", "storageReceiving"):
          if policy.get(name) is not None:
              part = vector(policy[name])
              residual = [left - right for left, right in zip(residual, part)]
      senders = [sender, controller_sender, ownership_sender, cache_sender, mount_sender, network_sender, boot_sender]
      receivers = [source, ownership, cache, mount, network]
      if any(sum(parts) > whole for parts, whole in zip(zip(*senders), manager)):
          raise ValueError("all fixed-service senders must be disjoint subdivisions inside M")
      if cache_present and (cache_sender[0] == 0 or cache_sender[1] == 0
                            or cache_sender[3] == 0 or cache_sender[21] != 1):
          raise ValueError("Cache sender requires one finite original interval")
      if ownership_present and (ownership_sender[0] == 0 or ownership_sender[1] == 0
                                or ownership_sender[3] == 0 or ownership_sender[21] != 1):
          raise ValueError("Ownership sender requires one finite original interval")
      if any(controller_sender) and (controller_sender[0] == 0 or controller_sender[1] == 0
                                     or controller_sender[3] == 0 or controller_sender[21] != 1):
          raise ValueError("Controller successor sender requires one finite original interval")
      if source_present and (sender[0] == 0 or sender[1] == 0 or sender[3] == 0 or sender[21] != 1):
          raise ValueError("Source sender requires one finite original interval")
      if any(sum(parts) > whole for parts, whole in zip(zip(*receivers), fixed)):
          raise ValueError("all fixed-service receivers must be disjoint subdivisions inside F")
      if any(left + right > available for left, right, available in zip(manager, fixed, residual)):
          raise ValueError("M and F exceed the already committed Components baseline")

      nofiles = [contract["managerOpenFilesPerProcess"], contract["fixedOpenFilesPerProcess"]]
      service_vectors = [(manager, nofiles[0]), (fixed, nofiles[1])]
      if source_present:
          service_vectors.append((source, nofiles[1]))
      if ownership_present:
          service_vectors.append((ownership, nofiles[1]))
      if cache_present:
          service_vectors.append((cache, nofiles[1]))
      if mount_present:
          service_vectors.append((mount, nofiles[1]))
      if network_present:
          service_vectors.append((network, nofiles[1]))
      if boot_selected:
          service_vectors.append((boot_receiving, nofiles[1]))
      for values, nofile in service_vectors:
          if any(values[index] == 0 for index in (0, 1, 2, 3, 21)):
              raise ValueError("parent service accounting is incomplete")
          if values[0] % 1000 != 0 or values[0] > maximum // 10:
              raise ValueError("100ms CPU quota must convert exactly without overflow")
          if values[1] % 4096 != 0 or values[1] > (1 << 63) - 1 or values[2] > (1 << 63) - 1:
              raise ValueError("memory and PID controls must fit finite native bounds")
          if type(nofile) is not int or nofile <= 0 or nofile > (1 << 32) - 1:
              raise ValueError("per-process NOFILE must fit its finite native limit")
          if any(values is part for part in receivers):
              # The genuine selected Source producer verifies its one-table
              # pre-exec profile and actual N+inherited-high peak before clone.
              # Service threads share CLONE_FILES; their metadata stays priced
              # independently. Source TasksMax is not a table multiplier.
              if nofile > values[3]:
                  raise ValueError("Fixed receiving FD provision cannot cover its one-table NOFILE")
          elif values[2] * nofile > values[3]:
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
      fixed_baseline = [whole - sum(parts) for whole, parts in zip(fixed, zip(*receivers))]
      if fixed_baseline[6] < persistent + audit_rotation or fixed_baseline[7] < runtime:
          raise ValueError("F minus all fixed service receivers must cover the configured journal/audit rotation provision")
      if fixed_baseline[1] < fixed_baseline[7]:
          raise ValueError("remaining tmpfs accounting must fit the remaining fixed memory envelope")

      names = [member["name"] for member in members]
      if not 1 <= len(names) <= 16 or names != sorted(set(names)) or "aoscomponents.slice" not in names:
          raise ValueError("parent membership must be a bounded canonical fixed table")
      bootstrap = Path(sys.argv[2]).read_bytes()
      body = b"AOSRPE05" + hashlib.sha256(bootstrap).digest()
      body += struct.pack(">44Q", *(manager + fixed))
      body += struct.pack(">2Q", *nofiles)
      body += dispositions(manager) + dispositions(fixed) + struct.pack(">H", len(members))
      body += struct.pack(">286Q", *(source + sender + controller_sender + ownership + ownership_sender + cache + cache_sender + mount + mount_sender + network + network_sender + boot_receiving + boot_sender))
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
          for profile in profiles:
              if path == profile.unit or path.startswith(profile.unit + ".d/"):
                  profile.observe(path, content)
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
      for profile in profiles:
          profile.require_complete()
      encoded = body + hashlib.sha256(body).digest()
      if len(encoded) != 2774 + 1506 * len(members):
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
          sourceSignerSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit one-shot PID1 Source delivery subdivision inside M; original sender storage and descriptors remain charged on failure.";
          };
          controllerSuccessorSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit PID1 Controller successor transport subdivision inside M, disjoint from Source sender and all remaining manager obligations.";
          };
          sourceSignerReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit Source signer startup and contacted receiving subdivision inside the same F; no additional Components grant.";
          };
          ownershipSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit one-shot PID1 Ownership launch subdivision inside M, disjoint from Source and Controller senders.";
          };
          ownershipReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit complete Ownership startup and receiving subdivision inside F, disjoint from Source; no additional Components grant.";
          };
          cacheSignerSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit one-shot PID1 Cache signer launch subdivision inside M, disjoint from all other senders.";
          };
          cacheSignerReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit complete independent Cache signer startup and receiving subdivision inside F; no additional Components grant.";
          };
          mountSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit Mount original service subdivision inside existing M, disjoint from all other named services; no additional Components grant.";
          };
          mountReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit Mount original service subdivision inside existing F, disjoint from all other named services; no additional Components grant.";
          };
          networkSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit Network original service subdivision inside existing M, disjoint from all other named services; no additional Components grant.";
          };
          networkReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit Network original service subdivision inside existing F, disjoint from all other named services; no additional Components grant.";
          };
          hostBootPreparationSender = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit one-shot PID1 BootPreparation source subdivision inside the same M, disjoint from every existing sender.";
          };
          hostBootPreparationReceiving = lib.mkOption {
            type = lib.types.nullOr vectorType;
            default = null;
            description = "Explicit one-shot BootPreparation receiver inside the existing HostService, disjoint from Host execution and its remaining baseline.";
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
        assertion =
          !bootPreparation
          || (config.aos.sandbox.hostBroker.componentControl
            && config.aos.sandbox.hostBroker.executionReceiving != null);
        message = "Boot preparation requires the existing genuine Host control and selected baseline subdivision.";
      }
      {
        assertion =
          builtins.length members
          <= 16
          && builtins.all (name: bodies ? ${name} && bodies.${name}.enable && bodies.${name}.aliases == []) members
          && builtins.all (name: leafOwnership ? ${"systemd/system/${name}"}) members
          && builtins.all (unit: unit.valid) (builtins.attrValues nativeAuditUnits)
          && (import ./_fixed-systemd-profile.nix {inherit config pkgs;});
        message = "Parent roster requires every real enabled image base from the selected manager or its authenticated native services.";
      }
      {
        assertion = builtins.all (name:
          builtins.length (dropinsFor name)
          <= 4
          && builtins.all (path: leafOwnership ? ${path}) (dropinsFor name))
        members;
        message = "Parent roster has too many exact image drop-ins.";
      }
    ];

    aos.sandbox.resourceBank._parentImage = manifest;
    # The parent owns the original unit fragments before native activation.
    # Project every enabled native service into that image; activation may
    # reconcile lifecycle but cannot replace definitions or reload PID 1.
    aos.servicesRetainImageDefinitions = true;
    # Host-stage replay evaluates the retained sources independently of this
    # image module. Keep the same definition owner in that authenticated input.
    aos.activation.stages.host.configuration = [retainedServiceDefinitions];
    environment.etc."aos/resource-parent-enclosure-v5" = {
      source = "${manifest}/enclosure.bin";
      mode = "0444";
    };
    # Selection is independent of successful manifest acquisition: a missing
    # selected manifest cannot silently fall back to the ordinary null path.
    environment.etc."aos/resource-parent-enclosure-required-v5" = {
      text = "AOSRPE05";
      mode = "0444";
    };

    # The exact selected base and its drop-ins share one final manager tree.
    systemd.packagedBaseUnits = ["systemd-journald.service"];

    # Audit keeps its genuine native lifecycle and base. Its resource controls
    # augment that base as drop-ins, and the same native input enters the image.
    aos.services = lib.mapAttrs (_: _: {bootstrap = true;}) nativeAuditNames;
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
    # Main and its two one-shot helpers share the very same Network F. These
    # controls repeat that subdivision's immutable values at the aggregate;
    # they allocate no additional component, service or worker budget.
    systemd.slices.aoscomponents-network = lib.mkIf config.aos.sandbox.networkBroker.enable {
      description = "Original Network receiver and enrolled one-shot helpers";
      sliceConfig = {
        CPUAccounting = true;
        CPUQuotaPeriodSec = "100ms";
        CPUQuota = selectedValue "${toString (cfg.networkReceiving.cpu-micros-per-period / 1000)}%";
        MemoryMax = selectedValue cfg.networkReceiving.memory-bytes;
        MemorySwapMax = 0;
        TasksMax = selectedValue cfg.networkReceiving.pids;
      };
    };
    systemd.services = lib.genAttrs serviceNames (name: {
      overrideStrategy = lib.mkIf (builtins.elem name (builtins.attrValues nativeAuditNames)) "asDropin";
      serviceConfig = let
        service =
          if name == "aos-sandbox-source-signerd"
          then cfg.sourceSignerReceiving
          else if name == "aos-sandbox-ownershipd"
          then cfg.ownershipReceiving
          else if name == "aos-sandbox-cache-signerd"
          then cfg.cacheSignerReceiving
          else if name == "aos-sandbox-mountd"
          then cfg.mountReceiving
          else if name == "aos-netd"
          then cfg.networkReceiving
          else cfg.fixedServices;
      in
        {
          Slice = lib.mkForce (
            if name == "aos-netd"
            then "aoscomponents-network.slice"
            else "aoscomponents.slice"
          );
          CPUAccounting = true;
          CPUQuotaPeriodSec = lib.mkForce "100ms";
          CPUQuota = lib.mkForce (selectedValue "${toString (service.cpu-micros-per-period / 1000)}%");
          MemoryMax = lib.mkForce (selectedValue service.memory-bytes);
          MemorySwapMax = lib.mkForce 0;
          TasksMax = lib.mkForce (selectedValue service.pids);
          LimitNOFILE = lib.mkForce (selectedValue cfg.fixedOpenFilesPerProcess);
        }
        // lib.optionalAttrs (builtins.elem name ["aos-sandbox-mountd" "aos-netd"]) {
          # The listener is the original stdin socket. Only origin/profile occupy
          # the two named initial entries; selected callers must not rescan them.
          StandardInput = lib.mkForce "socket";
          OpenFile = lib.mkAfter [
            "${config.aos.sandbox.policyAuthority._normalStartupProfile}/profile.json:${
              if name == "aos-netd"
              then "aos-network-root-profile"
              else "aos-mount-root-profile"
            }:read-only"
          ];
        };
    });
    systemd.sockets =
      lib.genAttrs (
        lib.optional config.aos.sandbox.mountBroker.enable "aos-sandbox-mountd"
        ++ lib.optional config.aos.sandbox.networkBroker.enable "aos-netd"
      ) (_: {
        socketConfig = {
          PassCredentials = lib.mkForce true;
          PassPIDFD = lib.mkForce true;
          PassSecurity = lib.mkForce false;
          PassSubjectBeforeListen = lib.mkForce true;
        };
      });

    aos.journald = {
      maxUseBytes = lib.mkForce (selectedValue cfg.journal.systemMaxUse);
      maxFileSizeBytes = lib.mkForce (selectedValue cfg.journal.systemMaxFileSize);
      runtimeMaxUse = lib.mkForce (selectedValue cfg.journal.runtimeMaxUse);
      runtimeMaxFileSize = lib.mkForce (selectedValue cfg.journal.runtimeMaxFileSize);
    };
    # Definition collection inspects this leaf before filtering the outer mkIf.
    aos.security.audit.bounds =
      if cfg == null
      then null
      else cfg.audit;
  };
}
