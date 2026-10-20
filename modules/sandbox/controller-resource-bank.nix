##! Image-owned policy for the existing PID1/Controller resource enrollment.
##!
##! Policy bytes are not a loan. PID1 must reserve the fixed bootstrap and
##! component envelopes under its original boot custody before selected jobs;
##! Controller then admits dynamic grants through the one protected bank.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.resourceBank;
  onlineNix = config.aos.sandbox.nixBroker.enable;
  controllerMinimum = {
    memory-bytes =
      if onlineNix
      then 4294967296
      else 536870912;
    pids = 8;
    open-files =
      if onlineNix
      then 16384
      else 128;
    concurrent-operations = 1;
  };
  componentMinimum = lib.optionalAttrs (config.aos.sandbox.storageBroker.enable
    && (cfg.policy == null || cfg.policy.storageReceiving == null)) {
    memory-bytes = 536870912;
    pids = 32;
    open-files = 256;
    concurrent-operations = 1;
  };
  dimensions = [
    "cpu-micros-per-period"
    "memory-bytes"
    "pids"
    "open-files"
    "mounts"
    "descendants"
    "storage-bytes"
    "tmpfs-bytes"
    "cache-reservation-bytes"
    "pinned-bytes"
    "metadata-entries"
    "mapped-index-bytes"
    "inflight-fetch-bytes"
    "inflight-decompressed-bytes"
    "publication-staging-bytes"
    "backing-registrations"
    "attachment-edges"
    "executions"
    "network-bytes"
    "log-bytes"
    "output-bytes"
    "concurrent-operations"
  ];
  vectorType = lib.types.attrsOf (lib.types.addCheck lib.types.int (value: value >= 0));
  policyType = lib.types.submodule {
    options = {
      node = lib.mkOption {
        type = lib.types.strMatching "[0-9a-f]{32}";
        description = "The exact provisioned node UUID, without separators.";
      };
      epoch = lib.mkOption {
        type = lib.types.strMatching "[0-9a-f]{32}";
        description = "The nonzero fresh-install image policy epoch, without separators.";
      };
      capacity = lib.mkOption {
        type = vectorType;
        description = "Explicit finite allocatable node policy in every resource dimension.";
      };
      baseline = lib.mkOption {
        type = vectorType;
        description = "Conservative competing node demand outside the two prepaid envelopes.";
      };
      controller = lib.mkOption {
        type = vectorType;
        description = "Prepaid Controller startup, bank replay, journal and control-service envelope.";
      };
      components = lib.mkOption {
        type = vectorType;
        description = "Prepaid aggregate manager, journald, audit and fixed component all-trigger envelope.";
      };
      hostService = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full immutable Host service vector inside Components; paired with hostControl.";
      };
      hostControl = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full reserved Host control interval vector inside Components, paid once.";
      };
      firstGlobalPrefix = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full once-only FirstGlobal prefix subdivision of Controller, not another Node grant.";
      };
      nixOriginalStartIntake = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full once-only original Nix Start intake subdivision; never an operation-effect payment.";
      };
      q04OriginalIntake = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full once-only original Q04 intake subdivision paying bounded observations before Project preparation.";
      };
      createContinuationIntake = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Full once-only original Create continuation capture subdivision; never Prepare or operation-use authority.";
      };
      storageReceiving = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Whole original Storage startup and contacted-service subdivision inside Components, paid once.";
      };
      executionOperationIntake = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Explicit permanent finite execution-operation intake subdivision inside the same Controller envelope; no execution authority.";
      };
      deleteOperationIntake = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Explicit permanent finite Delete-operation intake subdivision inside the same Controller envelope; no deletion authority.";
      };
      hostExecutionPrepare = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Explicit permanent Host Prepare capacity reserved inside the existing HostService total.";
      };
      hostExecutionAccept = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Paired permanent Host Accept capacity reserved inside the same HostService total.";
      };
      controllerRecovery = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Explicit recovery reserve R inside the existing Controller baseline B; normal allocation is bounded by B minus R.";
      };
      controllerRecoveryInvocation = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Explicit per-recipient allowance A prepaid within R for the finite Controller recovery range.";
      };
      controllerRecoveryRecipients = lib.mkOption {
        type = lib.types.nullOr (lib.types.addCheck lib.types.int (value: value > 0));
        default = null;
        description = "Explicit finite number K of recovery recipients; every issued ordinal permanently consumes its allowance.";
      };
      rootReceiving = lib.mkOption {
        type = lib.types.nullOr vectorType;
        default = null;
        description = "Finite original Root service and receiving-prefix subdivision inside Components, alongside Host.";
      };
    };
  };

  controllerLayoutPackage = config.aos.sandbox.controllerService.package;

  hostExecutionPolicy = builtins.removeAttrs cfg.policy ["controllerRecovery" "controllerRecoveryInvocation" "controllerRecoveryRecipients"];
  operationPolicy = builtins.removeAttrs hostExecutionPolicy ["hostExecutionPrepare" "hostExecutionAccept"];
  legacyPolicy = builtins.removeAttrs operationPolicy ["deleteOperationIntake" "executionOperationIntake"];

  policy =
    pkgs.runCommand "aos-controller-resource-bootstrap-policy-v1" {
      nativeBuildInputs =
        [pkgs.python3 pkgs.coreutils]
        ++ lib.optional (cfg.policy.controllerRecovery != null) controllerLayoutPackage;
      controllerPrefixFile = lib.optionalString (cfg.policy.controllerRecovery != null) "controller-prefix.json";
      policyJson = builtins.toJSON (
        if cfg.policy.controllerRecovery != null
        then cfg.policy
        else if cfg.policy.hostExecutionPrepare != null || cfg.policy.hostExecutionAccept != null
        then hostExecutionPolicy
        else if cfg.policy.deleteOperationIntake != null || cfg.policy.executionOperationIntake != null
        then operationPolicy
        else if legacyPolicy.createContinuationIntake != null || legacyPolicy.storageReceiving != null
        then legacyPolicy
        else if legacyPolicy.rootReceiving != null
        then builtins.removeAttrs legacyPolicy ["createContinuationIntake" "storageReceiving"]
        else if legacyPolicy.q04OriginalIntake != null
        then builtins.removeAttrs legacyPolicy ["rootReceiving" "createContinuationIntake" "storageReceiving"]
        else if legacyPolicy.nixOriginalStartIntake != null
        then builtins.removeAttrs legacyPolicy ["q04OriginalIntake" "rootReceiving" "createContinuationIntake" "storageReceiving"]
        else if legacyPolicy.firstGlobalPrefix != null
        then builtins.removeAttrs legacyPolicy ["nixOriginalStartIntake" "q04OriginalIntake" "rootReceiving" "createContinuationIntake" "storageReceiving"]
        else if legacyPolicy.hostService == null && legacyPolicy.hostControl == null
        then builtins.removeAttrs legacyPolicy ["hostService" "hostControl" "firstGlobalPrefix" "nixOriginalStartIntake" "q04OriginalIntake" "rootReceiving" "createContinuationIntake" "storageReceiving"]
        else builtins.removeAttrs legacyPolicy ["firstGlobalPrefix" "nixOriginalStartIntake" "q04OriginalIntake" "rootReceiving" "createContinuationIntake" "storageReceiving"]
      );
      dimensionJson = builtins.toJSON dimensions;
      controllerMinimumJson = builtins.toJSON controllerMinimum;
      componentMinimumJson = builtins.toJSON componentMinimum;
    } ''
      set -eu
      mkdir -p "$out"
      ${lib.optionalString (cfg.policy.controllerRecovery != null) ''
        # This is the exact installed target package. A missing native/target
        # execution path refuses; host type sizes are never substituted.
        ${controllerLayoutPackage}/bin/aos-sandboxd --print-enrollment-range-prefix ${lib.escapeShellArg (toString cfg.policy.controllerRecoveryRecipients)} > controller-prefix.json
      ''}
      ${pkgs.python3}/bin/python3 -B - "$out/bootstrap.bin" <<'PY'
      import hashlib
      import json
      import os
      import struct
      import sys
      from pathlib import Path

      policy = json.loads(os.environ["policyJson"])
      dimensions = json.loads(os.environ["dimensionJson"])
      maximum = (1 << 64) - 1
      controller_minimum = json.loads(os.environ["controllerMinimumJson"])
      component_minimum = json.loads(os.environ["componentMinimumJson"])
      if len(dimensions) != 22 or len(set(dimensions)) != 22:
          raise ValueError("resource dimension registry is inconsistent")
      legacy_fields = {"node", "epoch", "capacity", "baseline", "controller", "components"}
      host_fields = legacy_fields | {"hostService", "hostControl"}
      prefix_fields = host_fields | {"firstGlobalPrefix"}
      intake_fields = prefix_fields | {"nixOriginalStartIntake"}
      q04_fields = intake_fields | {"q04OriginalIntake"}
      root_fields = q04_fields | {"rootReceiving"}
      create_fields = root_fields | {"createContinuationIntake", "storageReceiving"}
      operation_fields = create_fields | {"deleteOperationIntake", "executionOperationIntake"}
      host_execution_fields = operation_fields | {"hostExecutionPrepare", "hostExecutionAccept"}
      recovery_fields = host_execution_fields | {"controllerRecovery", "controllerRecoveryInvocation", "controllerRecoveryRecipients"}
      recovery_selected = set(policy) == recovery_fields
      host_execution_selected = set(policy) in (host_execution_fields, recovery_fields)
      operation_selected = set(policy) in (operation_fields, host_execution_fields, recovery_fields)
      create_selected = set(policy) in (create_fields, operation_fields, host_execution_fields, recovery_fields)
      root_selected = set(policy) in (root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields)
      q04_selected = set(policy) in (q04_fields, root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields)
      intake_selected = set(policy) in (intake_fields, q04_fields, root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields)
      prefix_selected = set(policy) in (prefix_fields, intake_fields, q04_fields, root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields)
      host_selected = set(policy) in (host_fields, prefix_fields, intake_fields, q04_fields, root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields)
      if set(policy) not in (legacy_fields, host_fields, prefix_fields, intake_fields, q04_fields, root_fields, create_fields, operation_fields, host_execution_fields, recovery_fields):
          raise ValueError("resource policy must contain its complete fixed schema")

      def identity(name):
          encoded = bytes.fromhex(policy[name])
          if len(encoded) != 16 or encoded == bytes(16):
              raise ValueError("resource policy has an unspecified identity")
          return encoded

      def vector(name):
          values = policy[name]
          if set(values) != set(dimensions):
              raise ValueError("every resource dimension must be explicitly configured")
          ordered = [values[dimension] for dimension in dimensions]
          if any(type(value) is not int or value < 0 or value > (1 << 64) - 1 for value in ordered):
              raise ValueError("resource policy is not a finite unsigned vector")
          return ordered

      capacity, baseline, controller, components = map(
          vector, ("capacity", "baseline", "controller", "components")
      )
      for index in range(22):
          if baseline[index] + controller[index] + components[index] > capacity[index]:
              raise ValueError("the fixed prepaid envelopes exceed node policy")
      for envelope in (controller, components):
          if any(envelope[dimensions.index(name)] == 0 for name in (
              "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the fixed service envelope is incomplete")
      # The original PID1 reservation must pay at least the unchanged fixed
      # Controller enforcement envelope before its first capture or journal open.
      # These bounds do not issue payment; admission still requires that action.
      for name, minimum in controller_minimum.items():
          if controller[dimensions.index(name)] < minimum:
              raise ValueError("the prepaid Controller envelope is below its fixed enforcement bounds")
      # These are only Storage's existing bounds. The separately configured
      # aggregate must also cover competing manager, journald and audit demand;
      # this necessary comparison does not issue or subdivide their reservation.
      for name, minimum in component_minimum.items():
          if components[dimensions.index(name)] < minimum:
              raise ValueError("the prepaid component envelope is below fixed Storage enforcement bounds")

      host_vectors = ()
      if host_selected:
          host_service, host_control = map(vector, ("hostService", "hostControl"))
          for index in range(22):
              if host_service[index] + host_control[index] > components[index]:
                  raise ValueError("the Host subdivision exceeds the once-paid Components envelope")
          for envelope in (host_service, host_control):
              if any(envelope[dimensions.index(name)] == 0 for name in (
                  "memory-bytes", "pids", "open-files", "concurrent-operations"
              )):
                  raise ValueError("the Host service/control interval is incomplete")
          host_vectors = (host_service, host_control)

      prefix_vectors = ()
      if prefix_selected:
          prefix = vector("firstGlobalPrefix")
          if any(prefix[index] > controller[index] for index in range(22)):
              raise ValueError("the FirstGlobal prefix exceeds its already-paid Controller")
          for name, minimum in controller_minimum.items():
              index = dimensions.index(name)
              if controller[index] - prefix[index] < minimum:
                  raise ValueError("the retained Controller service envelope is below its existing producer bound")
          if any(prefix[dimensions.index(name)] == 0 for name in (
              "cpu-micros-per-period", "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the FirstGlobal prefix provision is incomplete")
          quota = prefix[dimensions.index("cpu-micros-per-period")]
          if quota % 1000 != 0:
              raise ValueError("the selected 100ms CPU quota must convert exactly to integral percent")
          prefix_vectors = (prefix,)

      intake_vectors = ()
      if intake_selected:
          intake = vector("nixOriginalStartIntake")
          if any(prefix[index] + intake[index] > controller[index] for index in range(22)):
              raise ValueError("the disjoint FirstGlobal and Nix intake subdivisions exceed Controller")
          for name, minimum in controller_minimum.items():
              index = dimensions.index(name)
              if controller[index] - prefix[index] - intake[index] < minimum:
                  raise ValueError("the retained Controller service envelope is below its existing producer bound")
          if any(intake[dimensions.index(name)] == 0 for name in (
              "cpu-micros-per-period", "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the original Nix intake provision is incomplete")
          intake_vectors = (intake,)

      q04_vectors = ()
      if q04_selected:
          q04 = vector("q04OriginalIntake")
          if any(prefix[index] + intake[index] + q04[index] > controller[index] for index in range(22)):
              raise ValueError("the disjoint Controller subdivisions exceed the once-paid envelope")
          for name, minimum in controller_minimum.items():
              index = dimensions.index(name)
              if controller[index] - prefix[index] - intake[index] - q04[index] < minimum:
                  raise ValueError("the retained Controller service envelope is below its existing producer bound")
          if any(q04[dimensions.index(name)] == 0 for name in (
              "cpu-micros-per-period", "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the original Q04 intake provision is incomplete")
          # Rust checks actual inline owners, eleven fixed error slots, bounded
          # journal names and both paired-clock samples against this provision.
          # This is not a bound for successful capture or observer admission.
          q04_failure = {
              "memory-bytes": 2 * 1024 * 1024,
              "open-files": 4,
              "metadata-entries": 2 * 1024 * 1024,
              "publication-staging-bytes": 2 * 1024 * 1024,
              "log-bytes": 2 * 1024 * 1024,
              "output-bytes": 2 * 1024 * 1024,
          }
          if any(q04[dimensions.index(name)] < minimum for name, minimum in q04_failure.items()):
              raise ValueError("the original Q04 intake lacks its retained failure allowance")
          if q04[dimensions.index("cpu-micros-per-period")] < prefix[dimensions.index("cpu-micros-per-period")]:
              raise ValueError("the Q04 intake does not cover the installed original Controller CPU rate")
          q04_vectors = (q04,)

      root_vectors = ()
      if root_selected:
          root = vector("rootReceiving")
          if any(host_service[index] + host_control[index] + root[index] > components[index] for index in range(22)):
              raise ValueError("the disjoint Host and Root subdivisions exceed Components")
          if any(root[dimensions.index(name)] == 0 for name in (
              "cpu-micros-per-period", "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the original Root service envelope is incomplete")
          if root[0] % 1000 != 0 or root[0] > ((1 << 64) - 1) // 10:
              raise ValueError("the Root 100ms CPU rate must convert exactly without overflow")
          if root[1] % 4096 != 0 or root[2] < 2 or root[3] < 80:
              raise ValueError("the Root peak service bounds cannot contain the fixed capture and worker")
          root_vectors = (root,)

      create_vectors = ()
      if create_selected:
          create = vector("createContinuationIntake")
          reserved = [sum(parts) for parts in zip(prefix, intake, q04, create)]
          if any(used > total for used, total in zip(reserved, controller)):
              raise ValueError("the disjoint P/I/Q/J subdivisions exceed Controller")
          for name, minimum in controller_minimum.items():
              index = dimensions.index(name)
              if controller[index] - reserved[index] < minimum:
                  raise ValueError("J would consume the unchanged Controller service baseline")
          for name, minimum in q04_failure.items():
              if create[dimensions.index(name)] < minimum:
                  raise ValueError("J lacks its retained negative-capture allowance")
          if any(create[dimensions.index(name)] == 0 for name in (
              "cpu-micros-per-period", "memory-bytes", "pids", "open-files", "concurrent-operations"
          )):
              raise ValueError("the original Create intake provision is incomplete")
          if create[0] < prefix[0]:
              raise ValueError("J does not cover the installed original Controller CPU rate")
          # Native checks its actual fixed owner/capture layout and the retained
          # observer archive before any corresponding allocation or capture.
          storage = vector("storageReceiving")
          used = [sum(parts) for parts in zip(host_service, host_control, root, storage)]
          if any(part > total for part, total in zip(used, components)):
              raise ValueError("the whole Storage service exceeds the once-paid Components envelope")
          if (storage[0] == 0 or storage[0] % 1000 != 0 or storage[0] > maximum // 10
                  or storage[1] < 512 * 1024 * 1024 or storage[1] % 4096 != 0
                  or storage[2] < 32 or storage[2] == maximum
                  or storage[3] < 256 or storage[3] == maximum
                  or storage[21] == 0):
              raise ValueError("Storage cannot contain its existing fixed service")
          # The whole reserved Storage service replaces its old aggregate baseline
          # charge; its actual contacted consumer separately proves operation fit.
          create_vectors = (create, storage)

      operation_vectors = ()
      if operation_selected:
          delete = vector("deleteOperationIntake")
          execution = vector("executionOperationIntake")
          reserved = [sum(parts) for parts in zip(prefix, intake, q04, create, delete, execution)]
          if any(part > total for part, total in zip(reserved, controller)):
              raise ValueError("the disjoint P/I/Q/J/Delete/Execution subdivisions exceed Controller")
          for name, minimum in controller_minimum.items():
              index = dimensions.index(name)
              if controller[index] - reserved[index] < minimum:
                  raise ValueError("Operation intake would consume the unchanged Controller service baseline")
          for interval in (delete, execution):
              if any(interval[dimensions.index(name)] == 0 for name in (
                  "memory-bytes", "open-files", "concurrent-operations"
              )):
                  raise ValueError("an explicit lifecycle-operation intake is incomplete")
          operation_vectors = (delete, execution)

      host_execution_vectors = ()
      if host_execution_selected:
          prepare = vector("hostExecutionPrepare")
          accept = vector("hostExecutionAccept")
          if any(left + right > total for left, right, total in zip(prepare, accept, host_service)):
              raise ValueError("Host Prepare/Accept exceed the same HostService total")
          for interval in (prepare, accept):
              if any(interval[dimensions.index(name)] == 0 for name in (
                  "memory-bytes", "open-files", "concurrent-operations"
              )):
                  raise ValueError("an explicit Host execution interval is incomplete")
          host_execution_vectors = (prepare, accept)

      recovery_vectors = ()
      if recovery_selected:
          recovery = vector("controllerRecovery")
          invocation = vector("controllerRecoveryInvocation")
          recipients = policy["controllerRecoveryRecipients"]
          if type(recipients) is not int or not 1 <= recipients <= maximum:
              raise ValueError("Controller recovery requires an explicit finite recipient count")
          for allowance, total in zip(invocation, recovery):
              if allowance > maximum // recipients or recipients * allowance > total:
                  raise ValueError("the complete funded recipient range exceeds the original reserve R")
          baseline_rows = [total - sum(parts) for total, *parts in zip(
              controller, *prefix_vectors, *intake_vectors, *q04_vectors,
              create_vectors[0], *operation_vectors)]
          normal = [total - reserve for total, reserve in zip(baseline_rows, recovery)]
          if any(value < 0 for value in normal):
              raise ValueError("Controller recovery reserve exceeds the same baseline B")
          for envelope in (normal, recovery, invocation):
              if any(envelope[dimensions.index(name)] == 0 for name in (
                  "memory-bytes", "pids", "open-files", "concurrent-operations"
              )):
                  raise ValueError("normal and recovery envelopes must be explicit and nonempty")
          prefix = json.loads(Path(os.environ["controllerPrefixFile"]).read_text())
          if (set(prefix) != {"format", "recipients", "dimensions"}
              or prefix["format"] != "aos-controller-enrollment-range-prefix-v2"
              or prefix["recipients"] != recipients):
              raise ValueError("compiled Controller prefix contract is unavailable")
          rows = prefix["dimensions"]
          if not isinstance(rows, list) or len(rows) != len(dimensions):
              raise ValueError("compiled Controller prefix registry differs")
          for row, name, normal_value, invocation_value in zip(rows, dimensions, normal, invocation):
              if (not isinstance(row, list) or len(row) != 2 or row[0] != name
                  or type(row[1]) is not int or not 0 <= row[1] <= maximum):
                  raise ValueError("compiled Controller prefix row is malformed")
              if row[1] > normal_value or row[1] > invocation_value:
                  raise ValueError("normal or invocation allowance cannot hold the compiled range prefix")
          recovery_vectors = (recovery,)

      magic = b"AOSRSB11" if recovery_selected else b"AOSRSB09" if host_execution_selected else b"AOSRSB08" if operation_selected else b"AOSRSB07" if create_selected else b"AOSRSB06" if root_selected else (b"AOSRSB05" if q04_selected else (b"AOSRSB04" if intake_selected else (b"AOSRSB03" if prefix_selected else (b"AOSRSB02" if host_selected else b"AOSRSB01"))))
      body = magic + identity("node") + identity("epoch")
      for values in (capacity, baseline, controller, components):
          body += struct.pack(">22Q", *values)
      for values in host_vectors:
          body += struct.pack(">22Q", *values)
      for values in prefix_vectors:
          body += struct.pack(">22Q", *values)
      for values in intake_vectors:
          body += struct.pack(">22Q", *values)
      for values in q04_vectors:
          body += struct.pack(">22Q", *values)
      for values in root_vectors:
          body += struct.pack(">22Q", *values)
      for values in create_vectors:
          body += struct.pack(">22Q", *values)
      for values in operation_vectors:
          body += struct.pack(">22Q", *values)
      for values in host_execution_vectors:
          body += struct.pack(">22Q", *values)
      for values in recovery_vectors:
          body += struct.pack(">22Q", *values)
      if recovery_selected:
          body += struct.pack(">Q22Q", recipients, *invocation)
      encoded = body + hashlib.sha256(body).digest()
      if len(encoded) != (3248 if recovery_selected else 2888 if host_execution_selected else 2536 if operation_selected else 2184 if create_selected else (1832 if root_selected else (1656 if q04_selected else (1480 if intake_selected else (1304 if prefix_selected else (1128 if host_selected else 776)))))):
          raise ValueError("native bootstrap policy width changed")
      Path(sys.argv[1]).write_bytes(encoded)
      PY
      chmod 0444 "$out/bootstrap.bin"
    '';
in {
  options.aos.sandbox.resourceBank = {
    _dimensionOrder = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = dimensions;
      internal = true;
      readOnly = true;
      description = "Canonical full-vector DATA order shared with the fixed Host image profile.";
    };
    policy = lib.mkOption {
      type = lib.types.nullOr policyType;
      default = null;
      description = "Mandatory explicit image-owned policy for fresh shared-bank enrollment; absence does not fund selected work.";
    };
    _imagePolicy = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      internal = true;
      readOnly = true;
      description = "The immutable native policy bytes, not a reservation owner.";
    };
  };

  config = lib.mkIf (cfg.policy != null) {
    assertions = [
      {
        assertion =
          (cfg.policy.controllerRecovery == null)
          == (cfg.policy.controllerRecoveryInvocation == null)
          && (cfg.policy.controllerRecovery == null)
          == (cfg.policy.controllerRecoveryRecipients == null);
        message = "Controller recovery requires paired explicit R, per-recipient A and finite recipient count K.";
      }
      {
        assertion = cfg.parentEnclosure == null || config.aos.sandbox.resourceBank._parentImage != null;
        message = "Selected parent enclosure requires its immutable image producer alongside the unchanged resource policy.";
      }
      {
        assertion =
          config.aos.security.selinux.enable
          && config.aos.security.selinux.mode == "enforcing"
          && config.aos.security.selinux.bootMode == "immutable-stage0";
        message = "Shared resource enrollment requires the existing immutable enforcing PID1/Controller trust boundary.";
      }
      {
        assertion = config.aos.sandbox.controllerService.enable;
        message = "Shared resource enrollment requires the existing fixed Controller service.";
      }
      {
        assertion =
          (cfg.policy.hostService == null && cfg.policy.hostControl == null)
          || (cfg.policy.hostService
            != null
            && cfg.policy.hostControl != null
            && config.aos.sandbox.hostBroker.enable
            && config.aos.sandbox.hostBroker.componentControl
            && !config.aos.sandbox.hostBroker.canary);
        message = "V2 resource policy requires the selected Host control service, not ordinary or Canary activation.";
      }
      {
        assertion =
          cfg.policy.firstGlobalPrefix
          == null
          || (cfg.policy.hostService != null && cfg.policy.hostControl != null);
        message = "V3 FirstGlobal policy extends the complete selected Host image family.";
      }
      {
        assertion =
          cfg.policy.nixOriginalStartIntake
          == null
          || (cfg.policy.firstGlobalPrefix != null && onlineNix);
        message = "V4 original Nix intake requires its separate full subdivision and selected Nix Controller.";
      }
      {
        assertion =
          cfg.policy.q04OriginalIntake
          == null
          || cfg.policy.nixOriginalStartIntake != null;
        message = "V5 Q04 intake extends the complete disjoint Controller image family.";
      }
      {
        assertion =
          cfg.policy.rootReceiving
          == null
          || (cfg.policy.q04OriginalIntake
            != null
            && config.aos.sandbox.policyAuthority.enable
            && config.aos.sandbox.policyAuthority.package == pkgs.aos-sandboxd);
        message = "V6 original Root receiving requires the complete V5 family and the selected confined Root service.";
      }
      {
        assertion =
          (cfg.policy.createContinuationIntake == null)
          == (cfg.policy.storageReceiving == null)
          && (cfg.policy.createContinuationIntake
            == null
            || (cfg.policy.rootReceiving
              != null
              && config.aos.sandbox.storageBroker.enable
              && config.aos.sandbox.storageBroker.package == pkgs.aos-storaged));
        message = "V7 requires both disjoint Controller capture and whole Storage receiving, the complete V6 family, and the exact installed Storage service.";
      }
      {
        assertion =
          (cfg.policy.deleteOperationIntake == null)
          == (cfg.policy.executionOperationIntake == null)
          && (cfg.policy.deleteOperationIntake
            == null
            || (cfg.policy.createContinuationIntake != null && cfg.policy.storageReceiving != null));
        message = "Delete intake requires the complete original Controller/Storage image declaration.";
      }
      {
        assertion =
          (cfg.policy.hostExecutionPrepare == null)
          == (cfg.policy.hostExecutionAccept == null)
          && (cfg.policy.hostExecutionPrepare
            == null
            || (cfg.policy.executionOperationIntake != null && cfg.policy.hostService != null));
        message = "Host Prepare/Accept require a paired explicit V9 subdivision of the same selected HostService.";
      }
      {
        assertion =
          cfg.policy.controllerRecovery
          == null
          || (cfg.policy.hostExecutionPrepare != null && cfg.policy.hostExecutionAccept != null);
        message = "Controller recovery requires the complete V10 image and an explicit reserve inside the existing baseline B.";
      }
    ];
    aos.sandbox.resourceBank._imagePolicy = policy;
    environment.etc."aos/resource-bootstrap-v1" = {
      source = "${policy}/bootstrap.bin";
      mode = "0444";
    };
    systemd.services.aos-sandboxd.serviceConfig = lib.mkIf (cfg.policy.firstGlobalPrefix != null) {
      # The same finite period is checked against the original cpu.max OFD;
      # configuration alone is not admission or proof of effective enforcement.
      CPUAccounting = true;
      CPUQuotaPeriodSec = "100ms";
      CPUQuota = "${toString (cfg.policy.firstGlobalPrefix.cpu-micros-per-period / 1000)}%";
    };
  };
}
