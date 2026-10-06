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
    memory-bytes = if onlineNix then 4294967296 else 536870912;
    pids = 8;
    open-files = if onlineNix then 16384 else 128;
    concurrent-operations = 1;
  };
  componentMinimum = lib.optionalAttrs config.aos.sandbox.storageBroker.enable {
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
    };
  };

  policy = pkgs.runCommand "aos-controller-resource-bootstrap-policy-v1" {
    nativeBuildInputs = [pkgs.python3 pkgs.coreutils];
    policyJson = builtins.toJSON (
      if cfg.policy.firstGlobalPrefix != null
      then cfg.policy
      else if cfg.policy.hostService == null && cfg.policy.hostControl == null
      then builtins.removeAttrs cfg.policy ["hostService" "hostControl" "firstGlobalPrefix"]
      else builtins.removeAttrs cfg.policy ["firstGlobalPrefix"]
    );
    dimensionJson = builtins.toJSON dimensions;
    controllerMinimumJson = builtins.toJSON controllerMinimum;
    componentMinimumJson = builtins.toJSON componentMinimum;
  } ''
    set -eu
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 -B - "$out/bootstrap.bin" <<'PY'
    import hashlib
    import json
    import os
    import struct
    import sys
    from pathlib import Path

    policy = json.loads(os.environ["policyJson"])
    dimensions = json.loads(os.environ["dimensionJson"])
    controller_minimum = json.loads(os.environ["controllerMinimumJson"])
    component_minimum = json.loads(os.environ["componentMinimumJson"])
    if len(dimensions) != 22 or len(set(dimensions)) != 22:
        raise ValueError("resource dimension registry is inconsistent")
    legacy_fields = {"node", "epoch", "capacity", "baseline", "controller", "components"}
    host_fields = legacy_fields | {"hostService", "hostControl"}
    prefix_fields = host_fields | {"firstGlobalPrefix"}
    prefix_selected = set(policy) == prefix_fields
    host_selected = set(policy) in (host_fields, prefix_fields)
    if set(policy) not in (legacy_fields, host_fields, prefix_fields):
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

    magic = b"AOSRSB03" if prefix_selected else (b"AOSRSB02" if host_selected else b"AOSRSB01")
    body = magic + identity("node") + identity("epoch")
    for values in (capacity, baseline, controller, components):
        body += struct.pack(">22Q", *values)
    for values in host_vectors:
        body += struct.pack(">22Q", *values)
    for values in prefix_vectors:
        body += struct.pack(">22Q", *values)
    encoded = body + hashlib.sha256(body).digest()
    if len(encoded) != (1304 if prefix_selected else (1128 if host_selected else 776)):
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
        assertion = config.aos.security.selinux.enable
          && config.aos.security.selinux.mode == "enforcing"
          && config.aos.security.selinux.bootMode == "immutable-stage0";
        message = "Shared resource enrollment requires the existing immutable enforcing PID1/Controller trust boundary.";
      }
      {
        assertion = config.aos.sandbox.controllerService.enable;
        message = "Shared resource enrollment requires the existing fixed Controller service.";
      }
      {
        assertion = (cfg.policy.hostService == null && cfg.policy.hostControl == null)
          || (cfg.policy.hostService != null && cfg.policy.hostControl != null
            && config.aos.sandbox.hostBroker.enable
            && config.aos.sandbox.hostBroker.componentControl
            && !config.aos.sandbox.hostBroker.canary);
        message = "V2 resource policy requires the selected Host control service, not ordinary or Canary activation.";
      }
      {
        assertion = cfg.policy.firstGlobalPrefix == null
          || (cfg.policy.hostService != null && cfg.policy.hostControl != null);
        message = "V3 FirstGlobal policy extends the complete selected Host image family.";
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
