##! pkgs/build-support/_expose-renderer.nix — RFC-0001 package expose renderer.
##!
##! Converts a package-authored `expose` attrset into a separate store path
##! containing rendered systemd units and a JSON manifest copy. The payload
##! derivation never receives the rendered path as a build input; consumers
##! reach it through `pkg.expose` / `pkg.passthru.expose`.
{
  lib,
  pkgs,
}: let
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../../lib/modules/systemd/unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ../../lib/modules/systemd/types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };
  renderRole = import ../../lib/modules/systemd/render-role.nix {
    inherit lib pkgs systemdLib;
  };

  knownUnitSuffixes = [
    ".automount"
    ".mount"
    ".path"
    ".service"
    ".slice"
    ".socket"
    ".target"
    ".timer"
  ];

  packageNameType = "^[A-Za-z0-9][A-Za-z0-9+._=-]*$";
  capabilityType = "^CAP_[A-Z0-9_]+$";
  kernelModuleType = "^[A-Za-z0-9_-]+$";
  sysctlKeyType = "^[A-Za-z0-9_.-]+$";
  sysctlValueType = "^[^[:space:]]+$";
  securityLabelType = "^[A-Za-z0-9._-]+$";

  throwIfNot = lib.throwIfNot;

  validateList = field: value:
    throwIfNot
    (builtins.isList value)
    "${field} must be a list"
    value;

  validateBool = field: value:
    throwIfNot
    (builtins.isBool value)
    "${field} must be a boolean"
    value;

  hasKnownSuffix = unit:
    builtins.any (suffix: lib.hasSuffix suffix unit) knownUnitSuffixes;

  validateUnitName = unit:
    throwIfNot
    (
      builtins.isString unit
      && unit != ""
      && builtins.match ".*/.*" unit == null
      && builtins.match ".*[[:space:]].*" unit == null
      && hasKnownSuffix unit
    )
    "expose.units contains invalid systemd unit name '${builtins.toString unit}'"
    unit;

  validateTargetName = target:
    throwIfNot
    (
      validateUnitName target
      == target
      && lib.hasPrefix "aos-pkg-" target
      && lib.hasSuffix ".target" target
    )
    "expose.target must be named aos-pkg-<name>.target: ${builtins.toString target}"
    target;

  validatePackageName = package:
    throwIfNot
    (
      builtins.isString package
      && builtins.match packageNameType package != null
    )
    "expose.requires contains invalid package name '${builtins.toString package}'"
    package;

  validateCapability = packageName: capability:
    throwIfNot
    (builtins.isString capability && builtins.match capabilityType capability != null)
    "package '${packageName}' has invalid capability '${builtins.toString capability}'"
    (
      throwIfNot
      (capability != "CAP_SYS_MODULE")
      "package '${packageName}' requests CAP_SYS_MODULE; load modules through kernel-modules instead"
      capability
    );

  validateAbsolutePath = kind: path:
    throwIfNot
    (builtins.isString path && lib.hasPrefix "/" path)
    "${kind} must be an absolute path: ${builtins.toString path}"
    path;

  validateHostPath = hostPath:
    throwIfNot
    (builtins.isAttrs hostPath)
    "permissions.host-paths entries must be attrsets"
    (
      throwIfNot
      (builtins.attrNames hostPath == ["mode" "path"])
      "permissions.host-paths entries must contain only `path` and `mode`"
      (
        throwIfNot
        (builtins.elem hostPath.mode ["read-only" "rw"])
        "permissions.host-paths mode must be `read-only` or `rw`"
        (hostPath // {path = validateAbsolutePath "host path" hostPath.path;})
      )
    );

  validateKernelModule = module:
    throwIfNot
    (builtins.isString module && builtins.match kernelModuleType module != null)
    "invalid kernel module name '${builtins.toString module}'"
    module;

  validateSysctlKey = key:
    throwIfNot
    (builtins.isString key && builtins.match sysctlKeyType key != null)
    "invalid sysctl key '${builtins.toString key}'"
    key;

  validateSysctlValue = key: value: let
    stringValue = builtins.toString value;
  in
    throwIfNot
    ((builtins.isString value || builtins.isInt value) && builtins.match sysctlValueType stringValue != null)
    "invalid sysctl value for '${builtins.toString key}': ${stringValue}"
    stringValue;

  validateSysctls = sysctls: let
    checkedSysctls =
      throwIfNot
      (builtins.isAttrs sysctls)
      "expose.kernel.sysctl must be an attrset"
      sysctls;
  in
    builtins.mapAttrs (
      key: value: validateSysctlValue (validateSysctlKey key) value
    )
    checkedSysctls;

  validateKernel = kernel: let
    checkedKernel =
      throwIfNot
      (builtins.isAttrs kernel)
      "expose.kernel must be an attrset"
      kernel;
    allowedKeys = ["modules" "sysctl"];
    extraKeys = builtins.filter (
      key: !(builtins.elem key allowedKeys)
    ) (builtins.attrNames checkedKernel);
  in
    throwIfNot
    (extraKeys == [])
    "expose.kernel contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    {
      modules =
        builtins.map
        validateKernelModule
        (validateList "expose.kernel.modules" (checkedKernel.modules or []));
      sysctl = validateSysctls (checkedKernel.sysctl or {});
    };

  validatePort = field: port:
    throwIfNot
    (builtins.isInt port && port >= 1 && port <= 65535)
    "${field} contains invalid port '${builtins.toString port}'"
    port;

  validateFirewall = firewall: let
    checkedFirewall =
      throwIfNot
      (builtins.isAttrs firewall)
      "expose.firewall must be an attrset"
      firewall;
    allowedKeys = ["allowedTCP" "allowedUDP" "forwardPolicy"];
    extraKeys = builtins.filter (
      key: !(builtins.elem key allowedKeys)
    ) (builtins.attrNames checkedFirewall);
  in
    throwIfNot
    (extraKeys == [])
    "expose.firewall contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    {
      allowedTCP =
        builtins.map
        (validatePort "expose.firewall.allowedTCP")
        (validateList "expose.firewall.allowedTCP" (checkedFirewall.allowedTCP or []));
      allowedUDP =
        builtins.map
        (validatePort "expose.firewall.allowedUDP")
        (validateList "expose.firewall.allowedUDP" (checkedFirewall.allowedUDP or []));
      forwardPolicy =
        throwIfNot
        (builtins.elem (checkedFirewall.forwardPolicy or "drop") ["drop" "accept"])
        "expose.firewall.forwardPolicy must be `drop` or `accept`"
        (checkedFirewall.forwardPolicy or "drop");
    };

  validateSecurityLabel = label:
    throwIfNot
    (builtins.isString label && builtins.match securityLabelType label != null)
    "invalid security label '${builtins.toString label}'"
    label;

  validateImage = image:
    throwIfNot
    (builtins.isAttrs image)
    "expose.images entries must be attrsets"
    (let
      allowedImageKeys = [
        "format"
        "store_path"
        "nar_hash"
        "nar_size"
        "sb_signer_cert_sha256"
        "sbat"
        "expected_pcr11"
      ];
      extraImageKeys = builtins.filter (
        key: !(builtins.elem key allowedImageKeys)
      ) (builtins.attrNames image);
    in
      throwIfNot
      (extraImageKeys == [])
      "expose.images entry contains unknown keys: ${builtins.concatStringsSep ", " extraImageKeys}"
      (
        throwIfNot
        (image ? format && image ? store_path && image ? nar_hash && image ? nar_size)
        "expose.images entries must include format, store_path, nar_hash, and nar_size"
        (
          throwIfNot
          (builtins.isString image.format && builtins.match kernelModuleType image.format != null)
          "invalid expose image format '${builtins.toString image.format}'"
          (
            throwIfNot
            (
              builtins.isString image.nar_hash
              && (lib.hasPrefix "sha256:" image.nar_hash || lib.hasPrefix "sha256-" image.nar_hash)
            )
            "expose image '${builtins.toString image.store_path}' has invalid NAR hash"
            (image // {store_path = validateAbsolutePath "image store path" image.store_path;})
          )
        )
      )
    );

  validatePermissions = packageName: permissions: let
    checkedPermissions =
      throwIfNot
      (builtins.isAttrs permissions)
      "expose.permissions must be an attrset"
      permissions;
    allowedKeys = [
      "capabilities"
      "network"
      "devices"
      "host-paths"
      "cgroup-delegate"
      "privileged-users"
      "kernel-modules"
      "syscalls"
      "security-label"
    ];
    extraKeys = builtins.filter (
      key: !(builtins.elem key allowedKeys)
    ) (builtins.attrNames checkedPermissions);
    capabilities =
      builtins.map
      (validateCapability packageName)
      (validateList "permissions.capabilities" (checkedPermissions.capabilities or []));
    network =
      if checkedPermissions ? network
      then
        throwIfNot
        (builtins.elem checkedPermissions.network ["private" "private-outbound" "host"])
        "permissions.network must be `private`, `private-outbound`, or `host`"
        checkedPermissions.network
      else null;
    devices =
      builtins.map
      (validateAbsolutePath "device")
      (validateList "permissions.devices" (checkedPermissions.devices or []));
    hostPaths =
      builtins.map
      validateHostPath
      (validateList "permissions.host-paths" (checkedPermissions.host-paths or []));
    cgroupDelegate =
      validateBool "permissions.cgroup-delegate" (checkedPermissions.cgroup-delegate or false);
    privilegedUsers =
      validateBool "permissions.privileged-users" (checkedPermissions.privileged-users or false);
    kernelModules =
      builtins.map
      validateKernelModule
      (validateList "permissions.kernel-modules" (checkedPermissions.kernel-modules or []));
    syscalls =
      if checkedPermissions ? syscalls
      then
        throwIfNot
        (builtins.elem checkedPermissions.syscalls ["restricted" "system-service" "privileged"])
        "permissions.syscalls must be `restricted`, `system-service`, or `privileged`"
        checkedPermissions.syscalls
      else null;
    securityLabel =
      if checkedPermissions ? security-label
      then validateSecurityLabel checkedPermissions.security-label
      else null;
  in
    throwIfNot
    (extraKeys == [])
    "expose.permissions contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    (
      lib.optionalAttrs (capabilities != []) {inherit capabilities;}
      // lib.optionalAttrs (network != null) {inherit network;}
      // lib.optionalAttrs (devices != []) {inherit devices;}
      // lib.optionalAttrs (hostPaths != []) {host-paths = hostPaths;}
      // lib.optionalAttrs cgroupDelegate {cgroup-delegate = cgroupDelegate;}
      // lib.optionalAttrs privilegedUsers {privileged-users = privilegedUsers;}
      // lib.optionalAttrs (kernelModules != []) {kernel-modules = kernelModules;}
      // lib.optionalAttrs (syscalls != null) {inherit syscalls;}
      // lib.optionalAttrs (securityLabel != null) {security-label = securityLabel;}
    );

  selectUnits = suffix: units:
    lib.mapAttrs' (
      name: value: lib.nameValuePair (lib.removeSuffix suffix name) value
    ) (lib.filterAttrs (name: _: lib.hasSuffix suffix name) units);

  splitUnits = units: {
    services = selectUnits ".service" units;
    targets = selectUnits ".target" units;
    sockets = selectUnits ".socket" units;
    timers = selectUnits ".timer" units;
    paths = selectUnits ".path" units;
    slices = selectUnits ".slice" units;
    mounts = builtins.attrValues (lib.filterAttrs (name: _: lib.hasSuffix ".mount" name) units);
    automounts = builtins.attrValues (lib.filterAttrs (name: _: lib.hasSuffix ".automount" name) units);
  };

  validateTypedUnits = units: let
    systemd = splitUnits units;
    evaluated = lib.evalModules {
      modules = [
        {
          options.systemd = {
            services = lib.mkOption {
              type = systemdTypes.services;
              default = {};
            };
            targets = lib.mkOption {
              type = systemdTypes.targets;
              default = {};
            };
            sockets = lib.mkOption {
              type = systemdTypes.sockets;
              default = {};
            };
            timers = lib.mkOption {
              type = systemdTypes.timers;
              default = {};
            };
            paths = lib.mkOption {
              type = systemdTypes.paths;
              default = {};
            };
            slices = lib.mkOption {
              type = systemdTypes.slices;
              default = {};
            };
            mounts = lib.mkOption {
              type = systemdTypes.mounts;
              default = [];
            };
            automounts = lib.mkOption {
              type = systemdTypes.automounts;
              default = [];
            };
          };
          config.systemd = systemd;
        }
      ];
      inherit lib;
      specialArgs = {};
    };
  in
    evaluated.config.systemd;

  unitNamesFromTypedSystemd = systemd:
    lib.sort builtins.lessThan (
      lib.mapAttrsToList (_: unit: unit.name) systemd.services
      ++ lib.mapAttrsToList (_: unit: unit.name) systemd.targets
      ++ lib.mapAttrsToList (_: unit: unit.name) systemd.sockets
      ++ lib.mapAttrsToList (_: unit: unit.name) systemd.timers
      ++ lib.mapAttrsToList (_: unit: unit.name) systemd.paths
      ++ lib.mapAttrsToList (_: unit: unit.name) systemd.slices
      ++ builtins.map (unit: unit.name) systemd.mounts
      ++ builtins.map (unit: unit.name) systemd.automounts
    );

  uniqueUnits = units: lib.unique (validateList "systemd unit list" units);
  forbiddenGlobalScanDirs = [
    "/etc/modules-load.d/"
    "/etc/sysctl.d/"
    "/etc/nftables.d/"
  ];
in rec {
  assertNoGlobalScanDirStorage = packageName: storageLinks: let
    violations = builtins.filter (
      link:
        builtins.any (prefix: lib.hasPrefix prefix link.path) forbiddenGlobalScanDirs
    )
    storageLinks;
  in
    throwIfNot
    (violations == [])
    "mkDerivation expose for package '${packageName}' emits forbidden global scan-dir storage links: ${builtins.toJSON violations}"
    storageLinks;

  render = {
    packageName,
    expose,
  }: let
    checkedExpose =
      throwIfNot
      (builtins.isAttrs expose)
      "mkDerivation expose for package '${packageName}' must be an attrset"
      expose;
    allowedExposeKeys = [
      "target"
      "units"
      "kernel"
      "firewall"
      "images"
      "requires"
      "permissions"
    ];
    exposeExtraKeys = builtins.filter (
      key: !(builtins.elem key allowedExposeKeys)
    ) (builtins.attrNames checkedExpose);

    units =
      throwIfNot
      (builtins.isAttrs (checkedExpose.units or {}))
      "mkDerivation expose.units for package '${packageName}' must be an attrset"
      (checkedExpose.units or {});
    authoredUnitNames = builtins.map validateUnitName (builtins.attrNames units);
    target = validateTargetName (checkedExpose.target or "aos-pkg-${packageName}.target");
    modulesUnit = "aos-pkg-${packageName}-modules.service";
    sysctlUnit = "aos-pkg-${packageName}-sysctl.service";
    firewallUnit = "aos-pkg-${packageName}-firewall.service";
    sideEffectUnitNames = [modulesUnit sysctlUnit firewallUnit];
    reservedUnitNames = [target] ++ sideEffectUnitNames;
    reservedCollisions = builtins.filter (
      unit: builtins.elem unit authoredUnitNames
    )
    reservedUnitNames;
    reservedUnitsAvailable =
      throwIfNot
      (reservedCollisions == [])
      "mkDerivation expose.units for package '${packageName}' must not define synthesized units: ${builtins.concatStringsSep ", " reservedCollisions}"
      true;
    requires =
      builtins.map
      validatePackageName
      (validateList "expose.requires" (checkedExpose.requires or []));
    images =
      builtins.map
      validateImage
      (validateList "expose.images" (checkedExpose.images or []));
    permissions = validatePermissions packageName (checkedExpose.permissions or {});
    kernel = validateKernel (checkedExpose.kernel or {});
    firewall = validateFirewall (checkedExpose.firewall or {});

    memberUnitNames = authoredUnitNames ++ sideEffectUnitNames;

    addTargetMembership = _: unit:
      unit
      // {
        wantedBy = [target];
        requiredBy = [];
        upheldBy = [];
        partOf = uniqueUnits ((unit.partOf or []) ++ [target]);
        after = uniqueUnits ((unit.after or []) ++ sideEffectUnitNames);
        requires = uniqueUnits ((unit.requires or []) ++ sideEffectUnitNames);
      };

    trueCommand = "${pkgs.coreutils}/bin/true";
    moduleCommand =
      if kernel.modules == []
      then trueCommand
      else "${pkgs.kmod}/sbin/modprobe -a ${builtins.concatStringsSep " " kernel.modules}";
    sysctlAssignments =
      lib.mapAttrsToList (key: value: "${key}=${value}") kernel.sysctl;
    sysctlCommand =
      if sysctlAssignments == []
      then trueCommand
      else "${pkgs.procps-ng}/sbin/sysctl -w ${builtins.concatStringsSep " " sysctlAssignments}";

    formatPorts = ports:
      builtins.concatStringsSep ", " (builtins.map builtins.toString ports);
    nft = "${pkgs.nftables}/sbin/nft";
    addElements = set: ports:
      lib.optional (ports != [])
      "${nft} add element inet filter ${set} { ${formatPorts ports} }";
    deleteElements = set: ports:
      lib.optional (ports != [])
      "${nft} delete element inet filter ${set} { ${formatPorts ports} }";
    forwardComment = "aos-pkg-${packageName}-forward";
    forwardDeleteScript = ''
      set -eu
      ${nft} -a list chain inet filter forward \
        | ${pkgs.gawk}/bin/gawk -v comment=${lib.escapeShellArg forwardComment} \
          '$0 ~ "comment \"" comment "\"" { for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1) }' \
        | while read -r handle; do
            if [ -n "$handle" ]; then
              ${nft} delete rule inet filter forward handle "$handle"
            fi
          done
    '';
    forwardDeleteTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-firewall-forward-stop"
      forwardDeleteScript;
    forwardDeleteCommand = "${forwardDeleteTool}/bin/aos-pkg-${packageName}-firewall-forward-stop";
    forwardAddScript = forwardDeleteScript + ''
      ${nft} add rule inet filter forward accept comment ${lib.escapeShellArg forwardComment}
    '';
    forwardAddTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-firewall-forward-start"
      forwardAddScript;
    forwardAddCommand = "${forwardAddTool}/bin/aos-pkg-${packageName}-firewall-forward-start";
    firewallStartCommands =
      addElements "allowed_tcp" firewall.allowedTCP
      ++ addElements "allowed_udp" firewall.allowedUDP
      ++ lib.optional (firewall.forwardPolicy == "accept") forwardAddCommand;
    firewallStopCommands =
      deleteElements "allowed_tcp" firewall.allowedTCP
      ++ deleteElements "allowed_udp" firewall.allowedUDP
      ++ lib.optional (firewall.forwardPolicy == "accept") forwardDeleteCommand;
    firewallStart =
      if firewallStartCommands == []
      then trueCommand
      else firewallStartCommands;
    firewallStop =
      if firewallStopCommands == []
      then trueCommand
      else firewallStopCommands;
    firewallActive = firewallStartCommands != [];

    sideEffectUnits = {
      "${modulesUnit}" = {
        description = "Apply kernel modules for ${packageName}";
        wantedBy = [target];
        partOf = [target];
        before = authoredUnitNames;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = moduleCommand;
        };
      };
      "${sysctlUnit}" = {
        description = "Apply sysctl settings for ${packageName}";
        wantedBy = [target];
        partOf = [target];
        before = authoredUnitNames;
        after = [modulesUnit];
        requires = [modulesUnit];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = sysctlCommand;
        };
      };
      "${firewallUnit}" = {
        description = "Apply firewall rules for ${packageName}";
        wantedBy = [target];
        partOf = [target];
        before = authoredUnitNames;
        after = lib.optional firewallActive "nftables.service";
        requires = lib.optional firewallActive "nftables.service";
        unitConfig.ReloadPropagatedFrom = "nftables.service";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = firewallStart;
          ExecReload = firewallStart;
          ExecStop = firewallStop;
        };
      };
    };
    synthesizedUnits =
      builtins.seq reservedUnitsAvailable (
        builtins.mapAttrs addTargetMembership units
        // sideEffectUnits
        // {
          "${target}" = {
            description = "Activation target for ${packageName}";
            wants = uniqueUnits memberUnitNames;
          };
        }
      );
    typedSystemd = validateTypedUnits synthesizedUnits;
    renderedUnitNames = unitNamesFromTypedSystemd typedSystemd;
    manifestUnitNames =
      throwIfNot
      (lib.sort builtins.lessThan (builtins.attrNames synthesizedUnits) == renderedUnitNames)
      "mkDerivation expose.units for package '${packageName}' has keys that differ from rendered unit names; authored ${builtins.toJSON (builtins.attrNames synthesizedUnits)}, rendered ${builtins.toJSON renderedUnitNames}"
      renderedUnitNames;
    rendered = renderRole {
      name = packageName;
      systemd = typedSystemd;
    };
    storageLinks = assertNoGlobalScanDirStorage packageName rendered.storageLinks;

    manifest = {
      expose = {
        inherit target requires images;
        units = manifestUnitNames;
      };
      inherit kernel firewall;
      inherit permissions;
    };
  in
    throwIfNot
    (exposeExtraKeys == [])
    "mkDerivation expose for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " exposeExtraKeys}"
    (builtins.seq storageLinks (
      pkgs.runCommand "expose-${packageName}" {
        unitsDrv = rendered.unitsDrv;
        manifest = builtins.toJSON manifest;
        passAsFile = ["manifest"];
        preferLocalBuild = true;
        allowSubstitutes = false;
      } ''
        set -eu
        mkdir -p "$out/units"
        cp -a "$unitsDrv"/. "$out/units/"
        cp "$manifestPath" "$out/manifest.json"
      ''
    ));
}
