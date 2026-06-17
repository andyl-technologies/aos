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
  configNameType = "^[A-Za-z0-9_.-]+$";
  configFieldType = "^[A-Za-z_][A-Za-z0-9_]*$";
  capabilityType = "^CAP_[A-Z0-9_]+$";
  capabilityRouteNameType = "^[A-Za-z0-9_.-]+$";
  credentialNameType = "^[A-Za-z0-9_.-]+$";
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

  validateServiceUnitName = field: unit: let
    checked = validateUnitName unit;
  in
    throwIfNot
    (lib.hasSuffix ".service" checked)
    "${field} must reference a service unit, got '${builtins.toString unit}'"
    checked;

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

  validateHostPathDirectory = path:
    validateAbsolutePath "host path directory" path;

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
    (
      let
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

  validateConfigField = field:
    throwIfNot
    (builtins.isString field && builtins.match configFieldType field != null)
    "invalid config field name '${builtins.toString field}'"
    field;

  validateConfigArtifact = packageName: artifact:
    throwIfNot
    (builtins.isAttrs artifact)
    "expose.config.artifacts entries must be attrsets"
    (
      let
        allowedKeys = ["name" "path" "format" "required" "optional" "units" "reload"];
        extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames artifact);
        name =
          throwIfNot
          (artifact ? name && builtins.isString artifact.name && builtins.match configNameType artifact.name != null && builtins.match ".*\\.\\..*" artifact.name == null)
          "invalid config artifact name '${builtins.toString (artifact.name or "")}'"
          artifact.name;
        path =
          throwIfNot
          (artifact ? path && builtins.isString artifact.path && lib.hasPrefix "/etc/aos/packages/" artifact.path)
          "config artifact '${name}' path must be under /etc/aos/packages"
          artifact.path;
        format =
          throwIfNot
          (builtins.elem (artifact.format or "env") ["env" "json" "toml"])
          "config artifact '${name}' format must be `env`, `json`, or `toml`"
          (artifact.format or "env");
        required = builtins.map validateConfigField (validateList "expose.config.artifacts.required" (artifact.required or []));
        optional = builtins.map validateConfigField (validateList "expose.config.artifacts.optional" (artifact.optional or []));
        units = builtins.map validateUnitName (validateList "expose.config.artifacts.units" (artifact.units or []));
        reload =
          throwIfNot
          (builtins.elem (artifact.reload or "restart") ["restart" "reload" "none"])
          "config artifact '${name}' reload must be `restart`, `reload`, or `none`"
          (artifact.reload or "restart");
      in
        throwIfNot
        (extraKeys == [])
        "expose.config.artifacts entry contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
        {
          inherit name path format required optional units reload;
        }
    );

  validateCredential = credential:
    throwIfNot
    (builtins.isAttrs credential)
    "expose.config.credentials entries must be attrsets"
    (
      let
        allowedKeys = ["name" "units" "encrypted"];
        extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames credential);
        name =
          throwIfNot
          (credential ? name && builtins.isString credential.name && builtins.match credentialNameType credential.name != null)
          "invalid credential name '${builtins.toString (credential.name or "")}'"
          credential.name;
        units =
          builtins.map
          (validateServiceUnitName "expose.config.credentials.units")
          (validateList "expose.config.credentials.units" (credential.units or []));
        encrypted = validateBool "expose.config.credentials.encrypted" (credential.encrypted or false);
      in
        throwIfNot
        (extraKeys == [])
        "expose.config.credentials entry contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
        {
          inherit name units encrypted;
        }
    );

  validateConfig = packageName: config: let
    checkedConfig =
      throwIfNot
      (builtins.isAttrs config)
      "expose.config must be an attrset"
      config;
    allowedKeys = ["artifacts" "credentials"];
    extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames checkedConfig);
  in
    throwIfNot
    (extraKeys == [])
    "expose.config contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    {
      artifacts = builtins.map (validateConfigArtifact packageName) (validateList "expose.config.artifacts" (checkedConfig.artifacts or []));
      credentials = builtins.map validateCredential (validateList "expose.config.credentials" (checkedConfig.credentials or []));
    };

  validateProvidedCapability = capability:
    throwIfNot
    (builtins.isAttrs capability)
    "expose.provides entries must be attrsets"
    (
      let
        allowedKeys = ["name" "kind" "path" "unit"];
        extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames capability);
        name =
          throwIfNot
          (capability ? name && builtins.isString capability.name && builtins.match capabilityRouteNameType capability.name != null)
          "invalid provided capability name '${builtins.toString (capability.name or "")}'"
          capability.name;
        kind =
          throwIfNot
          (builtins.elem (capability.kind or "") ["directory" "namespace" "socket"])
          "provided capability '${name}' kind must be `directory`, `namespace`, or `socket`"
          capability.kind;
        path =
          if capability ? path
          then validateAbsolutePath "provided capability path" capability.path
          else null;
        unit =
          if capability ? unit
          then validateUnitName capability.unit
          else null;
      in
        throwIfNot
        (extraKeys == [])
        "expose.provides entry contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
        (
          throwIfNot
          (
            if kind == "directory"
            then path != null && unit == null
            else path == null && unit != null
          )
          "provided capability '${name}' has invalid path/unit fields for kind '${kind}'"
          (
            {inherit name kind;}
            // lib.optionalAttrs (path != null) {inherit path;}
            // lib.optionalAttrs (unit != null) {inherit unit;}
          )
        )
    );

  validateRequiredCapability = capability:
    throwIfNot
    (builtins.isAttrs capability)
    "expose.uses entries must be attrsets"
    (
      let
        allowedKeys = ["provider" "name" "kind" "unit"];
        extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames capability);
        provider =
          throwIfNot
          (capability ? provider)
          "expose.uses entries must declare provider"
          (validatePackageName capability.provider);
        name =
          throwIfNot
          (capability ? name && builtins.isString capability.name && builtins.match capabilityRouteNameType capability.name != null)
          "invalid required capability name '${builtins.toString (capability.name or "")}'"
          capability.name;
        kind =
          throwIfNot
          (builtins.elem (capability.kind or "") ["directory" "namespace" "socket"])
          "required capability '${name}' kind must be `directory`, `namespace`, or `socket`"
          capability.kind;
        unit =
          throwIfNot
          (capability ? unit)
          "expose.uses entries must declare consumer unit"
          (validateUnitName capability.unit);
      in
        throwIfNot
        (extraKeys == [])
        "expose.uses entry contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
        (
          throwIfNot
          (lib.hasSuffix ".service" unit)
          "required capability '${provider}.${name}' consumer unit must be a service"
          {inherit provider name kind unit;}
        )
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
  systemLocationPrefixes = [
    "/boot"
    "/etc"
    "/lib"
    "/lib64"
    "/nix"
    "/sbin"
    "/usr"
    "/var"
  ];

  hasAnyPrefix = prefixes: path:
    builtins.any (prefix: path == prefix || lib.hasPrefix "${prefix}/" path) prefixes;

  syscallFilterFor = profile:
    if profile == "privileged"
    then {}
    else {
      SystemCallFilter = "@system-service";
      SystemCallErrorNumber = "EPERM";
    };

  execKeys = [
    "ExecStart"
    "ExecStartPre"
    "ExecStartPost"
    "ExecReload"
    "ExecStop"
    "ExecStopPost"
    "ExecCondition"
  ];

  asList = value:
    if builtins.isList value
    then value
    else [value];

  hexDigits = {
    "0" = 0;
    "1" = 1;
    "2" = 2;
    "3" = 3;
    "4" = 4;
    "5" = 5;
    "6" = 6;
    "7" = 7;
    "8" = 8;
    "9" = 9;
    a = 10;
    b = 11;
    c = 12;
    d = 13;
    e = 14;
    f = 15;
  };

  hexNibbleToInt = nibble: hexDigits.${nibble};

  hexPairToInt = pair:
    (hexNibbleToInt (builtins.substring 0 1 pair) * 16)
    + hexNibbleToInt (builtins.substring 1 1 pair);

  hasPrivilegedExecPrefix = command:
    builtins.match "[-@:]*[!+].*" (builtins.toString command) != null;

  validateNoPrivilegedExecPrefixes = packageName: unitName: serviceConfig: let
    presentExecKeys = builtins.filter (key: serviceConfig ? ${key}) execKeys;
    violations = lib.concatLists (
      builtins.map (
        key:
          builtins.map (command: "${key}=${builtins.toString command}") (
            builtins.filter hasPrivilegedExecPrefix (asList serviceConfig.${key})
          )
      )
      presentExecKeys
    );
  in
    throwIfNot
    (violations == [])
    "mkDerivation expose.units.${unitName} for package '${packageName}' uses systemd privileged exec prefixes that bypass generated sandboxing: ${builtins.concatStringsSep ", " violations}"
    serviceConfig;
in rec {
  assertNoGlobalScanDirStorage = packageName: storageLinks: let
    violations =
      builtins.filter (
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
    drv ? null,
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
      "config"
      "provides"
      "uses"
      "prepareHostPathDirectories"
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
    hostPathsUnit = "aos-pkg-${packageName}-host-paths.service";
    modulesUnit = "aos-pkg-${packageName}-modules.service";
    sysctlUnit = "aos-pkg-${packageName}-sysctl.service";
    firewallUnit = "aos-pkg-${packageName}-firewall.service";
    netnsUnit = "aos-pkg-${packageName}-netns.service";
    reservedCollisions =
      builtins.filter (
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
    config = validateConfig packageName (checkedExpose.config or {});
    provides =
      builtins.map
      validateProvidedCapability
      (validateList "expose.provides" (checkedExpose.provides or []));
    uses =
      builtins.map
      validateRequiredCapability
      (validateList "expose.uses" (checkedExpose.uses or []));
    permissions = validatePermissions packageName (checkedExpose.permissions or {});
    kernel = validateKernel (checkedExpose.kernel or {});
    firewall = validateFirewall (checkedExpose.firewall or {});
    prepareHostPathDirectories =
      builtins.map
      validateHostPathDirectory
      (validateList "expose.prepareHostPathDirectories" (checkedExpose.prepareHostPathDirectories or []));
    network = permissions.network or "private";
    legacyKernelModules = kernel.modules;
    permissionKernelModules = permissions.kernel-modules or [];
    sameKernelModules =
      lib.sort builtins.lessThan legacyKernelModules
      == lib.sort builtins.lessThan permissionKernelModules;
    kernelModules =
      if legacyKernelModules == []
      then permissionKernelModules
      else
        throwIfNot
        sameKernelModules
        "mkDerivation expose for package '${packageName}' declares expose.kernel.modules that do not match permissions.kernel-modules; kernel module loads must be declared in the signed permissions manifest"
        permissionKernelModules;
    sideEffectUnitNames =
      lib.optional (prepareHostPathDirectories != []) hostPathsUnit
      ++ [modulesUnit sysctlUnit firewallUnit]
      ++ lib.optional (network == "private-outbound") netnsUnit;
    reservedUnitNames = [target hostPathsUnit modulesUnit sysctlUnit firewallUnit netnsUnit];
    capabilities = permissions.capabilities or [];
    devices = permissions.devices or [];
    hostPaths = permissions.host-paths or [];
    cgroupDelegate = permissions.cgroup-delegate or false;
    privilegedUsers = permissions.privileged-users or false;
    syscallProfile = permissions.syscalls or "restricted";

    rwHostPaths = builtins.filter (hostPath: hostPath.mode == "rw") hostPaths;
    rootEquivalent =
      builtins.elem "CAP_SYS_ADMIN" capabilities
      || privilegedUsers
      || builtins.any (hostPath: hasAnyPrefix systemLocationPrefixes hostPath.path) rwHostPaths;
    confinementHoles =
      lib.optional (network != "private") "network:${network}"
      ++ builtins.map (capability: "capability:${capability}") capabilities
      ++ builtins.map (device: "device:${device}") devices
      ++ builtins.map (hostPath: "host-path:${hostPath.mode}:${hostPath.path}") hostPaths
      ++ lib.optional cgroupDelegate "cgroup-delegate"
      ++ lib.optional privilegedUsers "privileged-users"
      ++ lib.optional (syscallProfile != "restricted") "syscalls:${syscallProfile}";
    confinementClass =
      if rootEquivalent
      then "unconfined"
      else if confinementHoles == []
      then "sandboxed"
      else "sandboxed-with-holes";
    confinementLabel =
      if confinementClass == "sandboxed-with-holes"
      then "sandboxed-with-holes (${builtins.concatStringsSep ", " confinementHoles})"
      else confinementClass;
    confinement = {
      class = confinementClass;
      label = confinementLabel;
      holes = confinementHoles;
    };
    manifestKernel = kernel // {modules = kernelModules;};
    manifestPermissions =
      permissions
      // {
        security-label = permissions.security-label or "aos-pkg-${packageName}";
        inherit confinement;
      };
    readOnlyHostPaths = builtins.map (hostPath: hostPath.path) (
      builtins.filter (hostPath: hostPath.mode == "read-only") hostPaths
    );
    readWriteHostPaths =
      builtins.map (hostPath: hostPath.path) rwHostPaths;
    undeclaredPreparedHostPathDirectories =
      builtins.filter (
        path: !(builtins.elem path readWriteHostPaths)
      )
      prepareHostPathDirectories;
    preparedHostPathDirectoriesAvailable =
      throwIfNot
      (undeclaredPreparedHostPathDirectories == [])
      "expose.prepareHostPathDirectories for package '${packageName}' must be a subset of rw permissions.host-paths: ${builtins.concatStringsSep ", " undeclaredPreparedHostPathDirectories}"
      true;
    deviceAllows = builtins.map (device: "${device} rwm") devices;
    payloadRoot =
      throwIfNot
      (drv != null)
      "mkDerivation expose for package '${packageName}' needs the payload derivation to render RootDirectory"
      drv;
    addressFamilies = uniqueUnits (
      ["AF_UNIX" "AF_INET" "AF_INET6"]
      ++ lib.optional (network == "host" || builtins.elem "CAP_NET_ADMIN" capabilities) "AF_NETLINK"
    );
    netnsHash = builtins.substring 0 8 (builtins.hashString "sha256" packageName);
    netnsName = "aos-pkg-${packageName}";
    netnsHostIf = "aos${netnsHash}h";
    netnsPeerIf = "aos${netnsHash}p";
    netnsSubnetIndex =
      (hexPairToInt (builtins.substring 0 2 netnsHash) * 4096)
      + (hexPairToInt (builtins.substring 2 2 netnsHash) * 16)
      + hexNibbleToInt (builtins.substring 4 1 netnsHash);
    netnsSecondOctet = 64 + (netnsSubnetIndex / 16384);
    netnsSubnetRemainder = netnsSubnetIndex - ((netnsSubnetIndex / 16384) * 16384);
    netnsThirdOctet = netnsSubnetRemainder / 64;
    netnsFourthOctet = (netnsSubnetRemainder - ((netnsSubnetRemainder / 64) * 64)) * 4;
    netnsPrefix = "100.${builtins.toString netnsSecondOctet}.${builtins.toString netnsThirdOctet}";
    netnsCidr = "${netnsPrefix}.${builtins.toString netnsFourthOctet}/30";
    netnsHostAddress = "${netnsPrefix}.${builtins.toString (netnsFourthOctet + 1)}";
    netnsPeerAddress = "${netnsPrefix}.${builtins.toString (netnsFourthOctet + 2)}";

    configArtifactsForUnit = unitName:
      builtins.filter (
        artifact: artifact.units == [] || builtins.elem unitName artifact.units
      )
      config.artifacts;

    configArtifactPathsForUnit = unitName:
      builtins.map (artifact: artifact.path) (configArtifactsForUnit unitName);

    configConditionPathsForUnit = unitName:
      builtins.map (artifact: artifact.path) (
        builtins.filter (artifact: artifact.required != []) (configArtifactsForUnit unitName)
      );

    configReloadArtifactsForUnit = unitName:
      builtins.filter (
        artifact: artifact.reload != "none" && builtins.elem unitName artifact.units
      )
      config.artifacts;

    credentialsForUnit = unitName:
      builtins.filter (
        credential: credential.units == [] || builtins.elem unitName credential.units
      )
      config.credentials;

    credentialServiceConfigFor = unitName: authoredServiceConfig: let
      credentials = credentialsForUnit unitName;
      loadCredentials =
        builtins.map (credential: credential.name) (
          builtins.filter (credential: !credential.encrypted) credentials
        );
      loadEncryptedCredentials =
        builtins.map (credential: credential.name) (
          builtins.filter (credential: credential.encrypted) credentials
        );
    in
      lib.optionalAttrs (loadCredentials != []) {
        LoadCredential =
          lib.unique ((asList (authoredServiceConfig.LoadCredential or [])) ++ loadCredentials);
      }
      // lib.optionalAttrs (loadEncryptedCredentials != []) {
        LoadCredentialEncrypted =
          lib.unique ((asList (authoredServiceConfig.LoadCredentialEncrypted or [])) ++ loadEncryptedCredentials);
      };

    sandboxServiceConfig = unitName: authoredServiceConfig: let
      checkedAuthoredServiceConfig =
        validateNoPrivilegedExecPrefixes packageName unitName authoredServiceConfig;
    in
      checkedAuthoredServiceConfig
      // {
        RootDirectory = "${payloadRoot}";
        MountAPIVFS = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = "disconnected";
        TemporaryFileSystem = ["/tmp" "/var/tmp"];
        StateDirectory = authoredServiceConfig.StateDirectory or "aos-pkg-${packageName}";
        NoNewPrivileges = true;
        DynamicUser = !privilegedUsers;
        PrivateUsers =
          if privilegedUsers
          then false
          else "identity";
        PrivateNetwork = network == "private";
        DevicePolicy = "closed";
        DeviceAllow = deviceAllows;
        Delegate = cgroupDelegate;
        CapabilityBoundingSet = builtins.concatStringsSep " " capabilities;
        AmbientCapabilities = builtins.concatStringsSep " " capabilities;
        BindReadOnlyPaths = uniqueUnits (["/nix/store"] ++ readOnlyHostPaths ++ configArtifactPathsForUnit unitName);
        BindPaths = readWriteHostPaths;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = !cgroupDelegate;
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = addressFamilies;
        RestrictNamespaces = !privilegedUsers;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
      }
      // credentialServiceConfigFor unitName checkedAuthoredServiceConfig
      // syscallFilterFor syscallProfile
      // lib.optionalAttrs (network == "private-outbound") {
        PrivateNetwork = false;
        NetworkNamespacePath = "/run/netns/aos-pkg-${packageName}";
      };

    memberUnitNames = authoredUnitNames ++ sideEffectUnitNames;
    socketActivatedServiceFor = name: unit: let
      socketConfig = unit.socketConfig or {};
      accept = socketConfig.Accept or false;
      acceptString =
        if builtins.isString accept
        then lib.toLower accept
        else accept;
      acceptEnabled = acceptString == true || acceptString == "true" || acceptString == "yes" || acceptString == "on" || acceptString == "1";
    in
      if acceptEnabled
      then null
      else socketConfig.Service or "${lib.removeSuffix ".socket" name}.service";
    socketActivatedServiceUnitNames = uniqueUnits (
      builtins.filter (unit: unit != null)
      (
        lib.mapAttrsToList (
          name: unit:
            if lib.hasSuffix ".socket" name
            then socketActivatedServiceFor name unit
            else null
        )
        units
      )
      ++ builtins.map (route: route.unit) (builtins.filter (route: route.kind == "socket") uses)
    );
    targetMemberUnitNames =
      builtins.filter (
        unit: let
          authored = units.${unit} or {};
        in
          !(authored.onlyManualStart or false)
          && !(
            builtins.elem unit socketActivatedServiceUnitNames
            && builtins.hasAttr unit units
            && !(authored.notSocketActivated or false)
          )
      )
      memberUnitNames;
    referencedUnitNames =
      builtins.concatMap (artifact: artifact.units) config.artifacts
      ++ builtins.concatMap (credential: credential.units) config.credentials
      ++ builtins.filter (unit: unit != null) (builtins.map (capability: capability.unit or null) provides)
      ++ builtins.map (route: route.unit) uses;
    unknownUnitReferences =
      builtins.filter (unit: !(builtins.elem unit authoredUnitNames)) referencedUnitNames;
    unitReferencesValid =
      throwIfNot
      (unknownUnitReferences == [])
      "mkDerivation expose for package '${packageName}' references unknown authored units: ${builtins.concatStringsSep ", " unknownUnitReferences}"
      true;

    addTargetMembership = name: unit: let
      conditionPaths = configConditionPathsForUnit name;
      reloadArtifacts = configReloadArtifactsForUnit name;
      reloadPaths = builtins.map (artifact: artifact.path) reloadArtifacts;
      reloadableArtifacts = builtins.filter (artifact: artifact.reload == "reload") reloadArtifacts;
      directTargetMember =
        !(
          builtins.elem name socketActivatedServiceUnitNames
          && !((unit.notSocketActivated or false))
        )
        && !((unit.onlyManualStart or false));
    in
      unit
      // {
        wantedBy = lib.optional directTargetMember target;
        requiredBy = [];
        upheldBy = [];
        partOf = uniqueUnits ((unit.partOf or []) ++ [target]);
        after = uniqueUnits ((unit.after or []) ++ sideEffectUnitNames);
        requires = uniqueUnits ((unit.requires or []) ++ sideEffectUnitNames);
        unitConfig =
          (unit.unitConfig or {})
          // lib.optionalAttrs (conditionPaths != []) {
            ConditionPathExists = uniqueUnits ((asList ((unit.unitConfig or {}).ConditionPathExists or [])) ++ conditionPaths);
          };
        reloadTriggers = uniqueUnits ((unit.reloadTriggers or []) ++ reloadPaths);
        reloadIfChanged = (unit.reloadIfChanged or false) || reloadableArtifacts != [];
      }
      // lib.optionalAttrs (lib.hasSuffix ".service" name) {
        serviceConfig = sandboxServiceConfig name (unit.serviceConfig or {});
      };

    trueCommand = "${pkgs.coreutils}/bin/true";
    moduleCommand =
      if kernelModules == []
      then trueCommand
      else "${pkgs.kmod}/sbin/modprobe -a ${builtins.concatStringsSep " " kernelModules}";
    sysctlAssignments =
      lib.mapAttrsToList (key: value: "${key}=${value}") kernel.sysctl;
    sysctlCommand =
      if sysctlAssignments == []
      then trueCommand
      else "${pkgs.procps-ng}/sbin/sysctl -w ${builtins.concatStringsSep " " sysctlAssignments}";
    hostPathsCommand =
      if prepareHostPathDirectories == []
      then trueCommand
      else "${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArgs prepareHostPathDirectories}";

    formatPorts = ports:
      builtins.concatStringsSep ", " (builtins.map builtins.toString ports);
    nft = "${pkgs.nftables}/sbin/nft";
    ip = "${pkgs.iproute2}/sbin/ip";
    sysctl = "${pkgs.procps-ng}/sbin/sysctl";
    deleteInetForwardRulesByComment = comment: ''
      ${nft} -a list chain inet filter forward 2>/dev/null \
        | ${pkgs.gawk}/bin/gawk -v needle=${lib.escapeShellArg "comment \"${comment}\""} \
          'index($0, needle) { for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1) }' \
        | while read -r handle; do
            if [ -n "$handle" ]; then
              ${nft} delete rule inet filter forward handle "$handle"
            fi
          done
    '';
    addElements = set: ports:
      lib.optional (ports != [])
      "${nft} add element inet filter ${set} { ${formatPorts ports} }";
    deleteElements = set: ports:
      lib.optional (ports != [])
      "${nft} delete element inet filter ${set} { ${formatPorts ports} }";
    forwardComment = "aos-pkg-${packageName}-forward";
    forwardDeleteScript = ''
      set -eu
      ${deleteInetForwardRulesByComment forwardComment}
    '';
    forwardDeleteTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-firewall-forward-stop"
      forwardDeleteScript;
    forwardDeleteCommand = "${forwardDeleteTool}/bin/aos-pkg-${packageName}-firewall-forward-stop";
    forwardAddScript =
      forwardDeleteScript
      + ''
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
    netnsForwardComment = "aos-pkg-${packageName}-netns-forward";
    netnsNatTable = "aos_pkg_${netnsHash}";
    netnsCommonScript = ''
      netns=${lib.escapeShellArg netnsName}
      host_if=${lib.escapeShellArg netnsHostIf}
      peer_if=${lib.escapeShellArg netnsPeerIf}
      host_addr=${lib.escapeShellArg netnsHostAddress}
      peer_addr=${lib.escapeShellArg netnsPeerAddress}
      cidr=${lib.escapeShellArg netnsCidr}
      nat_table=${lib.escapeShellArg netnsNatTable}
      forward_comment=${lib.escapeShellArg netnsForwardComment}
      run_dir=/run/aos-pkg-netns
      marker="$run_dir/$netns.ip_forward"
      prev_file="$run_dir/ip_forward.prev"
      lock_file="$run_dir/lock"

      lock_state() {
        ${pkgs.coreutils}/bin/mkdir -p "$run_dir"
        exec 9>"$lock_file"
        ${pkgs.util-linux}/bin/flock 9
      }

      delete_forward_rules() {
        ${deleteInetForwardRulesByComment netnsForwardComment}
      }

      apply_forwarding_rules() {
        delete_forward_rules
        ${nft} delete table ip "$nat_table" 2>/dev/null || true
        ${nft} add table ip "$nat_table"
        ${nft} add chain ip "$nat_table" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
        ${nft} add rule ip "$nat_table" postrouting ip saddr "$cidr" oifname != "$host_if" masquerade comment "$forward_comment"
        ${nft} add rule inet filter forward iifname "$host_if" accept comment "$forward_comment"
        ${nft} add rule inet filter forward oifname "$host_if" ct state established,related accept comment "$forward_comment"
      }
    '';
    netnsCleanupScript = ''
      any_forward_markers() {
        for marker_path in "$run_dir"/*.ip_forward; do
          [ -e "$marker_path" ] || continue
          return 0
        done
        return 1
      }

      restore_ip_forward_if_last() {
        ${pkgs.coreutils}/bin/rm -f "$marker"
        if ! any_forward_markers && [ -f "$prev_file" ]; then
          previous_ip_forward=$(${pkgs.coreutils}/bin/cat "$prev_file")
          ${sysctl} -w "net.ipv4.ip_forward=$previous_ip_forward"
          ${pkgs.coreutils}/bin/rm -f "$prev_file"
        fi
      }

      cleanup_package_state() {
        delete_forward_rules
        ${nft} delete table ip "$nat_table" 2>/dev/null || true
        ${ip} link delete "$host_if" 2>/dev/null || true
        ${ip} netns delete "$netns" 2>/dev/null || true
        restore_ip_forward_if_last
      }
    '';
    netnsStartScript = ''
      set -eu
      ${netnsCommonScript}
      ${netnsCleanupScript}

      lock_state
      trap 'status=$?; if [ "$status" -ne 0 ]; then cleanup_package_state; fi; exit "$status"' EXIT

      if ! any_forward_markers; then
        ${pkgs.coreutils}/bin/cat /proc/sys/net/ipv4/ip_forward > "$prev_file"
      fi

      ${pkgs.coreutils}/bin/mkdir -p /run/netns
      if ${ip} netns list | ${pkgs.gawk}/bin/gawk -v netns="$netns" '$1 == netns { found = 1 } END { exit !found }'; then
        echo "netns $netns already exists; refusing to steal a private-outbound namespace" >&2
        exit 1
      fi

      if ${ip} link show "$host_if" >/dev/null 2>&1; then
        echo "interface $host_if already exists; refusing private-outbound veth collision" >&2
        exit 1
      fi

      if ${ip} -4 route show exact "$cidr" | ${pkgs.gawk}/bin/gawk 'NF > 0 { found = 1 } END { exit !found }'; then
        echo "route $cidr already exists; refusing private-outbound subnet collision" >&2
        exit 1
      fi

      ${pkgs.coreutils}/bin/printf '%s\n' "$netns" > "$marker"
      ${sysctl} -w net.ipv4.ip_forward=1

      ${ip} netns add "$netns"
      ${ip} link add "$host_if" type veth peer name "$peer_if"
      ${ip} link set "$peer_if" netns "$netns"
      ${ip} addr replace "$host_addr/30" dev "$host_if"
      ${ip} link set "$host_if" up
      ${ip} netns exec "$netns" ${ip} link set lo up
      ${ip} netns exec "$netns" ${ip} addr replace "$peer_addr/30" dev "$peer_if"
      ${ip} netns exec "$netns" ${ip} link set "$peer_if" up
      ${ip} netns exec "$netns" ${ip} route replace default via "$host_addr" dev "$peer_if"

      apply_forwarding_rules
      trap - EXIT
    '';
    netnsStartTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-netns-start"
      netnsStartScript;
    netnsStartCommand = "${netnsStartTool}/bin/aos-pkg-${packageName}-netns-start";
    netnsReloadScript = ''
      set -eu
      ${netnsCommonScript}

      lock_state
      ${sysctl} -w net.ipv4.ip_forward=1
      apply_forwarding_rules
    '';
    netnsReloadTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-netns-reload"
      netnsReloadScript;
    netnsReloadCommand = "${netnsReloadTool}/bin/aos-pkg-${packageName}-netns-reload";
    netnsStopScript = ''
      set -eu
      ${netnsCommonScript}
      ${netnsCleanupScript}

      lock_state
      cleanup_package_state
    '';
    netnsStopTool =
      pkgs.writeShellScriptBin
      "aos-pkg-${packageName}-netns-stop"
      netnsStopScript;
    netnsStopCommand = "${netnsStopTool}/bin/aos-pkg-${packageName}-netns-stop";

    sideEffectUnits =
      lib.optionalAttrs (prepareHostPathDirectories != []) {
        "${hostPathsUnit}" = {
          description = "Prepare host path directories for ${packageName}";
          wantedBy = [target];
          partOf = [target];
          before = authoredUnitNames;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = hostPathsCommand;
          };
        };
      }
      //
      {
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
      }
      // lib.optionalAttrs (network == "private-outbound") {
        "${netnsUnit}" = {
          description = "Create outbound network namespace for ${packageName}";
          wantedBy = [target];
          partOf = [target];
          before = authoredUnitNames;
          after = ["nftables.service"];
          requires = ["nftables.service"];
          unitConfig.ReloadPropagatedFrom = "nftables.service";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = netnsStartCommand;
            ExecReload = netnsReloadCommand;
            ExecStop = netnsStopCommand;
            ExecStopPost = netnsStopCommand;
          };
        };
      };
    synthesizedUnits = builtins.seq reservedUnitsAvailable (
      builtins.seq preparedHostPathDirectoriesAvailable (
        builtins.mapAttrs addTargetMembership units
        // sideEffectUnits
        // {
          "${target}" = {
            description = "Activation target for ${packageName}";
            wants = uniqueUnits targetMemberUnitNames;
          };
        }
      )
    );
    typedSystemd = builtins.seq unitReferencesValid (validateTypedUnits synthesizedUnits);
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
        inherit target requires images config provides uses;
        units = manifestUnitNames;
      };
      kernel = manifestKernel;
      inherit firewall;
      inherit confinement;
      permissions = manifestPermissions;
    };
  in
    throwIfNot
    (exposeExtraKeys == [])
    "mkDerivation expose for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " exposeExtraKeys}"
    (builtins.seq storageLinks (
      pkgs.runCommand "expose-${packageName}" {
        unitsDrv = rendered.unitsDrv;
        manifest = builtins.toJSON manifest;
        passthru = {
          inherit manifest confinement;
          permissions = manifestPermissions;
        };
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
