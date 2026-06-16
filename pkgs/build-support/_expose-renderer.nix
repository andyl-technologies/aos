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
in {
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
    unitNames = builtins.map validateUnitName (builtins.attrNames units);
    target = validateTargetName (checkedExpose.target or "aos-pkg-${packageName}.target");
    requires =
      builtins.map
      validatePackageName
      (validateList "expose.requires" (checkedExpose.requires or []));
    images =
      builtins.map
      validateImage
      (validateList "expose.images" (checkedExpose.images or []));
    permissions = validatePermissions packageName (checkedExpose.permissions or {});
    typedSystemd = validateTypedUnits units;
    renderedUnitNames = unitNamesFromTypedSystemd typedSystemd;
    manifestUnitNames =
      throwIfNot
      (unitNames == renderedUnitNames)
      "mkDerivation expose.units for package '${packageName}' has keys that differ from rendered unit names; authored ${builtins.toJSON unitNames}, rendered ${builtins.toJSON renderedUnitNames}"
      renderedUnitNames;
    rendered = renderRole {
      name = packageName;
      systemd = typedSystemd;
    };

    manifest = {
      expose = {
        inherit target requires images;
        units = manifestUnitNames;
      };
      inherit permissions;
    };
  in
    throwIfNot
    (exposeExtraKeys == [])
    "mkDerivation expose for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " exposeExtraKeys}"
    (
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
    );
}
