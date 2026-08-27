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
  exposeModule = import ./_expose-module.nix {inherit lib;};

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

  configNameType = "^[A-Za-z0-9_.-]+$";
  configFieldType = "^[A-Za-z_][A-Za-z0-9_]*$";
  capabilityType = "^CAP_[A-Z0-9_]+$";
  capabilityRouteNameType = "^[A-Za-z0-9_.-]+$";
  packageNameType = "^[A-Za-z0-9][A-Za-z0-9+._=-]*$";
  credentialNameType = "^[A-Za-z0-9_.-]+$";
  hostPathType = "^[A-Za-z0-9_./+=@-]+$";
  kernelModuleType = "^[A-Za-z0-9_-]+$";
  sysctlKeyType = "^[A-Za-z0-9_.-]+$";
  sysctlValueType = "^[^[:space:]]+$";
  securityLabelType = "^[A-Za-z0-9._-]+$";
  landlockWritableTempPrefixes = ["/tmp" "/var/tmp"];

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

  validateTargetName = packageName: target: let
    expected = "aos-pkg-${packageName}.target";
  in
    throwIfNot
    (
      validateUnitName target
      == target
      && lib.hasPrefix "aos-pkg-" target
      && lib.hasSuffix ".target" target
      && target == expected
    )
    "expose.target for package '${packageName}' must equal ${expected}: ${builtins.toString target}"
    target;

  validatePackageName = package:
    throwIfNot
    (
      builtins.isString package
      && builtins.match packageNameType package != null
    )
    "expose capability route contains invalid package name '${builtins.toString package}'"
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

  validateStorePath = kind: path: let
    checked = validatePathHasNoParent kind (validateAbsolutePath kind path);
  in
    throwIfNot
    (lib.hasPrefix "/nix/store/" checked)
    "${kind} must be a Nix store path: ${builtins.toString path}"
    checked;

  validatePathHasNoParent = kind: path:
    throwIfNot
    (!(builtins.elem ".." (lib.splitString "/" path)))
    "${kind} must not contain '..': ${builtins.toString path}"
    path;

  validateCredentialSourceChars = path:
    throwIfNot
    (builtins.match "[A-Za-z0-9_./+=@-]+" path != null)
    "credential source path contains unsupported characters: ${builtins.toString path}"
    path;

  validateCredentialCiphertext = ciphertext:
    throwIfNot
    (builtins.isString ciphertext && builtins.match "[A-Za-z0-9_./+=-]+" ciphertext != null)
    "credential ciphertext contains unsupported characters"
    ciphertext;

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
        (
          let
            checkedPath = validatePathHasNoParent "host path" (
              throwIfNot
              (builtins.match hostPathType (validateAbsolutePath "host path" hostPath.path) != null)
              "host path contains unsupported characters: ${builtins.toString hostPath.path}"
              hostPath.path
            );
          in
            throwIfNot
            (!(hostPath.mode == "read-only" && hasAnyPrefix landlockWritableTempPrefixes checkedPath))
            "read-only host paths under /tmp or /var/tmp would be writable through the package Landlock temp grants: ${checkedPath}"
            (hostPath // {path = checkedPath;})
        )
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

  validatePortList = field: ports: let
    checkedPorts =
      builtins.map
      (validatePort field)
      (validateList field ports);
  in
    throwIfNot
    (builtins.length checkedPorts == builtins.length (lib.unique checkedPorts))
    "${field} contains duplicate ports"
    checkedPorts;

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

  validateRelativeArtifactPath = field: path: let
    components = lib.splitString "/" path;
    invalidComponent = builtins.any (part: part == "" || part == "." || part == "..") components;
  in
    throwIfNot
    (
      builtins.isString path
      && path != ""
      && !lib.hasPrefix "/" path
      && builtins.match ".*\\\\.*" path == null
      && builtins.match hostPathType path != null
      && !invalidComponent
    )
    "${field} must be a safe relative artifact path"
    path;

  validateRelativeArtifactPathWithSuffix = field: suffix: path:
    throwIfNot
    (lib.hasSuffix suffix path)
    "${field} must be a relative ${suffix} artifact path"
    (validateRelativeArtifactPath field path);

  validateRootHash = field: hash:
    throwIfNot
    (builtins.isString hash && builtins.match "^sha256[:-][0-9A-Fa-f]{64}$" hash != null)
    "${field} must be a sha256 digest"
    hash;

  rootHashHex = hash:
    if lib.hasPrefix "sha256:" hash
    then lib.removePrefix "sha256:" hash
    else lib.removePrefix "sha256-" hash;

  selinuxIdentifierForLabel = label: let
    normalized =
      builtins.replaceStrings
      ["_" "." "-" "+" "="]
      ["_x5f" "_x2e" "_x2d" "_x2b" "_x3d"]
      label;
  in
    if builtins.match "^[A-Za-z_].*" normalized != null
    then normalized
    else "aos_pkg_${normalized}";

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
          "root_image"
          "root_verity"
          "root_hash"
          "root_hash_file"
          "root_hash_sig"
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
              (
                let
                  rootHashFile =
                    if image ? root_hash_file
                    then validateAbsolutePath "expose image root_hash_file" (builtins.toString image.root_hash_file)
                    else null;
                  rootHashPlaceholder = builtins.substring 0 64 (builtins.hashString "sha256" "aos-expose-root-hash:${builtins.toString image.store_path}:${builtins.toString (image.root_hash_file or "")}");
                  normalized =
                    builtins.removeAttrs image ["root_hash_file"]
                    // {
                      store_path = validateAbsolutePath "image store path" image.store_path;
                    };
                  verityFields = [
                    (image ? root_image)
                    (image ? root_verity)
                    (image ? root_hash || rootHashFile != null)
                    (image ? root_hash_sig)
                  ];
                  verityFieldCount = builtins.length (builtins.filter (present: present) verityFields);
                  verityFormat = builtins.elem image.format ["ext4-verity" "erofs-verity"];
                in
                  if verityFieldCount == 0 && !verityFormat
                  then normalized
                  else
                    throwIfNot
                    verityFormat
                    "expose image '${builtins.toString image.store_path}' declares dm-verity fields but format '${builtins.toString image.format}' is not a verity root format"
                    (
                      throwIfNot
                      (verityFieldCount == 4)
                      "expose image '${builtins.toString image.store_path}' must declare root_image, root_verity, root_hash, and root_hash_sig together"
                      (
                        throwIfNot
                        (!(image ? root_hash && rootHashFile != null))
                        "expose image '${builtins.toString image.store_path}' must not declare both root_hash and root_hash_file"
                        (
                          normalized
                          // {
                            root_image = validateRelativeArtifactPath "expose image root_image" image.root_image;
                            root_verity = validateRelativeArtifactPathWithSuffix "expose image root_verity" ".verity" image.root_verity;
                            root_hash =
                              if rootHashFile != null
                              then "sha256:${rootHashPlaceholder}"
                              else validateRootHash "expose image root_hash" image.root_hash;
                            root_hash_sig = validateRelativeArtifactPathWithSuffix "expose image root_hash_sig" ".p7s" image.root_hash_sig;
                          }
                          // lib.optionalAttrs (rootHashFile != null) {inherit rootHashFile;}
                        )
                      )
                    )
              )
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
      "tcp-bind"
      "tcp-connect"
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
    tcpBind =
      validatePortList "permissions.tcp-bind" (checkedPermissions.tcp-bind or []);
    tcpConnect =
      validatePortList "permissions.tcp-connect" (checkedPermissions.tcp-connect or []);
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
      // lib.optionalAttrs (tcpBind != []) {tcp-bind = tcpBind;}
      // lib.optionalAttrs (tcpConnect != []) {tcp-connect = tcpConnect;}
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

  validateCredential = packageName: credential:
    throwIfNot
    (builtins.isAttrs credential)
    "expose.config.credentials entries must be attrsets"
    (
      let
        allowedKeys = ["name" "source" "ciphertext" "units" "encrypted" "encryptedFile" "optional"];
        extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames credential);
        name =
          throwIfNot
          (credential ? name && builtins.isString credential.name && builtins.match credentialNameType credential.name != null)
          "invalid credential name '${builtins.toString (credential.name or "")}'"
          credential.name;
        vendored = credential ? encryptedFile;
        encrypted =
          if vendored
          then
            throwIfNot
            (validateBool "expose.config.credentials.encrypted" (credential.encrypted or true))
            "credential '${name}' with encryptedFile must be encrypted"
            true
          else validateBool "expose.config.credentials.encrypted" (credential.encrypted or false);
        source =
          if credential ? source
          then validateCredentialSource encrypted credential.source
          else if vendored
          then "/run/credstore.encrypted/aos/${packageName}/${name}"
          else null;
        generatedSource =
          source
          != null
          && (
            source
            == "/run/credstore.encrypted/aos"
            || lib.hasPrefix "/run/credstore.encrypted/aos/" source
          );
        ciphertext =
          if credential ? ciphertext
          then validateCredentialCiphertext credential.ciphertext
          else null;
        encryptedFile =
          if credential ? encryptedFile
          then
            validateStorePath
            "credential encryptedFile"
            (builtins.toString credential.encryptedFile)
          else null;
        units =
          builtins.map
          (validateServiceUnitName "expose.config.credentials.units")
          (validateList "expose.config.credentials.units" (credential.units or []));
        optional = validateBool "expose.config.credentials.optional" (credential.optional or false);
        manifestCredential =
          {
            inherit name units encrypted;
          }
          // lib.optionalAttrs optional {inherit optional;}
          // lib.optionalAttrs (source != null) {inherit source;}
          // lib.optionalAttrs (ciphertext != null) {inherit ciphertext;};
      in
        throwIfNot
        (extraKeys == [])
        "expose.config.credentials entry contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
        (
          throwIfNot
          (!(source != null && ciphertext != null))
          "credential '${name}' must not declare both source and ciphertext"
          (
            throwIfNot
            (!(ciphertext != null && !encrypted))
            "credential '${name}' declares ciphertext but is not encrypted"
            (
              throwIfNot
              (!(vendored && ciphertext != null))
              "credential '${name}' must not declare both encryptedFile and ciphertext"
              (
                throwIfNot
                (!(vendored && credential ? source))
                "credential '${name}' with encryptedFile uses the deterministic /run/credstore.encrypted/aos/<package>/<name> source path"
                (
                  throwIfNot
                  (!vendored || lib.hasPrefix "/run/credstore.encrypted/aos/" source)
                  "credential '${name}' with encryptedFile must use the AOS projected credstore namespace under /run/credstore.encrypted/aos"
                  (
                    throwIfNot
                    (vendored || !generatedSource)
                    "credential '${name}' must not use the AOS generated credential namespace /run/credstore.encrypted/aos without encryptedFile"
                    {
                      manifest = manifestCredential;
                      blob =
                        if vendored
                        then {
                          inherit name source encryptedFile;
                        }
                        else null;
                    }
                  )
                )
              )
            )
          )
        )
    );

  validateCredentialSource = encrypted: source: let
    checked = validateCredentialSourceChars (
      validatePathHasNoParent "credential source path" (
        validateAbsolutePath "credential source path" source
      )
    );
    prefixes =
      if encrypted
      then encryptedCredentialSourcePrefixes
      else plaintextCredentialSourcePrefixes;
  in
    throwIfNot
    (hasAnyPrefix prefixes checked && !(builtins.elem checked prefixes))
    (
      if encrypted
      then "encrypted credential source path must be under /usr/lib/credstore.encrypted, /etc/credstore.encrypted, or /run/credstore.encrypted"
      else "credential source path must be under /usr/lib/credstore, /etc/credstore, or /run/credstore"
    )
    checked;

  validateConfig = packageName: config: let
    checkedConfig =
      throwIfNot
      (builtins.isAttrs config)
      "expose.config must be an attrset"
      config;
    allowedKeys = ["artifacts" "credentials"];
    extraKeys = builtins.filter (key: !(builtins.elem key allowedKeys)) (builtins.attrNames checkedConfig);
    artifacts = builtins.map (validateConfigArtifact packageName) (validateList "expose.config.artifacts" (checkedConfig.artifacts or []));
    checkedCredentials = builtins.map (validateCredential packageName) (validateList "expose.config.credentials" (checkedConfig.credentials or []));
    credentials = builtins.map (credential: credential.manifest) checkedCredentials;
    credentialBlobs = builtins.filter (blob: blob != null) (builtins.map (credential: credential.blob) checkedCredentials);
    credentialNames = builtins.map (credential: credential.name) credentials;
    duplicateCredentialNames = lib.unique (
      builtins.filter (
        name: builtins.length (builtins.filter (candidate: candidate == name) credentialNames) > 1
      )
      credentialNames
    );
  in
    throwIfNot
    (extraKeys == [])
    "expose.config contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    (
      throwIfNot
      (duplicateCredentialNames == [])
      "expose.config.credentials declares duplicate credential name(s): ${builtins.concatStringsSep ", " duplicateCredentialNames}"
      {inherit artifacts credentials credentialBlobs;}
    );

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
  encryptedCredentialSourcePrefixes = [
    "/usr/lib/credstore.encrypted"
    "/etc/credstore.encrypted"
    "/run/credstore.encrypted"
  ];
  plaintextCredentialSourcePrefixes = [
    "/usr/lib/credstore"
    "/etc/credstore"
    "/run/credstore"
  ];

  hasAnyPrefix = prefixes: path:
    builtins.any (prefix: path == prefix || lib.hasPrefix "${prefix}/" path) prefixes;

  syscallFilterFor = profile: enableLandlock:
    if profile == "privileged"
    then {}
    else {
      SystemCallFilter =
        if enableLandlock
        then "@system-service landlock_create_ruleset landlock_add_rule landlock_restrict_self"
        else "@system-service";
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

  scriptExecFields = [
    {
      option = "script";
      key = "ExecStart";
    }
    {
      option = "preStart";
      key = "ExecStartPre";
    }
    {
      option = "postStart";
      key = "ExecStartPost";
    }
    {
      option = "reload";
      key = "ExecReload";
    }
    {
      option = "preStop";
      key = "ExecStop";
    }
    {
      option = "postStop";
      key = "ExecStopPost";
    }
  ];

  asList = value:
    if builtins.isList value
    then value
    else [value];

  effectiveSystemdList = values:
    builtins.foldl' (
      acc: value: let
        text = lib.trim (builtins.toString value);
      in
        if text == ""
        then []
        else acc ++ [text]
    ) []
    values;

  isDecimal = value:
    builtins.match "^[0-9]+$" value != null;

  tcpListenStreamPort = field: value: let
    text = lib.trim (builtins.toString value);
    parts = lib.splitString ":" text;
    lastPart = builtins.elemAt parts (builtins.length parts - 1);
    parsePort = portText:
      validatePort field (lib.toInt portText);
  in
    if text == "" || lib.hasPrefix "/" text || lib.hasPrefix "@" text || lib.hasPrefix "vsock:" text
    then null
    else if isDecimal text
    then parsePort text
    else if lib.hasPrefix "[" text && builtins.match "^.*\\]:[0-9]+$" text != null
    then parsePort lastPart
    else if builtins.length parts == 2 && isDecimal lastPart
    then parsePort lastPart
    else throw "mkDerivation ${field} contains unsupported ListenStream endpoint '${text}'; use a Unix socket path or a TCP port/host:port endpoint";

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

  execCommandText = command: lib.trim (builtins.toString command);

  isExecReset = command: execCommandText command == "";

  firstExecToken = command: builtins.head (lib.splitString " " (execCommandText command));

  hasPrivilegedExecPrefix = command:
    builtins.match "[-@:|]*[!+].*" (execCommandText command) != null;

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

  hasAnyExecPrefix = command:
    builtins.match "[-@:|!+].*" (execCommandText command) != null;

  validateNoLandlockExecPrefixes = packageName: unitName: key: command: let
    text = execCommandText command;
  in
    throwIfNot
    (!hasAnyExecPrefix text)
    "mkDerivation expose.units.${unitName} for package '${packageName}' uses a ${key} prefix that cannot be preserved by generated sandbox wrappers: ${text}"
    command;

  validateLandlockExecAbsolutePath = packageName: unitName: key: command: let
    text = execCommandText command;
  in
    throwIfNot
    (isExecReset command || lib.hasPrefix "/" (firstExecToken command))
    "mkDerivation expose.units.${unitName} for package '${packageName}' uses a ${key} command whose executable is not an absolute path and cannot be resolved exactly by generated sandbox wrappers: ${text}"
    command;
in rec {
  # Pure normalized schema shared with the generated configuration companion.
  # Credential build inputs are deliberately excluded; only signed manifest
  # handles may enter config-module source bytes.
  normalizeConfig = packageName: config: let
    checked = validateConfig packageName config;
  in {
    inherit (checked) artifacts credentials;
  };

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
    # Type-check the complete authored surface with the same module engine used
    # by on-host evaluation. Keep the original sparse attrset for the
    # legacy renderer below: its omitted-vs-present distinctions are part of
    # the signed RFC-0001 manifest contract (notably credential source fields).
    typedExposeContract = builtins.deepSeq (exposeModule.eval expose) true;
    checkedExpose = builtins.seq typedExposeContract (
      throwIfNot
      (builtins.isAttrs expose)
      "mkDerivation expose for package '${packageName}' must be an attrset"
      expose
    );
    allowedExposeKeys = [
      "target"
      "units"
      "kernel"
      "firewall"
      "images"
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
    target =
      validateTargetName
      packageName
      (checkedExpose.target or "aos-pkg-${packageName}.target");
    hostPathsUnit = "aos-pkg-${packageName}-host-paths.service";
    modulesUnit = "aos-pkg-${packageName}-modules.service";
    sysctlUnit = "aos-pkg-${packageName}-sysctl.service";
    firewallUnit = "aos-pkg-${packageName}-firewall.service";
    netnsUnit = "aos-pkg-${packageName}-netns.service";
    macUnit = "aos-pkg-${packageName}-mac.service";
    ebpfUnit = "aos-pkg-${packageName}-ebpf.service";
    packageSlice = "aos-pkg-${packageName}.slice";
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
    images =
      builtins.map
      validateImage
      (validateList "expose.images" (checkedExpose.images or []));
    manifestImages = builtins.map (image: builtins.removeAttrs image ["rootHashFile"]) images;
    dynamicRootHashImages = builtins.filter (image: image ? rootHashFile) images;
    passthruManifestImages =
      builtins.map (
        image: let
          manifestImage = builtins.removeAttrs image ["rootHashFile"];
        in
          if image ? rootHashFile
          then
            builtins.removeAttrs manifestImage ["root_hash"]
            // {
              root_hash_file = image.rootHashFile;
            }
          else manifestImage
      )
      images;
    verityImages = builtins.filter (image: builtins.elem image.format ["ext4-verity" "erofs-verity"]) images;
    verityImage =
      throwIfNot
      (builtins.length verityImages <= 1)
      "mkDerivation expose for package '${packageName}' declares multiple verity root images"
      (
        if verityImages == []
        then null
        else builtins.head verityImages
      );
    verityRootConfig =
      if verityImage == null
      then null
      else {
        RootImage = "${verityImage.store_path}/${verityImage.root_image}";
        RootVerity = "${verityImage.store_path}/${verityImage.root_verity}";
        RootHash = rootHashHex verityImage.root_hash;
        RootHashSignature = "${verityImage.store_path}/${verityImage.root_hash_sig}";
        RootImagePolicy = "root=signed";
      };
    checkedConfig = validateConfig packageName (checkedExpose.config or {});
    config = {
      inherit (checkedConfig) artifacts credentials;
    };
    credentialBlobs = checkedConfig.credentialBlobs;
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
      ++ lib.optional (network == "private-outbound") netnsUnit
      ++ lib.optional (confinementClass != "unconfined") macUnit
      ++ lib.optional (confinementClass != "unconfined") ebpfUnit;
    reservedUnitNames = [target hostPathsUnit modulesUnit sysctlUnit firewallUnit netnsUnit macUnit ebpfUnit packageSlice];
    capabilities = permissions.capabilities or [];
    tcpBind = permissions.tcp-bind or [];
    tcpConnect = permissions.tcp-connect or [];
    devices = permissions.devices or [];
    hostPaths = permissions.host-paths or [];
    cgroupDelegate = permissions.cgroup-delegate or false;
    privilegedUsers = permissions.privileged-users or false;
    syscallProfile = permissions.syscalls or "restricted";
    authoredStaticUsers = uniqueUnits (
      builtins.filter (user: user != null) (
        builtins.map (
          unitName: let
            serviceConfig = units.${unitName}.serviceConfig or {};
          in
            if lib.hasSuffix ".service" unitName && serviceConfig ? User
            then builtins.toString serviceConfig.User
            else null
        )
        authoredUnitNames
      )
    );

    rwHostPaths = builtins.filter (hostPath: hostPath.mode == "rw") hostPaths;
    rootEquivalent =
      builtins.elem "CAP_SYS_ADMIN" capabilities
      || privilegedUsers
      || builtins.any (hostPath: hasAnyPrefix systemLocationPrefixes hostPath.path) rwHostPaths;
    confinementHoles =
      lib.optional (network != "private") "network:${network}"
      ++ builtins.map (port: "tcp-bind:${builtins.toString port}") tcpBind
      ++ builtins.map (port: "tcp-connect:${builtins.toString port}") tcpConnect
      ++ builtins.map (capability: "capability:${capability}") capabilities
      ++ builtins.map (device: "device:${device}") devices
      ++ builtins.map (hostPath: "host-path:${hostPath.mode}:${hostPath.path}") hostPaths
      ++ lib.optional cgroupDelegate "cgroup-delegate"
      ++ lib.optional privilegedUsers "privileged-users"
      ++ builtins.map (user: "static-user:${user}") authoredStaticUsers
      ++ lib.optional (syscallProfile != "restricted") "syscalls:${syscallProfile}";
    confinementClass =
      if rootEquivalent
      then "unconfined"
      else if confinementHoles == []
      then "sandboxed"
      else "sandboxed-with-holes";
    verityConfinementValid =
      throwIfNot
      (!(verityImage != null && confinementClass == "unconfined"))
      "mkDerivation expose for package '${packageName}' declares a verity root image but package permissions require unconfined service rendering"
      true;
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
    landlockTcpEnabled = !rootEquivalent && (tcpBind != [] || tcpConnect != []);
    landlockFsEnabled = !rootEquivalent;
    landlockEnabled = landlockTcpEnabled || landlockFsEnabled;
    landlockDefaultReadOnlyPaths = ["/"];
    landlockDefaultReadWritePaths = ["/tmp" "/var/tmp"];
    readOnlyHostPaths = builtins.map (hostPath: hostPath.path) (
      builtins.filter (hostPath: hostPath.mode == "read-only") hostPaths
    );
    readWriteHostPaths =
      builtins.map (hostPath: hostPath.path) rwHostPaths;
    stateDirectoryNamesForUnit = unit: let
      authoredServiceConfig = unit.serviceConfig or {};
      values = asList (authoredServiceConfig.StateDirectory or "aos-pkg-${packageName}");
    in
      builtins.filter (name: name != "") (
        lib.concatMap (value: lib.splitString " " value) values
      );
    stateDirectoryPaths = uniqueUnits (
      lib.concatMap (
        unitName:
          if lib.hasSuffix ".service" unitName
          then builtins.map (name: "/var/lib/${name}") (stateDirectoryNamesForUnit units.${unitName})
          else []
      )
      (builtins.attrNames units)
    );
    landlockReadWritePaths =
      if landlockFsEnabled
      then
        uniqueUnits (
          landlockDefaultReadWritePaths ++ stateDirectoryPaths ++ readWriteHostPaths
        )
      else [];
    landlockReadOnlyPaths =
      if landlockFsEnabled
      then
        builtins.filter (
          path: !(builtins.elem path landlockReadWritePaths)
        )
        (uniqueUnits (landlockDefaultReadOnlyPaths ++ readOnlyHostPaths))
      else [];
    landlockArgs =
      ["--require-abi" "4"]
      ++ lib.optionals landlockFsEnabled (
        lib.concatMap (path: ["--fs-ro" path]) landlockReadOnlyPaths
        ++ lib.concatMap (path: ["--fs-rw" path]) landlockReadWritePaths
      )
      ++ lib.concatMap (port: ["--tcp-bind" (builtins.toString port)]) tcpBind
      ++ lib.concatMap (port: ["--tcp-connect" (builtins.toString port)]) tcpConnect;
    landlockPrefix = "${pkgs.aos-landlock}/bin/aos-landlock ${builtins.concatStringsSep " " landlockArgs} --";
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
    systemdSliceCgroupPath = slice: let
      base = lib.removeSuffix ".slice" slice;
      parts = lib.splitString "-" base;
      prefixes = builtins.genList (
        i: builtins.concatStringsSep "-" (lib.take (i + 1) parts)
      ) (builtins.length parts);
    in
      builtins.concatStringsSep "/" (builtins.map (prefix: "${prefix}.slice") prefixes);
    ebpfEnabled = confinementClass != "unconfined";
    ebpfPolicyPathPlaceholder = "@AOS_EXPOSE_ARTIFACT@/network-policy.json";
    ebpfCgroupPath = "/sys/fs/cgroup/${systemdSliceCgroupPath packageSlice}";
    ebpfCommand = "${pkgs.aos-ebpf-net-policy}/bin/aos-ebpf-net-policy run --policy ${ebpfPolicyPathPlaceholder} --cgroup ${ebpfCgroupPath} --object ${pkgs.aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o";
    macProfileEnabled = confinementClass != "unconfined";
    macModuleName = selinuxIdentifierForLabel manifestPermissions.security-label;
    macTypeName = "${macModuleName}_t";
    macContext = "system_u:system_r:${macTypeName}";
    macProfilePath = "mac/selinux/${macModuleName}.pp";
    macModulePath = "mac/selinux/${macModuleName}.mod";
    macSourcePath = "mac/selinux/${macModuleName}.te";
    macProfilePathPlaceholder = "@AOS_EXPOSE_ARTIFACT@/${macProfilePath}";
    macLoadCommand = "${pkgs.policycoreutils}/sbin/semodule -i ${macProfilePathPlaceholder}";
    macRunPrefix = "${pkgs.aos-selinux-run}/bin/aos-selinux-run --context ${macContext} --";
    verityRootHash =
      if verityImage == null
      then null
      else rootHashHex verityImage.root_hash;
    verityRootGuardPrefix =
      if verityRootConfig == null
      then null
      else "${pkgs.aos-verity-root-guard}/bin/aos-verity-root-guard ${verityRootHash} ${verityRootConfig.RootHashSignature} --";
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
        credential:
          !(credential.optional or false)
          && (credential.units == [] || builtins.elem unitName credential.units)
      )
      config.credentials;

    credentialSourcePathsForUnit = unitName:
      builtins.filter (path: path != null) (
        builtins.map (credential: credential.source or null) (credentialsForUnit unitName)
      );

    credentialLoadSpec = credential:
      if credential ? source
      then "${credential.name}:${credential.source}"
      else credential.name;

    credentialSetEncryptedSpec = credential: "${credential.name}:${credential.ciphertext}";

    credentialSpecParts = spec: lib.splitString ":" (builtins.toString spec);

    credentialSpecName = spec: builtins.head (credentialSpecParts spec);

    credentialImportSpecNames = spec: let
      parts = credentialSpecParts spec;
    in
      if builtins.length parts > 1
      then [(builtins.head parts) (builtins.elemAt parts 1)]
      else [builtins.head parts];

    assertNoCredentialDirectiveCollisions = unitName: authoredNames: generatedSpecs: let
      generatedNames = builtins.map credentialSpecName generatedSpecs;
      collisions = lib.unique (
        builtins.filter (name: builtins.elem name authoredNames) generatedNames
      );
    in
      throwIfNot
      (collisions == [])
      "mkDerivation expose.units.${unitName} for package '${packageName}' declares LoadCredential*/SetCredential* for credential(s) also declared by expose.config.credentials: ${builtins.concatStringsSep ", " collisions}"
      true;

    credentialServiceConfigFor = unitName: authoredServiceConfig: let
      credentials = credentialsForUnit unitName;
      authoredLoadCredentials = asList (authoredServiceConfig.LoadCredential or []);
      authoredLoadEncryptedCredentials = asList (authoredServiceConfig.LoadCredentialEncrypted or []);
      authoredSetCredentials = asList (authoredServiceConfig.SetCredential or []);
      authoredSetEncryptedCredentials = asList (authoredServiceConfig.SetCredentialEncrypted or []);
      authoredImportCredentials = asList (authoredServiceConfig.ImportCredential or []);
      importCredentialsAvailable =
        throwIfNot
        (authoredImportCredentials == [] || credentials == [])
        "mkDerivation expose.units.${unitName} for package '${packageName}' must not mix authored ImportCredential= with expose.config.credentials metadata"
        true;
      authoredCredentialNames =
        builtins.map credentialSpecName (
          authoredLoadCredentials
          ++ authoredLoadEncryptedCredentials
          ++ authoredSetCredentials
          ++ authoredSetEncryptedCredentials
        )
        ++ builtins.concatMap credentialImportSpecNames authoredImportCredentials;
      loadCredentials = builtins.map credentialLoadSpec (
        builtins.filter (credential: !credential.encrypted && !(credential ? ciphertext)) credentials
      );
      loadEncryptedCredentials = builtins.map credentialLoadSpec (
        builtins.filter (credential: credential.encrypted && !(credential ? ciphertext)) credentials
      );
      setEncryptedCredentials = builtins.map credentialSetEncryptedSpec (
        builtins.filter (credential: credential ? ciphertext) credentials
      );
      credentialIdsAvailable =
        assertNoCredentialDirectiveCollisions
        unitName
        authoredCredentialNames
        (loadCredentials ++ loadEncryptedCredentials ++ setEncryptedCredentials);
    in
      builtins.seq importCredentialsAvailable (
        builtins.seq credentialIdsAvailable (
          lib.optionalAttrs (loadCredentials != []) {
            LoadCredential =
              lib.unique (authoredLoadCredentials ++ loadCredentials);
          }
          // lib.optionalAttrs (loadEncryptedCredentials != []) {
            LoadCredentialEncrypted =
              lib.unique (authoredLoadEncryptedCredentials ++ loadEncryptedCredentials);
          }
          // lib.optionalAttrs (setEncryptedCredentials != []) {
            SetCredentialEncrypted =
              lib.unique (authoredSetEncryptedCredentials ++ setEncryptedCredentials);
          }
        )
      );

    sandboxExecWrapperPrefix = builtins.concatStringsSep " " (
      lib.optional macProfileEnabled macRunPrefix
      ++ lib.optional landlockEnabled landlockPrefix
    );
    verityRootGuardPrecheckCommand =
      if verityRootGuardPrefix == null
      then null
      else "${pkgs.aos-verity-root-guard}/bin/aos-verity-root-guard --signature-only ${verityRootHash} ${verityRootConfig.RootHashSignature}";
    execWrapperPrefix = sandboxExecWrapperPrefix;

    wrapSandboxExecCommand = unitName: key: value:
      if builtins.isList value
      then builtins.map (command: wrapSandboxExecCommand unitName key command) value
      else let
        checkedCommand = validateLandlockExecAbsolutePath packageName unitName key (
          validateNoLandlockExecPrefixes packageName unitName key value
        );
      in
        if isExecReset checkedCommand
        then ""
        else "${execWrapperPrefix} ${builtins.toString checkedCommand}";

    landlockServiceConfigFor = unitName: unit: authoredServiceConfig: let
      scriptDerivedExecs =
        builtins.filter (field: (unit.${field.option} or "") != "") scriptExecFields;
      scriptDerivedExecText =
        builtins.map (field: "${field.option} -> ${field.key}") scriptDerivedExecs;
      presentExecKeys = builtins.filter (key: authoredServiceConfig ? ${key}) execKeys;
      wrappedExecConfig = builtins.listToAttrs (
        builtins.map (key: {
          name = key;
          value = wrapSandboxExecCommand unitName key authoredServiceConfig.${key};
        })
        presentExecKeys
      );
      wrappedExecStartPre = asList (wrappedExecConfig.ExecStartPre or []);
      generatedExecStartPre = lib.optional (verityRootGuardPrecheckCommand != null) verityRootGuardPrecheckCommand;
      wrappedExecConfigWithPrecheck =
        builtins.removeAttrs wrappedExecConfig ["ExecStartPre"]
        // lib.optionalAttrs (generatedExecStartPre != [] || wrappedExecStartPre != []) {
          ExecStartPre = generatedExecStartPre ++ wrappedExecStartPre;
        };
      authoredExecConfigWithPrecheck = lib.optionalAttrs (generatedExecStartPre != []) {
        ExecStartPre = generatedExecStartPre ++ asList (authoredServiceConfig.ExecStartPre or []);
      };
      scriptSupported =
        throwIfNot
        (!(landlockEnabled && scriptDerivedExecs != []))
        "mkDerivation expose.units.${unitName} for package '${packageName}' uses script-derived service commands with Landlock policy (${builtins.concatStringsSep ", " scriptDerivedExecText}); use explicit serviceConfig.Exec* commands so the generated wrapper can preserve the sandbox boundary"
        true;
    in
      builtins.seq scriptSupported (
        if landlockEnabled
        then wrappedExecConfigWithPrecheck
        else authoredExecConfigWithPrecheck
      );

    sandboxServiceConfig = unitName: unit: let
      authoredServiceConfig = unit.serviceConfig or {};
      checkedAuthoredServiceConfig =
        validateNoPrivilegedExecPrefixes packageName unitName authoredServiceConfig;
      unconfined = confinementClass == "unconfined";
      hasStaticUser = checkedAuthoredServiceConfig ? User;
      authoredUser =
        if hasStaticUser
        then builtins.toString checkedAuthoredServiceConfig.User
        else "";
      hasAuthoredDynamicUser = checkedAuthoredServiceConfig ? DynamicUser;
      authoredDynamicUser = checkedAuthoredServiceConfig.DynamicUser or null;
      generatedDynamicUser =
        if hasAuthoredDynamicUser
        then authoredDynamicUser
        else !(privilegedUsers || hasStaticUser);
      dynamicUserIsBoolean =
        throwIfNot
        (!hasAuthoredDynamicUser || builtins.isBool authoredDynamicUser)
        "mkDerivation expose.units.${unitName} for package '${packageName}' sets DynamicUser to a non-boolean value"
        true;
      staticUserAllowed =
        throwIfNot
        (!(hasStaticUser && builtins.elem authoredUser ["root" "0"] && !privilegedUsers))
        "mkDerivation expose.units.${unitName} for package '${packageName}' sets User=${authoredUser} without privileged-users"
        true;
      dynamicUserDisabledHasIdentity =
        throwIfNot
        (!(generatedDynamicUser == false && !hasStaticUser && !privilegedUsers))
        "mkDerivation expose.units.${unitName} for package '${packageName}' disables DynamicUser without setting User"
        true;
      authoredRootDirectoryAllowed =
        throwIfNot
        (!(verityRootConfig != null && checkedAuthoredServiceConfig ? RootDirectory))
        "mkDerivation expose.units.${unitName} for package '${packageName}' sets serviceConfig.RootDirectory while expose.images declares a verity root image"
        true;
    in
      builtins.seq dynamicUserIsBoolean (
        builtins.seq staticUserAllowed (
          builtins.seq dynamicUserDisabledHasIdentity (
            builtins.seq authoredRootDirectoryAllowed (
              checkedAuthoredServiceConfig
              // lib.optionalAttrs (!unconfined) (
                {
                  MountAPIVFS = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = "disconnected";
                  TemporaryFileSystem = ["/tmp" "/var/tmp"];
                  StateDirectory = authoredServiceConfig.StateDirectory or "aos-pkg-${packageName}";
                  NoNewPrivileges = true;
                  BindReadOnlyPaths = uniqueUnits (
                    ["/nix/store"]
                    ++ lib.optional (verityRootConfig != null) "/sys/firmware/efi/efivars:/run/aos-secure-boot-efivars"
                    ++ readOnlyHostPaths
                    ++ configArtifactPathsForUnit unitName
                  );
                  BindPaths = readWriteHostPaths;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectKernelLogs = true;
                  ProtectClock = true;
                  ProtectHostname = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  RestrictSUIDSGID = true;
                }
                // (
                  if verityRootConfig == null
                  then {RootDirectory = "${payloadRoot}";}
                  else verityRootConfig
                )
              )
              // lib.optionalAttrs (unconfined && checkedAuthoredServiceConfig ? StateDirectory) {
                StateDirectory = checkedAuthoredServiceConfig.StateDirectory;
              }
              // lib.optionalAttrs unconfined {
                Slice = packageSlice;
              }
              // lib.optionalAttrs (unconfined && cgroupDelegate) {
                Delegate = true;
              }
              // lib.optionalAttrs (unconfined && privilegedUsers) {
                DynamicUser = false;
                PrivateUsers = false;
              }
              // lib.optionalAttrs (unconfined && network == "private") {
                PrivateNetwork = true;
              }
              // lib.optionalAttrs (unconfined && network == "private-outbound") {
                PrivateNetwork = false;
                NetworkNamespacePath = "/run/netns/aos-pkg-${packageName}";
              }
              // lib.optionalAttrs (!unconfined) {
                DynamicUser = generatedDynamicUser;
                PrivateUsers =
                  if privilegedUsers || generatedDynamicUser == false
                  then false
                  else "identity";
                PrivateNetwork = network == "private";
                PrivateDevices =
                  if verityRootConfig == null
                  then devices == []
                  else false;
                DevicePolicy = "closed";
                DeviceAllow = deviceAllows;
                Delegate = cgroupDelegate;
                CapabilityBoundingSet = builtins.concatStringsSep " " capabilities;
                AmbientCapabilities = builtins.concatStringsSep " " capabilities;
                ProtectControlGroups =
                  if cgroupDelegate
                  then false
                  else "private";
                SystemCallArchitectures = "native";
                RestrictAddressFamilies = addressFamilies;
                RestrictNamespaces = !privilegedUsers;
                RestrictRealtime = true;
                Slice = packageSlice;
              }
              // lib.optionalAttrs (verityRootConfig != null) {
                PermissionsStartOnly = true;
              }
              // lib.optionalAttrs (!rootEquivalent) {
                ProtectProc = "invisible";
                ProcSubset = "pid";
              }
              // credentialServiceConfigFor unitName checkedAuthoredServiceConfig
              // landlockServiceConfigFor unitName unit checkedAuthoredServiceConfig
              // lib.optionalAttrs (!unconfined) (syscallFilterFor syscallProfile landlockEnabled)
              // lib.optionalAttrs (network == "private-outbound") {
                PrivateNetwork = false;
                NetworkNamespacePath = "/run/netns/aos-pkg-${packageName}";
              }
            )
          )
        )
      );

    memberUnitNames = [packageSlice] ++ authoredUnitNames ++ sideEffectUnitNames;
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
    credentialSourcePathsForActivatedSocket = name: unit:
      if lib.hasSuffix ".socket" name
      then let
        service = socketActivatedServiceFor name unit;
      in
        if service != null && builtins.hasAttr service units
        then credentialSourcePathsForUnit service
        else []
      else [];
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
    tcpSocketListeners = lib.concatMap (
      socketName: let
        unit = typedSystemdUnchecked.sockets.${socketName};
        unitName = unit.name;
        socketConfigListenStreams =
          if unit.socketConfig ? ListenStream
          then asList unit.socketConfig.ListenStream
          else [];
        listenStreams = effectiveSystemdList (socketConfigListenStreams ++ unit.listenStreams);
        tcpPorts = builtins.filter (port: port != null) (
          builtins.map
          (tcpListenStreamPort "expose.units.${unitName}.ListenStream")
          listenStreams
        );
      in
        builtins.map (port: {
          inherit port unitName;
        })
        tcpPorts
    ) (builtins.attrNames typedSystemdUnchecked.sockets);
    tcpSocketListenerViolations =
      builtins.filter (listener: !(builtins.elem listener.port tcpBind)) tcpSocketListeners;
    socketTcpBindValid =
      throwIfNot
      (tcpSocketListenerViolations == [])
      "mkDerivation expose for package '${packageName}' has TCP socket listeners without matching permissions.tcp-bind grants: ${builtins.concatStringsSep ", " (builtins.map (listener: "${listener.unitName}:${builtins.toString listener.port}") tcpSocketListenerViolations)}"
      true;

    addTargetMembership = name: unit: let
      conditionPaths =
        configConditionPathsForUnit name
        ++ credentialSourcePathsForUnit name
        ++ credentialSourcePathsForActivatedSocket name unit;
      reloadArtifacts = configReloadArtifactsForUnit name;
      reloadPaths = builtins.map (artifact: artifact.path) reloadArtifacts;
      reloadableArtifacts = builtins.filter (artifact: artifact.reload == "reload") reloadArtifacts;
      rootImageUnitDependency = lib.optional (verityImage != null && lib.hasSuffix ".service" name) "systemd-udevd.service";
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
        after = uniqueUnits ((unit.after or []) ++ sideEffectUnitNames ++ rootImageUnitDependency);
        requires = uniqueUnits ((unit.requires or []) ++ sideEffectUnitNames ++ rootImageUnitDependency);
        unitConfig =
          (unit.unitConfig or {})
          // lib.optionalAttrs (conditionPaths != []) {
            ConditionPathExists = uniqueUnits ((asList ((unit.unitConfig or {}).ConditionPathExists or [])) ++ conditionPaths);
          };
        reloadTriggers = uniqueUnits ((unit.reloadTriggers or []) ++ reloadPaths);
        reloadIfChanged = (unit.reloadIfChanged or false) || reloadableArtifacts != [];
      }
      // lib.optionalAttrs (lib.hasSuffix ".service" name) {
        serviceConfig = sandboxServiceConfig name unit;
      };

    trueCommand = "${pkgs.coreutils}/bin/true";
    writeCommandScript = name: commands: let
      tool = pkgs.writeShellScriptBin name ''
        set -eu
        ${builtins.concatStringsSep "\n" commands}
      '';
    in "${tool}/bin/${name}";
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
      else writeCommandScript "aos-pkg-${packageName}-firewall-apply" firewallStartCommands;
    firewallStop =
      if firewallStopCommands == []
      then trueCommand
      else writeCommandScript "aos-pkg-${packageName}-firewall-revert" firewallStopCommands;
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
      // {
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
      }
      // lib.optionalAttrs macProfileEnabled {
        "${macUnit}" = {
          description = "Load SELinux policy module for ${packageName}";
          wantedBy = [target];
          partOf = [target];
          before = authoredUnitNames;
          unitConfig.ConditionSecurity = "selinux";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            Slice = packageSlice;
            ExecStart = macLoadCommand;
            NoNewPrivileges = true;
            CapabilityBoundingSet = "CAP_MAC_ADMIN";
            AmbientCapabilities = "";
            PrivateDevices = true;
            DevicePolicy = "closed";
            PrivateNetwork = true;
            PrivateTmp = true;
            ProtectSystem = "full";
            ReadWritePaths = "/etc/selinux /var/lib/selinux";
            ProtectHome = true;
            ProtectClock = true;
            ProtectHostname = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectProc = "invisible";
            ProcSubset = "pid";
            SystemCallArchitectures = "native";
            RestrictAddressFamilies = ["AF_UNIX"];
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            UMask = "0077";
          };
        };
      }
      // lib.optionalAttrs ebpfEnabled {
        "${ebpfUnit}" = {
          description = "Attach eBPF network policy for ${packageName}";
          wantedBy = [target];
          partOf = [target];
          before = authoredUnitNames;
          serviceConfig = {
            Type = "notify";
            NotifyAccess = "main";
            Slice = packageSlice;
            ExecStart = ebpfCommand;
            NoNewPrivileges = true;
            CapabilityBoundingSet = "CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE";
            AmbientCapabilities = "";
            LimitMEMLOCK = "infinity";
            PrivateDevices = true;
            DevicePolicy = "closed";
            PrivateNetwork = true;
            PrivateTmp = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            ProtectClock = true;
            ProtectHostname = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectProc = "invisible";
            ProcSubset = "pid";
            SystemCallArchitectures = "native";
            RestrictAddressFamilies = ["AF_UNIX"];
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            UMask = "0077";
          };
        };
      };
    synthesizedUnits = builtins.seq reservedUnitsAvailable (
      builtins.seq preparedHostPathDirectoriesAvailable (
        builtins.mapAttrs addTargetMembership units
        // sideEffectUnits
        // {
          "${packageSlice}" = {
            description = "Package cgroup slice for ${packageName}";
            wantedBy = [target];
            partOf = [target];
          };
          "${target}" = {
            description = "Activation target for ${packageName}";
            wants = uniqueUnits targetMemberUnitNames;
          };
        }
      )
    );
    typedSystemdUnchecked = builtins.seq unitReferencesValid (validateTypedUnits synthesizedUnits);
    typedSystemd = builtins.seq socketTcpBindValid typedSystemdUnchecked;
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
    credentialBlobCommands =
      lib.concatMapStringsSep "\n" (
        blob: let
          relative = lib.removePrefix "/run/credstore.encrypted/" blob.source;
        in ''
          credential_out="$out/credstore.encrypted/${relative}"
          mkdir -p "$(dirname "$credential_out")"
          cp ${lib.escapeShellArg blob.encryptedFile} "$credential_out"
          chmod 0400 "$credential_out"
        ''
      )
      credentialBlobs;

    manifest = {
      expose = {
        inherit target config provides uses;
        images = manifestImages;
        units = manifestUnitNames;
      };
      kernel = manifestKernel;
      inherit firewall;
      mac = macProfile;
      inherit confinement;
      permissions = manifestPermissions;
    };
    passthruManifest =
      manifest
      // {
        expose =
          manifest.expose
          // {
            images = passthruManifestImages;
          };
      };
    networkPolicy = {
      version = 1;
      package = packageName;
      mode = network;
      securityLabel = manifestPermissions.security-label;
      tcp = {
        bind = tcpBind;
        connect = tcpConnect;
      };
      fs = {
        readOnly = readOnlyHostPaths;
        readWrite = readWriteHostPaths;
      };
      landlock = {
        abi = 4;
        tcp = {
          bind = tcpBind;
          connect = tcpConnect;
        };
        fs = {
          readOnly = landlockReadOnlyPaths;
          readWrite = landlockReadWritePaths;
        };
      };
      ebpf = {
        identity = manifestPermissions.security-label;
        hooks = ["socket_bind" "socket_connect"];
        tcp = {
          bind = tcpBind;
          connect = tcpConnect;
        };
      };
    };
    macProfile = {
      version = 1;
      package = packageName;
      backend = "selinux";
      securityLabel = manifestPermissions.security-label;
      defaultDeny = macProfileEnabled;
      profilePath =
        if macProfileEnabled
        then macProfilePath
        else null;
    };
    selinuxProfile = ''
      # Generated by AOS package expose renderer.
      # RFC-0001 per-package SELinux default-deny module.
      module ${macModuleName} 1.0;

      require {
        type init_t;
        type kernel_t;
        type root_t;
        type tmp_t;
        type tmpfs_t;
        type unlabeled_t;
        type var_lib_t;
        type var_t;
        attribute domain;
        attribute file_type;
        role system_r;
        class dir { getattr open read search };
        class fd use;
        class file { execute execute_no_trans execmod getattr map open read };
        class lnk_file { getattr read };
        class process { dyntransition execmem execstack execheap };
        class process2 { nnp_transition nosuid_transition };
      }

      type ${macTypeName};
      typeattribute ${macTypeName} domain;
      role system_r types ${macTypeName};

      allow ${macTypeName} init_t:fd use;
      allow init_t ${macTypeName}:process dyntransition;
      allow init_t ${macTypeName}:process2 { nnp_transition nosuid_transition };
      allow ${macTypeName} kernel_t:fd use;
      allow kernel_t ${macTypeName}:process dyntransition;
      allow kernel_t ${macTypeName}:process2 { nnp_transition nosuid_transition };
      allow ${macTypeName} self:process { execmem execstack execheap };
      allow ${macTypeName} self:process2 { nnp_transition nosuid_transition };
      allow ${macTypeName} file_type:file execmod;
      allow ${macTypeName} root_t:dir { getattr open read search };
      allow ${macTypeName} tmp_t:dir { getattr open read search };
      allow ${macTypeName} tmp_t:lnk_file { getattr read };
      allow ${macTypeName} tmpfs_t:dir { getattr open read search };
      allow ${macTypeName} tmpfs_t:lnk_file { getattr read };
      allow ${macTypeName} unlabeled_t:dir { getattr open read search };
      allow ${macTypeName} unlabeled_t:file { execute execute_no_trans execmod getattr map open read };
      allow ${macTypeName} unlabeled_t:lnk_file { getattr read };
      allow ${macTypeName} var_t:dir { getattr open read search };
      allow ${macTypeName} var_t:lnk_file { getattr read };
      allow ${macTypeName} var_lib_t:dir { getattr open read search };
      allow ${macTypeName} var_lib_t:lnk_file { getattr read };
    '';
    macProfileCommands =
      if macProfileEnabled
      then ''
        mkdir -p "$out/mac/selinux"
        cp "$selinuxProfilePath" "$out/${macSourcePath}"
        checkmodule -M -m -o "$out/${macModulePath}" "$out/${macSourcePath}"
        semodule_package -o "$out/${macProfilePath}" -m "$out/${macModulePath}"
        test -s "$out/${macProfilePath}"
      ''
      else "";
    exposeArtifactPathCommands =
      if macProfileEnabled || ebpfEnabled
      then ''
        chmod u+w "$out/units"
        for unit in "$out"/units/*.service; do
          [ -e "$unit" ] || continue
          if grep -q '@AOS_EXPOSE_ARTIFACT@' "$unit"; then
            tmp="$unit.tmp"
            sed "s|@AOS_EXPOSE_ARTIFACT@|$out|g" "$unit" > "$tmp"
            rm -f "$unit"
            mv "$tmp" "$unit"
          fi
        done
      ''
      else "";
    rootHashFilePatchCommands = builtins.concatStringsSep "\n" (
      builtins.map (
        image: let
          placeholder = rootHashHex image.root_hash;
        in ''
          actual_root_hash=$(cat ${lib.escapeShellArg image.rootHashFile})
          if ! printf '%s' "$actual_root_hash" | ${pkgs.grep}/bin/grep -Eq '^[0-9a-f]{64}$'; then
            echo "invalid root hash in ${image.rootHashFile}: $actual_root_hash" >&2
            exit 1
          fi
          for path in \
            "$out/manifest.json" \
            "$out/network-policy.json" \
            "$out/mac-profile.json" \
            "$out"/units/* \
            "$out"/mac/selinux/*; do
            [ -f "$path" ] || continue
            tmp="$path.root-hash"
            ${pkgs.sed}/bin/sed "s|${placeholder}|$actual_root_hash|g" "$path" > "$tmp"
            rm -f "$path"
            mv "$tmp" "$path"
          done
        ''
      )
      dynamicRootHashImages
    );
    runCommandAttrs =
      {
        unitsDrv = rendered.unitsDrv;
        manifest = builtins.toJSON manifest;
        networkPolicy = builtins.toJSON networkPolicy;
        macProfile = builtins.toJSON macProfile;
        passthru = {
          inherit confinement networkPolicy macProfile;
          manifest = passthruManifest;
          manifestRequiresBuild = dynamicRootHashImages != [];
          permissions = manifestPermissions;
        };
        passAsFile = ["manifest" "networkPolicy" "macProfile"] ++ lib.optional macProfileEnabled "selinuxProfile";
        buildDeps =
          lib.optionals (dynamicRootHashImages != []) [
            pkgs.grep
            pkgs.sed
          ]
          ++ lib.optionals macProfileEnabled [
            pkgs.checkpolicy
            pkgs.semodule-utils
          ];
        preferLocalBuild = true;
        allowSubstitutes = false;
      }
      // lib.optionalAttrs macProfileEnabled {
        inherit selinuxProfile;
      };
  in
    throwIfNot
    (exposeExtraKeys == [])
    "mkDerivation expose for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " exposeExtraKeys}"
    (builtins.seq verityConfinementValid (
      builtins.seq storageLinks (
        pkgs.runCommand "expose-${packageName}" runCommandAttrs ''
          set -eu
          mkdir -p "$out/units"
          cp -a "$unitsDrv"/. "$out/units/"
          cp "$manifestPath" "$out/manifest.json"
          cp "$networkPolicyPath" "$out/network-policy.json"
          cp "$macProfilePath" "$out/mac-profile.json"
          ${macProfileCommands}
          ${exposeArtifactPathCommands}
          ${rootHashFilePatchCommands}
          ${credentialBlobCommands}
        ''
      )
    ));
}
