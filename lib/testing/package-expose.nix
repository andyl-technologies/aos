##! lib/testing/package-expose.nix — RFC-0001 package expose smoke check.
##!
##! Builds a normal discovered package with an `expose` block and verifies that
##! its integration artifacts are rendered in a separate store path.
{
  pkgs,
  lib,
  mkSystem,
  packagesWithExpose,
}: let
  pkg = pkgs.expose-smoke;
  minimal = pkgs.mkDerivation {
    pname = "expose-minimal";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-minimal"
          printf expose-minimal > "$out/share/expose-minimal/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-minimal.service" = {
        description = "RFC-0001 expose minimal service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
    };
  };
  manualStart = pkgs.mkDerivation {
    pname = "expose-manual-start";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-manual-start"
          printf expose-manual-start > "$out/share/expose-manual-start/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-manual-start.service" = {
        description = "RFC-0001 expose manual-start service";
        onlyManualStart = true;
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
    };
  };
  configPackage = pkgs.mkDerivation {
    pname = "expose-config";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-config"
          printf expose-config > "$out/share/expose-config/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-config.service" = {
        description = "RFC-0001 expose config service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          ExecReload = "${pkgs.bash}/bin/bash -c true";
        };
      };
      config = {
        artifacts = [
          {
            name = "env";
            path = "/etc/aos/packages/expose-config/config.env";
            format = "env";
            required = ["TOKEN"];
            optional = ["URL"];
            units = ["expose-config.service"];
            reload = "reload";
          }
        ];
        credentials = [
          {
            name = "join-token";
            source = "/usr/lib/credstore.encrypted/join-token";
            units = ["expose-config.service"];
            encrypted = true;
          }
          {
            name = "inline-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config.service"];
            encrypted = true;
          }
          {
            name = "plain-note";
          }
        ];
      };
      provides = [
        {
          name = "data";
          kind = "directory";
          path = "/var/lib/expose-config/data";
        }
      ];
      uses = [
        {
          provider = "expose-config";
          name = "data";
          kind = "directory";
          unit = "expose-config.service";
        }
      ];
    };
  };
  splitConfigPackage = pkgs.mkDerivation {
    pname = "expose-config-split";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-config-split"
          printf expose-config-split > "$out/share/expose-config-split/payload.txt"
        '';
      }
    ];

    expose = {
      units = {
        "expose-config-split-main.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-sidecar.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-socket.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-socket.socket" = {
          socketConfig.ListenStream = "127.0.0.1:18081";
        };
      };
      config.artifacts = [
        {
          name = "main";
          path = "/etc/aos/packages/expose-config-split/main.env";
          format = "env";
          required = ["TOKEN"];
          units = ["expose-config-split-main.service"];
        }
        {
          name = "sidecar";
          path = "/etc/aos/packages/expose-config-split/sidecar.env";
          format = "env";
          required = ["TOKEN"];
          units = ["expose-config-split-sidecar.service"];
        }
      ];
      config.credentials = [
        {
          name = "main-secret";
          source = "/usr/lib/credstore.encrypted/main-secret";
          units = ["expose-config-split-main.service"];
          encrypted = true;
        }
        {
          name = "sidecar-note";
          units = ["expose-config-split-sidecar.service"];
        }
        {
          name = "socket-secret";
          source = "/usr/lib/credstore.encrypted/socket-secret";
          units = ["expose-config-split-socket.service"];
          encrypted = true;
        }
      ];
    };
  };
  unknownConfigUnit = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.artifacts = [
          {
            name = "bad";
            path = "/etc/aos/packages/expose-config-split/bad.env";
            format = "env";
            units = ["missing.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  unknownConfigUnitRejected =
    if unknownConfigUnit.success
    then throw "expose renderer must reject config artifacts that reference unknown units"
    else "ok";
  credentialNonServiceUnit = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            units = ["expose-config-split-main.socket"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialNonServiceUnitRejected =
    if credentialNonServiceUnit.success
    then throw "expose renderer must reject credentials that reference non-service units"
    else "ok";
  credentialBadSource = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/etc/shadow";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadSourceRejected =
    if credentialBadSource.success
    then throw "expose renderer must reject credential sources outside systemd credstore paths"
    else "ok";
  credentialBadSourceInjection = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/usr/lib/credstore.encrypted/bad\nPrivateNetwork=false";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadSourceInjectionRejected =
    if credentialBadSourceInjection.success
    then throw "expose renderer must reject credential source unit syntax injection"
    else "ok";
  credentialBadCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            ciphertext = "abc\nPrivateNetwork=false";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadCiphertextRejected =
    if credentialBadCiphertext.success
    then throw "expose renderer must reject credential ciphertext unit syntax injection"
    else "ok";
  credentialPlainCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialPlainCiphertextRejected =
    if credentialPlainCiphertext.success
    then throw "expose renderer must reject ciphertext on unencrypted credentials"
    else "ok";
  credentialSourceAndCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/usr/lib/credstore.encrypted/bad";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialSourceAndCiphertextRejected =
    if credentialSourceAndCiphertext.success
    then throw "expose renderer must reject credentials that declare both source and ciphertext"
    else "ok";
  credentialDuplicateName = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "duplicate";
            source = "/usr/lib/credstore.encrypted/duplicate";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
          {
            name = "duplicate";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialDuplicateNameRejected =
    if credentialDuplicateName.success
    then throw "expose renderer must reject duplicate credential names"
    else "ok";
  credentialAuthoredCollision = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          SetCredentialEncrypted = "main-secret:abcDEF0123+/=";
        };
        config.credentials = [
          {
            name = "main-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialAuthoredCollisionRejected =
    if credentialAuthoredCollision.success
    then throw "expose renderer must reject authored credential directive collisions with expose.config.credentials"
    else "ok";
  credentialAuthoredImportCollision = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          ImportCredential = "main-secret";
        };
        config.credentials = [
          {
            name = "main-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialAuthoredImportCollisionRejected =
    if credentialAuthoredImportCollision.success
    then throw "expose renderer must reject authored ImportCredential collisions with expose.config.credentials"
    else "ok";
  serverSystem = mkSystem ../../systems/server.nix;
  k3sWorkerRole = serverSystem.config.aos.roles.k3s-worker;
  k3sWorkerPackage = pkgs.k3s-worker;
  k3sControlPlanePackage = pkgs.k3s-control-plane;
  k3sCombinedPackage = pkgs.k3s-combined;
  roleSystemdLinkTarget = unitName: let
    matches =
      builtins.filter
      (link: link.path == "/etc/systemd/system/${unitName}")
      (k3sWorkerRole.ignitionConfig.storage.links or []);
  in
    if builtins.length matches == 1
    then (builtins.head matches).target
    else throw "expected exactly one k3s-worker role ignition link for ${unitName}";
  k3sWorkerRoleUnitPath = roleSystemdLinkTarget "k3s.service";
  k3sWorkerRolePreflightPath = roleSystemdLinkTarget "k3s-preflight.service";
  overridden = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-override.service" = {
        description = "RFC-0001 expose override service";
        wantedBy = ["aos-pkg-expose-smoke.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private";
      requires = [];
    };
  });
  reservedCollision = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."aos-pkg-expose-smoke-firewall.service" = {};
        permissions.network = "private";
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  reservedCollisionRejected =
    if reservedCollision.success
    then throw "expose renderer must reject package-authored synthesized side-effect unit names"
    else "ok";
  privilegedExecPrefix = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-privileged-prefix.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "+${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  privilegedExecPrefixRejected =
    if privilegedExecPrefix.success
    then throw "expose renderer must reject systemd privileged Exec* prefixes on workload services"
    else "ok";
  kernelModulePermissionMismatch = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-kernel-module-mismatch.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        kernel.modules = ["br_netfilter"];
        permissions = {
          network = "private";
          kernel-modules = [];
        };
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  kernelModulePermissionMismatchRejected =
    if kernelModulePermissionMismatch.success
    then throw "expose renderer must reject host module loads that are absent from permissions.kernel-modules"
    else "ok";
  undeclaredPreparedHostPathDirectory = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-undeclared-prep.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [];
        };
        prepareHostPathDirectories = ["/srv/expose-smoke-rw"];
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  undeclaredPreparedHostPathDirectoryRejected =
    if undeclaredPreparedHostPathDirectory.success
    then throw "expose renderer must reject prepared host path directories absent from rw permissions.host-paths"
    else "ok";
  readOnlyPreparedHostPathDirectory = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-read-only-prep.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [
            {
              path = "/srv/expose-smoke-ro";
              mode = "read-only";
            }
          ];
        };
        prepareHostPathDirectories = ["/srv/expose-smoke-ro"];
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  readOnlyPreparedHostPathDirectoryRejected =
    if readOnlyPreparedHostPathDirectory.success
    then throw "expose renderer must reject read-only prepared host path directories"
    else "ok";
  permissionOnlyModules = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-permission-only-modules.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        kernel-modules = ["br_netfilter"];
      };
      requires = [];
    };
  });
  hostPathWithoutPrepare = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-rw-host-path.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        host-paths = [
          {
            path = "/srv/expose-smoke-rw";
            mode = "rw";
          }
        ];
      };
      requires = [];
    };
  });
  privateOutbound = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-private-outbound.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private-outbound";
      requires = [];
    };
  });
  withHoles = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-holes.service" = {
        description = "RFC-0001 expose sandboxed-with-holes label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        capabilities = ["CAP_NET_BIND_SERVICE"];
      };
      requires = [];
    };
  });
  unconfined = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-unconfined.service" = {
        description = "RFC-0001 expose unconfined label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "host";
        capabilities = ["CAP_NET_ADMIN"];
        privileged-users = true;
      };
      requires = [];
    };
  });
  privilegedSyscalls = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-privileged-syscalls.service" = {
        description = "RFC-0001 expose privileged syscalls label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        syscalls = "privileged";
      };
      requires = [];
    };
  });
  regexNamePrivateOutbound = pkg.overrideAttrs (_: {
    pname = "expose.smoke.regex";
    expose = {
      units."expose-smoke-regex-private-outbound.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private-outbound";
      requires = [];
    };
  });
in
  pkgs.mkDerivation {
    pname = "package-expose-check";
    version = "0";
    src = null;

    payload = pkg;
    exposePath = pkg.expose;
    exposeConfinement = builtins.toJSON pkg.expose.passthru.confinement;
    minimalPayload = minimal;
    minimalExposePath = minimal.expose;
    manualStartExposePath = manualStart.expose;
    configExposePath = configPackage.expose;
    splitConfigExposePath = splitConfigPackage.expose;
    overriddenPayload = overridden;
    overriddenExposePath = overridden.expose;
    permissionOnlyModulesExposePath = permissionOnlyModules.expose;
    withHolesExposePath = withHoles.expose;
    unconfinedExposePath = unconfined.expose;
    privilegedSyscallsExposePath = privilegedSyscalls.expose;
    privateOutboundExposePath = privateOutbound.expose;
    regexNamePrivateOutboundExposePath = regexNamePrivateOutbound.expose;
    hostPathWithoutPrepareExposePath = hostPathWithoutPrepare.expose;
    k3sWorkerExposePath = k3sWorkerPackage.expose;
    k3sControlPlaneExposePath = k3sControlPlanePackage.expose;
    k3sCombinedExposePath = k3sCombinedPackage.expose;
    inherit k3sWorkerRoleUnitPath k3sWorkerRolePreflightPath;
    inherit
      reservedCollisionRejected
      privilegedExecPrefixRejected
      kernelModulePermissionMismatchRejected
      unknownConfigUnitRejected
      credentialNonServiceUnitRejected
      credentialBadSourceRejected
      credentialBadSourceInjectionRejected
      credentialBadCiphertextRejected
      credentialPlainCiphertextRejected
      credentialSourceAndCiphertextRejected
      credentialDuplicateNameRejected
      credentialAuthoredCollisionRejected
      credentialAuthoredImportCollisionRejected
      undeclaredPreparedHostPathDirectoryRejected
      readOnlyPreparedHostPathDirectoryRejected
      ;

    buildDeps =
      (builtins.map (pkg: pkg.exposeCheck) (builtins.attrValues packagesWithExpose))
      ++ [
        minimal.exposeCheck
        manualStart.exposeCheck
        configPackage.exposeCheck
        splitConfigPackage.exposeCheck
        overridden.exposeCheck
        permissionOnlyModules.exposeCheck
        withHoles.exposeCheck
        unconfined.exposeCheck
        privilegedSyscalls.exposeCheck
        privateOutbound.exposeCheck
        regexNamePrivateOutbound.exposeCheck
        hostPathWithoutPrepare.exposeCheck
        k3sWorkerPackage.exposeCheck
        k3sControlPlanePackage.exposeCheck
        k3sCombinedPackage.exposeCheck
      ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          unit="$exposePath/units/expose-smoke.service"
          target="$exposePath/units/aos-pkg-expose-smoke.target"
          modules="$exposePath/units/aos-pkg-expose-smoke-modules.service"
          sysctl="$exposePath/units/aos-pkg-expose-smoke-sysctl.service"
          firewall="$exposePath/units/aos-pkg-expose-smoke-firewall.service"
          netns="$exposePath/units/aos-pkg-expose-smoke-netns.service"
          manifest="$exposePath/manifest.json"

          test -d "$exposePath/units"
          test -f "$unit"
          test -f "$target"
          test -f "$modules"
          test -f "$sysctl"
          test -f "$firewall"
          test ! -f "$netns"
          test -f "$manifest"

          grep -q 'Description=RFC-0001 expose smoke service' "$unit"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'After=network.target aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$unit"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$unit"
          grep -q 'ExecStart=${pkgs.bash}/bin/bash -c true' "$unit"
          grep -q "RootDirectory=$payload" "$unit"
          grep -q 'MountAPIVFS=true' "$unit"
          grep -q 'ProtectSystem=strict' "$unit"
          grep -q 'ProtectHome=true' "$unit"
          grep -q 'PrivateTmp=disconnected' "$unit"
          grep -q 'TemporaryFileSystem=/tmp' "$unit"
          grep -q 'TemporaryFileSystem=/var/tmp' "$unit"
          grep -q 'StateDirectory=aos-pkg-expose-smoke' "$unit"
          grep -q 'NoNewPrivileges=true' "$unit"
          grep -q 'DynamicUser=true' "$unit"
          grep -q 'PrivateUsers=identity' "$unit"
          grep -q 'PrivateNetwork=true' "$unit"
          grep -q 'DevicePolicy=closed' "$unit"
          grep -q '^CapabilityBoundingSet=$' "$unit"
          grep -q '^AmbientCapabilities=$' "$unit"
          grep -q 'BindReadOnlyPaths=/nix/store' "$unit"
          grep -q 'SystemCallFilter=@system-service' "$unit"
          grep -q 'SystemCallErrorNumber=EPERM' "$unit"
          grep -q 'SystemCallArchitectures=native' "$unit"
          grep -q 'RestrictAddressFamilies=AF_UNIX' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET6' "$unit"
          grep -q 'RestrictNamespaces=true' "$unit"
          grep -q 'LockPersonality=true' "$unit"
          grep -q 'MemoryDenyWriteExecute=true' "$unit"
          grep -q 'Where=/var/lib/exposesmoke' "$exposePath/units/var-lib-exposesmoke.mount"

          grep -q 'Description=Activation target for expose-smoke' "$target"
          grep -q 'Wants=expose-smoke.service var-lib-exposesmoke.mount aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$target"
          test ! -e "$exposePath/units/multi-user.target.wants/aos-pkg-expose-smoke.target"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/expose-smoke.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/var-lib-exposesmoke.mount"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-modules.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-sysctl.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-firewall.service"
          test ! -e "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-netns.service"
          test ! -e "$exposePath/units/multi-user.target.wants/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.requires/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.upholds/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.wants/var-lib-exposesmoke.mount"
          if find "$exposePath" \
            \( -path '*/modules-load.d/*' -o -path '*/sysctl.d/*' -o -path '*/nftables.d/*' \) \
            | grep .; then
            echo "package expose output must not contain global scan-dir entries" >&2
            exit 1
          fi

          grep -q 'Description=Apply kernel modules for expose-smoke' "$modules"
          if grep -q 'RootDirectory=' "$modules"; then
            echo "host-side modules service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' "$modules"

          grep -q 'Description=Apply sysctl settings for expose-smoke' "$sysctl"
          if grep -q 'RootDirectory=' "$sysctl"; then
            echo "host-side sysctl service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$sysctl"
          grep -q 'After=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'ExecStart=${pkgs.procps-ng}/sbin/sysctl -w net.ipv4.ip_forward=1' "$sysctl"

          grep -q 'Description=Apply firewall rules for expose-smoke' "$firewall"
          if grep -q 'RootDirectory=' "$firewall"; then
            echo "host-side firewall service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$firewall"
          grep -q 'After=nftables.service' "$firewall"
          grep -q 'Requires=nftables.service' "$firewall"
          grep -q 'ReloadPropagatedFrom=nftables.service' "$firewall"
          grep -q 'ExecStart=${pkgs.nftables}/sbin/nft add element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'ExecStart=${pkgs.nftables}/sbin/nft add element inet filter allowed_udp { 5353 }' "$firewall"
          grep -q 'ExecReload=${pkgs.nftables}/sbin/nft add element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'ExecStop=${pkgs.nftables}/sbin/nft delete element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'aos-pkg-expose-smoke-firewall-forward-start' "$firewall"
          grep -q 'aos-pkg-expose-smoke-firewall-forward-stop' "$firewall"

          grep -q '"target":"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-modules.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-sysctl.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-firewall.service"' "$manifest"
          grep -q '"expose-smoke.service"' "$manifest"
          grep -q '"var-lib-exposesmoke.mount"' "$manifest"
          grep -q '"modules":\["br_netfilter"\]' "$manifest"
          grep -q '"sysctl":{"net.ipv4.ip_forward":"1"}' "$manifest"
          grep -q '"allowedTCP":\[8000,8443\]' "$manifest"
          grep -q '"allowedUDP":\[5353\]' "$manifest"
          grep -q '"forwardPolicy":"accept"' "$manifest"
          grep -q '"confinement":{"class":"sandboxed","holes":\[\],"label":"sandboxed"}' "$manifest"
          test "$exposeConfinement" = '{"class":"sandboxed","holes":[],"label":"sandboxed"}'
          grep -q '"network":"private"' "$manifest"
          grep -q '"security-label":"aos.expose-smoke"' "$manifest"
          grep -q '"syscalls":"restricted"' "$manifest"

          minimal_unit="$minimalExposePath/units/expose-minimal.service"
          minimal_target="$minimalExposePath/units/aos-pkg-expose-minimal.target"
          minimal_modules="$minimalExposePath/units/aos-pkg-expose-minimal-modules.service"
          minimal_sysctl="$minimalExposePath/units/aos-pkg-expose-minimal-sysctl.service"
          minimal_firewall="$minimalExposePath/units/aos-pkg-expose-minimal-firewall.service"
          minimal_manifest="$minimalExposePath/manifest.json"
          test -f "$minimal_unit"
          test -f "$minimal_target"
          test -f "$minimal_modules"
          test -f "$minimal_sysctl"
          test -f "$minimal_firewall"
          test ! -f "$minimalExposePath/units/aos-pkg-expose-minimal-netns.service"
          test -f "$minimal_manifest"
          grep -q 'Description=RFC-0001 expose minimal service' "$minimal_unit"
          grep -q "RootDirectory=$minimalPayload" "$minimal_unit"
          grep -q 'PrivateNetwork=true' "$minimal_unit"
          grep -q '^CapabilityBoundingSet=$' "$minimal_unit"
          grep -q '^AmbientCapabilities=$' "$minimal_unit"
          grep -q 'DevicePolicy=closed' "$minimal_unit"
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_modules"
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_sysctl"
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_firewall"
          grep -q '"modules":\[\]' "$minimal_manifest"
          grep -q '"sysctl":{}' "$minimal_manifest"
          grep -q '"allowedTCP":\[\]' "$minimal_manifest"
          grep -q '"allowedUDP":\[\]' "$minimal_manifest"
          grep -q '"forwardPolicy":"drop"' "$minimal_manifest"
          grep -q '"confinement":{"class":"sandboxed","holes":\[\],"label":"sandboxed"}' "$minimal_manifest"
          grep -q '"security-label":"aos-pkg-expose-minimal"' "$minimal_manifest"
          if grep -q '"kernel-modules"\|"capabilities"\|"devices"\|"host-paths"\|"cgroup-delegate"\|"privileged-users"\|"network"' \
            "$minimal_manifest"; then
            echo "minimal expose manifest must not request explicit permission grants" >&2
            exit 1
          fi
          if find "$minimalExposePath/units" -name '*.mount' | grep .; then
            echo "minimal expose package must not render package-authored mount units" >&2
            exit 1
          fi

          manual_start_unit="$manualStartExposePath/units/expose-manual-start.service"
          manual_start_target="$manualStartExposePath/units/aos-pkg-expose-manual-start.target"
          test -f "$manual_start_unit"
          test -f "$manual_start_target"
          grep -q 'X-OnlyManualStart=true' "$manual_start_unit"
          grep -q 'PartOf=aos-pkg-expose-manual-start.target' "$manual_start_unit"
          if grep -q 'WantedBy=aos-pkg-expose-manual-start.target' "$manual_start_unit"; then
            echo "manual-start services must not be enabled by the package target preset" >&2
            exit 1
          fi
          if grep -q 'Wants=.*expose-manual-start.service' "$manual_start_target"; then
            echo "manual-start services must not be target members" >&2
            exit 1
          fi
          test ! -e "$manualStartExposePath/units/aos-pkg-expose-manual-start.target.wants/expose-manual-start.service"

          config_unit="$configExposePath/units/expose-config.service"
          config_manifest="$configExposePath/manifest.json"
          grep -q 'BindReadOnlyPaths=/nix/store' "$config_unit"
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config/config.env' "$config_unit"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config/config.env' "$config_unit"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/join-token' "$config_unit"
          grep -q 'LoadCredential=plain-note' "$config_unit"
          grep -q 'LoadCredentialEncrypted=join-token:/usr/lib/credstore.encrypted/join-token' "$config_unit"
          grep -q 'SetCredentialEncrypted=inline-secret:abcDEF0123+/=' "$config_unit"
          grep -q 'X-ReloadIfChanged=true' "$config_unit"
          grep -q 'X-Reload-Triggers=/etc/aos/packages/expose-config/config.env' "$config_unit"
          grep -q '"config":{"artifacts":\[{"format":"env","name":"env","optional":\["URL"\],"path":"/etc/aos/packages/expose-config/config.env","reload":"reload","required":\["TOKEN"\],"units":\["expose-config.service"\]}\],"credentials":\[{"encrypted":true,"name":"join-token","source":"/usr/lib/credstore.encrypted/join-token","units":\["expose-config.service"\]},{"ciphertext":"abcDEF0123+/=","encrypted":true,"name":"inline-secret","units":\["expose-config.service"\]},{"encrypted":false,"name":"plain-note","units":\[\]}\]}' "$config_manifest"
          grep -q '"provides":\[{"kind":"directory","name":"data","path":"/var/lib/expose-config/data"}\]' "$config_manifest"
          grep -q '"uses":\[{"kind":"directory","name":"data","provider":"expose-config","unit":"expose-config.service"}\]' "$config_manifest"
          test "$unknownConfigUnitRejected" = ok

          split_main="$splitConfigExposePath/units/expose-config-split-main.service"
          split_sidecar="$splitConfigExposePath/units/expose-config-split-sidecar.service"
          split_socket_service="$splitConfigExposePath/units/expose-config-split-socket.service"
          split_socket="$splitConfigExposePath/units/expose-config-split-socket.socket"
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config-split/main.env' "$split_main"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config-split/main.env' "$split_main"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/main-secret' "$split_main"
          grep -q 'LoadCredentialEncrypted=main-secret:/usr/lib/credstore.encrypted/main-secret' "$split_main"
          if grep -q 'expose-config-split/sidecar.env' "$split_main"; then
            echo "main service must not receive sidecar config artifact" >&2
            exit 1
          fi
          if grep -q 'sidecar-note' "$split_main"; then
            echo "main service must not receive sidecar credential" >&2
            exit 1
          fi
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config-split/sidecar.env' "$split_sidecar"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config-split/sidecar.env' "$split_sidecar"
          grep -q 'LoadCredential=sidecar-note' "$split_sidecar"
          if grep -q 'expose-config-split/main.env' "$split_sidecar"; then
            echo "sidecar service must not receive main config artifact" >&2
            exit 1
          fi
          if grep -q 'main-secret' "$split_sidecar"; then
            echo "sidecar service must not receive main credential" >&2
            exit 1
          fi
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/socket-secret' "$split_socket_service"
          grep -q 'LoadCredentialEncrypted=socket-secret:/usr/lib/credstore.encrypted/socket-secret' "$split_socket_service"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/socket-secret' "$split_socket"

          test "$payload" = "$overriddenPayload"
          test "$exposePath" != "$overriddenExposePath"
          test -f "$overriddenExposePath/units/expose-smoke-override.service"
          grep -q 'Description=RFC-0001 expose override service' \
            "$overriddenExposePath/units/expose-smoke-override.service"
          test "$reservedCollisionRejected" = ok
          test "$privilegedExecPrefixRejected" = ok
          test "$kernelModulePermissionMismatchRejected" = ok
          test "$undeclaredPreparedHostPathDirectoryRejected" = ok
          test "$readOnlyPreparedHostPathDirectoryRejected" = ok
          permission_only_modules="$permissionOnlyModulesExposePath/units/aos-pkg-expose-smoke-modules.service"
          permission_only_manifest="$permissionOnlyModulesExposePath/manifest.json"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' \
            "$permission_only_modules"
          grep -q '"modules":\["br_netfilter"\]' "$permission_only_manifest"
          grep -q '"kernel-modules":\["br_netfilter"\]' "$permission_only_manifest"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["capability:CAP_NET_BIND_SERVICE"\],"label":"sandboxed-with-holes (capability:CAP_NET_BIND_SERVICE)"}' \
            "$withHolesExposePath/manifest.json"
          grep -q '"security-label":"aos-pkg-expose-smoke"' \
            "$withHolesExposePath/manifest.json"
          grep -q 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          grep -q 'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          grep -q '"confinement":{"class":"unconfined","holes":\["network:host","capability:CAP_NET_ADMIN","privileged-users"\],"label":"unconfined"}' \
            "$unconfinedExposePath/manifest.json"
          grep -q 'RestrictAddressFamilies=AF_NETLINK' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'CapabilityBoundingSet=CAP_NET_ADMIN' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'PrivateUsers=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'DynamicUser=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["syscalls:privileged"\],"label":"sandboxed-with-holes (syscalls:privileged)"}' \
            "$privilegedSyscallsExposePath/manifest.json"
          if grep -q 'SystemCallFilter=' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"; then
            echo "privileged syscall profile must not render a restrictive SystemCallFilter" >&2
            exit 1
          fi
          grep -q 'SystemCallArchitectures=native' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"
          private_outbound_unit="$privateOutboundExposePath/units/expose-smoke-private-outbound.service"
          private_outbound_netns="$privateOutboundExposePath/units/aos-pkg-expose-smoke-netns.service"
          private_outbound_target="$privateOutboundExposePath/units/aos-pkg-expose-smoke.target"
          private_outbound_manifest="$privateOutboundExposePath/manifest.json"
          test -f "$private_outbound_unit"
          test -f "$private_outbound_netns"
          grep -q 'After=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service' \
            "$private_outbound_unit"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service' \
            "$private_outbound_unit"
          grep -q 'PrivateNetwork=false' "$private_outbound_unit"
          grep -q 'NetworkNamespacePath=/run/netns/aos-pkg-expose-smoke' "$private_outbound_unit"
          grep -q 'Wants=expose-smoke-private-outbound.service aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service' \
            "$private_outbound_target"
          grep -q 'Description=Create outbound network namespace for expose-smoke' \
            "$private_outbound_netns"
          if grep -q 'RootDirectory=' "$private_outbound_netns"; then
            echo "host-side netns service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$private_outbound_netns"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$private_outbound_netns"
          grep -q 'Before=expose-smoke-private-outbound.service' "$private_outbound_netns"
          grep -q 'After=nftables.service' "$private_outbound_netns"
          grep -q 'Requires=nftables.service' "$private_outbound_netns"
          grep -q 'ReloadPropagatedFrom=nftables.service' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-start' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-reload' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-stop' "$private_outbound_netns"
          grep -q 'ExecStopPost=.*aos-pkg-expose-smoke-netns-stop' "$private_outbound_netns"
          private_outbound_start=$(
            sed -n 's|^ExecStart=||p' "$private_outbound_netns"
          )
          private_outbound_reload=$(
            sed -n 's|^ExecReload=||p' "$private_outbound_netns"
          )
          private_outbound_stop=$(
            sed -n 's|^ExecStop=||p' "$private_outbound_netns"
          )
          test -x "$private_outbound_start"
          test -x "$private_outbound_reload"
          test -x "$private_outbound_stop"
          grep -q 'index($0, needle)' "$private_outbound_start"
          grep -q 'gawk -v netns="$netns"' "$private_outbound_start"
          grep -q 'refusing to steal a private-outbound namespace' "$private_outbound_start"
          grep -q 'refusing private-outbound veth collision' "$private_outbound_start"
          grep -q 'route show exact "$cidr"' "$private_outbound_start"
          grep -q 'refusing private-outbound subnet collision' "$private_outbound_start"
          grep -q '/proc/sys/net/ipv4/ip_forward' "$private_outbound_start"
          grep -q 'ip_forward.prev' "$private_outbound_start"
          grep -q 'flock 9' "$private_outbound_start"
          grep -q 'trap.*cleanup_package_state' "$private_outbound_start"
          grep -q 'restore_ip_forward_if_last' "$private_outbound_stop"
          if grep -q 'link delete "$host_if"' "$private_outbound_reload"; then
            echo "netns reload must not recreate the veth pair" >&2
            exit 1
          fi
          if grep -q 'netns add "$netns"' "$private_outbound_reload"; then
            echo "netns reload must not recreate the namespace" >&2
            exit 1
          fi
          grep -q '"aos-pkg-expose-smoke-netns.service"' "$private_outbound_manifest"
          grep -q '"network":"private-outbound"' "$private_outbound_manifest"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["network:private-outbound"\],"label":"sandboxed-with-holes (network:private-outbound)"}' \
            "$private_outbound_manifest"
          regex_name_start=$(
            sed -n 's|^ExecStart=||p' \
              "$regexNamePrivateOutboundExposePath/units/aos-pkg-expose.smoke.regex-netns.service"
          )
          test -x "$regex_name_start"
          grep -q 'index($0, needle)' "$regex_name_start"
          grep -q 'gawk -v netns="$netns"' "$regex_name_start"
          if grep -q 'grep -qx "$netns"' "$regex_name_start"; then
            echo "netns detection must not use regex grep for package names" >&2
            exit 1
          fi

          host_path_without_prepare_unit="$hostPathWithoutPrepareExposePath/units/expose-smoke-rw-host-path.service"
          host_path_without_prepare_target="$hostPathWithoutPrepareExposePath/units/aos-pkg-expose-smoke.target"
          test -f "$host_path_without_prepare_unit"
          grep -q 'BindPaths=/srv/expose-smoke-rw' "$host_path_without_prepare_unit"
          test ! -f "$hostPathWithoutPrepareExposePath/units/aos-pkg-expose-smoke-host-paths.service"
          if grep -q 'aos-pkg-expose-smoke-host-paths.service' "$host_path_without_prepare_target"; then
            echo "rw host paths must not implicitly synthesize host directory preparation" >&2
            exit 1
          fi

          k3s_worker_unit="$k3sWorkerExposePath/units/k3s.service"
          k3s_worker_target="$k3sWorkerExposePath/units/aos-pkg-k3s-worker.target"
          k3s_worker_host_paths="$k3sWorkerExposePath/units/aos-pkg-k3s-worker-host-paths.service"
          k3s_worker_modules="$k3sWorkerExposePath/units/aos-pkg-k3s-worker-modules.service"
          k3s_worker_manifest="$k3sWorkerExposePath/manifest.json"
          k3s_control_plane_unit="$k3sControlPlaneExposePath/units/k3s.service"
          k3s_control_plane_target="$k3sControlPlaneExposePath/units/aos-pkg-k3s-control-plane.target"
          k3s_control_plane_host_paths="$k3sControlPlaneExposePath/units/aos-pkg-k3s-control-plane-host-paths.service"
          k3s_control_plane_manifest="$k3sControlPlaneExposePath/manifest.json"
          k3s_combined_unit="$k3sCombinedExposePath/units/k3s.service"
          k3s_combined_target="$k3sCombinedExposePath/units/aos-pkg-k3s-combined.target"
          k3s_combined_host_paths="$k3sCombinedExposePath/units/aos-pkg-k3s-combined-host-paths.service"
          k3s_combined_manifest="$k3sCombinedExposePath/manifest.json"
          k3s_role_unit="$k3sWorkerRoleUnitPath"
          k3s_role_preflight="$k3sWorkerRolePreflightPath"
          test -f "$k3s_worker_unit"
          test -f "$k3sWorkerExposePath/units/k3s-preflight.service"
          test -f "$k3s_worker_target"
          test -f "$k3s_worker_host_paths"
          test -f "$k3s_worker_modules"
          test -f "$k3s_control_plane_unit"
          test -f "$k3s_control_plane_target"
          test -f "$k3s_control_plane_host_paths"
          test -f "$k3s_combined_unit"
          test -f "$k3s_combined_target"
          test -f "$k3s_combined_host_paths"
          test -f "$k3s_role_unit"
          test -f "$k3s_role_preflight"
          test ! -f "$k3sWorkerExposePath/units/aos-pkg-k3s-worker-netns.service"

          require_role_line() {
            key="$1"
            role_line=$(grep "^$key=" "$k3s_role_unit")
            test -n "$role_line"
            grep -Fxq "$role_line" "$k3s_worker_unit"
          }
          require_role_words() {
            key="$1"
            role_line=$(sed -n "s|^$key=||p" "$k3s_role_unit")
            package_line=$(sed -n "s|^$key=||p" "$k3s_worker_unit")
            test -n "$role_line"
            test -n "$package_line"
            for word in $role_line; do
              case " $package_line " in
                *" $word "*) ;;
                *)
                  echo "k3s worker package unit lost role $key word $word" >&2
                  exit 1
                  ;;
              esac
            done
          }
          require_role_path_environment() {
            role_path=$(sed -n 's|^Environment="PATH=||p' "$k3s_role_unit" | sed 's|"$||')
            package_path=$(sed -n 's|^Environment="PATH=||p' "$k3s_worker_unit" | sed 's|"$||')
            test -n "$role_path"
            test -n "$package_path"
            old_ifs=$IFS
            IFS=:
            for path_entry in $role_path; do
              case ":$package_path:" in
                *":$path_entry:"*) ;;
                *)
                  echo "k3s worker package unit lost role PATH entry $path_entry" >&2
                  IFS=$old_ifs
                  exit 1
                  ;;
              esac
            done
            IFS=$old_ifs
          }
          require_preflight_line() {
            key="$1"
            role_line=$(grep "^$key=" "$k3s_role_preflight")
            test -n "$role_line"
            grep -Fxq "$role_line" "$k3sWorkerExposePath/units/k3s-preflight.service"
          }

          require_role_line Description
          require_role_path_environment
          require_role_line EnvironmentFile
          require_role_line ExecStart
          require_role_line KillMode
          require_role_line LimitNOFILE
          require_role_line LimitNPROC
          require_role_line LimitCORE
          require_role_line TasksMax
          require_role_line TimeoutStartSec
          require_role_line Restart
          require_role_line RestartSec
          require_role_words After
          require_role_words Wants
          require_role_words Requisite
          require_preflight_line Description
          require_preflight_line ConditionPathExists
          require_preflight_line EnvironmentFile
          require_preflight_line ExecStart

          grep -q 'Description=Lightweight Kubernetes (agent / worker)' "$k3s_worker_unit"
          if grep -q 'X-OnlyManualStart=true' "$k3s_worker_unit"; then
            echo "k3s worker service must start with the package target" >&2
            exit 1
          fi
          grep -q 'WantedBy=aos-pkg-k3s-worker.target' "$k3s_worker_unit"
          grep -q 'ExecStart=${pkgs.k3s}/bin/k3s agent' "$k3s_worker_unit"
          grep -q 'KillMode=process' "$k3s_worker_unit"
          grep -q 'Requisite=k3s-preflight.service' "$k3s_worker_unit"
          grep -q 'After=.*k3s-preflight.service' "$k3s_worker_unit"
          grep -q 'PrivateNetwork=false' "$k3s_worker_unit"
          if grep -q 'NetworkNamespacePath=' "$k3s_worker_unit"; then
            echo "k3s worker must stay on host networking" >&2
            exit 1
          fi
          grep -q 'Delegate=true' "$k3s_worker_unit"
          grep -q 'PrivateUsers=false' "$k3s_worker_unit"
          grep -q 'DynamicUser=false' "$k3s_worker_unit"
          grep -q 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE CAP_SYS_PTRACE' \
            "$k3s_worker_unit"
          grep -q 'AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE CAP_SYS_PTRACE' \
            "$k3s_worker_unit"
          grep -q 'RestrictAddressFamilies=AF_NETLINK' "$k3s_worker_unit"
          grep -q 'DeviceAllow=/dev/net/tun rwm' "$k3s_worker_unit"
          grep -q 'DeviceAllow=/dev/kmsg rwm' "$k3s_worker_unit"
          grep -q 'DeviceAllow=/dev/fuse rwm' "$k3s_worker_unit"
          grep -q 'BindPaths=/var/lib/rancher' "$k3s_worker_unit"
          grep -q 'BindPaths=/var/lib/kubelet' "$k3s_worker_unit"
          grep -q 'BindPaths=/etc/rancher/k3s' "$k3s_worker_unit"
          grep -q 'BindPaths=/etc/rancher/node' "$k3s_worker_unit"
          grep -q 'BindReadOnlyPaths=/lib/modules' "$k3s_worker_unit"
          grep -q 'RootDirectory=' "$k3sWorkerExposePath/units/k3s-preflight.service"
          grep -q 'PartOf=aos-pkg-k3s-worker.target' "$k3sWorkerExposePath/units/k3s-preflight.service"
          if grep -q 'SystemCallFilter=' "$k3s_worker_unit"; then
            echo "k3s worker privileged syscall profile must not render a restrictive SystemCallFilter" >&2
            exit 1
          fi
          grep -q 'Wants=k3s-preflight.service k3s.service aos-pkg-k3s-worker-host-paths.service aos-pkg-k3s-worker-modules.service aos-pkg-k3s-worker-sysctl.service aos-pkg-k3s-worker-firewall.service' \
            "$k3s_worker_target"
          test -L "$k3sWorkerExposePath/units/aos-pkg-k3s-worker.target.wants/k3s.service"
          grep -q 'Description=Prepare host path directories for k3s-worker' \
            "$k3s_worker_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/var/lib/kubelet' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_worker_host_paths"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter vxlan ip_set' \
            "$k3s_worker_modules"
          grep -q '"confinement":{"class":"unconfined"' "$k3s_worker_manifest"
          grep -q '"label":"unconfined"' "$k3s_worker_manifest"
          grep -q '"network":"host"' "$k3s_worker_manifest"
          grep -q '"privileged-users":true' "$k3s_worker_manifest"
          grep -q '"cgroup-delegate":true' "$k3s_worker_manifest"
          grep -q '"kernel-modules":\["br_netfilter","vxlan","ip_set"\]' "$k3s_worker_manifest"
          grep -q '"security-label":"aos-pkg-k3s-worker"' "$k3s_worker_manifest"
          grep -q '"allowedTCP":\[10250\]' "$k3s_worker_manifest"
          grep -q '"allowedUDP":\[8472\]' "$k3s_worker_manifest"
          grep -q '"forwardPolicy":"accept"' "$k3s_worker_manifest"

          grep -q 'Description=Lightweight Kubernetes (control plane, no agent)' \
            "$k3s_control_plane_unit"
          grep -q 'WantedBy=aos-pkg-k3s-control-plane.target' "$k3s_control_plane_unit"
          grep -q 'ExecStart=${pkgs.k3s}/bin/k3s server --disable-agent' \
            "$k3s_control_plane_unit"
          grep -q 'BindPaths=/var/lib/rancher' "$k3s_control_plane_unit"
          grep -q 'BindPaths=/etc/rancher/k3s' "$k3s_control_plane_unit"
          grep -q 'BindPaths=/etc/rancher/node' "$k3s_control_plane_unit"
          if grep -q 'BindPaths=/var/lib/kubelet' "$k3s_control_plane_unit"; then
            echo "k3s control-plane package must not bind kubelet state" >&2
            exit 1
          fi
          grep -q 'Wants=k3s-preflight.service k3s.service aos-pkg-k3s-control-plane-host-paths.service aos-pkg-k3s-control-plane-modules.service aos-pkg-k3s-control-plane-sysctl.service aos-pkg-k3s-control-plane-firewall.service' \
            "$k3s_control_plane_target"
          grep -q 'Description=Prepare host path directories for k3s-control-plane' \
            "$k3s_control_plane_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_control_plane_host_paths"
          grep -q '"allowedTCP":\[6443\]' "$k3s_control_plane_manifest"
          grep -q '"allowedUDP":\[\]' "$k3s_control_plane_manifest"
          grep -q '"forwardPolicy":"drop"' "$k3s_control_plane_manifest"

          grep -q 'Description=Lightweight Kubernetes (combined: server + agent)' \
            "$k3s_combined_unit"
          grep -q 'WantedBy=aos-pkg-k3s-combined.target' "$k3s_combined_unit"
          grep -Fxq 'ExecStart=${pkgs.k3s}/bin/k3s server' "$k3s_combined_unit"
          grep -q 'BindPaths=/var/lib/rancher' "$k3s_combined_unit"
          grep -q 'BindPaths=/var/lib/kubelet' "$k3s_combined_unit"
          grep -q 'BindPaths=/etc/rancher/k3s' "$k3s_combined_unit"
          grep -q 'BindPaths=/etc/rancher/node' "$k3s_combined_unit"
          grep -q 'Wants=k3s-preflight.service k3s.service aos-pkg-k3s-combined-host-paths.service aos-pkg-k3s-combined-modules.service aos-pkg-k3s-combined-sysctl.service aos-pkg-k3s-combined-firewall.service' \
            "$k3s_combined_target"
          grep -q 'Description=Prepare host path directories for k3s-combined' \
            "$k3s_combined_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/var/lib/kubelet' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_combined_host_paths"
          grep -q '"allowedTCP":\[6443,10250\]' "$k3s_combined_manifest"
          grep -q '"allowedUDP":\[8472\]' "$k3s_combined_manifest"
          grep -q '"forwardPolicy":"accept"' "$k3s_combined_manifest"

          if grep -R "$exposePath" "$payload"; then
            echo "payload output must not contain a reference to its expose path" >&2
            exit 1
          fi

          mkdir -p "$out"
          echo "PASS" > "$out/result"
        '';
      }
    ];

    meta.description = "RFC-0001 package expose renderer regression check";
  }
