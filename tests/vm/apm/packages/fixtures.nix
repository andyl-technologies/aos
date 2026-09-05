# Shared derivations and environment setup for the packages VM workflows.
{
  pkgs,
  aosPkg,
}: let
  fixtures = import ../fixtures.nix {inherit pkgs aosPkg;};
  nixRuntimeDeps = [
    pkgs.nix
    pkgs.brotli
    pkgs.curl
    pkgs.openssl
    pkgs.sqlite
    pkgs.boost
    pkgs.editline
    pkgs.libsodium
    pkgs.libarchive
    pkgs.gc
    pkgs.lowdown
    pkgs.bzip2
    pkgs.zlib
  ];
  realLifecycleDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.oniguruma
      pkgs.pcre2
      pkgs.python3
      pkgs.zstd
    ];
  mkProfileTool = {
    pname,
    version,
    program ? pname,
  }:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf '${pname} ${version}\\n'" \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  idempotentTool = mkProfileTool {
    pname = "idempkg";
    version = "1.0.0";
  };
  installBasicTool = mkProfileTool {
    pname = "install-basic-tool";
    version = "1.0.0";
  };
  installDepTool = mkProfileTool {
    pname = "install-libfoo";
    version = "1.0.0";
  };
  installWithDepsTool = pkgs.mkDerivation {
    pname = "install-with-deps";
    version = "2.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      installDepTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            '${installDepTool}/bin/install-libfoo' \
            > "$out/bin/install-with-deps"
          chmod +x "$out/bin/install-with-deps"
        '';
      }
    ];
  };
  mkIdempotentWrapper = {
    pname,
    program ? pname,
  }:
    pkgs.mkDerivation {
      inherit pname;
      version = "1.0.0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      runtimeDeps = [
        idempotentTool
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              '${idempotentTool}/bin/idempkg' \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  idempotentWrapper = mkIdempotentWrapper {
    pname = "idemp-wrapper";
  };
  downloadOnlyWrapper = mkIdempotentWrapper {
    pname = "download-only-wrapper";
  };
  removeLeftTool = mkIdempotentWrapper {
    pname = "remove-left";
  };
  removeRightTool = mkIdempotentWrapper {
    pname = "remove-right";
  };
  removeBasicTool = mkProfileTool {
    pname = "remove-basic-tool";
    version = "1.0.0";
  };
  holdToolV1 = mkProfileTool {
    pname = "hold-tool";
    version = "1.0.0";
  };
  holdToolV2 = mkProfileTool {
    pname = "hold-tool";
    version = "2.0.0";
  };
  reinstallTool = mkProfileTool {
    pname = "reinstall-tool";
    version = "1.0.0";
  };
  reinstallPeerTool = mkProfileTool {
    pname = "reinstall-peer";
    version = "1.0.0";
  };
  rollbackToolV1 = mkProfileTool {
    pname = "rollback-tool";
    version = "1.0.0";
  };
  rollbackToolV2 = mkProfileTool {
    pname = "rollback-tool";
    version = "2.0.0";
  };
  rollbackToolV3 = mkProfileTool {
    pname = "rollback-tool";
    version = "3.0.0";
  };
  upgradeAlphaV1 = mkProfileTool {
    pname = "upgrade-alpha";
    version = "1.0.0";
  };
  upgradeAlphaV2 = mkProfileTool {
    pname = "upgrade-alpha";
    version = "2.0.0";
  };
  upgradeBetaV1 = mkProfileTool {
    pname = "upgrade-beta";
    version = "1.0.0";
  };
  upgradeBetaV2 = mkProfileTool {
    pname = "upgrade-beta";
    version = "2.0.0";
  };
  surfaceLeafTool = mkProfileTool {
    pname = "surface-leaf";
    version = "1.0.0";
  };
  surfaceTool = pkgs.mkDerivation {
    pname = "surfacepkg";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      surfaceLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${surfaceLeafTool}/bin/surface-leaf)"' \
            'printf "surfacepkg 1.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/surfacepkg"
          chmod +x "$out/bin/surfacepkg"
        '';
      }
    ];
  };
  surfaceUpgradeV1 = mkProfileTool {
    pname = "upgradeface";
    version = "1.0.0";
  };
  surfaceUpgradeV2 = mkProfileTool {
    pname = "upgradeface";
    version = "2.0.0";
  };
  sourcefulV1 = mkProfileTool {
    pname = "sourceful";
    version = "1.0.0";
  };
  sourcefulV2 = mkProfileTool {
    pname = "sourceful";
    version = "2.0.0";
  };
  mkSourceFixture = {
    pname,
    version,
    program,
    outputName,
  }:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf '${outputName} ${version}\\n'" \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  sourcefulSourceV1 = mkSourceFixture {
    pname = "sourceful-source";
    version = "1.0.0";
    program = "sourceful";
    outputName = "sourceful";
  };
  sourcefulSourceV2 = mkSourceFixture {
    pname = "sourceful-source";
    version = "2.0.0";
    program = "sourceful";
    outputName = "sourceful";
  };
  sourceClosureRuntime = mkProfileTool {
    pname = "sourceclosure";
    version = "1.0.0";
  };
  sourceClosureSourceDep = mkProfileTool {
    pname = "sourceclosure-source-helper";
    version = "1.0.0";
    program = "source-helper";
  };
  sourceClosureSourceRoot = pkgs.mkDerivation {
    pname = "sourceclosure-source";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      sourceClosureSourceDep
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'helper_output="$(${sourceClosureSourceDep}/bin/source-helper)"' \
            'printf "sourceclosure source 1.0.0 via %s\n" "$helper_output"' \
            > "$out/bin/sourceclosure-source"
          chmod +x "$out/bin/sourceclosure-source"
        '';
      }
    ];
  };
  realIdempotentDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      idempotentWrapper
    ];
  realDownloadOnlyDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      downloadOnlyWrapper
    ];
  realRemoveDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      removeBasicTool
      removeLeftTool
      removeRightTool
    ];
  realReinstallDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      reinstallTool
      reinstallPeerTool
    ];
  realHoldDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      holdToolV1
      holdToolV2
    ];
  realRollbackDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      rollbackToolV1
      rollbackToolV2
      rollbackToolV3
    ];
  realUpgradeDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      upgradeAlphaV1
      upgradeAlphaV2
      upgradeBetaV1
      upgradeBetaV2
    ];
  realCommandSurfaceDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      surfaceLeafTool
      surfaceTool
      surfaceUpgradeV1
      surfaceUpgradeV2
      sourcefulV1
      sourcefulV2
      sourcefulSourceV1
      sourcefulSourceV2
      sourceClosureRuntime
      sourceClosureSourceDep
      sourceClosureSourceRoot
    ];
  sourceVerifyAltDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      sourcefulV1
    ];
  gcAltDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.jq
    ];
  realInstallDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      installBasicTool
      installDepTool
      installWithDepsTool
    ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);
  setupNixEnv = ''
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    NIXCONF
    nix-store --init || true
    nix-store --load-db < /aos-registration
  '';
  setupAltNixEnv = ''
    export AOS_ROOT=/tmp/aos-alt-root
    export AOS_NIX_STORE_DIR=/nix/store
    export AOS_NIX_STATE_DIR=/tmp/apm-alt-nix-state/var/nix
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    rm -rf /nix/var/nix
    mkdir -p "$NIX_CONF_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    substituters =
    NIXCONF
    NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --init || true
    NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --load-db < /aos-registration
    alt_nix_store() {
      NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" nix-store "$@"
    }
  '';
  setupEmptyAltNixGcEnv = ''
    export AOS_ROOT=/tmp/aos-gc-alt-root
    export AOS_NIX_STORE_DIR=/tmp/apm-gc-alt-store
    export AOS_NIX_STATE_DIR=/tmp/apm-gc-alt-nix-state/var/nix
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    rm -rf /nix/var/nix
    mkdir -p "$NIX_CONF_DIR" "$AOS_NIX_STORE_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    substituters =
    NIXCONF
    NIX_STORE_DIR="$AOS_NIX_STORE_DIR" NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --init || true
  '';
in {
  inherit
    fixtures
    realLifecycleDeps
    idempotentTool
    installBasicTool
    installDepTool
    installWithDepsTool
    idempotentWrapper
    downloadOnlyWrapper
    removeLeftTool
    removeRightTool
    removeBasicTool
    holdToolV1
    holdToolV2
    reinstallTool
    reinstallPeerTool
    rollbackToolV1
    rollbackToolV2
    rollbackToolV3
    upgradeAlphaV1
    upgradeAlphaV2
    upgradeBetaV1
    upgradeBetaV2
    surfaceLeafTool
    surfaceTool
    surfaceUpgradeV1
    surfaceUpgradeV2
    sourcefulV1
    sourcefulV2
    sourcefulSourceV1
    sourcefulSourceV2
    sourceClosureRuntime
    sourceClosureSourceDep
    sourceClosureSourceRoot
    realIdempotentDeps
    realDownloadOnlyDeps
    realRemoveDeps
    realReinstallDeps
    realHoldDeps
    realRollbackDeps
    realUpgradeDeps
    realCommandSurfaceDeps
    sourceVerifyAltDeps
    gcAltDeps
    realInstallDeps
    setupNixEnv
    setupAltNixEnv
    setupEmptyAltNixGcEnv
    ;
}
