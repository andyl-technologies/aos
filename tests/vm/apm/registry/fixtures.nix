# Shared derivations and environment setup for the registry VM workflows.
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
  publishDeps = fixtures.commonDeps ++ nixRuntimeDeps;
  imageFixtures = import ../image-fixtures.nix {inherit pkgs;};
  publishSysrootImage = imageFixtures.imageRaw;
  publishSysrootDisk = imageFixtures.imageRawDisk;
  publishSysrootInfo = imageFixtures.imageRawInfo;
  publishSysrootUki = imageFixtures.imageUki;
  maintainerWorkflowDeps =
    publishDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.openssh
      pkgs.python3
      pkgs.zstd
    ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);
  setupNixPublishEnv = ''
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
  setupAltNixPublishEnv = ''
    export AOS_ROOT=/tmp/aos-alt-root
    export AOS_NIX_STORE_DIR=/nix/store
    export AOS_NIX_STATE_DIR=/tmp/apr-alt-nix-state/var/nix
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
  '';
  mkRegistryTool = {
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
  closureLeafTool = mkRegistryTool {
    pname = "closure-leaf";
    version = "1.0.0";
  };
  closureRootTool = pkgs.mkDerivation {
    pname = "closure-root";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafTool}/bin/closure-leaf)"' \
            'printf "closure-root 1.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  closureRootSourceTool = pkgs.mkDerivation {
    pname = "closure-root-source";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafTool}/bin/closure-leaf)"' \
            'printf "closure-root 1.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  closureLeafToolV2 = mkRegistryTool {
    pname = "closure-leaf";
    version = "2.0.0";
  };
  closureRootToolV2 = pkgs.mkDerivation {
    pname = "closure-root";
    version = "2.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafToolV2
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafToolV2}/bin/closure-leaf)"' \
            'printf "closure-root 2.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  closureRootSourceToolV2 = pkgs.mkDerivation {
    pname = "closure-root-source";
    version = "2.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafToolV2
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafToolV2}/bin/closure-leaf)"' \
            'printf "closure-root 2.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  closureLeafToolV3 = mkRegistryTool {
    pname = "closure-leaf";
    version = "3.0.0";
  };
  closureRootToolV3 = pkgs.mkDerivation {
    pname = "closure-root";
    version = "3.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafToolV3
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafToolV3}/bin/closure-leaf)"' \
            'printf "closure-root 3.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  mkSignedLeafTool = version:
    mkRegistryTool {
      pname = "signed-leaf";
      inherit version;
      program = "signed-leaf";
    };
  mkSignedRootTool = {
    version,
    leaf,
  }:
    pkgs.mkDerivation {
      pname = "signed-tool";
      inherit version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      runtimeDeps = [
        leaf
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/share/signed-tool"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              'leaf_output="$(${leaf}/bin/signed-leaf)"' \
              'printf "signed-tool ${version} via %s\n" "$leaf_output"' \
              > "$out/bin/signed-tool"
            chmod +x "$out/bin/signed-tool"
            printf '%s\n' "signed-tool payload ${version}" \
              > "$out/share/signed-tool/payload.txt"
          '';
        }
      ];
    };
  signedLeafToolV1 = mkSignedLeafTool "1.0.0";
  signedToolV1 = mkSignedRootTool {
    version = "1.0.0";
    leaf = signedLeafToolV1;
  };
  signedLeafToolV2 = mkSignedLeafTool "2.0.0";
  signedToolV2 = mkSignedRootTool {
    version = "2.0.0";
    leaf = signedLeafToolV2;
  };
  signedLeafToolV3 = mkSignedLeafTool "3.0.0";
  signedToolV3 = mkSignedRootTool {
    version = "3.0.0";
    leaf = signedLeafToolV3;
  };
  signedLeafToolV4 = mkSignedLeafTool "4.0.0";
  signedToolV4 = mkSignedRootTool {
    version = "4.0.0";
    leaf = signedLeafToolV4;
  };
  signedLeafToolV5 = mkSignedLeafTool "5.0.0";
  signedToolV5 = mkSignedRootTool {
    version = "5.0.0";
    leaf = signedLeafToolV5;
  };
  maintRunnerDepTool = mkRegistryTool {
    pname = "maint-runner-dep";
    version = "1.0.0";
  };
  maintRunnerTool = pkgs.mkDerivation {
    pname = "maint-runner";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      maintRunnerDepTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin" "$out/share/maint-runner"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'dep_output="$(${maintRunnerDepTool}/bin/maint-runner-dep)"' \
            'printf "maint-runner 1.0.0 via %s\n" "$dep_output"' \
            > "$out/bin/maint-runner"
          chmod +x "$out/bin/maint-runner"
          ln -s maint-runner "$out/bin/maint-runner-link"
          dd if=/dev/zero of="$out/share/maint-runner/payload.bin" \
            bs=1M count=12
          ln -s . "$out/share/maint-runner/current"
        '';
      }
    ];
  };
  retireDepTool = mkRegistryTool {
    pname = "retire-dep";
    version = "1.0.0";
  };
  retireTool = pkgs.mkDerivation {
    pname = "retire-tool";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      retireDepTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'dep_output="$(${retireDepTool}/bin/retire-dep)"' \
            'printf "retire-tool 1.0.0 via %s\n" "$dep_output"' \
            > "$out/bin/retire-tool"
          chmod +x "$out/bin/retire-tool"
        '';
      }
    ];
  };
  closureWorkflowDeps =
    publishDeps
    ++ [
      closureLeafTool
      closureRootTool
      retireDepTool
      retireTool
    ];
in {
  inherit
    fixtures
    publishDeps
    publishSysrootImage
    publishSysrootDisk
    publishSysrootInfo
    publishSysrootUki
    maintainerWorkflowDeps
    setupNixPublishEnv
    setupAltNixPublishEnv
    closureLeafTool
    closureRootTool
    closureRootSourceTool
    closureLeafToolV2
    closureRootToolV2
    closureRootSourceToolV2
    closureLeafToolV3
    closureRootToolV3
    signedLeafToolV1
    signedToolV1
    signedLeafToolV2
    signedToolV2
    signedLeafToolV3
    signedToolV3
    signedLeafToolV4
    signedToolV4
    signedLeafToolV5
    signedToolV5
    maintRunnerDepTool
    maintRunnerTool
    retireDepTool
    retireTool
    closureWorkflowDeps
    ;
}
