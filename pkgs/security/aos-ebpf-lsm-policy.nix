##! aos-ebpf-lsm-policy — Load fleet-managed BPF-LSM policy artifacts
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  json-c,
  patchelf,
  buildPackages,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
  targetTriple =
    {
      "x86_64-linux" = "x86_64-unknown-linux-gnu";
      "aarch64-linux" = "aarch64-unknown-linux-gnu";
    }
    .${
      stdenv.hostPlatform.system
    };
  staticBuildSetup = ''
    target_triple="$(rustc -vV | sed -n 's/^host: //p')"
    test "$target_triple" = "${targetTriple}"
    rustflags_var="CARGO_TARGET_$(printf '%s' "$target_triple" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
    mkdir -p "$TMPDIR/static-shim"
    ln -s "$(dirname "$(cc -print-libgcc-file-name)")/libgcc_s.a" \
      "$TMPDIR/static-shim/libgcc_eh.a"
    export "$rustflags_var=-C target-feature=+crt-static -C relocation-model=static -L $TMPDIR/static-shim"
    export CARGO_BUILD_TARGET="$target_triple"
  '';
  cargoArtifactContract = {
    family = "aos-ebpf-lsm-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-ebpf-lsm-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-ebpf-lsm-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-ebpf-lsm-provider --bin aos-ebpf-lsm-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-ebpf-lsm-provider"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-ebpf-lsm-policy: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-ebpf-lsm-policy.bpf.c;
  loaderSource = ./aos-ebpf-lsm-policy.c;
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "aos-ebpf-lsm-policy";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-ebpf-lsm-provider";
      entryPoint = "bin/aos-ebpf-lsm-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-ebpf-lsm-provider --bin aos-ebpf-lsm-provider";
    cargoTestFlags = "-p aos-ebpf-lsm-provider";
    doCheck = true;
    abilities = ./_aos-ebpf-lsm-policy/module.nix;

    buildDeps = [
      linux-headers
      llvm
      pkg-config
      patchelf
    ];
    runtimeDeps = [
      libbpf
      json-c
    ];
    propagatedDeps = [];
    disallowedReferences = [bpfSource loaderSource];

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-ebpf-lsm-provider" target/release/
    '';

    postInstall = ''
      mkdir -p $out/libexec $out/lib/bpf $out/share/aos/ebpf-lsm $out/share/aos/providers
      cp ${bpfSource} "$TMPDIR/aos-ebpf-lsm-policy.bpf.c"

      ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
        -D__TARGET_ARCH_${targetArch} \
        -I${linux-headers}/include \
        -I${libbpf}/include \
        -Wall -Wextra -Werror -Wno-unused-parameter \
        -c "$TMPDIR/aos-ebpf-lsm-policy.bpf.c" \
        -o $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

      # clang -g emits BTF (for CO-RE) but also DWARF embedding the
      # kernel-headers path. Strip DWARF; .BTF is retained, CO-RE works.
      ${buildPackages.llvm}/bin/llvm-strip -g $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

      $CC -O2 -Wall -Wextra -Werror \
        -I${linux-headers}/include \
        -o $out/libexec/aos-ebpf-lsm-loader \
        ${loaderSource} \
        $(pkg-config --cflags --libs libbpf json-c)

      cp ${./_aos-ebpf-lsm-policy/provider.nix} \
        $out/share/aos/providers/ebpf-lsm-policy-set.nix

      cat > $out/share/aos/ebpf-lsm/aos-task-audit.json <<'JSON'
      {
        "version": 1,
        "name": "aos-lsm-task-audit",
        "programs": ["aos_lsm_file_mprotect"]
      }
      JSON

      test -x $out/bin/aos-ebpf-lsm-provider
      test -x $out/libexec/aos-ebpf-lsm-loader
      if patchelf --print-interpreter "$out/bin/aos-ebpf-lsm-provider" \
          > "$TMPDIR/aos-ebpf-lsm-provider.interpreter" 2>/dev/null; then
        printf 'aos-ebpf-lsm-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-ebpf-lsm-provider.interpreter"
        exit 1
      fi
    '';

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-ebpf-lsm-policy.nix;
        name = "aos-ebpf-lsm-policy.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-ebpf-lsm-policy.bpf.c";
      })
      (builtins.path {
        path = loaderSource;
        name = "aos-ebpf-lsm-policy.c";
      })
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      policy-consumption = lib.mkArtifactConsumptionAudit {
        inherit pkgs;
        name = "ebpf-lsm-immutable-policy";
        consumer = self;
        consumerPath = "/libexec/aos-ebpf-lsm-loader";
        provider = self;
        providerPath = "/share/aos/ebpf-lsm/aos-task-audit.json";
        targetPlatform = {
          system = stdenv.hostPlatform.constraints.os;
          architecture = stdenv.hostPlatform.constraints.cpu;
        };
        mechanism = "immutable-data-input";
        arguments = [
          "validate"
          "--policy"
          "${self}/share/aos/ebpf-lsm/aos-task-audit.json"
          "--object"
          "${self}/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
        ];
        expectedOutputSha256 = "sha256:${builtins.hashString "sha256" ""}";
        inspector = pkgs.buildPackages.aos;
      };

      validate = pkgs.runCommand "security-aos-ebpf-lsm-policy-validate" {} ''
        ${self}/libexec/aos-ebpf-lsm-loader validate \
          --policy ${self}/share/aos/ebpf-lsm/aos-task-audit.json \
          --object ${self}/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o
        touch $out
      '';
    };

    meta = {
      description = "Load fleet-managed BPF-LSM policy artifacts";
      license = "MIT";
    };
  }
