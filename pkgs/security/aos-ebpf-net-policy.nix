##! aos-ebpf-net-policy — Load fleet-managed BPF network policy artifacts
{
  lib,
  mkAosCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
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
    family = "aos-ebpf-net-policy-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-ebpf-net-policy-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-ebpf-net-policy-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-ebpf-net-policy-provider --bin aos-ebpf-net-policy-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-ebpf-net-policy-provider"
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
    or (throw "aos-ebpf-net-policy: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-ebpf-net-policy.bpf.c;
  loaderSource = ./aos-ebpf-net-policy.c;
in
  mkAosCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "aos-ebpf-net-policy";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-ebpf-net-policy-provider";
      entryPoint = "bin/aos-ebpf-net-policy-provider";
    };

    inherit version cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-ebpf-net-policy-provider --bin aos-ebpf-net-policy-provider";
    cargoTestFlags = "-p aos-ebpf-net-policy-provider";
    doCheck = true;
    abilities = ./_aos-ebpf-net-policy;

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

    postInstall = ''
      mkdir -p $out/libexec $out/lib/bpf $out/share/aos/ebpf-net
      cp ${bpfSource} "$TMPDIR/aos-ebpf-net-policy.bpf.c"

      ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
        -D__TARGET_ARCH_${targetArch} \
        -I${linux-headers}/include \
        -I${libbpf}/include \
        -Wall -Wextra -Werror -Wno-unused-parameter \
        -c "$TMPDIR/aos-ebpf-net-policy.bpf.c" \
        -o $out/lib/bpf/aos-ebpf-net-policy.bpf.o

      # clang -g emits BTF (for CO-RE) but also DWARF embedding the
      # kernel-headers path. Strip DWARF; .BTF is retained, CO-RE works.
      ${buildPackages.llvm}/bin/llvm-strip -g $out/lib/bpf/aos-ebpf-net-policy.bpf.o

      $CC -O2 -Wall -Wextra -Werror \
        -I${linux-headers}/include \
        -o $out/libexec/aos-ebpf-net-policy-loader \
        ${loaderSource} \
        $(pkg-config --cflags --libs libbpf json-c)

      cat > $out/share/aos/ebpf-net/sample-policy.json <<'JSON'
      {
        "version": 1,
        "package": "sample",
        "mode": "private",
        "securityLabel": "aos-pkg-sample",
        "tcp": {"bind": [8000], "connect": [443]},
        "ebpf": {
          "identity": "aos-pkg-sample",
          "hooks": ["socket_bind", "socket_connect"],
          "tcp": {"bind": [8000], "connect": [443]}
        }
      }
      JSON

      test -x $out/bin/aos-ebpf-net-policy-provider
      test -x $out/libexec/aos-ebpf-net-policy-loader
      if patchelf --print-interpreter "$out/bin/aos-ebpf-net-policy-provider" \
          > "$TMPDIR/aos-ebpf-net-policy-provider.interpreter" 2>/dev/null; then
        printf 'aos-ebpf-net-policy-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-ebpf-net-policy-provider.interpreter"
        exit 1
      fi
    '';

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-ebpf-net-policy.nix;
        name = "aos-ebpf-net-policy.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-ebpf-net-policy.bpf.c";
      })
      (builtins.path {
        path = loaderSource;
        name = "aos-ebpf-net-policy.c";
      })
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      policy-consumption = lib.mkArtifactConsumptionAudit {
        inherit pkgs;
        name = "ebpf-net-immutable-policy";
        consumer = self;
        consumerPath = "/libexec/aos-ebpf-net-policy-loader";
        provider = self;
        providerPath = "/share/aos/ebpf-net/sample-policy.json";
        targetPlatform = {
          system = stdenv.hostPlatform.constraints.os;
          architecture = stdenv.hostPlatform.constraints.cpu;
        };
        mechanism = "immutable-data-input";
        arguments = [
          "validate"
          "--policy"
          "${self}/share/aos/ebpf-net/sample-policy.json"
          "--object"
          "${self}/lib/bpf/aos-ebpf-net-policy.bpf.o"
        ];
        expectedOutputSha256 = "sha256:${builtins.hashString "sha256" ""}";
        inspector = pkgs.buildPackages.aos;
      };

      validate = pkgs.runCommand "security-aos-ebpf-net-policy-validate" {} ''
        ${self}/libexec/aos-ebpf-net-policy-loader validate \
          --policy ${self}/share/aos/ebpf-net/sample-policy.json \
          --object ${self}/lib/bpf/aos-ebpf-net-policy.bpf.o
        touch $out
      '';
    };

    meta = {
      description = "Load fleet-managed BPF network policy artifacts";
      license = "MIT";
    };
  }
