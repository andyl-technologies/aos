##! crucible-guest — static RFC-0010 guest white-box emitter
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  patchelf,
  glibc,
  sqliteStatic,
  buildPackages,
}: let
  version = "0.1.0";

  # patchelf only inspects the installed guest, so it runs on the build
  # machine. Static SQLite is the opposite role: an archive linked into the
  # guest for its own platform. Cross package sets reject target-platform
  # buildDeps, so the archive enters through runtimeDeps there, which exposes
  # its headers and libraries to the cross linker. Native builds keep the
  # original buildDeps placement; the roles coincide and derivation
  # identities stay unchanged.
  buildPatchelf =
    if stdenv.isCross
    then buildPackages.patchelf
    else patchelf;
  guestBuildDeps = [buildPatchelf] ++ lib.optional (!stdenv.isCross) sqliteStatic;
  guestLinkDeps = lib.optional stdenv.isCross sqliteStatic;

  src = import ./crucible/_source.nix {inherit lib;};
  cargoDeps = aosWorkspaceVendor;
  cargoWorkspaceMembers = import ./crucible/_workspace.nix {inherit lib;};
  targetTriple =
    {
      "x86_64-linux" = "x86_64-unknown-linux-gnu";
      "aarch64-linux" = "aarch64-unknown-linux-gnu";
    }
    .${
      stdenv.hostPlatform.system
    };
  cargoEnv = {
    # Guest tests transitively use CAS. Force its SQLite dependency to link
    # the AOS-built archive even when Cargo enables bundled bindings.
    SQLITE3_LIB_DIR = "${sqliteStatic}/lib";
    SQLITE3_INCLUDE_DIR = "${sqliteStatic}/include";
    SQLITE3_STATIC = "1";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
  };
  staticBuildSetup = ''
    target_triple="${
      if stdenv.isCross
      then targetTriple
      else ''$(rustc -vV | sed -n 's/^host: //p')''
    }"
    test "$target_triple" = "${targetTriple}"
    rustflags_var="CARGO_TARGET_$(printf '%s' "$target_triple" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
    mkdir -p "$TMPDIR/static-shim"
    ln -s "$(dirname "$(cc -print-libgcc-file-name)")/libgcc_s.a" \
      "$TMPDIR/static-shim/libgcc_eh.a"
    ${lib.optionalString stdenv.isCross ''
      # The split static output retains libm's original runtime-output paths.
      # Rebase this link-only script locally without changing the toolchain.
      sed 's|${builtins.storeDir}/[^ /]*/lib/|${glibc.static}/lib/|g' \
        ${glibc.static}/lib/libm.a > "$TMPDIR/static-shim/libm.a"
    ''}
    export "$rustflags_var=-C target-feature=+crt-static -C relocation-model=static -L $TMPDIR/static-shim"
    export CARGO_BUILD_TARGET="$target_triple"
  '';
  cargoArtifactContract = {
    family = "crucible-static-guest-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [buildPatchelf sqliteStatic];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "crucible-static-guest-artifacts";
    inherit version cargoDeps cargoWorkspaceMembers cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-static-guest-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-guest --bin crucible-guest"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p crucible-guest"
    ];
    preBuild = staticBuildSetup;
    buildDeps = guestBuildDeps;
    runtimeDeps = guestLinkDeps;
  };
in
  mkCargoPackage {
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
    pname = "crucible-guest";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents verbs:.";
        "files" = {};
        "input" = "The packaged crucible-guest command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/crucible-guest\",\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"verbs:\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"crucible-guest operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "crucible-guest operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing its main operation.";
        "files" = {};
        "input" = "A crucible-guest invocation containing an unsupported command-line option.";
        "operation" = "Parse the unknown option without starting a service or contacting a remote endpoint.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/crucible-guest\",\"aos-invalid-verb\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"crucible-guest rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "crucible-guest rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    inherit cargoDeps cargoWorkspaceMembers cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-guest --bin crucible-guest";
    cargoTestFlags = "-p crucible-guest";
    doCheck = true;
    buildDeps = guestBuildDeps;
    runtimeDeps = guestLinkDeps;

    preBuild = ''
      ${staticBuildSetup}
      # crt-static linking asks for -lgcc_eh, which the AOS gcc (built with
      # shared libgcc) does not install. libgcc_s.a carries the same unwinder
      # symbols, so expose it under the name the linker wants.
      # relocation-model=static links a classic static executable instead of
      # static-pie; static-pie startup self-relocation SIGSEGVs against the
      # AOS glibc (IRELATIVE ordering), and the in-VM guest gains nothing
      # from PIE.
      # Build with an explicit --target (equal to the host triple) so cargo
      # separates host units from target units: proc-macro dylibs
      # (e.g. thiserror-impl) compile for the host WITHOUT +crt-static, which
      # cannot produce dylibs, while the guest binary itself links statically.
    '';

    postInstall = ''
      test -x "$out/bin/crucible-guest"
      if patchelf --print-interpreter "$out/bin/crucible-guest" > "$TMPDIR/crucible-guest.interpreter" 2>/dev/null; then
        printf 'crucible-guest unexpectedly has ELF interpreter: '
        cat "$TMPDIR/crucible-guest.interpreter"
        exit 1
      fi

      doorbell_instruction_abi_version=$(sed -n \
        's/^pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = \([0-9][0-9]*\);$/\1/p' \
        crucible/protocol/crucible-qemu-protocol/src/doorbell_abi.rs)
      test -n "$doorbell_instruction_abi_version"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-guest-build-info" <<INFO
      package=crucible-guest
      build_system=mkCargoPackage
      cargo_deps=fetchCargoVendor
      cargo_package=crucible-guest
      cargo_binary=crucible-guest
      rustflags=-C target-feature=+crt-static
      cargo_build_target=host-triple-explicit
      packaged_guest_system=${stdenv.hostPlatform.system}
      doorbell_instruction_abi_version=$doorbell_instruction_abi_version
      instruction_abi_architectures=x86_64,aarch64
      abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS
      frame_source=crucible-protocol::doorbell_frame
      marker_source=crucible-protocol::doorbell_marker
      INFO
    '';

    meta = {
      description = "Static Crucible guest marker and typed-selectable client";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "crucible-guest";
    };
  }
