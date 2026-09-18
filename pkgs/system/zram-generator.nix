##! zram-generator — systemd generator for compressed swap and filesystems
{
  lib,
  mkDerivation,
  fetchCargoDeps,
  fetchurl,
  stdenv,
  buildPackages,
  rust,
  jq,
  pkg-config,
  lowdown,
  systemd,
}: let
  version = "1.2.1";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  nativeCargoTarget = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
  targetCargoTarget = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.hostPlatform.config);
  rustForBuild =
    if isLinuxCross
    then rust.passthru.buildTool
    else rust;
  releaseDirectory =
    if isLinuxCross
    then "target/${stdenv.hostPlatform.config}/release"
    else "target/release";
  upstreamSrc = fetchurl {
    urls = ["https://github.com/systemd/zram-generator/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-nILNPbOG6C+6Kt/gHD0JQ2yenP48qLs0HX64gnaMWK8=";
  };
  src = mkDerivation {
    pname = "zram-generator-source";
    inherit version;
    src = upstreamSrc;
    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd zram-generator-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -R . "$out/"
          cp ${./zram-generator.Cargo.lock} "$out/Cargo.lock"
        '';
      }
    ];
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Nzrv8uaCpUeGraGe+DFNfO5hcIfK7p7AB0YbfW1EHdc=";
  };
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "zram-generator";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The generator emits the zram setup drop-in, swap unit, and swap target link.";
        "files" = {};
        "input" = "A synthetic host root with one 64 MB zram swap definition.";
        "operation" = "Run the systemd generator against the synthetic configuration and memory inventory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import os, pathlib, subprocess\nroot = pathlib.Path(\"root\").resolve()\n(root / \"etc/systemd\").mkdir(parents=True)\n(root / \"proc\").mkdir()\n(root / \"output\").mkdir()\n(root / \"etc/systemd/zram-generator.conf\").write_text(\"[zram0]\\nzram-size = 64M\\nswap-priority = 100\\n\")\n(root / \"proc/cmdline\").write_text(\"\\n\")\n(root / \"proc/meminfo\").write_text(\"MemTotal:       1048576 kB\\n\")\nenvironment = os.environ.copy()\nenvironment[\"ZRAM_GENERATOR_ROOT\"] = str(root)\nresult = subprocess.run([\"@out@/bin/zram-generator\", str(root / \"output\")], env=environment, capture_output=True)\nassert result.returncode == 0, result.stderr\noutput = root / \"output\"\nassert (output / \"dev-zram0.swap\").is_file()\nassert (output / \"systemd-zram-setup@zram0.service.d/bindings.conf\").is_file()\nassert (output / \"swap.target.wants/dev-zram0.swap\").is_symlink()\nprint(\"zram-generator operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "zram-generator operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The generator rejects the undefined expression and emits no swap unit.";
        "files" = {};
        "input" = "A synthetic host root whose zram-size expression is undefined.";
        "operation" = "Run the generator against the malformed size expression.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport os, pathlib, subprocess\nroot = pathlib.Path(\"root\").resolve()\n(root / \"etc/systemd\").mkdir(parents=True)\n(root / \"proc\").mkdir()\n(root / \"output\").mkdir()\n(root / \"etc/systemd/zram-generator.conf\").write_text(\"[zram0]\\nzram-size = qualification-invalid\\n\")\n(root / \"proc/cmdline\").write_text(\"\\n\")\n(root / \"proc/meminfo\").write_text(\"MemTotal:       1048576 kB\\n\")\nenvironment = os.environ.copy()\nenvironment[\"ZRAM_GENERATOR_ROOT\"] = str(root)\nresult = subprocess.run([\"@out@/bin/zram-generator\", str(root / \"output\")], env=environment, capture_output=True, text=True)\nassert result.returncode != 0 and \"Undefined\" in result.stderr\nassert not (root / \"output/dev-zram0.swap\").exists()\n\nsys.stderr.write(\"zram-generator rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "zram-generator rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    buildDeps = [rustForBuild jq pkg-config lowdown];
    runtimeDeps = [systemd];
    propagatedDeps = [];
    disallowedReferences = [cargoDeps rust];

    abilities = ./_zram-generator;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "patch";
        script = ''
          # The integration harness replaces /proc/self/exe so generated units
          # remain path-independent. Use an absolute synthetic target because
          # glibc requires the executable link used for $ORIGIN expansion to
          # begin at the filesystem root when the test later spawns diff.
          sed -i 's|symlink("zram-generator",|symlink("/zram-generator",|' \
            tests/test_cases.rs
          find tests -type f -exec sed -i \
            's|# Automatically generated by zram-generator|# Automatically generated by /zram-generator|' \
            {} +
        '';
      }
      {
        name = "configure";
        script =
          ''
            export CARGO_HOME="$TMPDIR/cargo"
            export CARGO_INCREMENTAL=0
            mkdir -p "$CARGO_HOME" .cargo
            cat > .cargo/config.toml <<EOF
            [source.crates-io]
            replace-with = "vendored-sources"

            [source.vendored-sources]
            directory = "${cargoDeps}"
            EOF
          ''
          + lib.optionalString isLinuxCross ''
            # Build scripts execute on the builder, while the generator and
            # integration tests link for the target platform.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<'EOF'
            #!${buildPackages.bash}/bin/bash
            unset AOS_CROSS_COMPILING AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_GOARCH AOS_GOOS
            unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
            unset LIBRARY_PATH NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
            exec ${buildPackages.cc}/bin/cc "$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export PATH="${rustForBuild}/bin:$PATH"
            export CARGO_TARGET_${nativeCargoTarget}_LINKER="$PWD/.aos-build-tools/cc-for-build"
            export CARGO_TARGET_${targetCargoTarget}_LINKER="${stdenv.cc}/bin/cc"
            export CARGO_BUILD_TARGET=${stdenv.hostPlatform.config}
          '';
      }
      {
        name = "build";
        script = ''
          export SYSTEMD_UTIL_DIR=${systemd}/lib/systemd
          cargo build --release --frozen --offline -j"$NIX_BUILD_CORES"

          sed \
            's|@SYSTEMD_SYSTEM_GENERATOR_DIR@|'"$out"'/lib/systemd/system-generators|' \
            units/systemd-zram-setup@.service.in \
            > units/systemd-zram-setup@.service

          lowdown -Tman man/zram-generator.md > man/zram-generator.8
          lowdown -Tman man/zram-generator.conf.md > man/zram-generator.conf.5
        '';
      }
      {
        name = "check";
        script =
          if isLinuxCross
          then ''
            export SYSTEMD_UTIL_DIR=${systemd}/lib/systemd
            cargo test --release --frozen --offline --lib --bin zram-generator
            cargo test --release --frozen --offline --test test_cases --no-run

            # The integration constructor creates user and mount namespaces,
            # which user-mode emulation cannot provide. Run its assertions on
            # the builder; target integration coverage needs a full target VM.
            export SYSTEMD_UTIL_DIR=${buildPackages.systemd}/lib/systemd
            export PATH="${buildPackages.diffutils}/bin:${buildPackages.coreutils}/bin:$PATH"
            cargo test --release --frozen --offline \
              --target ${stdenv.buildPlatform.config} --test test_cases
          ''
          else ''
            export SYSTEMD_UTIL_DIR=${systemd}/lib/systemd
            cargo test --release --frozen --offline
          '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 ${releaseDirectory}/zram-generator "$out/bin/zram-generator"
          mkdir -p "$out/lib/systemd/system-generators"
          ln -s ../../../bin/zram-generator \
            "$out/lib/systemd/system-generators/zram-generator"
          install -Dm644 units/systemd-zram-setup@.service \
            "$out/lib/systemd/system/systemd-zram-setup@.service"
          install -Dm644 zram-generator.conf.example \
            "$out/share/doc/zram-generator/zram-generator.conf.example"
          install -Dm644 man/zram-generator.8 "$out/share/man/man8/zram-generator.8"
          install -Dm644 man/zram-generator.conf.5 "$out/share/man/man5/zram-generator.conf.5"
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      lowdown-consumption = lib.mkArtifactConsumptionAudit {
        inherit pkgs;
        name = "zram-generator-lowdown-build-tool";
        consumer = self;
        consumerPath = "/share/man/man8/zram-generator.8";
        provider = pkgs.buildPackages.lowdown;
        providerPath = "/bin/lowdown";
        targetPlatform = {
          system = pkgs.stdenv.hostPlatform.constraints.os;
          architecture = pkgs.stdenv.hostPlatform.constraints.cpu;
        };
        mechanism = "build-tool-execution";
        arguments = [
          "-Tman"
          "${src}/man/zram-generator.md"
        ];
        expectedOutputSha256 = "sha256:48c86a9737fbac21786d0c60ba1d63651a09713a6001e36b84ee7ebd2d5c3e97";
        inspector = pkgs.buildPackages.aos;
      };

      tool = testing.mkToolCheck {
        pname = "tool-zram-generator";
        tool = self;
        command = "test -x ${self}/lib/systemd/system-generators/zram-generator && test -f ${self}/lib/systemd/system/systemd-zram-setup@.service";
      };
    };

    meta = {
      description = "Generates systemd units for compressed swap and filesystems on zram";
      homepage = "https://github.com/systemd/zram-generator";
      license = "MIT";
      mainProgram = "zram-generator";
    };
  }
