##! Distinct source-owned positive-native-progress candidate; no source-class qualification
{
  lib,
  stdenv,
  buildPackages,
  mkCargoPackage,
  mkCargoDummySource,
  fetchCargoVendor,
  mkDerivation,
  rust,
  coreutils,
  tar,
  gzip,
  sed,
}: let
  version = "1";
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

  # This installation is tested on its native builder. Cross installations need
  # their own source-built manifest emitter and executable test environment.
  nativeOnly = !stdenv.isCross;
  baseSource = import ./crucible/_source.nix {inherit lib;};
  src = mkDerivation {
    pname = "crucible-reference-progress-source";
    inherit version;
    buildDeps = [coreutils];
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -R ${baseSource}/. "$out/"
          chmod -R u+w "$out"
          mkdir -p "$out/pkgs/emulation/_gem5"
          # Provider test compilation authenticates these original source bytes;
          # retaining them does not bring an emulator into the runtime boundary.
          cp ${../emulation/_gem5/native-owner.py} "$out/pkgs/emulation/_gem5/native-owner.py"
          cp ${../emulation/_gem5/native-owner-model.py} "$out/pkgs/emulation/_gem5/native-owner-model.py"
        '';
      }
    ];
  };
  cargoDeps = fetchCargoVendor {
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-public-progress-reference-dummy-source";
      cargoRoot = "crates";
    };
    name = "crucible-public-progress-reference-vendor";
    sourceRoot = "source/crates";
    hash = import ./crucible/_cargo-deps-hash.nix;
  };
  binaries = mkCargoPackage {
    inherit src cargoDeps platformSupport;
    pname = "crucible-reference-progress-binaries";
    version = "0.1.0";
    cargoRoot = "crates";
    cargoFlags = "-p crucible-node-provider --bin crucible-reference-progress-provider --bin crucible-reference-progress-device --bin crucible-reference-progress-manifest";
    # Keep package selection before libtest arguments. The shared sequential
    # check switch places libtest arguments before cargoTestFlags.
    cargoTestFlags = "-p crucible-node-provider --all-targets -- --test-threads=1";
    doCheck = true;
    doParallelCheck = true;
    buildDeps = [rust.dev];
    runtimeDeps = [];
    postBuild = ''
      cargo clippy --frozen --offline -p crucible-node-provider --lib --bins -- -D warnings
    '';
    meta = {
      description = "Builds and tests the distinct positive-native-progress reference provider and native companion";
      license = "Apache-2.0";
    };
  };

  buildRoots = lib.unique [rust stdenv.cc coreutils tar gzip sed];
  closureInfo = lib.build.closureInfo {pkgs = buildPackages;};
  runtimeClosure = closureInfo {
    rootPaths = [binaries];
    pname = "crucible-reference-progress-runtime-graph";
  };
  buildClosure = closureInfo {
    rootPaths = buildRoots;
    pname = "crucible-reference-progress-build-graph";
  };
  installed = "@out@/share/crucible/reference-progress";
  instructions = builtins.toJSON {
    provider = "${binaries}/bin/crucible-reference-progress-provider";
    device = "${binaries}/bin/crucible-reference-progress-device";
    source = "${installed}/source.tar.gz";
    recipe = "${installed}/recipe.nix";
    contract = "${installed}/contract.tar.gz";
    reference_graph = "${runtimeClosure}/inventory.json";
    build_reference_graph = "${buildClosure}/inventory.json";
    build_roots = map toString buildRoots;
    build_tools = {
      rustc = "${rust}/bin/rustc";
      cargo = "${rust}/bin/cargo";
      c_compiler = "${stdenv.cc}/bin/cc";
      archive = "${tar}/bin/tar";
      compression = "${gzip}/bin/gzip";
      copy = "${coreutils}/bin/cp";
    };
  };
in
  assert nativeOnly;
    mkDerivation {
      pname = "crucible-reference-progress-implementation";
      inherit version platformSupport;
      dontStrip = true;
      # The already measured JSON and provenance references are immutable
      # protocol data. Scrubbing their tool paths would invalidate identities.
      dontNukeRefs = true;
      buildDeps = [coreutils tar gzip sed];
      runtimeDeps = [binaries];
      passthru = {
        inherit binaries;
        implementationManifestRelativePath = "share/crucible/reference-progress/implementation.json";
      };
      phases = [
        {
          name = "build";
          script = ''
            profile="$out/share/crucible/reference-progress"
            mkdir -p "$profile" "$out/share/licenses/crucible-reference-progress-implementation" archive/workspace archive/vendor
            cp -R ${src}/. archive/workspace/
            cp -R ${cargoDeps}/. archive/vendor/
            ${tar}/bin/tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
              -cf source.tar -C archive workspace vendor
            ${gzip}/bin/gzip -n -c source.tar > "$profile/source.tar.gz"
            ${tar}/bin/tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
              -cf contract.tar -C ${src}/docs/rfcs 0025-crucible-node-contract
            ${gzip}/bin/gzip -n -c contract.tar > "$profile/contract.tar.gz"
            cp ${./crucible-reference-progress-implementation.nix} "$profile/recipe.nix"
            cp ${../../LICENSES/Apache-2.0.txt} "$out/share/licenses/crucible-reference-progress-implementation/LICENSE"
            cat > manifest-input.template.json <<'EOF'
            ${instructions}
            EOF
            ${sed}/bin/sed "s|@out@|$out|g" manifest-input.template.json > manifest-input.json
            ${binaries}/bin/crucible-reference-progress-manifest manifest-input.json "$profile"
            test -s "$profile/implementation.json"
            test -s "$profile/runtime-closure.json"
          '';
        }
      ];
      meta = {
        description = "Pins measured source, tools and runtime ELF content for one positive-native-progress candidate; native progress enrollment and loss qualification remain separate";
        license = ["Apache-2.0" "MIT"];
      };
    }
