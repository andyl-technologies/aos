##! Measured private pure-derivation worker installation; admission remains separate.
{
  lib,
  stdenv,
  buildPackages,
  mkCargoPackage,
  aosWorkspaceVendor,
  mkDerivation,
  rust,
  openssl,
  sqlite,
  pkg-config,
  protobuf,
  aos-landlock,
  qemu-crucible,
  crucible-qemu-plugin,
  linux-crucible,
  crucible-fixtures,
  coreutils,
  tar,
  gzip,
  sed,
}: let
  version = "0.1.0";
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
  src = import ./crucible/_source.nix {inherit lib;};
  cargoDeps = aosWorkspaceVendor;
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    PROTOC = "${protobuf}/bin/protoc";
  };
  forbiddenRuntimePaths =
    map
    (package: builtins.unsafeDiscardStringContext (toString package))
    [qemu-crucible crucible-qemu-plugin linux-crucible crucible-fixtures];
  binaries = mkCargoPackage {
    pname = "crucible-source-birth-worker-binaries";
    inherit version src cargoDeps platformSupport cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "-p crucible-source-birth-worker --no-default-features --bin crucible-source-birth-worker";
    cargoTestFlags = "-p crucible-source-birth-worker --no-default-features --all-targets";
    doCheck = true;
    buildDeps = [rust.dev pkg-config protobuf];
    runtimeDeps = [openssl sqlite];
    disallowedReferences = forbiddenRuntimePaths;
    disallowedRequisites = forbiddenRuntimePaths;
    postBuild = ''
      cargo clippy --frozen --offline -j"$NIX_BUILD_CORES" -p crucible-source-birth-worker --no-default-features --all-targets -- -D warnings
    '';
    meta = {
      description = "Private safe SourceBirth DATA process entry point for bounded source-birth derivation";
      license = "Apache-2.0";
    };
  };
  # This build-only tool is deliberately not a runtime graph root. Its legacy
  # two-argument provider mode is unchanged; the new mode is closed separately.
  measurement = mkCargoPackage {
    pname = "crucible-pure-worker-manifest-emitter";
    inherit version src cargoDeps platformSupport;
    cargoRoot = "crates";
    cargoFlags = "-p crucible-node-transport --bin crucible-reference-manifest";
    cargoTestFlags = "-p crucible-node-transport --bin crucible-reference-manifest";
    doCheck = true;
    buildDeps = [rust.dev];
    runtimeDeps = [];
    meta = {
      description = "Measures immutable pure-worker content and complete realized runtime closure";
      license = "Apache-2.0";
    };
  };
  closureInfo = lib.build.closureInfo {pkgs = buildPackages;};
  runtimeClosure = closureInfo {
    rootPaths = [binaries aos-landlock];
    pname = "crucible-source-birth-worker-runtime-graph";
  };
  # This declaration closes installation compatibility with the selected helper
  # source. It is DATA; actual program/currentness/kernel admission stays separate.
  launcherContract = aos-landlock.passthru or aos-landlock;
  installed = "@out@/share/crucible/source-birth-worker";
  instructions = builtins.toJSON {
    launcher = "${aos-landlock}/bin/aos-landlock";
    worker = "${binaries}/bin/crucible-source-birth-worker";
    source = "${installed}/source.tar.gz";
    vendor = "${installed}/vendor.tar.gz";
    recipe = "${installed}/recipe.nix";
    reference_graph = "${runtimeClosure}/inventory.json";
  };
in
  # The installed emitter must run on this builder; cross installations require
  # a separate native measurement and executable verification environment.
  assert !stdenv.isCross;
  assert (launcherContract.pureWorkerProfileId or null) == "pure-worker-v1";
    mkDerivation {
      pname = "crucible-source-birth-worker";
      inherit version platformSupport;
      dontStrip = true;
      dontNukeRefs = true;
      buildDeps = [coreutils tar gzip sed measurement];
      runtimeDeps = [binaries aos-landlock];
      disallowedReferences = forbiddenRuntimePaths;
      disallowedRequisites = forbiddenRuntimePaths;
      passthru = {
        inherit binaries measurement runtimeClosure;
        installationManifestRelativePath = "share/crucible/source-birth-worker/installation.json";
      };
      phases = [
        {
          name = "build";
          script = ''
            profile="$out/share/crucible/source-birth-worker"
            mkdir -p "$profile" "$out/share/licenses/crucible-source-birth-worker"
            ${tar}/bin/tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
              -cf source.tar -C ${src} .
            ${gzip}/bin/gzip -n -c source.tar > "$profile/source.tar.gz"
            ${tar}/bin/tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
              -cf vendor.tar -C ${cargoDeps} .
            ${gzip}/bin/gzip -n -c vendor.tar > "$profile/vendor.tar.gz"
            cp ${./crucible-source-birth-worker.nix} "$profile/recipe.nix"
            cp ${../../LICENSES/Apache-2.0.txt} "$out/share/licenses/crucible-source-birth-worker/LICENSE"
            cat > worker-input.template.json <<'EOF'
            ${instructions}
            EOF
            ${sed}/bin/sed "s|@out@|$out|g" worker-input.template.json > worker-input.json
            ${measurement}/bin/crucible-reference-manifest --pure-worker worker-input.json "$profile"
            for metadata in installation runtime-closure algorithm request-codec result-codec; do
              test -s "$profile/$metadata.json"
            done
          '';
        }
      ];
      meta = {
        description = "Retains measured worker, launcher, full runtime tree and matching source/vendor/recipe; no admission or preservation claim";
        license = ["Apache-2.0" "MIT"];
      };
    }
