##! Builds the pinned upstream manifest extractor once, before Bazel actions.
{pkgs}: let
  inventory = builtins.fromJSON (builtins.readFile ../../../third_party/bazel/modules.json);
  rules = inventory.modules.rules_rust;
  archive = pkgs.fetchurl {
    urls = [rules.source.url];
    hash = rules.source.integrity;
  };
  source = pkgs.runCommand "aos-bazel-manifest-extractor-source" {buildDeps = [pkgs.tar pkgs.gzip];} ''
    mkdir -p unpacked "$out"
    tar xf ${archive} -C unpacked
    root=unpacked/${pkgs.lib.escapeShellArg rules.source.strip_prefix}
    cp -R "$root/cargo/private/cargo_toml_variable_extractor/." "$out/"
    cp "$root/cargo/3rdparty/Cargo.Bazel.lock" "$out/Cargo.lock"
  '';
  ruleInputs = (builtins.fromJSON (builtins.readFile ../../../third_party/bazel/rule-inputs.json)).repositories;
  crateInputs =
    builtins.filter
    (name: pkgs.lib.hasPrefix "rules_rust++i2+rrc__" name)
    (builtins.attrNames ruleInputs);
  vendor = pkgs.runCommand "aos-bazel-manifest-extractor-vendor" {buildDeps = [pkgs.tar pkgs.gzip pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.lib.concatMapStringsSep "\n" (name: let
        input = ruleInputs.${name};
        crate = pkgs.fetchurl {
          urls = [input.url];
          hash = input.sha256;
        };
      in ''
        tar xf ${crate} -C "$out"
        printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
          files = {};
          package = input.sha256;
        })} \
          > "$out/${input.strip_prefix}/.cargo-checksum.json"
      '')
      crateInputs}
    ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/source_only.py} "$out"
  '';
in
  pkgs.mkCargoPackage {
    pname = "aos-bazel-manifest-extractor";
    version = rules.version;
    src = source;
    sharedBuildCache = false;
    cargoDeps = vendor;
    # The upstream lock covers two helper packages. Select this package's
    # closure offline from those exact vendored versions before locked builds.
    postConfigure = ''
      cargo generate-lockfile --offline
    '';
    doCheck = false;
    meta = {
      description = "Pinned rules_rust Cargo manifest environment extractor";
      license = "Apache-2.0";
      mainProgram = "cargo_toml_variable_extractor";
    };
  }
