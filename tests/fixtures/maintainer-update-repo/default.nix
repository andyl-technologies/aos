{
  crossSystem ? null,
  bash ? (import ./fixture-inputs.nix).bash,
}: let
  system =
    if crossSystem == null
    then builtins.currentSystem
    else crossSystem;

  mkCheck = name:
    builtins.derivation {
      inherit name system;
      builder = "${bash}/bin/bash";
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out"
          printf '%s\n' passed > "$out/result"
        ''
      ];
    };

  mkUpstream = spec: let
    component = spec.components.main;
    sourceSpec = component.sources.source;
    sourceUrl = "https://aos.andyl.org/_assets/style.css";
    source = builtins.derivation {
      name = "style.css";
      inherit system;
      builder = "builtin:fetchurl";
      url = sourceUrl;
      outputHash = sourceSpec.hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };
    normalizedComponent =
      builtins.removeAttrs component ["discovery"]
      // {
        primary = component.discovery.primary;
        advisors = [];
        sources.source = sourceSpec // {derivation = source.drvPath;};
      };
    forPackage = {member}:
      builtins.removeAttrs spec ["schema"]
      // {
        components.main = normalizedComponent;
        artifacts = {};
        members = [member];
        platforms = ["x86_64-linux"];
        policy = spec.policy // {repairScope = spec.policy.repairScope or [];};
      };
  in {
    version = spec.package.currentVersion;
    components.main.sources.source = source;
    inherit forPackage;
  };

  mkFixturePackage = {
    version,
    src,
    update,
  }:
    (builtins.derivation {
      name = "maintain-fixture-${version}";
      inherit system src;
      builder = "${bash}/bin/bash";
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out/share/maintain-fixture"
          cp "$src" "$out/share/maintain-fixture/source.css"
          printf '%s\n' "$version" > "$out/share/maintain-fixture/version"
        ''
      ];
      inherit version;
    })
    // {
      inherit update version;
    };

  fixture = import ./pkgs/maintain-fixture.nix {
    inherit mkFixturePackage mkUpstream;
  };
  pass = mkCheck "maintainer-update-fixture-check";
in {
  pkgs = {
    maintain-fixture = fixture;
    targetPackagesFor = _: {maintain-fixture = fixture;};
  };

  maintenanceInventory = {
    schema = "aos.maintenance-inventory/v1";
    units = [fixture.update];
  };

  checks = {
    eval = pass;
    rust = pass;
    build = pass;
    vm = pass;
    fleet = pass;
    lint.maintain-fixture = pass;
  };
}
