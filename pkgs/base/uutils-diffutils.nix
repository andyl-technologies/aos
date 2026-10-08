##! uutils diffutils — Rust diff and cmp.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.5.0";
  src = fetchurl {
    urls = ["https://github.com/uutils/diffutils/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-TAXSNuvd73c4RGmApZzRNSG2mQ6gIkLbazIyHdk4U8o=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-bgKOJqUSFG2gHvPvPbARbMXIJZg0k1J/GY4ce+9Y5vM=";
  };
in
  mkCargoPackage {
    pname = "uutils-diffutils";
    inherit version src cargoDeps;

    cargoFlags = "--bin diffutils";
    doCheck = false;

    postInstall = ''
      # The upstream multicall binary currently implements diff and cmp.
      ln -s diffutils "$out/bin/diff"
      ln -s diffutils "$out/bin/cmp"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-diffutils";
        tool = self;
        command = ''
          printf 'same\n' > /tmp/uutils-diff-left
          printf 'same\n' > /tmp/uutils-diff-right
          ${self}/bin/diff /tmp/uutils-diff-left /tmp/uutils-diff-right
          ${self}/bin/cmp /tmp/uutils-diff-left /tmp/uutils-diff-right
          printf 'matched\n'
        '';
        expectedOutput = "matched";
      };
    };

    meta = {
      description = "Rust diff and cmp utilities";
      homepage = "https://github.com/uutils/diffutils";
      license = "MIT OR Apache-2.0";
      mainProgram = "diff";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
