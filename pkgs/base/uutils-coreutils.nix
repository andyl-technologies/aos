##! uutils coreutils — Rust implementation of the GNU core utilities.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.12.0";
  src = fetchurl {
    urls = ["https://github.com/uutils/coreutils/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-T7MnZVy0/8vy8WVQz5I0B5/+g5aS96oabtoQSvaE4SI=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Qlm3xR7l4Qx6Oh2uhx5VgHfoKXKUMg9/1r+A3d+AldQ=";
  };
in
  mkCargoPackage {
    pname = "uutils-coreutils";
    inherit version src cargoDeps;

    buildFeatures = ["unix"];
    cargoFlags = "--bin coreutils";
    doCheck = false;

    postInstall = ''
      # Resolve enabled utilities from Cargo's feature graph, including when
      # the target binary cannot execute on the build machine.
      cargo tree --offline --depth 1 --features unix --format '{p}' --prefix none \
        | sed -n 's/^uu_\([^ ]*\) .*/\1/p' \
        | while read -r utility; do
            ln -s coreutils "$out/bin/$utility"
          done

      # `[` is an alias of `test`, so it has no separate uu_* crate.
      ln -s coreutils "$out/bin/["

      test -x "$out/bin/coreutils"
      test -L "$out/bin/["
      test -L "$out/bin/cp"
      test -L "$out/bin/install"
      test -L "$out/bin/stdbuf"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-coreutils";
        tool = self;
        command = ''
          printf 'payload' > /tmp/uutils-source
          ${self}/bin/cp /tmp/uutils-source /tmp/uutils-copy
          ${self}/bin/[ -f /tmp/uutils-copy ]
          ${self}/bin/cat /tmp/uutils-copy
        '';
        expectedOutput = "payload";
      };
    };

    meta = {
      description = "Rust implementation of the GNU core utilities";
      homepage = "https://github.com/uutils/coreutils";
      license = "MIT";
      mainProgram = "coreutils";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
