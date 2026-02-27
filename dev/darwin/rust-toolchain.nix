{system}: let
  version = "1.93.1";
  targets = {
    "aarch64-darwin" = {
      triple = "aarch64-apple-darwin";
      hash = "0siq58acv5llrcfn7rnhr4l8yzvi0rg2jh8pfmvca6bh6sss7bvb";
    };
    "x86_64-darwin" = {
      triple = "x86_64-apple-darwin";
      hash = "0m82lsnarc2k9p12yv82lvka11iq0yn79ai2k920bc3cbmqd6jsx";
    };
  };
  target =
    targets.${system}
    or (throw "darwin/rust-toolchain.nix: unsupported system ${system}");
  tarball = builtins.fetchurl {
    url = "https://static.rust-lang.org/dist/rust-${version}-${target.triple}.tar.gz";
    sha256 = target.hash;
  };
in
  builtins.derivation {
    name = "rust-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH=/usr/bin:/bin
        mkdir -p "$out"
        tar xf "${tarball}" -C "$TMPDIR"
        "$TMPDIR/rust-${version}-${target.triple}/install.sh" \
          --prefix="$out" --disable-ldconfig
      ''
    ];
  }
