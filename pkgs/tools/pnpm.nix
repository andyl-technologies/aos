##! pnpm — Fast, disk-space-efficient package manager
{
  mkCargoPackage,
  mkDerivation,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "11.25.0";
  upstreamSrc = fetchurl {
    urls = ["https://github.com/pnpm/pnpm/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-paGneVnkw2IYOuqUeJ46xGbm8hFCLjQhonDzSKz5P7E=";
  };
  src = mkDerivation {
    pname = "pnpm-source";
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
          cd pnpm-${version}
        '';
      }
      {
        name = "install";
        script = ''
                   mkdir -p "$out"
                   cp -R . "$out/"

                   # The upstream lock selected patch releases whose MSRV rose after
                   # pnpm 11.25 was tagged. Keep the same declared dependency ranges
                   # while selecting their newest Rust 1.93-compatible releases.
                   sed -i '
                     /name = "tree-sitter-iter"/,/^$/ {
                       s/version = "1.29.0"/version = "1.27.0"/
                       s/1d3bd5c9821bacab907511ede9a21837b2a2be02ee8143ba145780f8d2a638bc/0cbef0ee83b87916292355e78f4fdee268d719ececa729be8914882428ca86b0/
                     }
                     /name = "yamlpath"/,/^$/ {
                       s/version = "1.29.0"/version = "1.27.0"/
                       s/df6cc1b09a8b90e81e3bdd695ffd6583269fd3f9897c863342167aafd448b6f0/1362068e6e34bf985c39ee42ee8d410fcc398fedbd5f9303602616db26f542b5/
                     }
                   ' "$out/Cargo.lock"
                   sed -i '
                     /name = "yamlpatch"/,/^$/ {
                       s/version = "1.29.0"/version = "1.25.2"/
                       s/45ee9380e1d493eeb5ceb2cc026f595fc99901f7763edad124134b0446adbcaa/f5c7aa995e374499b0decb17a2fa138430d6cd4683705e905e1e6619635d5fbd/
                       /"line-index"/a\
          "serde",
                     }
                   ' "$out/Cargo.lock"

                   # yamlpath 1.27 predates the source-location fields added to
                   # QueryError::InvalidInput. The error still reports malformed YAML;
                   # adapt pnpm's constructor to that Rust-1.93-compatible API.
                   sed -i \
                     's/QueryError::InvalidInput(line, column)/QueryError::InvalidInput/' \
                     "$out/pnpm/crates/cli/src/github_actions.rs"
        '';
      }
    ];
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-HlfLLP5VYdCOXzm3PtgLtGyyMTwWU2AGtfpHzGHtzyI=";
  };
in
  mkCargoPackage {
    pname = "pnpm";
    inherit version src cargoDeps;

    cargoFlags = "--bin pnpm";
    doCheck = false;
    runtimeDeps = [];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-pnpm";
        tool = self;
        command = "pnpm --version && pnpm help >/dev/null";
      };
    };

    meta = {
      description = "Fast, disk-space-efficient package manager";
      homepage = "https://pnpm.io/";
      license = "MIT";
      mainProgram = "pnpm";
    };
  }
