##! Nix — The purely functional package manager
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  pkg-config,
  meson,
  ninja,
  python3,
  bison,
  flex,
  curl,
  openssl,
  sqlite,
  boost,
  editline,
  libsodium,
  nlohmann-json,
  toml11,
  libgit2,
  brotli,
  libarchive,
  gc,
  lowdown,
  bzip2,
  zlib,
}: let
  version = "2.24.12";
in
  mkDerivation {
    pname = "nix";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/NixOS/nix/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-862Kc2J+EH5X9JFIaKzWN6oODXCmh91nGLrC0vZPUMg=";
    };

    buildDeps = [
      make
      cmake
      pkg-config
      meson
      ninja
      python3
      bison
      flex
    ];
    runtimeDeps = [
      curl
      openssl
      sqlite
      boost
      editline
      libsodium
      nlohmann-json
      toml11
      libgit2
      brotli
      libarchive
      gc
      lowdown
      bzip2
      zlib
    ];
    propagatedDeps = [];

    LDFLAGS = "-Wl,-rpath,$out/lib";

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nix-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          # Strip meson.build to only core libraries + nix executable
          # Remove docs, tests, perl bindings, C wrappers we don't need
          sed -i '/internal-api-docs/d' meson.build
          sed -i '/external-api-docs/d' meson.build
          sed -i '/libutil-c/d' meson.build
          sed -i '/libstore-c/d' meson.build
          sed -i '/libexpr-c/d' meson.build
          sed -i '/libmain-c/d' meson.build
          sed -i '/perl/d' meson.build
          sed -i '/nix-.*-test/d' meson.build
          sed -i '/nix-.*-tests/d' meson.build
          mkdir -p build && cd build
          meson setup .. \
            --prefix=$out \
            --buildtype=release
        '';
      }
      {
        name = "build";
        script = ''
          ninja -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      stack = testing.mkVMTest {
        name = "cross-cutting-nix-stack";
        rootfsDeps = [
          self
          pkgs.brotli
          pkgs.curl
          pkgs.openssl
          pkgs.sqlite
          pkgs.boost
          pkgs.editline
          pkgs.libsodium
          pkgs.libarchive
          pkgs.gc
          pkgs.lowdown
          pkgs.bzip2
          pkgs.zlib
        ];
        memory = 512;
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.brotli}/lib:${pkgs.curl}/lib:${pkgs.openssl}/lib:${pkgs.sqlite}/lib:${pkgs.boost}/lib:${pkgs.editline}/lib:${pkgs.libsodium}/lib:${pkgs.libarchive}/lib:${pkgs.gc}/lib:${pkgs.lowdown}/lib:${pkgs.bzip2}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
          # nix needs a /tmp and writable home
          export HOME=/tmp
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p /tmp/nix-conf

          # Disable features that need network/daemon
          cat > /tmp/nix-conf/nix.conf << 'NIXCONF'
          sandbox = false
          experimental-features = nix-command
          NIXCONF

          echo "==> Testing nix --version"
          nix --version

          echo "==> Testing nix eval"
          RESULT=$(nix eval --expr '1 + 1')
          echo "    nix eval '1 + 1' = $RESULT"
          if [ "$RESULT" != "2" ]; then
            echo "ERROR: expected 2, got $RESULT"
            exit 1
          fi

          echo "Nix stack: PASS"
        '';
      };

      store-ops = testing.mkVMTest {
        name = "cross-cutting-nix-store-ops";
        rootfsDeps = [
          self
          pkgs.brotli
          pkgs.curl
          pkgs.openssl
          pkgs.sqlite
          pkgs.boost
          pkgs.editline
          pkgs.libsodium
          pkgs.libarchive
          pkgs.gc
          pkgs.lowdown
          pkgs.bzip2
          pkgs.zlib
        ];
        memory = 512;
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.brotli}/lib:${pkgs.curl}/lib:${pkgs.openssl}/lib:${pkgs.sqlite}/lib:${pkgs.boost}/lib:${pkgs.editline}/lib:${pkgs.libsodium}/lib:${pkgs.libarchive}/lib:${pkgs.gc}/lib:${pkgs.lowdown}/lib:${pkgs.bzip2}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
          export HOME=/tmp
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p /tmp/nix-conf /nix/var/nix/db

          cat > /tmp/nix-conf/nix.conf << 'NIXCONF'
          sandbox = false
          experimental-features = nix-command
          NIXCONF

          echo "==> Testing nix store init"
          nix store init
          echo "    Store initialized"

          echo "==> Testing nix eval --expr"
          RESULT=$(nix eval --expr '1 + 1')
          echo "    nix eval '1 + 1' = $RESULT"
          if [ "$RESULT" != "2" ]; then
            echo "ERROR: expected 2, got $RESULT"
            exit 1
          fi

          echo "==> Testing nix eval builtins.currentSystem"
          RESULT2=$(nix eval --expr 'builtins.currentSystem')
          echo "    builtins.currentSystem = $RESULT2"

          echo "Nix store ops: PASS"
        '';
      };
    };

    meta = {
      description = "Nix — the purely functional package manager";
      homepage = "https://nixos.org/nix";
      license = "LGPL-2.1-or-later";
    };
  }
