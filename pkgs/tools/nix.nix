##! Nix — The purely functional package manager
{
  mkDerivation,
  fetchurl,
  gnumake,
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

    # `out` ships the CLI + shared libraries (the runtime image uses the nix
    # CLI only); `dev` holds the headers and pkg-config files. Keeping the
    # pkg-config out of `out` is what stops nix's `.pc` files from dragging
    # boost's header output (`boost.dev`) back into the runtime closure.
    outputs = ["out" "dev"];

    src = fetchurl {
      urls = [
        "https://github.com/NixOS/nix/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-862Kc2J+EH5X9JFIaKzWN6oODXCmh91nGLrC0vZPUMg=";
    };

    buildDeps = [
      gnumake
      cmake
      pkg-config
      meson
      ninja
      python3
      bison
      flex
      # Boost headers for compilation only; the runtime lib reference comes
      # from `boost` (the lib output) in runtimeDeps below.
      boost.dev
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
          patch -p1 < ${./nix-patches/0001-aos-pure-eval-inputs.patch}

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
          # Fix SYSTEM define: meson build at 2.24.x only sets it to the OS name
          # ("linux") instead of the full system pair ("x86_64-linux"). Fixed
          # upstream in 2.28.0 (commit 6a1a3fa1c).
          sed -i "s|configdata.set_quoted('SYSTEM', host_machine.system())|configdata.set_quoted('SYSTEM', host_machine.cpu_family() + '-' + host_machine.system())|" \
            src/libstore/meson.build
          # Boost is split across two outputs (headers in boost.dev, libs in
          # boost). Point meson's Boost finder at each explicitly — these
          # split-aware vars work where BOOST_ROOT (single prefix) would not.
          export BOOST_INCLUDEDIR=${boost.dev}/include
          export BOOST_LIBRARYDIR=${boost}/lib

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

          # Create legacy command symlinks (multi-call binary)
          for cmd in nix-store nix-build nix-instantiate nix-env \
                     nix-collect-garbage nix-copy-closure nix-daemon \
                     nix-hash nix-prefetch-url nix-channel; do
            if [ ! -e "$out/bin/$cmd" ]; then
              ln -s nix "$out/bin/$cmd"
            fi
          done

          # AOS config evaluation keeps pure evaluation enabled while admitting
          # only authenticated input roots. Prove that admitted paths retain
          # their exact identity and that siblings, symlink escapes, and impure
          # builtins remain unavailable.
          pure_test_root="$TMPDIR/aos-pure-eval-inputs"
          mkdir -p "$pure_test_root/allowed" "$pure_test_root/allowed-sibling" "$pure_test_root/duplicate"
          printf '%s\n' '42' > "$pure_test_root/allowed/value.nix"
          printf '%s\n' '{ root = toString ./.; value = import ./value.nix; }' > "$pure_test_root/allowed/entry.nix"
          printf '%s\n' '43' > "$pure_test_root/allowed-sibling/value.nix"
          printf '%s\n' '{ root = toString ./.; value = import ./value.nix; }' > "$pure_test_root/duplicate/entry.nix"
          printf '%s\n' '42' > "$pure_test_root/duplicate/value.nix"
          ln -s ../allowed-sibling/value.nix "$pure_test_root/allowed/escape.nix"

          pure_eval() {
            "$out/bin/nix-instantiate" \
              --store dummy:// \
              --eval --strict --json --pure-eval \
              --option restrict-eval true \
              --option allow-import-from-derivation false \
              --option allowed-uris "" \
              "$@"
          }

          allowed_result=$(pure_eval \
            --aos-pure-eval-input "$pure_test_root/allowed" \
            "$pure_test_root/allowed/entry.nix")
          expected_allowed="{\"root\":\"$pure_test_root/allowed\",\"value\":42}"
          if [ "$allowed_result" != "$expected_allowed" ]; then
            echo "ERROR: admitted pure-eval input changed path identity"
            exit 1
          fi

          duplicate_result=$(pure_eval \
            --aos-pure-eval-input "$pure_test_root/duplicate" \
            "$pure_test_root/duplicate/entry.nix")
          expected_duplicate="{\"root\":\"$pure_test_root/duplicate\",\"value\":42}"
          if [ "$duplicate_result" != "$expected_duplicate" ]; then
            echo "ERROR: equal-content pure-eval inputs collapsed path identity"
            exit 1
          fi

          if pure_eval \
            --aos-pure-eval-input "$pure_test_root/allowed" \
            --expr "import $pure_test_root/allowed-sibling/value.nix"; then
            echo "ERROR: pure-eval input admitted a prefix sibling"
            exit 1
          fi
          if pure_eval \
            --aos-pure-eval-input "$pure_test_root/allowed" \
            --expr "import $pure_test_root/allowed/escape.nix"; then
            echo "ERROR: pure-eval input admitted a symlink escape"
            exit 1
          fi
          if pure_eval \
            --aos-pure-eval-input "$pure_test_root/allowed/entry.nix" \
            "$pure_test_root/allowed/entry.nix"; then
            echo "ERROR: admitting one file also admitted its sibling"
            exit 1
          fi
          if pure_eval --expr 'builtins.readFile /etc/passwd'; then
            echo "ERROR: pure evaluation exposed an ambient filesystem path"
            exit 1
          fi
          if pure_eval --expr "builtins.readFile $out/bin/nix"; then
            echo "ERROR: pure evaluation exposed an unlisted store path"
            exit 1
          fi
          if pure_eval --expr builtins.currentSystem; then
            echo "ERROR: pure evaluation exposed builtins.currentSystem"
            exit 1
          fi
          if pure_eval --expr builtins.currentTime; then
            echo "ERROR: pure evaluation exposed builtins.currentTime"
            exit 1
          fi
          get_env_result=$(HOME=/ambient pure_eval --expr 'builtins.getEnv "HOME"')
          if [ "$get_env_result" != '""' ]; then
            echo "ERROR: pure evaluation exposed an environment variable"
            exit 1
          fi
          if pure_eval --aos-pure-eval-input relative/path --expr '1'; then
            echo "ERROR: pure-eval input accepted a relative path"
            exit 1
          fi
          if "$out/bin/nix-instantiate" \
            --store dummy:// --eval --strict --json \
            --aos-pure-eval-input "$pure_test_root/allowed" \
            --expr '1'; then
            echo "ERROR: pure-eval input was accepted without pure evaluation"
            exit 1
          fi

          # Move build-against artifacts into $dev so the runtime $out (CLI +
          # libs) carries no headers and no pkg-config. The pkg-config files
          # reference boost's header output; leaving them in $out would pull
          # boost.dev back into the runtime closure. Nothing on the appliance
          # compiles against libnix, so $out needs neither.
          mkdir -p "$dev"
          if [ -d "$out/include" ]; then
            mv "$out/include" "$dev/include"
          fi
          if [ -d "$out/lib/pkgconfig" ]; then
            mkdir -p "$dev/lib"
            mv "$out/lib/pkgconfig" "$dev/lib/pkgconfig"
          fi
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
