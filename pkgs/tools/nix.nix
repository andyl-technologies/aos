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
  stdenv,
  buildPackages,
}: let
  version = "2.24.12";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildMeson =
    if isDarwinCross
    then buildPackages.meson
    else meson;
  mesonSetupFlags =
    if isDarwinCross
    then ''      --buildtype=release \
            $mesonFlags''
    else "--buildtype=release";
  darwinGitCacheFix =
    if isDarwinCross
    then
      "\n"
      + ''
        # Clang 22 correctly diagnoses discarded libc++ nodiscard results,
        # which Nix promotes to errors.  The unique_ptr::get() call has no
        # side effect, while extract() is intentionally used for its erase.
        sed -i \
          's|lookupCache.emplace(path2, std::move(copy)).first->second.get();|lookupCache.emplace(path2, std::move(copy));|' \
          src/libfetchers/git-utils.cc
        sed -i \
          's|goal->waiters.extract(shared_from_this());|static_cast<void>(goal->waiters.extract(shared_from_this()));|' \
          src/libstore/build/goal.cc
      ''
    else "";
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
          export PYTHONPATH="${buildMeson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
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
            src/libstore/meson.build${darwinGitCacheFix}
          # Boost is split across two outputs (headers in boost.dev, libs in
          # boost). Point meson's Boost finder at each explicitly — these
          # split-aware vars work where BOOST_ROOT (single prefix) would not.
          export BOOST_INCLUDEDIR=${boost.dev}/include
          export BOOST_LIBRARYDIR=${boost}/lib
          # toml11 is header-only and publishes only a CMake package.  Meson's
          # CMake dependency backend does not derive prefix roots from the
          # compiler include path, so expose the AOS package explicitly.
          export CMAKE_PREFIX_PATH=${toml11}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}

          mkdir -p build && cd build
          meson setup .. \
            --prefix=$out \
            ${mesonSetupFlags}
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
