##! ruby — Ruby programming language
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  rust,
  openssl,
  zlib,
  libyaml,
  gdbm,
  gmp,
  libffi,
  libxcrypt,
  readline,
  ncurses,
}: let
  version = "4.0.6";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  rustForBuild =
    if isLinuxCross
    then rust.passthru.buildTool
    else rust;
  crossTestFlags = lib.optionalString isLinuxCross (
    " TEST_RUNNABLE=yes RUNRUBY=\"${buildPackages.ruby}/bin/ruby"
    + " tool/runruby.rb --extout=.ext --\""
  );
in
  mkDerivation {
    pname = "ruby";
    inherit version;

    src = fetchurl {
      urls = ["https://cache.ruby-lang.org/pub/ruby/4.0/ruby-${version}.tar.xz"];
      hash = "sha256-nJ0SH+MxTqfIAeaQud6YHSudEteEnbmcJ0gkaKVBugo=";
    };

    buildDeps =
      [gnumake pkg-config rust buildPackages.glibc-locales]
      ++ lib.optionals isLinuxCross [buildPackages.ruby rustForBuild];
    runtimeDeps = [
      openssl
      zlib
      libyaml
      gdbm
      gmp
      libffi
      libxcrypt
      readline
      ncurses
    ];
    propagatedDeps = [openssl zlib libyaml gdbm libffi readline];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ruby-${version}
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString isLinuxCross ''
            # Ruby executes its source generators on the build machine. YJIT
            # still needs Rust to emit the target architecture's static library.
            export BASERUBY=${buildPackages.ruby}/bin/ruby
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/rustc-for-target <<'EOF'
            #!${buildPackages.bash}/bin/bash
            exec ${rustForBuild}/bin/rustc --target=${stdenv.hostPlatform.config} "$@"
            EOF
            chmod +x .aos-build-tools/rustc-for-target
            export RUSTC="$PWD/.aos-build-tools/rustc-for-target"
          ''
          + ''
            ./configure $configureFlags \
              --prefix="$out" \
              --enable-shared \
              --enable-yjit \
              --with-openssl-dir=${openssl} \
              --with-gdbm-dir=${gdbm} \
              --with-libyaml-dir=${libyaml} \
              --with-libffi-dir=${libffi} \
              --with-readline-dir=${readline}
          '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          export LOCPATH=${buildPackages.glibc-locales}/lib/locale
          export LC_ALL=C.UTF-8
          check_cores=$NIX_BUILD_CORES
          if [ "$check_cores" -gt 16 ]; then check_cores=16; fi
          # The full test-all target requires mutable ownership, set-id mode,
          # and network-service behavior that the Nix build sandbox forbids.
          # Ruby's core test target exercises the interpreter and native
          # extensions without those host integration assumptions.
          ${lib.optionalString isLinuxCross ''
            # Cross builds use BASERUBY for generators, but the basic suite
            # also invokes the target miniruby executable directly.
            make -j"$check_cores" miniruby
          ''}make -j"$check_cores" test${crossTestFlags}
        '';
      }
      {
        name = "install";
        script =
          ''
            make install
            "$out/bin/ruby" -ropenssl -rzlib -rpsych -e \
              'abort unless RUBY_VERSION == "${version}"'
          ''
          + lib.optionalString isLinuxCross ''
            # Bundled gems install compilation intermediates whose debug
            # metadata retains paths to the build compiler.
            find "$out/lib/ruby/gems" -type f -name '*.o' -delete
          '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-ruby";
        tool = self;
        command = "ruby --version && ruby -ropenssl -rpsych -e 'exit unless 6 * 7 == 42'";
      };
    };

    meta = {
      description = "Dynamic object-oriented programming language";
      homepage = "https://www.ruby-lang.org/";
      license = "Ruby OR BSD-2-Clause";
      mainProgram = "ruby";
    };
  }
