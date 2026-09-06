##! ruby — Ruby programming language
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  rust,
  glibc-locales,
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
in
  mkDerivation {
    pname = "ruby";
    inherit version;

    src = fetchurl {
      urls = ["https://cache.ruby-lang.org/pub/ruby/4.0/ruby-${version}.tar.xz"];
      hash = "sha256-nJ0SH+MxTqfIAeaQud6YHSudEteEnbmcJ0gkaKVBugo=";
    };

    buildDeps = [gnumake pkg-config rust glibc-locales];
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
        script = ''
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
          export LOCPATH=${glibc-locales}/lib/locale
          export LC_ALL=C.UTF-8
          check_cores=$NIX_BUILD_CORES
          if [ "$check_cores" -gt 16 ]; then check_cores=16; fi
          # The full test-all target requires mutable ownership, set-id mode,
          # and network-service behavior that the Nix build sandbox forbids.
          # Ruby's core test target exercises the interpreter and native
          # extensions without those host integration assumptions.
          make -j"$check_cores" test
        '';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/ruby" -ropenssl -rzlib -rpsych -e \
            'abort unless RUBY_VERSION == "${version}"'
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
