##! git — Distributed version control system
##!
##! Two variants share this builder via the `minimal` flag (both registered
##! from the same source and version): `pkgs.git` (full) and
##! `pkgs.git-minimal`. The minimal build omits the Perl/Python/Tcl/gitweb
##! features so its runtime closure carries no interpreter — apm/apr and the
##! image's admin git use only C builtins, so it is fully sufficient there
##! while keeping Perl (~75 MiB) out of the system image.
{
  mkDerivation,
  fetchurl,
  lib,
  gnumake,
  pkg-config,
  perl,
  python3,
  autoconf,
  curl,
  openssl,
  zlib,
  expat,
  pcre2,
  gettext,
  minimal ? false,
}: let
  version = "2.48.1";

  # In minimal mode, disable the interpreter-backed features. `git fetch`,
  # `init`, `rev-parse`, `cat-file`, `hash-object`, `archive`, `rev-list`,
  # `merge-base`, `tag`, `update-server-info`, and `verify-commit`/`verify-tag`
  # are all C builtins, so nothing the registry or admins use is lost.
  featureFlags =
    if minimal
    then "NO_PERL=1 NO_PYTHON=1 NO_TCLTK=1 NO_GITWEB=1"
    else "PERL_PATH=${perl}/bin/perl PYTHON_PATH=${python3}/bin/python3";
in
  mkDerivation {
    pname = "git" + lib.optionalString minimal "-minimal";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
        "https://www.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
      ];
      hash = "sha256-HF1UX13B61HpXSxQ2Y/fiLGja6H6MOmuXVOFxgJPgq0=";
    };

    buildDeps = [
      gnumake
      pkg-config
      perl
      python3
      autoconf
    ];
    runtimeDeps = [
      curl
      openssl
      zlib
      expat
      pcre2
      gettext
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd git-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          make configure
          ./configure \
            --prefix=$out \
            --with-curl=${curl} \
            --with-openssl=${openssl} \
            --with-expat=${expat} \
            --with-zlib=${zlib} \
            --with-pcre2=${pcre2} \
            --with-libpcre2 \
            --without-tcltk \
            --without-iconv
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            NO_INSTALL_HARDLINKS=1 \
            ${featureFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            NO_INSTALL_HARDLINKS=1 \
            ${featureFlags}
          ${lib.optionalString minimal ''
            # Drop residual Perl-referencing artifacts so the closure is
            # interpreter-free: gitweb (a Perl CGI), the example hooks (several
            # are Perl scripts whose shebangs would pin the Perl store path),
            # and any installed Perl/Python library trees.
            rm -rf $out/share/gitweb
            rm -rf $out/share/git-core/templates/hooks
            rm -rf $out/share/perl5 $out/lib/perl5
          ''}
        '';
      }
    ];

    meta = {
      description =
        "git — distributed version control system"
        + lib.optionalString minimal " (minimal: no Perl/Python/gitweb)";
      homepage = "https://git-scm.com";
      license = "GPL-2.0-only";
    };
  }
