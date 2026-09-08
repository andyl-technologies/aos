##! git — Distributed version control system
##!
##! Two variants share this builder via the `minimal` flag (both registered
##! from the same source and version): `pkgs.git` (full) and
##! `pkgs.git-minimal`. The minimal build omits the Perl/Python/Tcl/gitweb
##! features. It retains Bash for Git's shell helpers, while keeping the large
##! Perl/Python runtimes out of the closure; apm/apr and the image's admin Git
##! use only C builtins, so it is fully sufficient there.
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
  bash,
  stdenv,
  buildPackages,
  minimal ? false,
}: let
  version = "2.48.1";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildBash =
    if stdenv.isCross
    then buildPackages.bash
    else bash;
  buildPerl =
    if stdenv.isCross
    then buildPackages.perl
    else perl;
  buildPython3 =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  gettextRuntime =
    if isDarwinCross
    then gettext.lib
    else gettext;

  # In minimal mode, disable the interpreter-backed features. `git fetch`,
  # `init`, `rev-parse`, `cat-file`, `hash-object`, `archive`, `rev-list`,
  # `merge-base`, `tag`, `update-server-info`, and `verify-commit`/`verify-tag`
  # are all C builtins, so nothing the registry or admins use is lost.
  featureFlags =
    if minimal
    then "NO_PERL=1 NO_PYTHON=1 NO_TCLTK=1 NO_GITWEB=1"
    else "PERL_PATH=${perl}/bin/perl PYTHON_PATH=${python3}/bin/python3";
  buildFeatureFlags =
    if minimal
    then featureFlags
    else "PERL_PATH=${buildPerl}/bin/perl PYTHON_PATH=${buildPython3}/bin/python3";
  buildShellFlag = "SHELL_PATH=${buildBash}/bin/bash";
  # Git's Makefile runs uname independently of configure. Select the target
  # Darwin capabilities, or at least report the target CPU on cross Linux.
  targetPlatformFlags =
    if isDarwinCross
    then " uname_S=Darwin uname_M=${stdenv.hostPlatform.darwinArch} uname_R=22.1.0"
    else lib.optionalString stdenv.isCross " HOST_CPU=${stdenv.hostPlatform.parsed.cpu.name}";
  # Darwin's precompose support calls iconv directly; its SDK provides the
  # canonical header and system-library stub.
  iconvConfigureFlag = lib.optionalString (!isDarwinCross) "--without-iconv";
  # CURLDIR supplies the target include and library paths. Disable curl-config
  # execution and spell out the remaining facts for the pinned target curl.
  crossCurlFlags = assert !stdenv.isCross || builtins.compareVersions curl.version "7.34.0" >= 0;
    lib.optionalString stdenv.isCross " CURL_CONFIG=: CURL_LDFLAGS=-lcurl USE_CURL_FOR_IMAP_SEND=YesPlease";
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

    buildDeps =
      [
        gnumake
        pkg-config
        autoconf
      ]
      ++ lib.optionals stdenv.isCross [
        buildBash
        buildPackages.gettext
      ]
      ++ lib.optionals (!minimal) [
        buildPerl
        buildPython3
      ];
    runtimeDeps =
      [
        curl
        openssl
        zlib
        expat
        pcre2
        gettextRuntime
        bash
      ]
      ++ lib.optionals (!minimal) [
        perl
        python3
      ];
    propagatedDeps = [];
    disallowedReferences = lib.optionals stdenv.isCross (
      [buildBash buildPackages.gettext]
      ++ lib.optionals (!minimal) [buildPerl buildPython3]
    );

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
          make configure${lib.optionalString stdenv.isCross ''

            # These runtime probes describe fixed target libc behavior. Seed
            # them when target binaries cannot run on the builder.
            export ac_cv_fread_reads_directories=yes
            export ac_cv_snprintf_returns_bogus=no
          ''}${lib.optionalString isDarwinCross ''

            # Darwin keeps iconv enabled, so its runtime-only BOM probe also
            # needs a target answer during cross compilation.
            export ac_cv_iconv_omits_bom=no
          ''}
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-curl=${curl} \
            --with-openssl=${openssl} \
            --with-expat=${expat} \
            --with-zlib=${zlib} \
            --with-pcre2=${pcre2} \
            --with-libpcre2 \
            --without-tcltk \
            ${iconvConfigureFlag}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            NO_INSTALL_HARDLINKS=1${targetPlatformFlags}${crossCurlFlags} \
            ${buildShellFlag} \
            ${buildFeatureFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            NO_INSTALL_HARDLINKS=1${targetPlatformFlags}${crossCurlFlags} \
            ${buildShellFlag} \
            ${buildFeatureFlags}
          ${lib.optionalString stdenv.isCross ''
            retarget_tool_root() {
              nativeRoot=$1
              targetRoot=$2
              [ "$nativeRoot" = "$targetRoot" ] && return
              if [ "''${#nativeRoot}" -ne "''${#targetRoot}" ]; then
                echo "cannot retarget unequal-length store paths" >&2
                exit 1
              fi
              # Git also compiles these paths into ELF or Mach-O binaries, so
              # search binary and text outputs. Equal-length replacement
              # preserves load-command and string-table offsets.
              { grep -rlZ -F "$nativeRoot" "$out" 2>/dev/null || true; } \
                | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
            }
            retarget_tool_root ${buildBash} ${bash}
            ${lib.optionalString (!minimal) ''
              retarget_tool_root ${buildPerl} ${perl}
              retarget_tool_root ${buildPython3} ${python3}
            ''}
          ''}
          ${lib.optionalString minimal ''
            # Drop residual Perl-referencing artifacts so the closure is
            # Perl/Python-free: gitweb (a Perl CGI), the example hooks (several
            # are Perl scripts whose shebangs would pin the Perl store path),
            # and any installed language-specific library trees.
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
