##! git-2_42 -- Pinned minimum Git for registry compatibility tests
{
  mkDerivation,
  fetchurl,
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
}: let
  version = "2.42.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildBash =
    if isDarwinCross
    then buildPackages.bash
    else bash;
  buildPerl =
    if isDarwinCross
    then buildPackages.perl
    else perl;
  buildPython3 =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  gettextRuntime =
    if isDarwinCross
    then gettext.lib
    else gettext;
  buildToolFlags = ''
    SHELL_PATH=${buildBash}/bin/bash \
    PERL_PATH=${buildPerl}/bin/perl \
    PYTHON_PATH=${buildPython3}/bin/python3
  '';
  # Git's Makefile runs uname independently of configure. Override the Linux
  # builder result so config.mak.uname selects the target Darwin capabilities.
  targetPlatformFlags =
    if isDarwinCross
    then " uname_S=Darwin uname_M=${stdenv.hostPlatform.darwinArch} uname_R=22.1.0"
    else "";
  # Darwin's precompose support calls iconv directly; its SDK provides the
  # canonical header and system-library stub.
  iconvConfigureFlag =
    if isDarwinCross
    then ""
    else "--without-iconv";
in
  mkDerivation {
    pname = "git-2_42";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
        "https://www.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
      ];
      hash = "sha256-MnghDp/SmUuEhN1+Pd2eqLlA71IXDNtgbaqU2IfJOw0=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
        perl
        python3
        autoconf
      ]
      ++ (
        if isDarwinCross
        then [buildPackages.gettext]
        else []
      );
    runtimeDeps = [
      curl
      openssl
      zlib
      expat
      pcre2
      gettextRuntime
      perl
      python3
      bash
    ];
    propagatedDeps = [];
    disallowedReferences =
      if isDarwinCross
      then [buildBash buildPerl buildPython3 buildPackages.gettext]
      else [];

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
          make configure${
            if isDarwinCross
            then ''

              # These runtime probes describe fixed Darwin libc behavior. Seed
              # them when the target binaries cannot run on the Linux builder.
              export ac_cv_fread_reads_directories=yes
              export ac_cv_snprintf_returns_bogus=no
              export ac_cv_iconv_omits_bom=no
            ''
            else ""
          }
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
            NO_INSTALL_HARDLINKS=1${targetPlatformFlags} \
            ${buildToolFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            NO_INSTALL_HARDLINKS=1${targetPlatformFlags} \
            ${buildToolFlags}
          ${
            if isDarwinCross
            then ''
              retarget_tool_root() {
                nativeRoot=$1
                targetRoot=$2
                [ "$nativeRoot" = "$targetRoot" ] && return
                if [ "''${#nativeRoot}" -ne "''${#targetRoot}" ]; then
                  echo "cannot retarget unequal-length store paths" >&2
                  exit 1
                fi
                # Git also compiles these paths into Mach-O binaries, so search
                # binary and text outputs. Equal-length replacement preserves
                # load-command and string-table offsets.
                { grep -rlZ -F "$nativeRoot" "$out" 2>/dev/null || true; } \
                  | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
              }
              retarget_tool_root ${buildBash} ${bash}
              retarget_tool_root ${buildPerl} ${perl}
              retarget_tool_root ${buildPython3} ${python3}
            ''
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "git 2.42.0 -- pinned registry compatibility floor";
      homepage = "https://git-scm.com";
      license = "GPL-2.0-only";
    };
  }
