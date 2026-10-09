##! PostgreSQL Linux cross-build driver and target metadata retargeting
{
  bison,
  buildPackages,
  configureArguments,
  coreutils,
  docbook-xml,
  docbook-xsl,
  flex,
  gettext,
  glibc,
  libxml2,
  libxslt,
  linux-headers,
  llvm,
  perl,
  pkg-config,
  python3,
  stdenv,
  tar,
  tcl,
}: let
  toolVersionsMatch =
    buildPackages.llvm.version
    == llvm.version
    && buildPackages.perl.version == perl.version
    && buildPackages.python3.version == python3.version
    && buildPackages.tcl.version == tcl.version;
in {
  versionCheck =
    toolVersionsMatch
    || throw "postgresql: Linux cross builds require matching build and target LLVM, Perl, Python, and Tcl versions";

  configureScript = ''
    # Build drivers execute on the build machine, while every discovered
    # header, library, and pkg-config record remains target-side.
    export BISON=${buildPackages.bison}/bin/bison
    export FLEX=${buildPackages.flex}/bin/flex
    export MSGFMT=${buildPackages.gettext}/bin/msgfmt
    export MSGMERGE=${buildPackages.gettext}/bin/msgmerge
    export PKG_CONFIG=${buildPackages.pkg-config}/bin/pkg-config
    export XGETTEXT=${buildPackages.gettext}/bin/xgettext
    export XMLLINT=${buildPackages.libxml2}/bin/xmllint
    export XSLTPROC=${buildPackages.libxslt}/bin/xsltproc
    export TCLSH=${buildPackages.tcl}/bin/tclsh9.0

    mkdir -p .aos-native-tools

    # llvm-config describes target headers and libraries, but its bindir must
    # contain native llvm-lto for install-world.
    cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
    #!${buildPackages.bash}/bin/bash
    set -euo pipefail

    case "$1" in
      --bindir)
        printf '%s\n' '${buildPackages.llvm}/bin'
        ;;
      *)
        native_output=$('${buildPackages.llvm}/bin/llvm-config' "$@")
        target_output=$(printf '%s\n' "$native_output" |
          sed 's|${buildPackages.llvm}|${llvm}|g')

        for store_root in $(printf '%s\n' "$target_output" |
          grep -oE '/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+' || true); do
          case "$store_root" in
            '${llvm}') ;;
            *)
              echo "llvm-config exposed an unmapped build-side path: $store_root" >&2
              exit 1
              ;;
          esac
        done
        printf '%s\n' "$target_output"
        ;;
    esac
    LLVM_CONFIG_WRAPPER
    chmod +x .aos-native-tools/llvm-config
    export LLVM_CONFIG=$PWD/.aos-native-tools/llvm-config
    export CLANG="${buildPackages.llvm}/bin/clang --target=${stdenv.hostPlatform.config} -isystem ${glibc.dev}/include -isystem ${linux-headers}/include"

    # Locate exactly one target Perl ABI configuration. The wrapper exposes it
    # only to configure's Config and ExtUtils::Embed queries; ordinary source
    # generators use native Perl modules.
    target_perl_config=
    for candidate in $(find ${perl.dev}/lib -name Config.pm -print); do
      candidate_directory=$(dirname "$candidate")
      if [ -f "$candidate_directory/Config_heavy.pl" ]; then
        if [ -n "$target_perl_config" ]; then
          echo "multiple target Perl ABI configurations found" >&2
          exit 1
        fi
        target_perl_config=$candidate
      fi
    done
    if [ -z "$target_perl_config" ]; then
      echo "target Perl ABI configuration not found" >&2
      exit 1
    fi
    target_perl_archlib=$(dirname "$target_perl_config")
    target_perl_privlib=$(dirname "$target_perl_archlib")

    # Perl's dev output preserves unscrubbed Config modules at the same relative
    # path where the target output installs its headers and shared library.
    # Validate that split explicitly before exposing the metadata to configure.
    case "$target_perl_archlib" in
      '${perl.dev}'/*)
        target_perl_output_archlib=$(printf '%s\n' "$target_perl_archlib" |
          sed 's|^${perl.dev}|${perl}|')
        ;;
      *)
        echo "target Perl ABI configuration escaped its dev output" >&2
        exit 1
        ;;
    esac
    if [ ! -f "$target_perl_output_archlib/CORE/perl.h" ]; then
      echo "target Perl CORE headers not found" >&2
      exit 1
    fi

    cat > .aos-native-tools/perl <<PERL_CONFIG_WRAPPER
    #!${buildPackages.bash}/bin/bash
    set -euo pipefail

    case " \$* " in
      *" -MConfig "*|*" -MExtUtils::Embed "*)
        export PERL5LIB='$target_perl_archlib:$target_perl_privlib'
        ;;
    esac
    exec '${buildPackages.perl}/bin/perl' "\$@"
    PERL_CONFIG_WRAPPER
    chmod +x .aos-native-tools/perl
    export PERL=$PWD/.aos-native-tools/perl

    # Python's target sysconfig data is pure Python. Route only the closed set
    # of ABI queries used by PostgreSQL through it; all source-generation work
    # remains on the native standard library.
    target_python_sysconfig=
    for candidate in $(find ${python3}/lib -name '_sysconfigdata_*.py' -print); do
      if [ -n "$target_python_sysconfig" ]; then
        echo "multiple target Python sysconfig modules found" >&2
        exit 1
      fi
      target_python_sysconfig=$candidate
    done
    if [ -z "$target_python_sysconfig" ]; then
      echo "target Python sysconfig module not found" >&2
      exit 1
    fi
    target_python_stdlib=$(dirname "$target_python_sysconfig")
    target_python_sysconfig_name=$(basename "$target_python_sysconfig" .py)

    cat > .aos-native-tools/python3 <<PYTHON_CONFIG_WRAPPER
    #!${buildPackages.bash}/bin/bash
    set -euo pipefail

    if [ "\''${1:-}" = -c ]; then
      case "\''${2:-}" in
        *"import sysconfig"*)
          case "\$2" in
            "import sysconfig"|*"get_config_vars('LIBPL')"*|*"get_config_var('INCLUDEPY')"*|*"get_config_vars('LIBDIR')"*|*"get_config_vars('LDLIBRARY')"*|*"get_config_vars('LDVERSION')"*|*"get_config_vars('VERSION')"*|*"get_config_vars('LIBS','LIBC','LIBM','BASEMODLIBS')"*)
              export PYTHONPATH='$target_python_stdlib'
              export _PYTHON_SYSCONFIGDATA_NAME='$target_python_sysconfig_name'
              ;;
            *)
              echo "unsupported target Python sysconfig query" >&2
              exit 1
              ;;
          esac
          ;;
      esac
    fi
    exec '${buildPackages.python3}/bin/python3' "\$@"
    PYTHON_CONFIG_WRAPPER
    chmod +x .aos-native-tools/python3
    export PYTHON=$PWD/.aos-native-tools/python3

    # PostgreSQL tests backend symbol export by running a linked program, so
    # configure otherwise assumes the flag is unsupported while cross-building.
    # The Linux cross smoke check verifies this exact target linker and loader
    # contract; loadable extensions require the exported backend symbols.
    export pgac_cv_prog_cc_LDFLAGS_EX_BE__Wl___export_dynamic=yes

    export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
    ./configure \
      $configureFlags \
      ${configureArguments}

    # Build wrappers remain active in generated makefiles. Public
    # configuration metadata names only target-side tools.
    sed -i \
      -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
      -e "s|$PWD/.aos-native-tools/perl|${perl}/bin/perl|g" \
      -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
      -e "s|CC=$CC|CC=${llvm}/bin/clang|g" \
      -e "s|CXX=$CXX|CXX=${llvm}/bin/clang++|g" \
      -e 's|${buildPackages.llvm}|${llvm}|g' \
      -e "s| 'PKG_CONFIG_PATH=[^']*'||g" \
      src/include/pg_config.h

    for macro in \
      ENABLE_GSS ENABLE_NLS HAVE_LIBNUMA USE_ICU USE_LDAP USE_LIBURING USE_LLVM \
      USE_LIBCURL USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM \
      USE_SYSTEMD USE_ZSTD HAVE_LIBSELINUX HAVE_UUID_E2FS; do
      grep "^#define $macro 1$" src/include/pg_config.h
    done

    # pg_config and installed PGXS must advertise a compiler that executes on
    # the target, never the Linux-hosted cross wrapper.
    sed -i '/#include "common\/config_info.h"/a\
    #undef VAL_CC\
    #define VAL_CC "${llvm}/bin/clang"' \
      src/common/config_info.c
  '';

  installScript = ''
    export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
    ${buildPackages.gnumake}/bin/make install-world
    test -f "$out/share/doc/html/index.html"
    test -f "$out/share/man/man1/postgres.1"
    test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"

    # PGXS runs on the target. Replace only generated tool metadata; configure
    # and link already consumed the real target libraries.
    find "$out/lib/pgxs" -type f -exec sed -i \
      -e 's|${buildPackages.perl}|${perl}|g' \
      -e 's|${buildPackages.python3}|${python3}|g' \
      -e 's|${buildPackages.llvm}|${llvm}|g' \
      -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
      -e "s|$PWD/.aos-native-tools/perl|${perl}/bin/perl|g" \
      -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
      -e "s|^CPP = .*|CPP = ${llvm}/bin/clang -E|" \
      -e "s|^CC = .*|CC = ${llvm}/bin/clang|" \
      -e "s|^CXX = .*|CXX = ${llvm}/bin/clang++|" \
      -e "s|^AR = .*|AR = ${llvm}/bin/llvm-ar|" \
      -e "s|^LLVM_BINPATH = .*|LLVM_BINPATH = ${llvm}/bin|" \
      -e "s|^CLANG = .*|CLANG = ${llvm}/bin/clang -idirafter ${glibc.dev}/include|" \
      -e "s|^PERL[[:space:]]*= .*|PERL = '${perl}/bin/perl'|" \
      -e "s|^PYTHON[[:space:]]*= .*|PYTHON = ${python3}/bin/python3|" \
      -e "s|^BISON = .*|BISON = ${bison}/bin/bison|" \
      -e "s|^FLEX = .*|FLEX = ${flex}/bin/flex|" \
      -e "s|^MSGFMT  = .*|MSGFMT  = ${gettext}/bin/msgfmt|" \
      -e "s|^MSGMERGE = .*|MSGMERGE = ${gettext}/bin/msgmerge|" \
      -e "s|^PKG_CONFIG[[:space:]]*= .*|PKG_CONFIG = ${pkg-config}/bin/pkg-config|" \
      -e "s|^TAR[[:space:]]*= .*|TAR = ${tar}/bin/tar|" \
      -e "s|^TCLSH[[:space:]]*= .*|TCLSH = ${tcl}/bin/tclsh9.0|" \
      -e "s|^XGETTEXT = .*|XGETTEXT = ${gettext}/bin/xgettext|" \
      -e "s|^install_bin = .*|install_bin = ${coreutils}/bin/install -c|" \
      -e "s|^MKDIR_P = .*|MKDIR_P = ${coreutils}/bin/mkdir -p|" \
      -e "s|^STRIP[[:space:]]*= .*|STRIP = ${llvm}/bin/llvm-strip|" \
      -e "s|^STRIP_STATIC_LIB = .*|STRIP_STATIC_LIB = ${llvm}/bin/llvm-strip --strip-unneeded|" \
      -e "s|^STRIP_SHARED_LIB = .*|STRIP_SHARED_LIB = ${llvm}/bin/llvm-strip --strip-unneeded|" \
      -e "s|^XMLLINT[[:space:]]*= .*|XMLLINT = ${libxml2}/bin/xmllint|" \
      -e "s|^XSLTPROC[[:space:]]*= .*|XSLTPROC = ${libxslt}/bin/xsltproc|" \
      -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
      -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
      {} +

    for build_path in \
      ${buildPackages.llvm} \
      ${buildPackages.perl} \
      ${buildPackages.python3} \
      ${buildPackages.tcl}; do
      if grep -R -F "$build_path" "$out/lib/pgxs" >/dev/null; then
        echo "PGXS retained build-side tool path: $build_path" >&2
        exit 1
      fi
    done
    if grep -R -F '.aos-native-tools' "$out/lib/pgxs" >/dev/null \
      || grep -R -F "$CC" "$out/lib/pgxs" >/dev/null \
      || grep -R -F "$CXX" "$out/lib/pgxs" >/dev/null; then
      echo "PGXS retained a Linux-hosted cross-build wrapper" >&2
      exit 1
    fi

    pgxs_global="$out/lib/pgxs/src/Makefile.global"
    grep -F "CC = ${llvm}/bin/clang" "$pgxs_global"
    grep -F "PERL = '${perl}/bin/perl'" "$pgxs_global"
    grep -F "PYTHON = ${python3}/bin/python3" "$pgxs_global"
    grep -F "TCLSH = ${tcl}/bin/tclsh9.0" "$pgxs_global"
    grep -F "LLVM_BINPATH = ${llvm}/bin" "$pgxs_global"
  '';
}
