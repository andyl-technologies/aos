##! PostgreSQL — Object-relational database server
{
  lib,
  mkDerivation,
  writeShellScriptBin,
  fetchurl,
  gnumake,
  bash,
  coreutils,
  pkg-config,
  bison,
  flex,
  tar,
  perl,
  python3,
  llvm,
  glibc,
  linux-headers,
  curl,
  docbook-xml,
  docbook-xsl,
  gettext,
  icu,
  krb5,
  libselinux,
  liburing,
  libxml2,
  libxslt,
  linux-pam,
  openpam,
  lz4,
  numactl,
  openldap,
  openssl,
  readline,
  systemd,
  tcl,
  tzdata,
  util-linux,
  zlib,
  zstd,
  stdenv,
  buildPackages,
  darwin-sdk,
}: let
  version = "18.6";
  isDarwin = stdenv.hostPlatform.isDarwin;
  isCross = stdenv.isCross;
  control = writeShellScriptBin "postgresql-control" ''
    set -euo pipefail

    program_dir="''${0%/*}"

    running() {
      "$program_dir/pg_ctl" status -D "$data_directory" >/dev/null 2>&1
    }

    case "''${1:-}" in
      prepare)
        state_directory=$2
        server_config=$3
        topology=$4
        superuser=$5
        initialization_credential=$6
        primary_host=$7
        primary_port=$8
        replication_user=$9
        replication_slot=''${10}
        data_directory="$state_directory/data"
        staging_directory="$state_directory/.data-initializing"

        if [[ -L "$data_directory" ]]; then
          echo "PostgreSQL data directory must not be a symbolic link" >&2
          exit 78
        fi

        if [[ ! -s "$data_directory/PG_VERSION" ]]; then
          if [[ -e "$data_directory" || -L "$data_directory" ]]; then
            if [[ -d "$data_directory" && ! -L "$data_directory" ]] \
              && [[ -z "$(ls -A "$data_directory")" ]]; then
              rmdir "$data_directory"
            else
              echo "PostgreSQL data directory exists without PG_VERSION; refusing to overwrite it" >&2
              exit 78
            fi
          fi

          # This exact service-owned sibling contains no accepted database
          # state. A prior interrupted attempt can be retried safely, while
          # the final data directory is never recursively removed.
          rm -rf "$staging_directory"
          mkdir -m 0700 "$staging_directory"

          if [[ "$topology" == standby ]]; then
            passfile=$initialization_credential
            if [[ ! -r "$passfile" ]]; then
              echo "PostgreSQL standby initialization requires replication-passfile" >&2
              exit 78
            fi
            slot_args=()
            if [[ -n "$replication_slot" ]]; then
              slot_args+=(--slot="$replication_slot")
            fi
            PGPASSFILE="$passfile" "$program_dir/pg_basebackup" \
              --pgdata="$staging_directory" \
              --host="$primary_host" \
              --port="$primary_port" \
              --username="$replication_user" \
              --wal-method=stream \
              --checkpoint=fast \
              --no-password \
              "''${slot_args[@]}"
          else
            password_file=$initialization_credential
            if [[ ! -r "$password_file" ]]; then
              echo "PostgreSQL initialization requires bootstrap-superuser-password" >&2
              exit 78
            fi
            "$program_dir/initdb" \
              --pgdata="$staging_directory" \
              --username="$superuser" \
              --pwfile="$password_file" \
              --auth-local=peer \
              --auth-host=scram-sha-256 \
              --encoding=UTF8 \
              --locale=C
          fi

          if [[ ! -s "$staging_directory/PG_VERSION" ]]; then
            echo "PostgreSQL initialization completed without PG_VERSION" >&2
            exit 78
          fi
          mv "$staging_directory" "$data_directory"
        fi

        if [[ "$topology" == standby ]]; then
          touch "$data_directory/standby.signal"
        else
          rm -f "$data_directory/standby.signal"
        fi

        # -C processes the complete postgresql.conf and rejects malformed or
        # unknown parameters without starting a second postmaster.
        "$program_dir/postgres" -D "$data_directory" -C port \
          -c config_file="$server_config" >/dev/null
        ;;
      run)
        state_directory=$2
        server_config=$3
        exec "$program_dir/postgres" -D "$state_directory/data" \
          -c config_file="$server_config"
        ;;
      reload)
        state_directory=$2
        server_config=$3
        data_directory="$state_directory/data"
        "$program_dir/postgres" -D "$data_directory" -C port \
          -c config_file="$server_config" >/dev/null
        "$program_dir/pg_ctl" reload -D "$data_directory"
        ;;
      stop)
        state_directory=$2
        data_directory="$state_directory/data"
        if running; then
          "$program_dir/pg_ctl" stop -D "$data_directory" -m fast -w
        fi
        ;;
      *)
        echo "usage: postgresql-control {prepare|run|reload|stop} ..." >&2
        exit 64
        ;;
    esac
  '';
  clangForBitcode = buildPackages.writeShellScriptBin "clang" ''
    exec ${buildPackages.llvm}/bin/clang \
      ${lib.optionalString isCross "--target=${stdenv.hostPlatform.config}"} \
      -isystem ${glibc.dev}/include \
      -isystem ${linux-headers}/include \
      "$@"
  '';
  llvmConfigForBitcode = buildPackages.writeShellScriptBin "llvm-config" ''
    ${buildPackages.llvm}/bin/llvm-config "$@" \
      | ${buildPackages.sed}/bin/sed 's|${buildPackages.llvm}|${llvm}|g'
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "postgresql";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "database/PG_VERSION";
            "text" = "18\n";
          }
        ];
        "expected" = "PostgreSQL creates a version 18 data directory.";
        "files" = {};
        "input" = "An empty directory for a UTF-8 PostgreSQL cluster using trust authentication.";
        "operation" = "Initialize the cluster locally through initdb without locale discovery.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/initdb"
              "--no-locale"
              "--encoding=UTF8"
              "--auth=trust"
              "-D"
              "@work@/primary/database"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "PostgreSQL rejects the authentication method with status 1.";
        "files" = {};
        "input" = "A cluster request naming an unsupported local authentication method.";
        "operation" = "Initialize the cluster through initdb with the invalid authentication method.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/initdb"
              "--no-locale"
              "--auth=qualification-invalid"
              "-D"
              "@work@/bad-input/database"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.postgresql.org/pub/source/v${version}/postgresql-${version}.tar.bz2"
      ];
      hash = "sha256-VVYQwk1T5DFtpbfT/CXCedloVtXg4j7jCMMoxfqIHZ8=";
    };

    buildDeps =
      if isDarwin
      then [
        docbook-xml
        docbook-xsl
      ]
      else [
        gnumake
        pkg-config
        bison
        flex
        perl
        python3
        llvm
        clangForBitcode
        tcl
        docbook-xml
        docbook-xsl
        gettext
        libxml2
        libxslt
        util-linux
      ];
    runtimeDeps =
      if isDarwin
      then [
        bison
        flex
        coreutils
        pkg-config
        tar
        curl
        gettext
        icu
        krb5
        libxml2
        libxslt
        openpam
        llvm
        lz4
        openldap
        openssl
        perl
        python3
        readline
        tcl
        tzdata
        zlib
        zstd
      ]
      else
        [
          curl
          icu
          krb5
          libselinux
          liburing
          libxml2
          libxslt
          linux-pam
          llvm
          lz4
          numactl
          openldap
          openssl
          perl
          python3
          readline
          systemd
          tcl
          tzdata
          util-linux
          zlib
          zstd
        ]
        ++ [bash coreutils control];
    propagatedDeps = [];

    abilities = ./_postgresql/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd postgresql-${version}
        '';
      }
      {
        name = "configure";
        script =
          if isDarwin
          then ''
            # Build drivers must execute on Linux without adding their native
            # headers, libraries, or pkg-config files to the target search
            # environment. Reference only their executables here; target
            # counterparts remain runtime dependencies for installed PGXS.
            export BISON=${buildPackages.bison}/bin/bison
            export FLEX=${buildPackages.flex}/bin/flex
            export MSGFMT=${buildPackages.gettext}/bin/msgfmt
            export MSGMERGE=${buildPackages.gettext}/bin/msgmerge
            export PKG_CONFIG=${buildPackages.pkg-config}/bin/pkg-config
            export XGETTEXT=${buildPackages.gettext}/bin/xgettext
            export XMLLINT=${buildPackages.libxml2}/bin/xmllint
            export XSLTPROC=${buildPackages.libxslt}/bin/xsltproc

            # PostgreSQL needs native LLVM utilities to generate bitcode, but
            # must compile and link against the Darwin LLVM headers and dylib.
            mkdir -p .aos-native-tools
            cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
            case "$1" in
              --bindir)
                printf '%s\n' '${buildPackages.llvm}/bin'
                ;;
              *)
                '${buildPackages.llvm}/bin/llvm-config' "$@" |
                  sed 's|${buildPackages.llvm}|${llvm}|g'
                ;;
            esac
            LLVM_CONFIG_WRAPPER
            chmod +x .aos-native-tools/llvm-config
            export LLVM_CONFIG=$PWD/.aos-native-tools/llvm-config
            export CLANG="${buildPackages.llvm}/bin/clang --target=${stdenv.hostPlatform.config} --sysroot=${stdenv.sdk}"
            export TCLSH=${buildPackages.tcl}/bin/tclsh9.0

            # Query the Darwin Perl configuration using the native interpreter.
            # Config.pm is pure Perl and the versions are identical across the
            # build and host package sets, so no target executable is run.
            # Net/Config.pm has the same basename and may sort before the
            # architecture configuration on x86_64. Select the latter
            # explicitly so configure sees useshrplib and libperl.dylib.
            target_perl_config=$(find ${perl.dev}/lib \
              -name Config.pm ! -path '*/Net/Config.pm' -print -quit)
            test -n "$target_perl_config"
            target_perl_archlib=$(dirname "$target_perl_config")
            target_perl_privlib=$(dirname "$target_perl_archlib")
            export PERL=${buildPackages.perl}/bin/perl
            export PERL5LIB="$target_perl_archlib:$target_perl_privlib"

            # Only PostgreSQL's small sysconfig queries need target Python
            # answers. The wrapper delegates every other operation to the
            # native interpreter used for source generation.
            cat > .aos-native-tools/python3 <<'PYTHON_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
            if [ "$1" = -c ]; then
              case "$2" in
                *"get_config_vars('LIBPL')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_var('INCLUDEPY')"*)
                  printf '%s\n' '-I${python3}/include/python3.14'
                  exit 0
                  ;;
                *"get_config_vars('LIBDIR')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_vars('LDLIBRARY')"*)
                  printf '%s\n' 'libpython3.14.dylib'
                  exit 0
                  ;;
                *"get_config_vars('LIBS','LIBC','LIBM','BASEMODLIBS')"*)
                  printf '\n'
                  exit 0
                  ;;
              esac
            fi
            exec '${buildPackages.python3}/bin/python3' "$@"
            PYTHON_CONFIG_WRAPPER
            chmod +x .aos-native-tools/python3
            export PYTHON=$PWD/.aos-native-tools/python3

            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-nls \
              --with-llvm \
              --with-icu \
              --with-tcl \
              --with-tclconfig=${tcl}/lib \
              --with-gssapi \
              --with-ldap \
              --with-system-tzdata=${tzdata}/share/zoneinfo \
              --with-perl \
              --with-python \
              --with-pam \
              --with-uuid=e2fs \
              --with-libcurl \
              --with-libxml \
              --with-libxslt \
              --with-lz4 \
              --with-zstd \
              --with-ssl=openssl

            # CONFIGURE_ARGS is compiled into pg_config and the server, and
            # the generated header is also installed for extensions. Keep the
            # native wrappers active in the build makefiles, but publish only
            # the corresponding Darwin-side tool paths in that metadata.
            sed -i \
              -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
              -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
              -e "s|CC=$CC|CC=${llvm}/bin/clang|g" \
              -e "s|CXX=$CXX|CXX=${llvm}/bin/clang++|g" \
              -e 's|${buildPackages.llvm}|${llvm}|g' \
              -e 's|${buildPackages.gettext}|${gettext}|g' \
              -e 's|${buildPackages.pkg-config}|${pkg-config}|g' \
              -e 's|${buildPackages.perl}|${perl}|g' \
              -e 's|${buildPackages.python3}|${python3}|g' \
              -e 's|${buildPackages.tcl}|${tcl}|g' \
              -e "s|${stdenv.sdk}|$out/share/darwin-sdk|g" \
              -e "s| 'PKG_CONFIG_PATH=[^']*'||g" \
              src/include/pg_config.h

            for macro in \
              ENABLE_GSS ENABLE_NLS USE_ICU USE_LDAP USE_LLVM USE_LIBCURL \
              USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM USE_ZSTD \
              HAVE_UUID_E2FS; do
              grep "^#define $macro 1$" src/include/pg_config.h
            done

            # pg_config and installed PGXS makefiles must name a compiler that
            # runs on Darwin, not the Linux-hosted cross wrapper used here.
            sed -i '/#include "common\/config_info.h"/a\
            #undef VAL_CC\
            #define VAL_CC "${llvm}/bin/clang"' \
              src/common/config_info.c
          ''
          else ''
            export LLVM_CONFIG=${
              if isCross
              then llvmConfigForBitcode
              else llvm
            }/bin/llvm-config
            # PostgreSQL invokes Clang directly for LLVM bitcode, so retain
            # the libc header path normally injected by the AOS GCC wrapper.
            export CLANG=${clangForBitcode}/bin/clang
            export TCLSH=${tcl}/bin/tclsh9.0
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ./configure \
              --prefix=$out \
              --enable-nls \
              --with-llvm \
              --with-icu \
              --with-tcl \
              --with-tclconfig=${tcl}/lib \
              --with-gssapi \
              --with-ldap \
              --with-liburing \
              --with-libnuma \
              --with-system-tzdata=${tzdata}/share/zoneinfo \
              --with-perl \
              --with-python \
              --with-pam \
              --with-selinux \
              --with-systemd \
              --with-uuid=e2fs \
              --with-libcurl \
              --with-libxml \
              --with-libxslt \
              --with-lz4 \
              --with-zstd \
              --with-ssl=openssl

            for macro in \
              ENABLE_GSS ENABLE_NLS HAVE_LIBNUMA USE_ICU USE_LDAP USE_LIBURING USE_LLVM \
              USE_LIBCURL USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM \
              USE_SYSTEMD USE_ZSTD HAVE_LIBSELINUX HAVE_UUID_E2FS; do
              grep "^#define $macro 1$" src/include/pg_config.h
            done
          '';
      }
      {
        name = "build";
        script =
          if isDarwin
          then ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ${buildPackages.gnumake}/bin/make -j$NIX_BUILD_CORES world
          ''
          else ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            make -j$NIX_BUILD_CORES world
          '';
      }
      {
        name = "install";
        script =
          (
            if isDarwin
            then ''
              export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
              ${buildPackages.gnumake}/bin/make install-world
              test -f "$out/share/doc/html/index.html"
              test -f "$out/share/man/man1/postgres.1"
              test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"

              # Installed PGXS can compile extensions with LLVM on Darwin, but
              # must not retain the Linux-hosted compiler SDK used by this cross
              # build. Publish the clean target SDK beside PostgreSQL and point
              # only installed metadata at that self-contained copy.
              mkdir -p "$out/share/darwin-sdk/share"
              cp -R \
                ${darwin-sdk}/SDKSettings.json \
                ${darwin-sdk}/System \
                ${darwin-sdk}/usr \
                "$out/share/darwin-sdk/"
              cp -R ${darwin-sdk}/share/licenses "$out/share/darwin-sdk/share/"

              # PGXS is target-side tooling. Retarget interpreter and LLVM
              # paths recorded while Linux-native generators built the tree.
              find "$out/lib/pgxs" -type f -exec sed -i \
                -e 's|${buildPackages.perl}|${perl}|g' \
                -e 's|${buildPackages.python3}|${python3}|g' \
                -e 's|${buildPackages.llvm}|${llvm}|g' \
                -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
                -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
                -e "s|${stdenv.sdk}|$out/share/darwin-sdk|g" \
                -e "s|$CC|${llvm}/bin/clang|g" \
                -e "s|^CXX = .*|CXX = ${llvm}/bin/clang++|" \
                -e "s|^AR = .*|AR = ${llvm}/bin/llvm-ar|" \
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
                -e "s|^STRIP_STATIC_LIB = .*|STRIP_STATIC_LIB = ${llvm}/bin/llvm-strip -S|" \
                -e "s|^STRIP_SHARED_LIB = .*|STRIP_SHARED_LIB = ${llvm}/bin/llvm-strip -S|" \
                -e "s|^XMLLINT[[:space:]]*= .*|XMLLINT = ${libxml2}/bin/xmllint|" \
                -e "s|^XSLTPROC[[:space:]]*= .*|XSLTPROC = ${libxslt}/bin/xsltproc|" \
                -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
                -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
                {} +
            ''
            else ''
              export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
              make install-world
              test -f "$out/share/doc/html/index.html"
              test -f "$out/share/man/man1/postgres.1"
              test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"
              sed -i \
                -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
                -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
                "$out/lib/pgxs/src/Makefile.global"
              ${
                lib.optionalString isCross ''
                  find "$out/lib/pgxs" -type f -exec sed -i \
                    -e 's|${clangForBitcode}/bin/clang|${llvm}/bin/clang|g' \
                    -e 's|${llvmConfigForBitcode}/bin/llvm-config|${llvm}/bin/llvm-config|g' \
                    {} +
                ''
              }
            ''
          )
          + ''
            ln -s ${control}/bin/postgresql-control "$out/bin/postgresql-control"
          '';
      }
    ];

    meta = {
      description = "PostgreSQL object-relational database server";
      homepage = "https://www.postgresql.org/";
      license = "PostgreSQL";
    };

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      requirements = self.abilities.requirementTemplates;
      requirementMethods = alias: requirements.${alias}.methods;
      contractHolds =
        builtins.deepSeq self.contract.value.option_declarations true
        && self.abilities.interfaces == {}
        && self.abilities.implementations == {}
        && builtins.elem "configuration-materialization" (builtins.attrNames requirements)
        && builtins.elem "service-lifecycle" (builtins.attrNames requirements)
        && requirementMethods "configuration-materialization" == ["materialize" "observe" "release"]
        && requirementMethods "credential-delivery" == ["deliver" "observe" "release"]
        && requirementMethods "network-readiness" == ["observe"]
        && requirementMethods "persistent-storage-allocation" == ["allocate" "observe" "release"]
        && requirementMethods "storage-allocation" == ["allocate" "observe" "release"]
        && requirementMethods "service-lifecycle" == ["observe" "reload" "restart" "start" "stop"];
    in {
      version = testing.mkToolCheck {
        pname = "storage-postgresql";
        tool = self;
        command = "postgres --version";
      };

      features = testing.mkVMTest {
        name = "storage-postgresql-features";
        rootfsDeps = [self];
        testScript = ''
          pg_config --configure > /tmp/postgresql-configure
          for flag in \
            --enable-nls --with-llvm --with-icu --with-tcl --with-tclconfig=${tcl}/lib \
            --with-gssapi --with-ldap --with-liburing --with-libnuma \
            --with-system-tzdata=${tzdata}/share/zoneinfo \
            --with-perl --with-python --with-pam \
            --with-selinux --with-systemd --with-uuid=e2fs --with-libcurl \
            --with-libxml --with-libxslt --with-lz4 --with-zstd \
            --with-ssl=openssl; do
            grep -- "$flag" /tmp/postgresql-configure
          done
          test -f ${self}/share/doc/html/index.html
          test -f ${self}/share/man/man1/postgres.1
          test -n "$(find ${self}/share/locale -name '*.mo' -print -quit)"
        '';
      };

      runtime-contract = import ./_postgresql-tests/lifecycle.nix {
        inherit testing self;
        inherit (pkgs) coreutils grep sed;
      };

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "storage-postgresql-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the PostgreSQL ability module contract checks failed";

      artifact-consumption = let
        architecture = stdenv.hostPlatform.constraints.cpu;
        loaderName =
          if architecture == "x86_64"
          then "ld-linux-x86-64.so.2"
          else "ld-linux-aarch64.so.1";
      in
        lib.mkArtifactConsumptionAudit {
          inherit pkgs;
          name = "postgresql-openssl-linkage";
          consumer = self;
          consumerPath = "/bin/postgres";
          provider = openssl;
          providerPath = "/lib/libssl.so.4";
          targetPlatform = {
            system = stdenv.hostPlatform.constraints.os;
            inherit architecture;
          };
          soname = "libssl.so.4";
          needed = [
            "libc.so.6"
            "libcrypto.so.4"
            "libgssapi_krb5.so.2"
            "libicui18n.so.78"
            "libicuuc.so.78"
            "libldap.so.2"
            "liblz4.so.1"
            "libm.so.6"
            "libnuma.so.1"
            "libpam.so.0"
            "libssl.so.4"
            "libsystemd.so.0"
            "liburing.so.2"
            "libxml2.so.16"
            "libz.so.1"
            "libzstd.so.1"
          ];
          searchPath = map (dependency: "${dependency}/lib") [
            glibc
            icu
            krb5
            liburing
            libxml2
            linux-pam
            lz4
            numactl
            openldap
            openssl
            systemd
            zlib
            zstd
          ];
          searchPathKind = "runpath";
          symbols = [
            {
              name = "SSL_CTX_new";
              version = "OPENSSL_4.0.0";
            }
          ];
          loader = "${glibc}/lib/${loaderName}";
          inspector = pkgs.buildPackages.aos;
        };
    };
  }
