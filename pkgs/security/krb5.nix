##! MIT Kerberos — GSSAPI authentication and Kerberos network services
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  pkg-config,
  perl,
  openssl,
  bash,
  stdenv,
  buildPackages,
  coreutils,
  writeShellScriptBin,
}: let
  version = "1.22.2";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  bootstrapCmdsRevision = "c71d2d72f48995baaea76148f61002e5299841de";
  bootstrapCmdsSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/bootstrap_cmds/archive/${bootstrapCmdsRevision}.tar.gz"
    ];
    hash = "sha256-SmxCzFs5b2jIQIU5WaKxnDoQDyOybC3EhbRBMTdEvAs=";
  };
  xnuRevision = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea";
  xnuSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/xnu/archive/${xnuRevision}.tar.gz"
    ];
    hash = "sha256-B2MUbStUWbBw2AKqupUmzq1/sNVdDVG6AGmBgDAVCxU=";
  };

  # The Darwin KCM backend is generated from Mach Interface Generator defs.
  # Build Apple's generator for Linux and let it preprocess the defs with the
  # target compiler; target Mach-O executables never run on the build host.
  nativeMig =
    if !isDarwinCross
    then null
    else
      buildPackages.mkDerivation {
        pname = "darwin-mig";
        version = "2026-08-25";
        src = bootstrapCmdsSrc;

        buildDeps = [
          buildPackages.flex
          buildPackages.bison
        ];
        runtimeDeps = [
          buildPackages.bash
          buildPackages.coreutils
          buildPackages.sed
        ];
        propagatedDeps = [];

        phases = [
          {
            name = "unpack";
            script = ''
              tar xf $src
              tar xf ${xnuSrc}
              cd bootstrap_cmds-${bootstrapCmdsRevision}/migcom.tproj
            '';
          }
          {
            name = "build";
            script = ''
              cp -R ${buildPackages.darwin-sdk}/usr/include apple-headers
              chmod -R u+w apple-headers
              flex -o lexxer.c lexxer.l
              bison -y -d parser.y

              # migcom executes on Linux but consumes Darwin's public types.
              # Adapt only its private header copy to the native C runtime.
              sed -i 's/[[:space:]]*__asm("_".*$//' apple-headers/sys/cdefs.h
              sed -i \
                -e 's/__stdinp/stdin/g' \
                -e 's/__stdoutp/stdout/g' \
                -e 's/__stderrp/stderr/g' \
                apple-headers/_stdio.h
              sed -i 's/__error/__errno_location/g' apple-headers/sys/errno.h
              sed -i 's|#include <ctype.h>|#include "aos-mig-ctype.h"|' string.c
              cat > aos-mig-ctype.h <<'EOF'
              #define islower(c) ((unsigned int)((c) - 'a') <= (unsigned int)('z' - 'a'))
              #define toupper(c) (islower(c) ? ((c) - 'a' + 'A') : (c))
              EOF

              buildCC=${buildPackages.stdenv.cc}/bin/cc
              runBuildCC() (
                unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
                unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
                unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH
                unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
                exec "$buildCC" "$@"
              )
              compilerIncludes=$(runBuildCC -print-file-name=include)
              runBuildCC -nostdinc -I. -Iapple-headers -isystem "$compilerIncludes" \
                -Ulinux -U__linux -U__linux__ -D__APPLE__=1 -D__MACH__=1 \
                -D__private_extern__= -D__kernel_ptr_semantics= \
                -D__LITTLE_ENDIAN__=1 -DNDEBUG -DMIG_VERSION='"aos-mig"' \
                -o migcom \
                error.c global.c header.c lexxer.c mig.c y.tab.c \
                routine.c server.c statement.c string.c type.c user.c utils.c
            '';
          }
          {
            name = "install";
            script = ''
              mkdir -p \
                "$out/bin" \
                "$out/libexec" \
                "$out/share/man/man1" \
                "$out/share/mig/mach"
              cp migcom "$out/libexec/migcom"
              cp mig.sh "$out/libexec/mig-driver"
              cp -R ../../xnu-${xnuRevision}/osfmk/mach/. "$out/share/mig/mach/"
              chmod 0755 "$out/libexec/migcom" "$out/libexec/mig-driver"
              sed -i \
                -e '1c #!${buildPackages.bash}/bin/bash' \
                -e 's|`/usr/bin/arch`|`uname -m`|' \
                -e 's|/usr/bin/mktemp|${buildPackages.coreutils}/bin/mktemp|' \
                -e 's|/bin/rmdir|${buildPackages.coreutils}/bin/rmdir|' \
                "$out/libexec/mig-driver"

              cat > "$out/bin/mig" <<'EOF'
              #!${buildPackages.bash}/bin/bash
              set -e
              migcc="''${MIGCC:-''${CC:-cc}}"
              case "''${AOS_TARGET_ARCH:-}" in
                aarch64 | arm64) migarch=arm64 ;;
                x86_64) migarch=x86_64 ;;
                *)
                  case "$("$migcc" -dumpmachine)" in
                    aarch64-* | arm64-*) migarch=arm64 ;;
                    x86_64-*) migarch=x86_64 ;;
                    *) echo "mig: cannot determine target architecture" >&2; exit 1 ;;
                  esac
                  ;;
              esac
              export MIGCC="$migcc"
              export MIGCOM="@out@/libexec/migcom"
              exec "@out@/libexec/mig-driver" \
                -arch "$migarch" -I@out@/share/mig "$@"
              EOF
              sed -i "s|@out@|$out|g" "$out/bin/mig"
              chmod 0755 "$out/bin/mig"
              cp mig.1 migcom.1 "$out/share/man/man1/"
            '';
          }
        ];
      };
  control = writeShellScriptBin "krb5-kdc-control" ''
    set -euo pipefail

    case "''${1:-}" in
      prepare)
        [[ $# -eq 4 ]] || {
          echo "usage: krb5-kdc-control prepare REALM STATE-DIRECTORY PASSWORD-FILE" >&2
          exit 64
        }
        realm=$2
        state_directory=$3
        password=$4

        if [[ ! -f "$state_directory/principal" ]]; then
          [[ -r "$password" ]] || {
            echo "krb5 KDC database initialization requires master-password" >&2
            exit 1
          }
          kdb5_util create -s -r "$realm" -P "$(<"$password")"
        fi
        ;;
      run-kdc)
        [[ $# -eq 2 ]] || {
          echo "usage: krb5-kdc-control run-kdc RUNTIME-DIRECTORY" >&2
          exit 64
        }
        exec krb5kdc -n -P "$2/krb5kdc.pid"
        ;;
      run-administration)
        [[ $# -eq 2 ]] || {
          echo "usage: krb5-kdc-control run-administration RUNTIME-DIRECTORY" >&2
          exit 64
        }
        exec kadmind -nofork -P "$2/kadmind.pid"
        ;;
      *)
        echo "usage: krb5-kdc-control {prepare|run-kdc|run-administration} ..." >&2
        exit 64
        ;;
    esac
  '';
in
  mkDerivation {
    pname = "krb5";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The canonical principal text round-trips unchanged.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"krb5 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"krb5 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdlib.h>\n#include <string.h>\n#include <krb5.h>\nint main(void) {\n    krb5_context context = NULL; krb5_principal principal = NULL; char *text = NULL;\n    if (krb5_init_context(&context) != 0) return 2;\n    if (krb5_parse_name(context, \"user/admin@EXAMPLE.TEST\", &principal) != 0) return 3;\n    if (krb5_unparse_name(context, principal, &text) != 0) return 4;\n    int ok = strcmp(text, \"user/admin@EXAMPLE.TEST\") == 0;\n    krb5_free_unparsed_name(context, text); krb5_free_principal(context, principal); krb5_free_context(context);\n    return ok ? pass() : 5;\n}\n\n";
        };
        "input" = "The Kerberos principal user/admin in the EXAMPLE.TEST realm.";
        "operation" = "Parse and unparse the principal through the krb5 context API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lkrb5"
              "-lk5crypto"
              "-lcom_err"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "krb5 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The Kerberos parser returns a nonzero parse error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"krb5 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"krb5 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <krb5.h>\nint main(void) {\n    krb5_context context = NULL; krb5_principal principal = NULL;\n    if (krb5_init_context(&context) != 0) return 2;\n    int status = krb5_parse_name(context, \"user\\\\\", &principal);\n    if (principal != NULL) krb5_free_principal(context, principal);\n    krb5_free_context(context);\n    if (status == 0) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A Kerberos principal with an empty realm.";
        "operation" = "Parse the malformed principal through krb5_parse_name.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lkrb5"
              "-lk5crypto"
              "-lcom_err"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "krb5 rejected invalid input\n";
            };
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
        "https://kerberos.org/dist/krb5/1.22/krb5-${version}.tar.gz"
      ];
      hash = "sha256-MkP/vI6k1Kwi3cfdKh3FTFeHTEBki2D/lwCXY1VOrxM=";
    };

    # Upstream's release-branch compatibility fix for OpenSSL 4, where ASN.1
    # strings are opaque and several X.509 accessors return const pointers.
    patches = [./krb5-openssl-4.patch];

    buildDeps =
      [gnumake bison pkg-config perl]
      ++ (
        if isDarwinCross
        then [nativeMig]
        else []
      );
    runtimeDeps = [openssl bash coreutils control];
    propagatedDeps = [];

    abilities = ./_krb5-kdc/module.nix;

    phases = [
      {
        name = "unpack";
        script =
          if isDarwinCross
          then ''
            tar xf $src
            cd krb5-${version}/src

            # Apple's resolver keeps the legacy HEADER and C_IN aliases in
            # its compatibility header. MIT Kerberos still uses those aliases
            # when ns_initparse/res_nsearch are unavailable.
            sed -i \
              '/#include <arpa\/nameser.h>/a #include <arpa/nameser_compat.h>' \
              lib/krb5/os/dnsglue.h

            # Apple's open SDK exposes the public libresolv API, not Libinfo's
            # private dns_open family. Keep DNS realm/KDC discovery by using
            # MIT Kerberos's portable res_init/res_search implementation.
            sed -i \
              's/#if defined(__APPLE__)/#if defined(__APPLE__) \&\& defined(KRB5_USE_PRIVATE_DNS_API)/' \
              lib/krb5/os/dnsglue.c

            # The proprietary Kerberos framework supplies Apple's CCAPI cache.
            # Use the upstream KCM cache backend generated by native MIG instead
            # while retaining the complete Mach RPC cache implementation.
            sed -i \
              -e 's/macos_defccname=API:/macos_defccname=KCM:/' \
              -e 's/MACOS_FRAMEWORK="-framework Kerberos"/MACOS_FRAMEWORK=/' \
              configure
          ''
          else ''
            tar xf $src
            cd krb5-${version}/src
          '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
            # MIT Kerberos insists on executing a constructor/destructor
            # probe. Clang's attributes are supported by Mach-O, but target
            # executables cannot run on the Linux builder, so seed the result.
            export krb5_cv_attr_constructor_destructor=yes,yes
            # Darwin's libc implements POSIX numbered printf conversions.
            # Configure otherwise insists on executing the target probe.
            export ac_cv_printf_positional=yes

            YACC='bison -y' ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --with-crypto-impl=openssl \
              --with-tls-impl=openssl
          ''
          else ''
            YACC='bison -y' ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --with-crypto-impl=openssl \
              --with-tls-impl=openssl
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          (
            if stdenv.hostPlatform.isDarwin
            then ''
              make install
              for script in compile_et k5srvutil krb5-send-pr; do
                [ -f "$out/bin/$script" ] || continue
                sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/$script"
              done
            ''
            else ''
              make install
            ''
          )
          + ''
            ln -s ${control}/bin/krb5-kdc-control "$out/bin/krb5-kdc-control"
          '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
      mkSystem,
      ...
    }: let
      qualifiedResultOf = request: output: {
        _type = "aos-request-output-reference";
        inherit request output;
      };
      evaluate = krb5Config:
        mkSystem {
          systemName = "krb5-package-check";
          modules = [
            {
              environment.systemPackages = [self];
              krb5Kdc = krb5Config;
            }
          ];
        };
      enabled = evaluate {
        enable = true;
        realm = "EXAMPLE.TEST";
        kdcServers = ["kdc.example.test"];
        adminServer = "kdc.example.test";
        masterPassword.name = "krb5-master";
      };
      withAdministration = evaluate {
        enable = true;
        enableAdminServer = true;
        realm = "EXAMPLE.TEST";
        masterPassword.name = "krb5-master";
      };
      disabled = evaluate {};
      missingPassword = evaluate {enable = true;};
      detachedAdministration = evaluate {enableAdminServer = true;};
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      ownedValues = lib.filterAttrs (name: _: lib.hasPrefix "krb5:" name);
      abilities = enabled.config.aos.abilities;
      administrationAbilities = withAdministration.config.aos.abilities;
      disabledAbilities = disabled.config.aos.abilities;
      requests = abilities.requests;
      administrationRequests = administrationAbilities.requests;
      clientSource = requests."krb5:client-configuration".parameters.source;
      kdcSource = requests."krb5:kdc-profile".parameters.source;
      kdcLiteralText = lib.concatStringsSep "" (builtins.map
        (fragment:
          if fragment.kind == "literal"
          then fragment.text
          else "")
        kdcSource.fragments);
      passwordSource = requests."krb5:master-password-source".parameters;
      passwordDelivery = requests."krb5:master-password".parameters;
      kdcDependencies = requests."krb5:kdc-dependencies".parameters;
      administrationDependencies =
        administrationRequests."krb5:administration-dependencies".parameters;
      kdcIngress = requests."krb5:kdc-ingress".parameters;
      administrationIngress =
        administrationRequests."krb5:administration-ingress".parameters;
      kdcLinuxIsolation = requests."krb5:kdc-linux_isolation".parameters;
      contractHolds =
        assertionsHold enabled
        && assertionsHold withAdministration
        && !assertionsHold missingPassword
        && !assertionsHold detachedAdministration
        && ownedValues disabledAbilities.instances == {}
        && ownedValues disabledAbilities.requests == {}
        && builtins.elem "krb5:named-credential-resolution"
        (builtins.attrNames disabledAbilities.requirementTemplates)
        && builtins.elem "krb5:credential-delivery"
        (builtins.attrNames disabledAbilities.requirementTemplates)
        && builtins.hasAttr "krb5:initialize-lifecycle" requests
        && builtins.hasAttr "krb5:kdc-lifecycle" requests
        && !(builtins.hasAttr "krb5:administration-lifecycle" requests)
        && builtins.hasAttr "krb5:administration-lifecycle" administrationRequests
        && passwordSource
        == {
          name = "krb5-master";
          scope = "system";
        }
        && passwordDelivery.source
        == qualifiedResultOf "krb5:master-password-source" "credential-resource"
        && passwordDelivery.name == "master-password"
        && clientSource.kind == "inline-text"
        && lib.hasInfix "default_realm = EXAMPLE.TEST" clientSource.content
        && lib.hasInfix "kdc = kdc.example.test:88" clientSource.content
        && kdcSource.kind == "interpolated-text"
        && lib.hasInfix "max_life = 10h" kdcLiteralText
        && !(lib.hasInfix "/var/lib/" (builtins.toJSON kdcSource))
        && !(lib.hasInfix "/var/log/" (builtins.toJSON kdcSource))
        && !(lib.hasInfix "krb5-master" (builtins.toJSON kdcSource))
        && passwordDelivery.source.request == "krb5:master-password-source"
        && kdcDependencies.after
        == [(qualifiedResultOf "krb5:initialize-lifecycle" "service-resource")]
        && kdcDependencies.requires
        == [(qualifiedResultOf "krb5:initialize-lifecycle" "service-resource")]
        && kdcDependencies.prerequisites
        == [(qualifiedResultOf "krb5:kdc-ingress" "readiness-resource")]
        && administrationDependencies.after
        == [(qualifiedResultOf "krb5:initialize-lifecycle" "service-resource")]
        && administrationDependencies.requires
        == [(qualifiedResultOf "krb5:initialize-lifecycle" "service-resource")]
        && administrationDependencies.prerequisites
        == [(qualifiedResultOf "krb5:administration-ingress" "readiness-resource")]
        && kdcIngress.endpoints
        == [
          {
            transport = "tcp";
            port = 88;
          }
          {
            transport = "udp";
            port = 88;
          }
        ]
        && administrationIngress.endpoints
        == [
          {
            transport = "tcp";
            port = 749;
          }
        ]
        && kdcLinuxIsolation.ambient_capabilities == ["CAP_NET_BIND_SERVICE"]
        && !(requests."krb5:service-group".parameters ? requested_id)
        && !(requests."krb5:service-principal".parameters ? requested_id);
      krb5Conf = builtins.toFile "krb5-lifecycle.conf" ''
        [libdefaults]
          default_realm = EXAMPLE.TEST
          dns_lookup_kdc = false
          dns_lookup_realm = false
          rdns = false

        [realms]
          EXAMPLE.TEST = {
            kdc = 127.0.0.1
            admin_server = 127.0.0.1
          }
      '';
      kdcConf = builtins.toFile "kdc-lifecycle.conf" ''
        [kdcdefaults]
          kdc_ports = 88
          kdc_tcp_ports = 88

        [realms]
          EXAMPLE.TEST = {
            database_name = /var/lib/aos-pkg-krb5-kdc/principal
            key_stash_file = /var/lib/aos-pkg-krb5-kdc/.k5.EXAMPLE.TEST
            acl_file = /etc/aos/packages/krb5-kdc/kadm5.acl
            max_life = 10h
            max_renewable_life = 7d
          }

        [logging]
          kdc = FILE:/var/log/krb5-kdc/kdc.log
          admin_server = FILE:/var/log/krb5-kdc/kadmind.log
      '';
      acl = builtins.toFile "kadm5-lifecycle.acl" "*/admin@EXAMPLE.TEST *\n";
    in {
      cli = testing.mkToolCheck {
        pname = "tool-krb5-config";
        tool = self;
        command = "krb5-config --version";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libkrb5.so" "libgssapi_krb5.so"];
      };

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "krb5-kdc-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the Kerberos native ability checks failed";

      config-lifecycle = testing.mkVMTest {
        name = "security-krb5-kdc-config-lifecycle";
        rootfsDeps = [self krb5Conf kdcConf acl pkgs.grep pkgs.iproute2];
        testScript = ''
          ${pkgs.iproute2}/sbin/ip link set lo up
          mkdir -p \
            /etc/aos/packages/krb5-kdc \
            /run/aos-pkg-krb5-kdc \
            /var/lib/aos-pkg-krb5-kdc \
            /var/log/krb5-kdc
          cp ${krb5Conf} /etc/aos/packages/krb5-kdc/krb5.conf
          cp ${kdcConf} /etc/aos/packages/krb5-kdc/kdc.conf
          cp ${acl} /etc/aos/packages/krb5-kdc/kadm5.acl
          export KRB5_CONFIG=/etc/aos/packages/krb5-kdc/krb5.conf
          export KRB5_KDC_PROFILE=/etc/aos/packages/krb5-kdc/kdc.conf

          printf '%s\n' aos-master-password > /tmp/krb5-master-password
          ${self}/bin/krb5-kdc-control prepare \
            EXAMPLE.TEST \
            /var/lib/aos-pkg-krb5-kdc \
            /tmp/krb5-master-password
          ${self}/sbin/kadmin.local -q 'addprinc -pw aos-client-password client@EXAMPLE.TEST'

          start_kdc() {
            ${self}/bin/krb5-kdc-control run-kdc \
              /run/aos-pkg-krb5-kdc \
              >/tmp/krb5kdc.log 2>&1 &
            kdc_pid=$!
            sleep 1
            if ! kill -0 "$kdc_pid" 2>/dev/null; then
              cat /tmp/krb5kdc.log >&2
              exit 1
            fi
          }

          acquire_ticket() {
            printf '%s\n' aos-client-password \
              | ${self}/bin/kinit client@EXAMPLE.TEST
            ${self}/bin/klist | ${pkgs.grep}/bin/grep -F 'client@EXAMPLE.TEST'
            ${self}/bin/kdestroy
          }

          start_kdc
          acquire_ticket
          kill "$kdc_pid"
          wait "$kdc_pid" || true
          start_kdc
          acquire_ticket
          kill "$kdc_pid"
          wait "$kdc_pid" || true
          echo 'Kerberos KDC typed config and real-binary lifecycle: PASS'
        '';
      };
    };

    meta = {
      description = "MIT Kerberos and GSSAPI implementation";
      homepage = "https://web.mit.edu/kerberos/";
      license = "MIT";
    };
  }
