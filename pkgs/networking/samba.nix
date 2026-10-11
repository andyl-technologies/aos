##! samba — SMB file, print, identity, and directory services
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  python3,
  python3-cffi,
  python3-cryptography,
  python3-dnspython,
  python3-markdown,
  python3-pycparser,
  perl,
  perl-parse-yapp,
  flex,
  bison,
  libxslt,
  docbook-xml,
  docbook-xml-4_2,
  docbook-xsl,
  bash,
  bind,
  coreutils,
  patch,
  acl,
  attr,
  avahi-core,
  cups-full,
  dbus,
  gpgme,
  gnutls,
  glusterfs-client,
  icu,
  jansson,
  libarchive,
  libcap,
  libtasn1,
  libtirpc,
  liburing,
  libxcrypt,
  linux-pam,
  lmdb,
  ncurses,
  openldap,
  openssl,
  popt,
  readline,
  rpcsvc-proto,
  zlib,
  lib,
  stdenv,
  buildPackages,
  smbdOnly ? false,
}: let
  version = "4.24.7";

  src = fetchurl {
    urls = [
      "https://download.samba.org/pub/samba/stable/samba-${version}.tar.gz"
    ];
    hash = "sha256-Rbd0ekdFLv8rIVmkTMY+tDaQ0zn9EGkIjgI6AV/tBsc=";
  };

  # Waf, pidl, and the documentation rules run during the build. Select their
  # interpreters and data from the build package set so a cross build never
  # executes target binaries; natively these are the host packages.
  buildPython3 = buildPackages.python3;
  buildPerl = buildPackages.perl;
  buildPerlParseYapp = buildPackages.perl-parse-yapp;

  # Waf cannot run configure probes for a foreign host. Each supported cross
  # host carries a reviewed answers file for those probes and the ELF machine
  # number that the installed programs must carry.
  crossTargets = {
    aarch64-linux = {
      answers = ./_samba-cross/aarch64-linux.answers;
      elfMachine = "183";
    };
  };
  crossTarget =
    crossTargets.${stdenv.hostPlatform.system}
    or (throw "samba: no reviewed Waf cross answers for ${stdenv.hostPlatform.system}");
  heimdalBuildTools = buildPackages.callPackage ./_samba-cross/heimdal-build-tools.nix {
    inherit src version;
  };

  # Waf rejects Autoconf's --build/--host pair. Cross builds use Waf's own
  # cross mode, which answers every target run-time probe from the reviewed
  # file and fails configure when Waf asks a question the file lacks.
  configureModeFlags =
    if stdenv.isCross
    then "--cross-compile --cross-answers=cross-answers.txt"
    else "$configureFlags";
  crossPreparePhase = {
    name = "cross-prepare";
    script = ''
      # Waf appends unanswered questions to the answers file it reads.
      cp ${crossTarget.answers} cross-answers.txt
      chmod u+w cross-answers.txt

      # Waf's cross-answers mode replays each answer through an FHS shell.
      sed -i "s|'/bin/sh', '-c'|'${buildPackages.bash}/bin/bash', '-c'|" \
        buildtools/wafsamba/samba_cross.py
      grep -Fq "'${buildPackages.bash}/bin/bash', '-c'" buildtools/wafsamba/samba_cross.py

      # The embedded Heimdal generators would otherwise be compiled for the
      # target and executed during the build. Select build-platform generators
      # from the same source through Waf's system-generator switches.
      cat >> third_party/heimdal_build/wscript_configure <<'EOF'

      conf.env.ASN1_COMPILE = '${heimdalBuildTools}/bin/asn1_compile'
      conf.define('USING_SYSTEM_ASN1_COMPILE', 1)
      conf.env.COMPILE_ET = '${heimdalBuildTools}/bin/compile_et'
      conf.define('USING_SYSTEM_COMPILE_ET', 1)
      EOF
    '';
  };

  # Native builds ask the installed server for its compiled-in layout. A cross
  # build cannot execute it, so require target ELF objects and the same
  # compiled-in layout strings instead.
  smbdOnlyIdentityChecks =
    if stdenv.isCross
    then ''
      for file in "$out/sbin/smbd" $(find "$out/lib" -type f -name '*.so*'); do
        magic=$(od -An -t x1 -N 4 "$file" | tr -d ' ')
        machine=$(od -An -t u2 -j 18 -N 2 "$file" | tr -d ' ')
        if [ "$magic" != 7f454c46 ] || [ "$machine" != ${crossTarget.elfMachine} ]; then
          echo "$file is not an ELF object for ${stdenv.hostPlatform.system}" >&2
          exit 1
        fi
      done
      grep -rqaF "$out/bin" "$out/sbin/smbd" "$out/lib"
      grep -rqaF "$out/sbin" "$out/sbin/smbd" "$out/lib"
      grep -rqaF "$out/share" "$out/sbin/smbd" "$out/lib"
    ''
    else ''
      "$out/sbin/smbd" --version | grep -F "Version ${version}"
      "$out/sbin/smbd" -b | grep -F "BINDIR: $out/bin"
      "$out/sbin/smbd" -b | grep -F "SBINDIR: $out/sbin"
      "$out/sbin/smbd" -b | grep -F "DATADIR: $out/share"
    '';

  pythonSitePackages = "lib/python3.14/site-packages";
  pythonPath =
    if smbdOnly
    then ""
    else "${python3-cryptography}/${pythonSitePackages}:${python3-cffi}/${pythonSitePackages}:${python3-pycparser}/${pythonSitePackages}:${python3-dnspython}/${pythonSitePackages}:${python3-markdown}/${pythonSitePackages}";
  installedPythonPath = "${builtins.placeholder "out"}/${pythonSitePackages}:${pythonPath}";
  nsupdateCommand =
    if smbdOnly
    then "nsupdate"
    else "${bind.dnsutils}/bin/nsupdate";
  xmlCatalogFiles = "${buildPackages.docbook-xml-4_2}/share/xml/docbook/schema/dtd/4.2/catalog.xml ${buildPackages.docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml";

  # Cross preparation runs between unpack and configure. Native builds keep
  # their phase list unchanged.
  withCrossPreparation = args:
    if stdenv.isCross
    then args // {phases = lib.addPhaseAfter args.phases "unpack" crossPreparePhase;}
    else args;
in
  mkDerivation (withCrossPreparation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          # Only the narrow server carries reviewed ARM64 cross answers; the
          # full AD/DC suite still needs target Python cross configuration.
          cpu = ["x86_64"] ++ lib.optional smbdOnly "aarch64";
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname =
      if smbdOnly
      then "samba-smbd"
      else "samba";
    inherit version src;

    buildDeps =
      [
        gnumake
        pkg-config
        gettext
        python3
        perl
        perl-parse-yapp
        flex
        bison
        libxslt
        docbook-xml
        docbook-xml-4_2
        docbook-xsl
        bash
        libtasn1
      ]
      ++ (
        if smbdOnly
        then []
        else [
          python3-cffi
          python3-cryptography
          python3-dnspython
          python3-markdown
          python3-pycparser
        ]
      );
    runtimeDeps =
      [
        acl
        attr
        bash
        gnutls
        libcap
        libtasn1
        libtirpc
        liburing
        libxcrypt
        lmdb
        ncurses
        popt
        readline
        rpcsvc-proto
        zlib
      ]
      ++ (
        if smbdOnly
        then []
        else [
          avahi-core
          bind.dnsutils
          cups-full
          dbus
          gpgme
          glusterfs-client
          icu
          jansson
          libarchive
          linux-pam
          openldap
          openssl
          python3
          coreutils
          patch
        ]
      );
    propagatedDeps = [];

    # The full command suite uses these Python modules through the wrapper in
    # $out. Preserve those exact references without adding Python packages to
    # the native linker's global runtime dependency set.
    nukeRefsKeep =
      if smbdOnly
      then []
      else [
        python3-cffi
        python3-cryptography
        python3-dnspython
        python3-markdown
        python3-pycparser
      ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd samba-${version}

          # Generated build helpers are executed in the hermetic sandbox and
          # installed Python scripts run from the immutable package closure.
          # Point both groups at AOS interpreters instead of FHS paths.
          find . -type f \( -name '*.py' -o -name 'waf' \) | while read file; do
            if head -n 1 "$file" | grep -Eq '^#! */usr/bin/(env +)?python'; then
              sed -i "1s|^#!.*|#!${buildPython3}/bin/python3|" "$file"
            fi
          done
          find . -type f \( -name '*.pl' -o -name 'pidl' \) | while read file; do
            if head -n 1 "$file" | grep -Eq '^#! */usr/bin/(env +)?perl'; then
              sed -i "1s|^#!.*|#!${buildPerl}/bin/perl|" "$file"
            fi
          done

          # These call sites execute configured hooks or helper commands. The
          # remaining /bin/sh strings describe account data or test fixtures.
          for file in \
            source3/lib/smbrun.c \
            source3/rpc_server/samr/srv_samr_chgpasswd.c \
            source4/nbt_server/wins/wins_hook.c \
            source4/dsdb/common/util.c \
            python/samba/gp/gp_scripts_ext.py \
            python/samba/gp/vgp_startup_scripts_ext.py \
            third_party/heimdal/lib/roken/getuserinfo.c
          do
            sed -i 's|/bin/sh|${bash}/bin/bash|g' "$file"
          done

          # Avoid Python's implicit FHS shell while preserving policy-script
          # parameter expansion through the declared AOS bash interpreter.
          sed -i \
            "s|shell=True).wait()|shell=True, executable='${bash}/bin/bash').wait()|" \
            python/samba/gp/vgp_startup_scripts_ext.py

          # This command is already argument-free, so it needs no shell.
          sed -i \
            "s|subprocess.Popen(\['named -V'\], shell=True,|subprocess.Popen(['named', '-V'],|" \
            python/samba/provision/sambadns.py

          # The full suite resolves the packaged DNS updater directly. The
          # narrow build retains only a PATH-resolved inactive default, which
          # avoids adding BIND to QEMU's closure. Keep the optional xdot viewer
          # selectable through PATH or SAMBA_TOOL_XDOT_PATH.
          grep -rl '/usr/bin/nsupdate' . | while read file; do
            sed -i 's|/usr/bin/nsupdate|${nsupdateCommand}|g' "$file"
          done
          grep -rl '/usr/bin/xdot' . | while read file; do
            sed -i 's|/usr/bin/xdot|xdot|g' "$file"
          done

          # The generated smb.conf manual exceeds libxslt's default template
          # recursion limit. Keep the complete manpage build and raise the
          # processor limit for every Waf documentation rule.
          sed -i 's|''${XSLTPROC} |''${XSLTPROC} --maxdepth 10000 |g' \
            buildtools/wafsamba/wafsamba.py
        '';
      }
      {
        name = "configure";
        script = ''
          export PERL5LIB="${buildPerlParseYapp}/lib/perl5''${PERL5LIB:+:$PERL5LIB}"
          export PYTHONPATH="${pythonPath}''${PYTHONPATH:+:$PYTHONPATH}"
          export XML_CATALOG_FILES="${xmlCatalogFiles}"

          "$CONFIG_SHELL" ./configure \
            ${configureModeFlags} \
            --prefix="$out" \
            --bindir="$out/bin" \
            --sbindir="$out/sbin" \
            --libdir="$out/lib" \
            --libexecdir="$out/libexec" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --with-configdir=/etc/samba \
            --with-privatedir=/var/lib/samba/private \
            --with-bind-dns-dir=/var/lib/samba/bind-dns \
            --with-lockdir=/run/lock/samba \
            --with-piddir=/run/samba \
            --with-statedir=/var/lib/samba \
            --with-cachedir=/var/cache/samba \
            --with-logfilebase=/var/log/samba \
            --with-sockets-dir=/run/samba \
            --with-privileged-socket-dir=/run/samba \
            ${
            if smbdOnly
            then ''
              --without-ad-dc \
              --disable-python \
              --without-winbind \
              --without-ads \
              --without-ldap \
              --without-json \
              --disable-cups \
              --disable-iprint \
              --disable-avahi \
              --disable-glusterfs \
              --disable-wsp \
              --disable-spotlight \
              --without-libarchive \
              --without-pam \
              --without-regedit \
              --without-cluster-support \
              --with-smb1-server \
              --with-acl-support \
              --with-quotas \
              --with-sendfile-support \
              --with-shared-modules='!DEFAULT' \
              --enable-fhs
            ''
            else "--enable-fhs"
          }
        '';
      }
      {
        name = "build";
        script = ''
          export PERL5LIB="${buildPerlParseYapp}/lib/perl5''${PERL5LIB:+:$PERL5LIB}"
          export PYTHONPATH="${pythonPath}''${PYTHONPATH:+:$PYTHONPATH}"
          export XML_CATALOG_FILES="${xmlCatalogFiles}"
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          export PERL5LIB="${buildPerlParseYapp}/lib/perl5''${PERL5LIB:+:$PERL5LIB}"
          export PYTHONPATH="${pythonPath}''${PYTHONPATH:+:$PYTHONPATH}"
          make install DESTDIR="$out"

          # Waf combines DESTDIR with the immutable program prefix while
          # placing runtime templates under /etc and /var. Flatten only the
          # doubly-prefixed program tree back into the package output.
          if [ -d "$out$out" ]; then
            cp -a "$out$out"/. "$out"/
            rm -rf "$out/nix"
          fi

          ${
            if smbdOnly
            then
              ''
                # QEMU needs only the file server entry point. This separately
                # configured build has no AD/DC, Python, winbind, discovery,
                # printing, Gluster, or administration contract to preserve.
                rm -rf "$out/bin" "$out/include" "$out/share/man"
                rm -rf "$out/lib/pkgconfig" "$out/${pythonSitePackages}"
                find "$out/sbin" -mindepth 1 -maxdepth 1 ! -name smbd -delete
                mkdir -p "$out/bin" "$out/share/samba/codepages"

                test -x "$out/sbin/smbd"
                test "$(find "$out/sbin" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1
                test -d "$out/bin"
                test -d "$out/share/samba"
                test -d "$out/share/samba/codepages"
              ''
              + smbdOnlyIdentityChecks
              + ''
                ! find "$out" -path '*/python*' | grep .
              ''
            else ''
              # Keep the complete service suite at the paths compiled into
              # Samba. The AD/DC supervisor executes both native helpers and
              # Python service scripts through these exact directories.
              for directory in bin sbin lib libexec; do
                test -d "$out/$directory"
              done

              test -x "$out/sbin/smbd"
              "$out/sbin/smbd" --version | grep -F "Version ${version}"
              "$out/sbin/smbd" -b | grep -F "BINDIR: $out/bin"
              "$out/sbin/smbd" -b | grep -F "SBINDIR: $out/sbin"
              test -f "$out/lib/samba/vfs/glusterfs.so"
              test -f "$out/lib/samba/vfs/glusterfs_fuse.so"
              test -x "$out/sbin/samba"
              test -x "$out/sbin/winbindd"
              test -x "$out/sbin/nmbd"
              test -x "$out/bin/smbclient"
              test -x "$out/sbin/samba_kcc"
              test -x "$out/sbin/samba_dnsupdate"
              test -x "$out/sbin/samba-gpupdate"
              test -x "$out/sbin/samba_spnupdate"

              mkdir -p "$out/libexec/samba"
              cat > "$out/libexec/samba/python3" <<'EOF'
              #!${bash}/bin/bash
              export PATH="${coreutils}/bin:${patch}/bin:${lmdb}/bin:''${PATH:-}"
              export PYTHONPATH="${installedPythonPath}''${PYTHONPATH:+:$PYTHONPATH}"
              exec ${python3}/bin/python3 "$@"
              EOF
              chmod 0755 "$out/libexec/samba/python3"
            ''
          }

          # This installed private library depends on another private Samba
          # library, but Waf gives it only the public lib directory RUNPATH.
          # Preserve standalone loader correctness for tools that use it.
          patchelf --add-rpath "$out/lib/samba" \
            "$out/lib/samba/libsmbpasswdparser-private-samba.so"

          # Rewrite every installed script, including non-executable examples
          # and completions. Native binaries have no shebang and pass through.
          find "$out" -type f | while read file; do
            if [ "$(head -c 2 "$file")" != '#!' ]; then
              continue
            fi

            firstLine=$(head -n 1 "$file")
            case "$firstLine" in
              '#!'${python3}'/bin/python3'*)
                [ "$file" = "$out/libexec/samba/python3" ] || \
                  sed -i '1s|.*|#!${builtins.placeholder "out"}/libexec/samba/python3|' "$file"
                ;;
              '#!/bin/sh'*|'#!/bin/bash'*|'#!/usr/bin/env sh'*|'#!/usr/bin/env bash'*)
                sed -i '1s|.*|#!${bash}/bin/bash|' "$file"
                ;;
              '#!/usr/bin/perl'*|'#!/usr/bin/env perl'*)
                sed -i '1s|.*|#!${perl}/bin/perl|' "$file"
                ;;
              '#!/usr/bin/python'*|'#!/usr/bin/env python'*)
                sed -i '1s|.*|#!${builtins.placeholder "out"}/libexec/samba/python3|' "$file"
                ;;
            esac
          done

          ${
            if smbdOnly
            then ""
            else ''
              head -n 1 "$out/bin/smbtar" | grep -Fx '#!${bash}/bin/bash'
              sed -i \
                '2i export PATH="${coreutils}/bin:${patch}/bin:${lmdb}/bin:''${PATH:-}"' \
                "$out/bin/smbtar"
              head -n 1 "$out/bin/samba-log-parser" \
                | grep -Fx '#!${builtins.placeholder "out"}/libexec/samba/python3'
            ''
          }

          # Active FHS interpreter paths cannot remain in shipped programs or
          # libraries. Heimdal's account-shell default and Samba's installed
          # test fixtures are data contracts rather than command execution.
          for root in "$out"; do
            for directory in bin sbin lib libexec; do
              [ -d "$root/$directory" ] || continue
              find "$root/$directory" -type f | while read file; do
                if ! grep -aEq '(^|[^[:alnum:]_./-])(/bin/(sh|bash)|/usr/bin/env[[:space:]]+(sh|bash|python[^[:space:]]*|perl))' "$file"; then
                  continue
                fi

                relativePath=''${file#"$root/"}
                case "$relativePath" in
                  lib/python*/site-packages/samba/netcmd/user/add_unix_attrs.py|lib/python*/site-packages/samba/tests/*)
                    continue
                    ;;
                esac

                echo "forbidden FHS interpreter path in $file" >&2
                exit 1
              done
            done
          done

          ${
            if smbdOnly
            then ""
            else ''
              "$out/bin/samba-tool" --help > /dev/null
              "$out/bin/samba-tool" domain provision --help > /dev/null
            ''
          }
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
      ...
    }:
      if smbdOnly
      then {
        version = testing.mkToolCheck {
          pname = "tool-samba-smbd";
          tool = self;
          command = "smbd --version";
        };

        runtime = testing.mkVMTest {
          name = "service-samba-smbd-runtime";
          rootfsDeps = [self pkgs.samba pkgs.iproute2];
          testScript = ''
            ${pkgs.iproute2}/sbin/ip link set lo up

            mkdir -p \
              /tmp/smbd/cache \
              /tmp/smbd/lock \
              /tmp/smbd/private \
              /tmp/smbd/run \
              /tmp/smbd/run/ncalrpc \
              /tmp/smbd/share \
              /tmp/smbd/state
            cat > /tmp/smbd/smb.conf <<'EOF'
            [global]
              server role = standalone server
              interfaces = 127.0.0.1
              bind interfaces only = yes
              smb ports = 1445
              private dir = /tmp/smbd/private
              state directory = /tmp/smbd/state
              cache directory = /tmp/smbd/cache
              lock directory = /tmp/smbd/lock
              pid directory = /tmp/smbd/run
              ncalrpc dir = /tmp/smbd/run/ncalrpc
              log file = /tmp/smbd/log.%m
              map to guest = Bad User

            [share]
              path = /tmp/smbd/share
              read only = no
              guest ok = yes
            EOF

            chmod 0777 /tmp/smbd/share
            ${self}/sbin/smbd --foreground --no-process-group \
              --log-basename=/tmp/smbd \
              --configfile=/tmp/smbd/smb.conf &
            smbdPid=$!
            trap 'kill -KILL "$smbdPid" 2>/dev/null || true' EXIT

            attempt=0
            until ${pkgs.samba}/bin/smbclient //127.0.0.1/share \
              -p 1445 -N -c 'ls'; do
              kill -0 "$smbdPid"
              attempt=$((attempt + 1))
              if [ "$attempt" -ge 20 ]; then
                cat /tmp/smbd/log.* >&2
                exit 1
              fi
              sleep 1
            done

            printf '%s\n' 'narrow smbd share access' > /tmp/upload.txt
            ${pkgs.samba}/bin/smbclient //127.0.0.1/share -p 1445 -N \
              -c 'put /tmp/upload.txt uploaded.txt'
            read -r uploadedContent < /tmp/smbd/share/uploaded.txt
            test "$uploadedContent" = 'narrow smbd share access'

            trap - EXIT
            kill -KILL "$smbdPid"
            wait "$smbdPid" || true
          '';
        };
      }
      else {
        smbd = testing.mkToolCheck {
          pname = "tool-samba-smbd";
          tool = self;
          command = "smbd --version";
        };

        samba-tool = testing.mkToolCheck {
          pname = "tool-samba-tool";
          tool = self;
          command = "samba-tool --help && samba-tool domain provision --help && samba-tool computer create --help";
        };

        pkg-config = testing.mkVMTest {
          name = "build-samba-pkg-config";
          rootfsDeps = [self pkgs.pkg-config];
          testScript = ''
            export PKG_CONFIG_PATH="${self}/lib/pkgconfig"

            cat > /tmp/smbclient-check.c <<'EOF'
            #include <libsmbclient.h>

            int main(void) {
                return smbc_version() == 0;
            }
            EOF

            gcc -o /tmp/smbclient-check /tmp/smbclient-check.c \
              $(pkg-config --cflags --libs smbclient)
            /tmp/smbclient-check
          '';
        };

        ad-dc-lifecycle = testing.mkVMTest {
          name = "service-samba-ad-dc-lifecycle";
          rootfsDeps = [self pkgs.iproute2];
          memory = 512;
          testScript = ''
            ${pkgs.iproute2}/sbin/ip link set lo up

            env -i PATH=/no/such/path ${self}/bin/samba-tool domain provision \
              --targetdir=/tmp/domain \
              --realm=EXAMPLE.TEST \
              --domain=EXAMPLE \
              --server-role=dc \
              --dns-backend=SAMBA_INTERNAL \
              --host-name=aosdc \
              --host-ip=127.0.0.1 \
              --users=root \
              --adminpass='Aos-Samba-Test-Password-1!'

            test -f /tmp/domain/etc/smb.conf
            test -f /tmp/domain/private/sam.ldb

            env -i PATH=/no/such/path ${self}/bin/samba-tool visualize ntdsconn \
              --URL=/tmp/domain/private/sam.ldb \
              > /tmp/domain/replication-graph.txt
            test -s /tmp/domain/replication-graph.txt

            read_oom_kills() {
              while read -r key value _; do
                if [ "$key" = oom_kill ]; then
                  printf '%s\n' "$value"
                  return 0
                fi
              done < /proc/vmstat

              return 1
            }

            oomKillsBefore=$(read_oom_kills)
            set +e
            ${coreutils}/bin/timeout --signal=KILL 8 \
              env -i PATH=/no/such/path ${self}/sbin/samba -i -M single \
              --configfile=/tmp/domain/etc/smb.conf \
              --option='interfaces=127.0.0.1' \
              --option='bind interfaces only=yes' \
              > /tmp/domain/startup.log 2>&1
            status=$?
            set -e
            oomKillsAfter=$(read_oom_kills)

            if [ "$status" -ne 137 ] || [ "$oomKillsAfter" -ne "$oomKillsBefore" ]; then
              cat /tmp/domain/startup.log >&2
              exit 1
            fi
          '';
        };
      };

    meta = {
      description =
        if smbdOnly
        then "Standalone SMB file server helper for QEMU user networking"
        else "SMB file, print, identity, and directory services";
      homepage = "https://www.samba.org/";
      license = "GPL-3.0-or-later";
      mainProgram = "smbd";
    };
  })
