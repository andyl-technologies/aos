##! Audit — Linux auditing framework
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  stdenv,
  linux-headers,
  libcap,
  bash,
}: let
  version = "4.2.1";
in
  mkDerivation {
    pname = "audit";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <libaudit.h>\n\nint main(void) {\n    int machine = audit_detect_machine();\n    int syscall = audit_name_to_syscall(\"read\", machine);\n    const char *name = audit_syscall_to_name(syscall, machine);\n    if (machine < 0 || syscall < 0 || name == NULL || strcmp(name, \"read\") != 0) {\n        return 2;\n    }\n    return puts(\"audit api passed\") == EOF;\n}\n";
        };
        "input" = "The portable audit syscall name read and the detected machine type.";
        "operation" = "Resolve the syscall name to a machine-specific number and back to its canonical name.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-laudit"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "audit api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <libaudit.h>\n\nint main(void) {\n    int machine = audit_detect_machine();\n    if (machine < 0 || audit_name_to_syscall(\"aos_no_such_syscall\", machine) != -1) {\n        return 2;\n    }\n    fputs(\"audit rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A syscall name absent from the Linux audit tables.";
        "operation" = "Resolve the unknown name with audit_name_to_syscall.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-laudit"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "audit rejected invalid input\n";
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
        "https://github.com/linux-audit/audit-userspace/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-QodtGV7i3tGeX3LXZkCW7uMUkoqjatNGcZulslgY/IQ=";
    };

    buildDeps = [gnumake autoconf automake libtool linux-headers];
    runtimeDeps = [libcap bash];
    propagatedDeps = [];

    abilities = ./_audit/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd audit-userspace-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # IPX support was removed from Linux kernel headers (6.x+).
          # Define the missing struct so auparse/interpret.c compiles.
          sed -i '1i\
          #ifndef _LINUX_IPX_H\
          #define _LINUX_IPX_H\
          #include <stdint.h>\
          struct sockaddr_ipx { short sipx_family; uint16_t sipx_port; uint32_t sipx_network; };\
          #endif' auparse/interpret.c

        '';
      }
      {
        name = "configure";
        script = ''
          libtoolize --force --copy
          autoreconf -fiv

          # auparse/Makefile.in and lib/Makefile.in both compile
          # gen_tables.c into `<dir>/gen_flagtabs_h-gen_tables.o` with
          # *different* `-DTABLE_H=` macros. Automake happens to write
          # both object files to the SAME path: `lib/gen_flagtabs_h-gen_tables.o`
          # (auparse/Makefile.in writes it at `../lib/...`). The second
          # compile stomps the first, so the `gen_flagtabs_h` binary that
          # eventually generates lib/flagtabs.h ends up linked against
          # auparse's flagtab.h (RHEL4 record flags: "follow", "directory",
          # "continue"…) instead of lib's (filter names: "task", "exit",
          # "user", "exclude", "filesystem"). The runtime effect is that
          # `audit_name_to_flag("exit")` returns -1, so `auditctl -a always,exit`
          # sends `rule->flags = -1 (0xFFFFFFFF)` on the netlink wire and
          # the kernel rejects every syscall rule with EINVAL.
          #
          # Fix: rename auparse's copy of that object file so it lands
          # inside auparse/ and doesn't collide with lib/'s copy.
          sed -i \
            -e 's|../lib/gen_flagtabs_h-gen_tables\.\$(OBJEXT)|gen_flagtabs_h-gen_tables.\$(OBJEXT)|g' \
            -e 's|../lib/gen_flagtabs_h-gen_tables\.o|gen_flagtabs_h-gen_tables.o|g' \
            -e 's|../lib/\$(DEPDIR)/gen_flagtabs_h-gen_tables|\$(DEPDIR)/gen_flagtabs_h-gen_tables|g' \
            auparse/Makefile.in

          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --sbindir=$out/sbin \
            --runstatedir=/run \
            --disable-zos-remote \
            --without-python \
            --without-python3 \
            --without-golang \
            ${
            if stdenv.hostPlatform.isAarch64
            then "--with-aarch64"
            else ""
          } \
            --enable-shared \
            --disable-static
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
        script = ''
          make install

          mkdir -p $out/libexec
          cat > $out/libexec/aos-audit-rules <<'EOF'
          #!${bash}/bin/bash
          set -u

          rules=$1
          failed=0
          loaded=0
          while IFS= read -r line; do
            [ -z "$line" ] && continue
            [ "''${line#\#}" != "$line" ] && continue
            error=$($out/sbin/auditctl $line 2>&1 >/dev/null) && status=0 || status=$?
            if [ "$status" -eq 0 ]; then
              loaded=$((loaded + 1))
            else
              failed=$((failed + 1))
              echo "audit-rules: rejected [$status]: $line -- $error"
            fi
          done < "$rules"
          echo "audit-rules: loaded $loaded rule(s), rejected $failed"
          EOF
          chmod 0755 $out/libexec/aos-audit-rules
        '';
      }
    ];

    meta = {
      description = "Linux Audit — userspace auditing framework";
      homepage = "https://people.redhat.com/sgrubb/audit/";
      license = "LGPL-2.1-or-later";
    };
  }
