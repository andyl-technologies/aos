##! util-linux — Miscellaneous system utilities
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  ncurses,
  libselinux,
  libxcrypt,
  audit,
  readline,
  libutempter,
  libcap-ng,
  gettext,
  python3,
  cython,
  linux-pam,
  sqlite,
  bash,
}: let
  # 2.42.1 is the first stable release including
  # mount --beneath (commit cbf05f69 by Karel Zak, 2025-08-11; in-tree
  # at sys-utils/mount.c:562,720,989 and
  # libmount/src/hook_mount.c:547-548). Required by the apm-side
  # stage-2 /etc swap (spec v12 §7.1 Phase B).
  version = "2.42.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "util-linux";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <uuid/uuid.h>\n\nint main(void) {\n    const char expected[] = \"12345678-1234-5678-9234-567812345678\";\n    char output[37];\n    uuid_t value;\n\n    if (uuid_parse(expected, value) != 0) {\n        return 2;\n    }\n    uuid_unparse_lower(value, output);\n    if (strcmp(output, expected) != 0) {\n        return 2;\n    }\n    return puts(\"util-linux api passed\") == EOF;\n}\n";
        };
        "input" = "A canonical UUID string.";
        "operation" = "Parse and format the identifier through libuuid's public API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luuid"
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
              "exact" = "util-linux api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <uuid/uuid.h>\n\nint main(void) {\n    uuid_t value;\n    if (uuid_parse(\"12345678-1234-5678-9234-56781234567z\", value) == 0) {\n        return 2;\n    }\n    fputs(\"util-linux rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A UUID string containing a non-hexadecimal digit.";
        "operation" = "Parse the malformed identifier through uuid_parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luuid"
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
              "exact" = "util-linux rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    # Mounting filesystems does not require the optional Python bindings.
    # Keep those bindings available without retaining Python in boot images.
    outputs = ["out" "python"];

    src = fetchurl {
      urls = [
        "https://cdn.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-${version}.tar.xz"
      ];
      hash = "sha256-Zqx8DnJSeOsrA54xBPLJERk0HZQbQbrHooXGlflAvVc=";
    };

    buildDeps = [
      gnumake
      pkg-config
      gettext
      python3
      cython
    ];
    runtimeDeps = [
      zlib
      ncurses
      libselinux
      # sulogin calls crypt(3) to compare root's shadow hash with the
      # entered password; util-linux's configure fails with "required
      # crypt function not available" if libxcrypt (or glibc's bundled
      # libcrypt) isn't on the link line.
      libxcrypt
      audit
      readline
      libutempter
      libcap-ng
      gettext
      python3
      linux-pam
      sqlite
      bash
    ];
    propagatedDeps = [libselinux];

    abilities = ./_util-linux-getty;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd util-linux-${version}
          # Fix shebangs: /bin/bash doesn't exist in Nix sandbox
          for f in tools/all_syscalls tools/all_errnos tools/config-gen tools/git-tp-sync tools/*.sh; do
            if [ -f "$f" ]; then
              sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
            fi
          done

          # The 2.42.3 tarball omitted the common fallback definitions from
          # this new caller. Upstream now includes fileutils.h here as well.
          test "$(grep -c '^#include "all-io.h"' libmount/src/hook_idmap.c)" -eq 1
          sed -i '/^#include "all-io.h"/a #include "fileutils.h"' libmount/src/hook_idmap.c
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared \
            --with-python=3 \
            --without-systemd \
            --without-ncurses \
            --with-ncursesw \
            --with-readline \
            --without-slang \
            --with-utempter \
            --without-btrfs \
            --with-selinux \
            --with-audit \
            --without-udev \
            --without-cryptsetup \
            --without-econf \
            --enable-libblkid \
            --enable-libmount \
            --enable-libfdisk \
            --enable-libuuid \
            --enable-libsmartcols \
            --enable-fsck \
            --enable-mount \
            --enable-losetup \
            --enable-blkid \
            --enable-lsblk \
            --enable-nsenter \
            --enable-unshare \
            --disable-makeinstall-chown \
            --disable-makeinstall-setuid
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

          mkdir -p "$out/libexec"
          cat > "$out/libexec/aos-autologin-shell" <<EOF
          #!${bash}/bin/bash
          export USER=root
          export LOGNAME=root
          export HOME=/root
          export SHELL=${bash}/bin/bash
          cd /root 2>/dev/null || true
          exec ${bash}/bin/bash -l
          EOF
          chmod 0555 "$out/libexec/aos-autologin-shell"

          cat > "$out/libexec/aos-autologin-getty" <<EOF
          #!${bash}/bin/bash
          exec "$out/sbin/agetty" \
            --autologin root \
            --login-program="$out/libexec/aos-autologin-shell" \
            "\$@"
          EOF
          chmod 0555 "$out/libexec/aos-autologin-getty"

          mkdir -p "$python/lib"
          for bindings in "$out"/lib/python*; do
            test -d "$bindings"
            mv "$bindings" "$python/lib/"
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-util-linux";
        tool = self;
        command = "mount --version && su --version && lastlog2 --version && wall --version";
      };

      mount = testing.mkLinkCheck {
        pname = "link-libmount";
        library = self;
        libs = ["-lmount"];
        testSource = ''
          #include <libmount/libmount.h>

          int main(void) {
              struct libmnt_context *context = mnt_new_context();
              if (context == NULL) return 1;
              mnt_free_context(context);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "util-linux — miscellaneous system utilities for Linux";
      homepage = "https://github.com/util-linux/util-linux";
      license = "GPL-2.0-or-later";
    };
  }
