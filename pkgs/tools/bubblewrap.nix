##! Bubblewrap — unprivileged Linux process isolation.
{
  mkDerivation,
  lib,
  fetchurl,
  buildPackages,
  stdenv,
  libcap,
  libselinux,
}: let
  version = "0.12.0";
in
  mkDerivation {
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
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "bubblewrap";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The signed Bubblewrap package closure.";
        operation = "Start a user and mount namespace containing only that closure.";
        expected = "The nested Bubblewrap executable starts from the private root filesystem.";
        artifacts = [];
        files."probe.py" = ''
          import json
          import os

          bubblewrap = "@out@/bin/bwrap"
          closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
          arguments = [
              bubblewrap,
              "--unshare-user",
              "--tmpfs", "/",
              "--dir", "/nix",
              "--dir", "/nix/store",
          ]
          for store_path in closure:
              arguments.extend(("--ro-bind", store_path, store_path))

          arguments.extend(("--chdir", "/", "--", bubblewrap, "--version"))
          os.execv(bubblewrap, arguments)
        '';
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "bubblewrap ${version}\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A bind source that does not exist in the probe work directory.";
        operation = "Attempt to create a read-only bind mount from the missing source.";
        expected = "Bubblewrap rejects the absent source before starting the child.";
        artifacts = [];
        files = {};
        steps = [
          {
            argv = [
              "@out@/bin/bwrap"
              "--unshare-user"
              "--ro-bind"
              "missing"
              "/missing"
              "--"
              "@out@/bin/bwrap"
              "--version"
            ];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "bwrap: Can't find source path missing: No such file or directory\n";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/containers/bubblewrap/releases/download/v${version}/bubblewrap-${version}.tar.xz"];
      hash = "051kgb4s6vrr5qld6fxsag59ybgqz489jj27qykvnfiy6q3x0q4p";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.inetutils buildPackages.python-seccomp buildPackages.strace buildPackages.util-linux buildPackages.libcap buildPackages.pkg-config buildPackages.bash buildPackages.libxslt buildPackages.docbook-xsl buildPackages.docbook-xml];
    runtimeDeps = [libcap libselinux];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd bubblewrap-${version}
            # The build sandbox supplies a writable TMPDIR, not a host /var/tmp.
            sed -i 's|mktemp -d /var/tmp/tap-test.XXXXXX|mktemp -d "$TMPDIR/tap-test.XXXXXX"|' tests/libtest.sh
            # Preserve the recursive-root mount test with an AOS-only /usr fixture.
            sed -i '/cd "''${tempdir}"/a\mkdir -p "$tempdir/usr"' tests/libtest.sh
            sed -i 's|--ro-bind /usr /usr|--ro-bind $tempdir/usr /usr|g' tests/libtest.sh
            sed -i \
              -e 's|/bin/sh|${buildPackages.bash}/bin/bash|g' \
              -e 's|/usr/bin/env|${buildPackages.coreutils}/bin/env|g' \
              tests/test-run.sh
            # statfs writes its complete Linux ABI structure, not just the first
            # two fields inspected by this upstream Python test helper.
            ${buildPackages.python3}/bin/python3 - <<'PYTHON'
            from pathlib import Path
            path = Path("tests/test-sandbox.py")
            source = path.read_text()
            old = "_fields_ = [('f_type', ctypes.c_long), ('f_bsize', ctypes.c_long)]"
            new = """_fields_ = [
                        ('f_type', ctypes.c_long), ('f_bsize', ctypes.c_long),
                        ('f_blocks', ctypes.c_ulong), ('f_bfree', ctypes.c_ulong),
                        ('f_bavail', ctypes.c_ulong), ('f_files', ctypes.c_ulong),
                        ('f_ffree', ctypes.c_ulong), ('f_fsid', ctypes.c_int * 2),
                        ('f_namelen', ctypes.c_long), ('f_frsize', ctypes.c_long),
                        ('f_flags', ctypes.c_long), ('f_spare', ctypes.c_long * 4),
                    ]"""
            assert old in source
            path.write_text(source.replace(old, new))
            PYTHON
          '';
        }
        {
          name = "configure";
          script = ''
            export XML_CATALOG_FILES="${buildPackages.docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Dselinux=enabled -Dman=enabled \
              -Dbash_completion_dir="$out/share/bash-completion/completions" \
              -Dzsh_completion_dir="$out/share/zsh/site-functions"
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              # The namespace and overlay TAP suite can exceed Meson's 30-second
              # default while other hermetic packages build concurrently.
              PYTHONPATH=${buildPackages.python-seccomp}/lib/python3.14/site-packages:${buildPackages.meson}/lib/python3/site-packages \
                ${buildPackages.python3}/bin/python3 -m mesonbuild.mesonmain test -C build --print-errorlogs --verbose --timeout-multiplier 4
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/bubblewrap"
            cp COPYING "$out/share/licenses/bubblewrap/"
          '';
        }
      ];

    meta = {
      description = "Unprivileged Linux namespace sandbox utility";
      homepage = "https://github.com/containers/bubblewrap";
      license = "LGPL-2.0-or-later";
    };
  }
