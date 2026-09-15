##! ZFS — OpenZFS filesystem and volume manager
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  util-linux,
  openssl,
  zlib,
  libtirpc,
  bash,
  perl,
  python3,
  kmod,
  elfutils,
  dwarves,
  kernel ? null,
}: let
  version = "2.4.0";
in
  mkDerivation {
    pname = "zfs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Zgenhostid writes the identifier as the four native-order bytes 78 56 34 12.";
        "files" = {};
        "input" = "The fixed host identifier 0x12345678 and a work-directory output path.";
        "operation" = "Encode the host identifier with zgenhostid without loading a kernel module.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\noutput = pathlib.Path(\"hostid\")\nresult = subprocess.run([\"@out@/sbin/zgenhostid\", \"-f\", \"-o\", str(output), \"12345678\"], capture_output=True)\nassert result.returncode == 0 and output.read_bytes() == bytes.fromhex(\"78563412\")\nprint(\"zfs operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "zfs operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Zgenhostid rejects the malformed identifier and creates no output.";
        "files" = {};
        "input" = "A host identifier containing non-hexadecimal characters.";
        "operation" = "Validate the identifier before writing the hostid file.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\noutput = pathlib.Path(\"invalid-hostid\")\nresult = subprocess.run([\"@out@/sbin/zgenhostid\", \"-o\", str(output), \"not-hex\"], capture_output=True, text=True)\nassert result.returncode != 0 and not output.exists()\n\nsys.stderr.write(\"zfs rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "zfs rejected invalid input\n";
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
        "https://github.com/openzfs/zfs/releases/download/zfs-${version}/zfs-${version}.tar.gz"
      ];
      hash = "sha256-e98T3gpx2VVUwOPkfV6PUHhsMNT0tjt8WTsdEa91ye4=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if kernel == null
        then []
        else [bash perl python3 kmod elfutils dwarves]
      );
    runtimeDeps = [
      util-linux
      openssl
      zlib
      libtirpc
    ];
    propagatedDeps = [];
    disallowedReferences = lib.optional (kernel != null) kernel.dev;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd zfs-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Kbuild invokes the exact kernel tree's objtool while compiling
          # feature probes. objtool links against libelf, which is a build
          # dependency of the kernel SDK rather than part of its output.
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          configure_args=(
            --prefix="$out"
            --sysconfdir="$out/etc"
            --with-config=${
            if kernel == null
            then "user"
            else "all"
          }
            --with-mounthelperdir="$out/sbin"
            --with-udevdir="$out/lib/udev"
            --with-systemdunitdir="$out/lib/systemd/system"
            --with-systemdpresetdir="$out/lib/systemd/system-preset"
            --enable-sysvinit=no
            --disable-static
          )
          ${
            if kernel == null
            then ""
            else ''
              configure_args+=(
                --with-linux=${kernel.dev}/lib/modules/${kernel.version}/build
                --with-linux-obj=${kernel.dev}/lib/modules/${kernel.version}/build
              )
            ''
          }
          if ! ./configure "''${configure_args[@]}"; then
            for probe_log in build/build.log*; do
              [ -f "$probe_log" ] || continue
              echo "OpenZFS kernel probe log: $probe_log" >&2
              cat "$probe_log" >&2
            done
            exit 1
          fi
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          ${
            if kernel == null
            then ""
            else ''
              export KCFLAGS="''${KCFLAGS:-} -ffile-prefix-map=${kernel.dev}=/build/kernel-sdk"
            ''
          }
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          # Override hardcoded paths that would install outside the store
          make install \
            ${
            if kernel == null
            then ""
            else ''INSTALL_MOD_PATH="$out"''
          } \
            ${
            if kernel == null
            then ""
            else ''INSTALL_MOD_STRIP=1''
          } \
            i_tdir=$out/share/initramfs-tools \
            initconfdir=$out/etc/default \
            dracutdir=$out/lib/dracut \
            bashcompletiondir=$out/share/bash-completion/completions

          # The upstream install target includes its full functional test
          # suite. It belongs in a dedicated test output, not on a production
          # host, and its compiled fixtures retain compiler paths.
          rm -rf "$out/share/zfs/zfs-tests"

          # zvol_id is installed below lib/udev rather than bin/libexec, so the
          # generic fixup pass does not recognize it as a runtime executable.
          # Remove its compile-time include paths explicitly.
          strip --strip-debug "$out/lib/udev/zvol_id"
        '';
      }
    ];

    meta = {
      description = "OpenZFS — advanced filesystem and volume manager";
      homepage = "https://openzfs.org";
      license = "CDDL-1.0";
    };

    passthru = {
      inherit kernel;
    };
  }
