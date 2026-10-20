##! D-Bus — Message bus system
{
  lib,
  service-management,
  mkDerivation,
  fetchurl,
  buildPackages,
  patchelf,
  meson,
  ninja,
  pkg-config,
  python3,
  expat,
  libselinux,
  audit,
  libcap-ng,
  systemd,
  stdenv,
}: let
  version = "1.16.2";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  darwinCpu =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86_64";
  buildPython =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  linuxRuntimeLibraryPath = builtins.concatStringsSep ":" (map (dependency: "${dependency}/lib") [expat libselinux audit libcap-ng systemd]);
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "dbus";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected result and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <dbus/dbus.h>\n\nint main(void) {\n    DBusMessage *message = dbus_message_new_method_call(\n        \"org.aos.Qualification\", \"/org/aos/Qualification\",\n        \"org.aos.Qualification\", \"Probe\");\n    if (message == NULL\n        || strcmp(dbus_message_get_path(message), \"/org/aos/Qualification\") != 0\n        || strcmp(dbus_message_get_member(message), \"Probe\") != 0) {\n        if (message != NULL) dbus_message_unref(message);\n        return 2;\n    }\n    dbus_message_unref(message);\n    return puts(\"dbus api passed\") == EOF;\n}\n";
        };
        "input" = "A valid bus name, object path, interface, and method name.";
        "operation" = "Construct a method-call message and read its routing metadata back.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include/dbus-1.0"
              "-I@out@/lib/dbus-1.0/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ldbus-1"
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
              "exact" = "dbus api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <dbus/dbus.h>\n\nint main(void) {\n    DBusError error;\n    dbus_error_init(&error);\n    dbus_bool_t valid = dbus_validate_path(\"org/aos/invalid\", &error);\n    if (valid || !dbus_error_is_set(&error)) {\n        dbus_error_free(&error);\n        return 2;\n    }\n    dbus_error_free(&error);\n    fputs(\"dbus rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An object path without the required leading slash.";
        "operation" = "Validate the malformed path with dbus_validate_path.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include/dbus-1.0"
              "-I@out@/lib/dbus-1.0/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ldbus-1"
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
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://dbus.freedesktop.org/releases/dbus/dbus-${version}.tar.xz"
      ];
      hash = "sha256-C6KhpLFq/nvOssB+nOmajCw1COXewpDbtkM4S9a+t+I=";
    };

    buildDeps =
      [meson ninja pkg-config python3]
      ++ lib.optionals isLinuxCross [patchelf];
    runtimeDeps =
      [expat]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [
          libselinux
          audit
          libcap-ng
          # libsystemd for sd_notify + unit file installation. Systemd
          # no longer depends on dbus at the pkg level (sd-bus replaces
          # libdbus), so this direction is cycle-free.
          systemd
        ]
      );
    # dbus-1.pc requires libsystemd, including when consumers only request
    # compiler flags. Keep that metadata dependency visible downstream.
    propagatedDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [systemd];

    module = ./_dbus;
    moduleDeps = [service-management];

    # dbus-daemon crash-loops on activation under -fstrict-flex-arrays=3
    # (its trailing-array message structs trip _FORTIFY_SOURCE at runtime).
    # Step down to level 1; fortify3 and the rest stay on.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dbus-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          for script in \
            meson_post_install.py \
            test/data/copy_data_for_tests.py \
            tools/build-timestamp.py; do
            sed -i "1s|^#!.*|#!${buildPython}/bin/python3|" "$script"
          done
        '';
      }
      {
        name = "configure";
        # Enable systemd so dbus installs its user service/socket units and
        # sockets.target.wants link for the packaged unit tree.
        # --sysconfdir=/etc so
        # baked-in config lookups go to /etc/dbus-1 on the running system,
        # not a read-only store path.
        script = ''
          export PYTHONPATH="${meson}/lib/python3/site-packages"
          ${lib.optionalString isDarwinCross ''
              # Without a cross file Meson executes its Mach-O compiler probe.
              cat > aos-darwin-cross.ini <<EOF
            [binaries]
            c = '$CC'
            cpp = '$CXX'
            pkg-config = 'pkg-config'

            [host_machine]
            system = 'darwin'
            cpu_family = '${darwinCpu}'
            cpu = '${darwinCpu}'
            endian = 'little'

            [properties]
            needs_exe_wrapper = true
            EOF
          ''}
          meson setup build \
            ${lib.optionalString isDarwinCross "--cross-file=$PWD/aos-darwin-cross.ini"} \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            -Dintrusive_tests=false \
            -Dmodular_tests=disabled \
            -Dinstalled_tests=false \
            -Ddoxygen_docs=disabled \
            -Dducktype_docs=disabled \
            -Dqt_help=disabled \
            -Dxml_docs=disabled \
            -Dsystemd_system_unitdir="$out/lib/systemd/system" \
            -Dsystemd_user_unitdir="$out/lib/systemd/user" \
            -Dsystemd=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Duser_session=true \
            -Dapparmor=disabled \
            -Dselinux=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Dlibaudit=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Dx11_autolaunch=disabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        # DESTDIR=$out redirects /etc and /var install paths under $out
        # (writable nix build dir) so the runtime paths stay as /etc/...
        # and /var/... per the --sysconfdir/--localstatedir above.
        script = ''
          DESTDIR=$out ninja -C build install
          # Flatten $out/$out/... concat from DESTDIR + --prefix.
          if [ -d "$out$out" ]; then
            cp -a $out$out/. $out/
            rm -rf $out/nix
          fi
          # Preserve upstream defaults for ordinary dbus-daemon --system users.
          # The native controller includes a separate base so local overrides
          # follow authenticated package policy in its generated configuration.
          sed -E \
            -e '/<includedir>(\/etc\/dbus-1\/)?system\.d<\/includedir>/d' \
            -e '/<include.*system-local\.conf<\/include>/d' \
            "$out/share/dbus-1/system.conf" \
            > "$out/share/dbus-1/aos-system-base.conf"

          ${lib.optionalString isLinuxCross ''
            # Meson's install step drops some cross-wrapper runtime paths.
            # Restore declared libraries before the normal unused-path shrink.
            find "$out" -type f | while read -r binary; do
              patchelf --print-needed "$binary" >/dev/null 2>&1 || continue
              patchelf --add-rpath "$out/lib:${linuxRuntimeLibraryPath}" "$binary"
            done
          ''}'';
      }
    ];

    checks = {
      self,
      pkgs,
      ...
    }: {
      native-base-configuration =
        pkgs.runCommand "dbus-native-base-configuration-check" {
          buildDeps = [pkgs.grep pkgs.sed pkgs.coreutils];
        } ''
          stock=${self}/share/dbus-1/system.conf
          native=${self}/share/dbus-1/aos-system-base.conf
          grep -F '<includedir>system.d</includedir>' "$stock"
          grep -F '<includedir>/etc/dbus-1/system.d</includedir>' "$stock"
          grep -F 'system-local.conf</include>' "$stock"
          if grep -E 'system\.d</includedir>|system-local\.conf</include>' "$native"; then
            echo "Native D-Bus base includes local overrides before package policy" >&2
            exit 1
          fi
          sed -E \
            -e '/<includedir>(\/etc\/dbus-1\/)?system\.d<\/includedir>/d' \
            -e '/<include.*system-local\.conf<\/include>/d' \
            "$stock" > expected
          cmp expected "$native"
          mkdir -p "$out"
          printf '%s\n' PASS > "$out/result"
        '';
    };

    meta = {
      description = "D-Bus — freedesktop.org message bus system";
      homepage = "https://www.freedesktop.org/wiki/Software/dbus/";
      license = "AFL-2.1";
    };
  }
