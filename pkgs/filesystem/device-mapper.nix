##! device-mapper — Device-mapper userspace library and tools
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libaio,
  util-linux,
}: let
  version = "2.03.28";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "device-mapper";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected result and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <libdevmapper.h>\n\nint main(void) {\n    struct dm_task *task = dm_task_create(DM_DEVICE_INFO);\n    if (task == NULL || !dm_task_set_name(task, \"aos-qualification\")) {\n        if (task != NULL) dm_task_destroy(task);\n        return 2;\n    }\n    dm_task_destroy(task);\n    return puts(\"device-mapper api passed\") == EOF;\n}\n";
        };
        "input" = "A syntactically valid device-mapper name.";
        "operation" = "Create an information task and assign the name without contacting the kernel.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ldevmapper"
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
              "exact" = "device-mapper api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <libdevmapper.h>\n\nint main(void) {\n    struct dm_task *task = dm_task_create(DM_DEVICE_INFO);\n    if (task == NULL) {\n        return 2;\n    }\n    int accepted = dm_task_set_name(task, \"invalid/name\");\n    dm_task_destroy(task);\n    if (accepted) {\n        return 3;\n    }\n    fputs(\"device-mapper rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A device-mapper name containing a slash.";
        "operation" = "Assign the invalid name to an information task.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ldevmapper"
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
        "https://sourceware.org/ftp/lvm2/LVM2.${version}.tgz"
        "https://mirrors.kernel.org/sourceware/lvm2/LVM2.${version}.tgz"
      ];
      hash = "sha256-uCK6/2ti3zY4LHF866mKJojrsxvyt2jz/6K21eJVckI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libaio
      util-linux
    ];
    propagatedDeps = [
      libaio
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd LVM2.${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-pkgconfig \
            --enable-cmdlib \
            --enable-udev_rules \
            --enable-dmeventd=none \
            --with-thin=none \
            --with-cache=none \
            --disable-selinux \
            --disable-readline \
            --disable-editline
        '';
      }
      {
        name = "build";
        script = ''
          make device-mapper -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install_device-mapper

          # Without libudev at build time, upstream generates an external
          # blkid rule using our own sbin directory. The helper belongs to
          # util-linux; adding systemd here would create a dependency cycle.
          sed -i "s|$out/sbin/blkid |${util-linux}/sbin/blkid |" \
            $out/lib/udev/rules.d/13-dm-disk.rules

          # systemd can observe the initial dm add event before activation and
          # persist SYSTEMD_READY=0. Since libdevmapper cannot depend on
          # systemd's libudev in the bootstrap graph, clear that conservative
          # state only after sysfs confirms that the mapping is unsuspended.
          cat > $out/lib/udev/rules.d/99-z-aos-dm-ready.rules <<'EOF'
          SUBSYSTEM=="block", KERNEL=="dm-*", TEST=="dm/name", ATTR{dm/suspended}=="0", ENV{DM_NAME}="$attr{dm/name}", ENV{SYSTEMD_READY}="1", TAG+="systemd"
          EOF
        '';
      }
    ];

    meta = {
      description = "Device-mapper userspace library and tools (libdevmapper, dmsetup)";
      homepage = "https://sourceware.org/lvm2/";
      license = "LGPL-2.1-only";
    };
  }
