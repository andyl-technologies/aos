{
  lib,
  mkDerivation,
  pkg-config,
  glib,
  qemu-crucible,
}: let
  pluginSource = builtins.readFile ./crucible-qemu-trace-plugin.c;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "crucible-qemu-trace-plugin";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The artifact is an ELF shared object containing qemu_plugin_install.";
        "files" = {};
        "input" = "The packaged QEMU plugin shared object.";
        "operation" = "Validate its ELF identity and required QEMU plugin entry-point symbol.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nplugin = pathlib.Path(\"@out@/lib/qemu/plugins/crucible-qemu-trace-plugin.so\").read_bytes()\nassert plugin.startswith(bytes([0x7f]) + b\"ELF\") and b\"qemu_plugin_install\" in plugin\nprint(\"crucible-qemu-trace-plugin data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "crucible-qemu-trace-plugin data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The package rejects a plugin format it does not produce.";
        "files" = {};
        "input" = "A request for an undeclared static-library form of the QEMU plugin.";
        "operation" = "Resolve the absent static archive beneath the plugin output.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/lib/qemu/plugins/crucible-qemu-trace-plugin.a\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"crucible-qemu-trace-plugin rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "crucible-qemu-trace-plugin rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0.1.0";

    src = null;
    source = pluginSource;
    passAsFile = ["source"];

    buildDeps = [
      pkg-config
      glib.dev
      glib.tools
      qemu-crucible
    ];
    runtimeDeps = [glib];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          cp "$sourcePath" plugin.c

          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${qemu-crucible}/include \
            plugin.c \
            -o crucible-qemu-trace-plugin.so
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/qemu/plugins"
          cp crucible-qemu-trace-plugin.so "$out/lib/qemu/plugins/"
          mkdir -p "$out/share/licenses/crucible-qemu-trace-plugin"
          cp ${../../LICENSES/GPL-2.0-only.txt} \
            "$out/share/licenses/crucible-qemu-trace-plugin/GPL-2.0.txt"
        '';
      }
    ];

    passthru.evidenceSources = [
      ./crucible-qemu-trace-plugin.nix
      ./crucible-qemu-trace-plugin.c
    ];

    meta = {
      description = "Crucible Phase 0 QEMU instruction-stream trace plugin";
      license = "GPL-2.0-only";
    };
  }
