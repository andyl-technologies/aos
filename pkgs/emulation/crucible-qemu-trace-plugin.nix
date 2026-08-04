{
  mkDerivation,
  pkg-config,
  glib,
  qemu-crucible,
}: let
  pluginSource = builtins.readFile ./crucible-qemu-trace-plugin.c;
in
  mkDerivation {
    pname = "crucible-qemu-trace-plugin";
    version = "0.1.0";

    src = null;
    source = pluginSource;
    passAsFile = ["source"];

    buildDeps = [
      pkg-config
      glib
      qemu-crucible
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          cp "$sourcePath" plugin.c
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

    meta = {
      description = "Crucible Phase 0 QEMU instruction-stream trace plugin";
      license = "GPL-2.0-only";
    };
  }
