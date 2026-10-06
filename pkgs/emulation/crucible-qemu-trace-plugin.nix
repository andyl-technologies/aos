{
  mkDerivation,
  pkg-config,
  glib,
  qemu-crucible,
  callPackage,
}: let
  pluginSource = builtins.readFile ./crucible-qemu-trace-plugin.c;
  ramObserver = callPackage ./crucible-qemu-plugin.nix {
    nativeConformance = true;
    inherit qemu-crucible;
  };
  correspondingSource = callPackage ./qemu-crucible-source.nix {
    inherit qemu-crucible;
  };
in
  mkDerivation {
    pname = "crucible-qemu-trace-plugin";
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
          ln -s ${ramObserver}/lib/libcrucible_qemu_plugin.so \
            "$out/lib/qemu/plugins/crucible-ram-observer.so"
          mkdir -p "$out/share/aos"
          ln -s ${correspondingSource} "$out/share/aos/qemu-crucible-source"
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
