##! crucible-qemu-plugin — RFC-0010 QEMU plugin cdylib
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  glib,
  pkg-config,
  qemu-crucible,
}: let
  version = "0.1.0";
  src = import ../tools/crucible/_source.nix {inherit lib;};
in
  mkCargoPackage {
    pname = "crucible-qemu-plugin";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
    };

    cargoFlags = "-p crucible-qemu-plugin";
    cargoTestFlags = "-p crucible-qemu-plugin";
    installBins = false;
    installLibs = true;
    doCheck = true;

    buildDeps = [glib pkg-config qemu-crucible];
    runtimeDeps = [qemu-crucible];

    preBuild = ''
      header="${qemu-crucible}/include/qemu/qemu-plugin.h"
      test -f "$header"
      grep -q 'qemu_plugin_crucible_rr_switch_quantum' "$header"

      cat > "$TMPDIR/crucible-qemu-plugin-header-probe.c" <<'EOF'
      #include <stdint.h>
      #include <qemu/qemu-plugin.h>

      uint64_t (*crucible_probe_rr_switch_quantum)(void) =
          qemu_plugin_crucible_rr_switch_quantum;
      EOF

      cc -fPIC -I"${qemu-crucible}/include" $(pkg-config --cflags glib-2.0) \
        -c "$TMPDIR/crucible-qemu-plugin-header-probe.c" \
        -o "$TMPDIR/crucible-qemu-plugin-header-probe.o"

      cd crates
    '';

    postInstall = ''
      test -f "$out/lib/libcrucible_qemu_plugin.so"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-qemu-plugin-build-info" <<INFO
      package=crucible-qemu-plugin
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      qemu_package=qemu-crucible
      qemu_plugin_header=${qemu-crucible}/include/qemu/qemu-plugin.h
      INFO
    '';

    meta = {
      description = "Crucible QEMU plugin cdylib built against AOS QEMU headers";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
