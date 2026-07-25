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
      hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
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
      grep -q 'qemu_plugin_read_vcpu_regs' "$header"
      grep -q 'qemu_plugin_rr_cursor' "$header"
      grep -q 'qemu_plugin_inject_preemption' "$header"

      qemu_plugin_api_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const QEMU_PLUGIN_API_VERSION: c_int = "*";")
            qemu_plugin_api_version=''${line#pub const QEMU_PLUGIN_API_VERSION: c_int = }
            qemu_plugin_api_version=''${qemu_plugin_api_version%;}
            ;;
        esac
      done < crates/crucible-qemu-plugin/src/abi.rs
      test -n "$qemu_plugin_api_version"

      shmem_abi_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const ABI_VERSION: u32 = "*";")
            shmem_abi_version=''${line#pub const ABI_VERSION: u32 = }
            shmem_abi_version=''${shmem_abi_version%;}
            ;;
        esac
      done < crates/crucible-shmem/src/lib.rs
      test -n "$shmem_abi_version"

      shmem_header="${qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h"
      test -f "$shmem_header"
      grep -q "#define CRUCIBLE_SHMEM_ABI_VERSION ''${shmem_abi_version}u" \
        "$shmem_header"

      cat > "$TMPDIR/crucible-qemu-plugin-header-probe.c" <<'EOF'
      #include <stdint.h>
      #include <aos/crucible/crucible_shmem_abi.h>
      #include <qemu/qemu-plugin.h>

      #ifndef QEMU_PLUGIN_VERSION
      #error "QEMU_PLUGIN_VERSION must be exposed by qemu-crucible headers"
      #endif

      #if QEMU_PLUGIN_VERSION != CRUCIBLE_EXPECTED_QEMU_PLUGIN_API_VERSION
      #error "qemu-crucible header plugin API version does not match the Rust plugin"
      #endif

      #if CRUCIBLE_SHMEM_ABI_VERSION != CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION
      #error "qemu-crucible generated shmem header ABI does not match the Rust plugin"
      #endif

      uint64_t (*crucible_probe_rr_switch_quantum)(void) =
          qemu_plugin_crucible_rr_switch_quantum;
      int (*crucible_probe_read_vcpu_regs)(unsigned int, uint8_t *, size_t,
                                           size_t *, uint64_t *) =
          qemu_plugin_read_vcpu_regs;
      int (*crucible_probe_rr_cursor)(struct qemu_plugin_rr_cursor *) =
          qemu_plugin_rr_cursor;
      int (*crucible_probe_inject_preemption)(uint64_t, uint64_t, uint64_t,
                                              unsigned int, uint32_t,
                                              uint32_t, uint32_t) =
          qemu_plugin_inject_preemption;
      EOF

      cc -fPIC -I"${qemu-crucible}/include" \
        -DCRUCIBLE_EXPECTED_QEMU_PLUGIN_API_VERSION="$qemu_plugin_api_version" \
        -DCRUCIBLE_EXPECTED_SHMEM_ABI_VERSION="$shmem_abi_version" \
        $(pkg-config --cflags glib-2.0) \
        -c "$TMPDIR/crucible-qemu-plugin-header-probe.c" \
        -o "$TMPDIR/crucible-qemu-plugin-header-probe.o"

      cd crates
    '';

    postInstall = ''
      test -f "$out/lib/libcrucible_qemu_plugin.so"
      mkdir -p "$out/lib/qemu/plugins"
      ln -s ../../libcrucible_qemu_plugin.so \
        "$out/lib/qemu/plugins/crucible-qemu-plugin.so"

      qemu_plugin_api_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const QEMU_PLUGIN_API_VERSION: c_int = "*";")
            qemu_plugin_api_version=''${line#pub const QEMU_PLUGIN_API_VERSION: c_int = }
            qemu_plugin_api_version=''${qemu_plugin_api_version%;}
            ;;
        esac
      done < crucible-qemu-plugin/src/abi.rs
      test -n "$qemu_plugin_api_version"

      shmem_abi_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const ABI_VERSION: u32 = "*";")
            shmem_abi_version=''${line#pub const ABI_VERSION: u32 = }
            shmem_abi_version=''${shmem_abi_version%;}
            ;;
        esac
      done < crucible-shmem/src/lib.rs
      test -n "$shmem_abi_version"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-qemu-plugin-build-info" <<INFO
      package=crucible-qemu-plugin
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      qemu_package=qemu-crucible
      qemu_build_id=${qemu-crucible.passthru.qemuBuildIdentity}
      qemu_sim_capability_marker=${qemu-crucible}/share/aos/crucible/qemu-build-identity.env
      qemu_plugin_header=${qemu-crucible}/include/qemu/qemu-plugin.h
      qemu_plugin_api_version=$qemu_plugin_api_version
      qemu_plugin_abi=qemu-plugin-api-v$qemu_plugin_api_version
      shmem_abi_version=$shmem_abi_version
      shmem_abi=crucible-shmem-abi-v$shmem_abi_version
      qemu_shmem_abi=${qemu-crucible.passthru.shmemAbi}
      shmem_generated_header=${qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
      shmem_generated_header_hash=${qemu-crucible.passthru.shmemHeaderHash}
      plugin_abi=crucible-shmem-abi-v$shmem_abi_version
      INFO
    '';

    meta = {
      description = "Crucible QEMU plugin cdylib built against AOS QEMU headers";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
