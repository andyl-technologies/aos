##! Checks the Rust plugin declarations against the matching source-built QEMU headers.
{
  lib,
  glib,
  qemu-crucible,
  pluginAbiSource,
  shmemAbiSource,
}: ''
  export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

  export CRUCIBLE_QEMU_BUILD_ID=${qemu-crucible.passthru.qemuBuildIdentity}
  export CRUCIBLE_QEMU_ATOMIC_PATCH_HASH=${qemu-crucible.passthru.atomicPatchHash}
  export CRUCIBLE_SHMEM_HEADER_HASH=${qemu-crucible.passthru.shmemHeaderHash}
  header="${qemu-crucible}/include/qemu/qemu-plugin.h"
  test -f "$header"
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
  done < ${lib.escapeShellArg "${pluginAbiSource}"}
  test -n "$qemu_plugin_api_version"

  shmem_abi_version=
  while IFS= read -r line; do
    case "$line" in
      "pub const ABI_VERSION: u32 = "*";")
        shmem_abi_version=''${line#pub const ABI_VERSION: u32 = }
        shmem_abi_version=''${shmem_abi_version%;}
        ;;
    esac
  done < ${lib.escapeShellArg "${shmemAbiSource}"}
  test -n "$shmem_abi_version"

  shmem_header="${qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h"
  test -f "$shmem_header"
  if ! grep -q "#define CRUCIBLE_SHMEM_ABI_VERSION ''${shmem_abi_version}u" \
    "$shmem_header"; then
    echo "qemu-crucible generated shmem header ABI does not match the Rust plugin" >&2
    exit 1
  fi

  cat > "$TMPDIR/crucible-qemu-plugin-header-probe.c" <<'EOF'
  #include <stdint.h>
  #include <aos/crucible/crucible_shmem_abi.h>
  #include <qemu-plugin.h>

  #ifndef QEMU_PLUGIN_VERSION
  #error "QEMU_PLUGIN_VERSION must be exposed by qemu-crucible headers"
  #endif

  #if QEMU_PLUGIN_VERSION != CRUCIBLE_EXPECTED_QEMU_PLUGIN_API_VERSION
  #error "qemu-crucible header plugin API version does not match the Rust plugin"
  #endif

  #if CRUCIBLE_SHMEM_ABI_VERSION != CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION
  #error "qemu-crucible generated shmem header ABI does not match the Rust plugin"
  #endif

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

''
