##! Installs the declared GPL Bazel artifacts with the AOS package layout.
{
  mkDerivation,
  python3,
  glib,
  qemu-crucible,
  sqlite,
  lib,
  aosBazelQemuPluginAbi,
  build,
}: let
  installer = ../../tools/bazel/metadata/install_package.py;
in {
  plugin = mkDerivation {
    pname = "crucible-qemu-plugin";
    version = "0.1.0";
    src = null;
    sharedBuildCache = false;
    buildDeps = [python3];
    runtimeDeps = [glib qemu-crucible sqlite];
    meta.license = "GPL-2.0-only";
    phases = [
      {
        name = "install";
        script = ''
          ${python3}/bin/python3 ${installer} \
            --build ${build} \
            --label //crates/crucible/crucible-qemu-plugin:compiler_artifact \
            --name crucible-qemu-plugin --version 0.1.0 --output "$out"
          ${python3}/bin/python3 ${../../tools/bazel/metadata/install_qemu_plugin_metadata.py} \
            --output "$out" --abi ${aosBazelQemuPluginAbi} \
            --qemu ${qemu-crucible} \
            --qemu-shmem-abi ${lib.escapeShellArg qemu-crucible.passthru.shmemAbi} \
            --gpl ${../../LICENSES/GPL-2.0-only.txt} --mit ${../../LICENSES/MIT.txt}
        '';
      }
    ];
  };
  gateway = mkDerivation {
    pname = "crucible-debug-gateway";
    version = "0.1.0";
    src = null;
    sharedBuildCache = false;
    buildDeps = [python3];
    runtimeDeps = [sqlite];
    meta.license = "GPL-2.0-only";
    phases = [
      {
        name = "install";
        script = ''
          ${python3}/bin/python3 ${installer} \
            --build ${build} \
            --label //crates/crucible/crucible-qemu-debug-gateway:compiler_artifact \
            --name crucible-qemu-debug-gateway --version 0.1.0 --output "$out"
          mkdir -p "$out/share/licenses/crucible-debug-gateway"
          cp ${../../LICENSES/GPL-2.0-only.txt} \
            "$out/share/licenses/crucible-debug-gateway/GPL-2.0.txt"
          cp ${../../LICENSES/MIT.txt} \
            "$out/share/licenses/crucible-debug-gateway/MIT.txt"
          cat > "$out/share/licenses/crucible-debug-gateway/COMPONENT" <<'LICENSE_SCOPE'
          crucible-debug-gateway is a standalone QEMU RSP mediation process.
          SPDX-License-Identifier: GPL-2.0-only
          crucible-qemu-protocol is used under its MIT option.
          LICENSE_SCOPE
        '';
      }
    ];
  };
}
