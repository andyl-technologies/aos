##! Exercises the GPL install layouts without changing production consumers.
{
  pkgs,
  build,
}: let
  installer = ../../tools/bazel/metadata/install_package.py;
in {
  plugin = pkgs.mkDerivation {
    pname = "crucible-qemu-plugin";
    version = "0.1.0";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.python3];
    runtimeDeps = [pkgs.glib pkgs.qemu-crucible pkgs.sqlite];
    meta.license = "GPL-2.0-only";
    phases = [
      {
        name = "install";
        script = ''
          ${pkgs.python3}/bin/python3 ${installer} \
            --build ${build} \
            --label //crates/crucible/qemu/crucible-qemu-plugin:compiler_artifact \
            --name crucible-qemu-plugin --version 0.1.0 --output "$out"
          ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/install_qemu_plugin_metadata.py} \
            --output "$out" --abi ${pkgs.aosBazelQemuPluginAbi} \
            --qemu ${pkgs.qemu-crucible} \
            --qemu-shmem-abi ${pkgs.lib.escapeShellArg pkgs.qemu-crucible.passthru.shmemAbi} \
            --gpl ${../../LICENSES/GPL-2.0-only.txt} --mit ${../../LICENSES/MIT.txt}
        '';
      }
    ];
  };
  gateway = pkgs.mkDerivation {
    pname = "crucible-debug-gateway";
    version = "0.1.0";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.python3];
    runtimeDeps = [pkgs.sqlite];
    meta.license = "GPL-2.0-only";
    phases = [
      {
        name = "install";
        script = ''
          ${pkgs.python3}/bin/python3 ${installer} \
            --build ${build} \
            --label //crates/crucible/qemu/crucible-qemu-debug-gateway:compiler_artifact \
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
