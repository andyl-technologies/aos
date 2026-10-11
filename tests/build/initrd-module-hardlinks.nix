##! Exercises module sharing through the production helper and archive transport.
{
  pkgs,
  lib,
  ...
}:
pkgs.mkDerivation {
  pname = "initrd-module-hardlinks-check";
  version = "1";
  src = null;
  buildDeps = [pkgs.bash pkgs.coreutils pkgs.diffutils pkgs.findutils pkgs.cpio pkgs.libarchive pkgs.python3];
  outputChecks.out = {};
  phases = [
    {
      name = "check";
      script = ''
        set -euo pipefail
        module_tree=/nix/store/kernel-fixture/lib/modules/test-release
        retained="root$module_tree/kernel"
        view=root/lib/modules/test-release/kernel
        mkdir -p "$retained" "$view"

        printf 'unchanged module\n' > "$retained/shared.ko"
        cp "$retained/shared.ko" "$view/shared.ko"
        printf 'original module\n' > "$retained/overlaid.ko"
        printf 'external overlay\n' > "$view/overlaid.ko"
        printf 'same bytes, different mode\n' > "$retained/mode.ko"
        cp "$retained/mode.ko" "$view/mode.ko"
        chmod 0444 "$retained/mode.ko"
        chmod 0644 "$view/mode.ko"
        printf 'external module\n' > "$view/external.ko"
        printf 'generated metadata\n' > "root$module_tree/modules.dep"
        cp "root$module_tree/modules.dep" root/lib/modules/test-release/modules.dep

        ${pkgs.bash}/bin/bash -eu -o pipefail \
          ${../../pkgs/system/_systemd-abilities/platform/share-kernel-modules.sh} \
          "$PWD/root" "$module_tree" test-release

        # A second invocation must tolerate already-shared files.
        ${pkgs.bash}/bin/bash -eu -o pipefail \
          ${../../pkgs/system/_systemd-abilities/platform/share-kernel-modules.sh} \
          "$PWD/root" "$module_tree" test-release

        # A retained ancestor alias must never authorize linking to a file
        # outside staging, even when the external bytes and mode match.
        mkdir -p outside escape-root/lib/modules/test-release/kernel/escape \
          "escape-root$module_tree/kernel"
        printf 'external immutable payload\n' > outside/outside.ko
        cp outside/outside.ko escape-root/lib/modules/test-release/kernel/escape/outside.ko
        ln -s "$PWD/outside" "escape-root$module_tree/kernel/escape"
        ${pkgs.bash}/bin/bash -eu -o pipefail \
          ${../../pkgs/system/_systemd-abilities/platform/share-kernel-modules.sh} \
          "$PWD/escape-root" "$module_tree" test-release
        test ! outside/outside.ko -ef escape-root/lib/modules/test-release/kernel/escape/outside.ko
        test "$(stat -c %h outside/outside.ko)" = 1
        ${pkgs.diffutils}/bin/cmp outside/outside.ko \
          escape-root/lib/modules/test-release/kernel/escape/outside.ko

        (cd root && find . -print0 | LC_ALL=C sort -z \
          | ${pkgs.cpio}/bin/cpio --quiet -o -H newc -R +0:+0 --reproducible --null) > modules.cpio
        ${pkgs.libarchive}/bin/bsdtar --format=pax -cf modules.tar @modules.cpio
        mkdir extracted
        ${pkgs.libarchive}/bin/bsdtar -xpf modules.tar -C extracted
        ${pkgs.python3}/bin/python3 ${./_initrd-module-hardlinks.py} extracted "$module_tree"

        # The overlay and generated metadata survive transport independently;
        # sharing must not restore the admitted kernel's original contents.
        ${pkgs.diffutils}/bin/cmp "$view/overlaid.ko" extracted/lib/modules/test-release/kernel/overlaid.ko
        ${pkgs.diffutils}/bin/cmp "$view/external.ko" extracted/lib/modules/test-release/kernel/external.ko
        ${pkgs.diffutils}/bin/cmp "root$module_tree/modules.dep" "extracted$module_tree/modules.dep"
        test "$(stat -c %a "extracted$module_tree/kernel/mode.ko")" = 444
        test "$(stat -c %a extracted/lib/modules/test-release/kernel/mode.ko)" = 644
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    }
  ];
}
