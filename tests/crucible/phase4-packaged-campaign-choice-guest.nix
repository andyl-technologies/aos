{pkgs}:
# A diskless Linux guest whose PID 1 consumes two real typed selectable
# replies. The selected pair controls the marker emitted before the guest
# parks, giving campaign tests a deterministic, host-observable result and an
# unbounded exact-checkpoint window.
pkgs.mkDerivation {
  pname = "crucible-packaged-campaign-choice-initramfs";
  version = "0";
  src = ./phase4-packaged-campaign-choice-init.c;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.crucible-guest
  ];

  phases = [
    {
      name = "build-packaged-campaign-choice-initramfs";
      script = ''
        set -eu

        cp "$src" init.c

        cc -static -O2 -Wall -Wextra -Werror -o init init.c
        strip --strip-all init

        mkdir -p root
        cp init root/init
        cp ${pkgs.crucible-guest}/bin/crucible-guest root/crucible-guest
        chmod 0755 root/init root/crucible-guest

        mkdir -p "$out"
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            > "$out/initrd.img"
        )
        test -s "$out/initrd.img"

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=uncompressed-newc-initramfs
        guest_init=typed-choice-marker-pid1
        selectable_surface=crucible-guest-typed-cli
        discrete_selectable=campaign.recovery-policy
        integer_selectable=campaign.retry-quanta
        result_surface=guest-event-marker-derived-from-both-selected-replies
        checkpoint_window=guest-parks-after-result-marker
        EVIDENCE
      '';
    }
  ];
}
