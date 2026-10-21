##! Checks shared vendor rules and rejects conflicting immutable package rules.
{pkgs, ...}:
pkgs.mkDerivation {
  pname = "initrd-udev-rules-check";
  version = "1";
  src = null;
  buildDeps = [pkgs.bash pkgs.coreutils pkgs.diffutils pkgs.grep];
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        first=root/nix/store/a-systemd/lib/udev/rules.d
        second=root/nix/store/b-systemd-deployment/lib/udev/rules.d
        selected=/nix/store/z-selected-systemd
        foreign=/nix/store/c-foreign-systemd
        for provider in "$selected" "$foreign"; do
          mkdir -p "root$provider/lib/udev/rules.d" "root$provider/lib/systemd" "root$provider/bin"
          touch "root$provider/bin/udevadm"
          chmod 0755 "root$provider/bin/udevadm"
          ln -s ../../bin/udevadm "root$provider/lib/systemd/systemd-udevd"
        done
        printf 'RUN+="%s/bin/udevadm trigger"\n' "$selected" > "root$selected/lib/udev/rules.d/64-btrfs.rules"
        printf 'RUN+="%s/bin/udevadm trigger"\n' "$foreign" > "root$foreign/lib/udev/rules.d/64-btrfs.rules"
        printf 'TAG+="foreign-daemon"\n' > "root$foreign/lib/udev/rules.d/65-foreign.rules"

        mkdir -p "$first" "$second"
        printf 'SUBSYSTEM=="block", TAG+="systemd"\n' > "$first/50-shared.rules"
        cp "$first/50-shared.rules" "$second/50-shared.rules"
        printf 'SUBSYSTEM=="net", TAG+="systemd"\n' > "$second/80-network.rules"

        collector=${../../pkgs/system/_systemd-abilities/platform/collect-udev-rules.sh}
        ${pkgs.bash}/bin/bash "$collector" "$PWD/root" "$selected"
        test "$(readlink root/lib/udev/rules.d/50-shared.rules)" = "/nix/store/a-systemd/lib/udev/rules.d/50-shared.rules"
        test "$(readlink root/lib/udev/rules.d/80-network.rules)" = "/nix/store/b-systemd-deployment/lib/udev/rules.d/80-network.rules"
        test "$(readlink root/lib/udev/rules.d/64-btrfs.rules)" = "$selected/lib/udev/rules.d/64-btrfs.rules"
        test ! -e root/lib/udev/rules.d/65-foreign.rules
        test ! -L root/lib/udev/rules.d/65-foreign.rules

        # Repeated collection preserves the same links, including when their
        # absolute store targets are absent outside the staging tree.
        ${pkgs.bash}/bin/bash "$collector" "$PWD/root" "$selected"

        if ${pkgs.bash}/bin/bash "$collector" "$PWD/root" /nix/store/missing > missing.log 2>&1; then
          echo "missing selected udev provider was accepted" >&2
          exit 1
        fi
        grep -Fq 'selected udev provider is incomplete' missing.log

        printf 'SUBSYSTEM=="block", TAG-="systemd"\n' > "$second/50-shared.rules"
        if ${pkgs.bash}/bin/bash "$collector" "$PWD/root" "$selected" > conflict.log 2>&1; then
          echo "conflicting udev rules were accepted" >&2
          exit 1
        fi
        grep -Fq 'conflicting udev rule 50-shared.rules' conflict.log

        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
