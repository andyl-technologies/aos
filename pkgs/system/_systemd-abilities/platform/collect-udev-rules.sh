# Collects immutable package rules into the initrd's vendor directory.
set -eu

cd "${1:?missing initrd staging root}"
staging_root=$PWD
udev_provider="${2:?missing selected udev provider}"
selected_provider="$staging_root$udev_provider"
vendor_directory="$staging_root/lib/udev/rules.d"

if [ ! -e "$selected_provider/lib/systemd/systemd-udevd" ] ||
   [ ! -x "$selected_provider/bin/udevadm" ] ||
   [ ! -d "$selected_provider/lib/udev/rules.d" ]; then
    echo "initrd-builder: selected udev provider is incomplete: $udev_provider" >&2
    exit 1
fi

mkdir -p "$vendor_directory"

for rules_directory in "$staging_root"/nix/store/*/lib/udev/rules.d; do
    [ -d "$rules_directory" ] || continue
    package_root="${rules_directory%/lib/udev/rules.d}"

    # Dependencies may retain another complete systemd build. Its rules call
    # that build's helpers; only the selected initrd daemon supplies udev's
    # own vendor rules. Other packages still participate in strict merging.
    if [ "$package_root" != "$selected_provider" ] &&
       [ -e "$package_root/lib/systemd/systemd-udevd" ] &&
       [ -x "$package_root/bin/udevadm" ]; then
        continue
    fi

    for rule in "$rules_directory"/*.rules; do
        [ -f "$rule" ] || continue
        name=$(basename "$rule")
        target="${rule#"$staging_root"}"
        vendor_rule="$vendor_directory/$name"

        if [ -e "$vendor_rule" ] || [ -L "$vendor_rule" ]; then
            retained_target=$(readlink "$vendor_rule")
            # Full and deployment outputs can carry the same vendor rules.
            # Keep one deterministic link only when the complete bytes agree.
            if cmp -s "$rule" "$staging_root$retained_target"; then
                continue
            fi

            echo "initrd-builder: conflicting udev rule $name: $retained_target and $target" >&2
            exit 1
        fi

        ln -s "$target" "$vendor_rule"
    done
done
