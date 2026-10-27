# Collects immutable package rules for the selected udev daemon.
set -eu

cd "${1:?missing staging root}"
staging_root=$PWD
udev_provider="${2:?missing selected udev provider}"
# Immutable roots store their closure below /usr/lib/aos until the /nix
# overlay is assembled. Rule symlinks must still name the runtime /nix path.
store_root="$staging_root${3:-}"
provider_list="${4:-}"
selected_provider="$store_root$udev_provider"
vendor_directory="$staging_root/lib/udev/rules.d"

if [ ! -e "$selected_provider/lib/systemd/systemd-udevd" ] ||
   [ ! -x "$selected_provider/bin/udevadm" ] ||
   [ ! -d "$selected_provider/lib/udev/rules.d" ]; then
    echo "initrd-builder: selected udev provider is incomplete: $udev_provider" >&2
    exit 1
fi

mkdir -p "$vendor_directory"

collect_directory() {
    rules_directory=$1
    [ -d "$rules_directory" ] || return 0
    package_root="${rules_directory%/lib/udev/rules.d}"

    # Dependencies may retain another complete systemd build. Its rules call
    # that build's helpers; only the selected initrd daemon supplies udev's
    # own vendor rules. Other packages still participate in strict merging.
    if [ "$package_root" != "$selected_provider" ] &&
       [ -e "$package_root/lib/systemd/systemd-udevd" ] &&
       [ -x "$package_root/bin/udevadm" ]; then
        return 0
    fi

    for rule in "$rules_directory"/*.rules; do
        [ -f "$rule" ] || continue
        name=$(basename "$rule")
        target="${rule#"$store_root"}"
        vendor_rule="$vendor_directory/$name"

        if [ -e "$vendor_rule" ] || [ -L "$vendor_rule" ]; then
            retained_target=$(readlink "$vendor_rule")
            # Full and deployment outputs can carry the same vendor rules.
            # Keep one deterministic link only when the complete bytes agree.
            if cmp -s "$rule" "$store_root$retained_target"; then
                continue
            fi

            echo "initrd-builder: conflicting udev rule $name: $retained_target and $target" >&2
            exit 1
        fi

        ln -s "$target" "$vendor_rule"
    done
}

if [ -n "$provider_list" ]; then
    # Additional stored upgrade and fixture closures are deliberately absent
    # from this list; they must not contribute rules to the active system.
    while IFS= read -r package; do
        case "$package" in
            /nix/store/*) ;;
            *)
                echo "udev collector: invalid active package path: $package" >&2
                exit 1
                ;;
        esac
        collect_directory "$store_root$package/lib/udev/rules.d"
    done < "$provider_list"
else
    for directory in "$store_root"/nix/store/*/lib/udev/rules.d; do
        collect_directory "$directory"
    done
fi
