# aos-ignition-preset — apply ignition's systemd presets in the initrd.
#
# Loaded as the `script` field of aos-ignition-preset.service in
# modules/services/ignition.nix. The unit injects a private mount
# namespace via BindPaths=/sysroot/var/etc:/sysroot/etc so that
# /sysroot/etc/* paths in this script resolve to /sysroot/var/etc/*
# on the rw /var partition. After switch_root, stage 2 surfaces the
# writes through the /etc overlay's lowerdir=/var/etc:/etc.lower.
#
# We don't use `systemctl preset-all`: AOS systemd is built with
# --sysconfdir=$out/etc, so its compiled-in SYSTEM_CONFIG_UNIT_DIR
# points inside the read-only systemd package. systemctl's enable /
# preset-all logic would write symlinks there and fail. This script
# parses the preset file directly and lays down the four [Install]
# symlink kinds the renderer in lib/modules/systemd/lib.nix emits.
#
# Tools available via the unit's environment.PATH (see ignition.nix):
# gawk, coreutils (mkdir/ln), bash, plus the rest of ignitionPath.
set -euo pipefail

preset=/sysroot/etc/systemd/system-preset/20-ignition.preset
units=/sysroot/etc/systemd/system

# Parse one unit's `[Install]` section and emit the four symlink
# kinds. Lines outside the section are ignored; the section ends at
# the next `[…]` header or EOF.
apply_install() {
  local unit_path="$1" unit_name="$2"
  awk -v unit="$unit_name" -v dir="$units" '
    BEGIN { in_install = 0 }
    /^\[Install\]/  { in_install = 1; next }
    /^\[/           { in_install = 0; next }
    !in_install     { next }
    /^Alias=/       { sub(/^Alias=/, ""); split($0, a, " ");
                      for (i in a) print "alias", a[i] }
    /^WantedBy=/    { sub(/^WantedBy=/, ""); split($0, a, " ");
                      for (i in a) print "wants", a[i] }
    /^RequiredBy=/  { sub(/^RequiredBy=/, ""); split($0, a, " ");
                      for (i in a) print "requires", a[i] }
    /^UpheldBy=/    { sub(/^UpheldBy=/, ""); split($0, a, " ");
                      for (i in a) print "upholds", a[i] }
  ' "$unit_path" | while read -r kind target; do
    [ -z "$target" ] && continue
    case "$kind" in
      alias)
        ln -sfn "$unit_name" "$units/$target"
        ;;
      wants|requires|upholds)
        mkdir -p "$units/$target.$kind"
        ln -sfn "../$unit_name" "$units/$target.$kind/$unit_name"
        ;;
    esac
  done
}

# Read the preset file: lines are `enable <unit>` or `disable <unit>`
# (we skip comments and blanks). For `disable`, removing pre-existing
# symlinks would mean walking [Install] on the on-disk unit; v1 leaves
# disable as a no-op since AOS doesn't ship pre-enabled image-time
# units that ignition would need to undo.
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ""|"#"*) continue ;;
  esac
  set -- $line
  action="$1"; name="${2:-}"
  [ -z "$name" ] && continue
  case "$action" in
    enable)
      unit_path="$units/$name"
      if [ ! -f "$unit_path" ]; then
        echo "aos-ignition-preset: preset enables $name but $unit_path does not exist" >&2
        continue
      fi
      apply_install "$unit_path" "$name"
      ;;
    disable)
      : # no-op — see comment above
      ;;
    *)
      echo "aos-ignition-preset: ignoring unknown preset directive '$action' for $name" >&2
      ;;
  esac
done < "$preset"
