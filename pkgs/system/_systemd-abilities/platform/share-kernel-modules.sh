# Share immutable module payloads only after overlays and depmod have finished.
# Both names remain in the archive; neither an admitted artifact nor generated
# module metadata may be changed to obtain a smaller representation.
staging_root=$(realpath -e -- "$1")
module_tree=$2
module_view="$staging_root/lib/modules/$3"
retained_tree="$staging_root$module_tree"

if [ -d "$retained_tree" ]; then
  find "$module_view" -type f -name '*.ko' -print0 |
    while IFS= read -r -d '' module; do
      relative_module="${module#"$module_view/"}"
      retained_module="$retained_tree/$relative_module"
      [ -f "$retained_module" ] && [ ! -L "$retained_module" ] || continue

      # Never follow an external module's alias into the real Nix store.
      resolved_module=$(realpath -e -- "$module")
      resolved_retained=$(realpath -e -- "$retained_module")
      case "$resolved_module" in "$staging_root/"*) ;; *) continue ;; esac
      case "$resolved_retained" in "$staging_root/"*) ;; *) continue ;; esac

      [ "$(stat -c %a -- "$module")" = "$(stat -c %a -- "$retained_module")" ] || continue
      cmp -s -- "$module" "$retained_module" || continue
      [ "$retained_module" -ef "$module" ] || ln -f -- "$retained_module" "$module"
    done
fi
