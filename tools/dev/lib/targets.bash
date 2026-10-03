aos_dev_category() {
  case ${1:-} in
    package|packages|pkg) printf 'packages' ;;
    image|images) printf 'images' ;;
    container|containers) printf 'containers' ;;
    check|checks|test|tests) printf 'checks' ;;
    build|builds|output|outputs) printf 'builds' ;;
    eval|evals) printf 'evals' ;;
    *) return 1 ;;
  esac
}

_aos_dev_target_entries() {
  local category=$1 scope=${2:-} cross_system=${3:-}
  aos_dev_require_command nix

  local -a eval_args=(--argstr category "$category")
  if [[ -n $scope ]]; then
    eval_args+=(--argstr scope "$scope")
  fi
  if [[ -n $cross_system ]]; then
    eval_args+=(--argstr crossSystem "$cross_system")
  fi
  (cd "$aos_dev_root" && nix --extra-experimental-features nix-command \
    eval --raw --file tools/dev/targets.nix "${eval_args[@]}" entries)
}

aos_dev_list() {
  local category=${1:-packages}
  local filter=${2:-}
  local cross_system=${3:-}
  category=$(aos_dev_category "$category") || aos_dev_error "unknown target category '$1'"

  local entries
  # Descend through a check scope while it exists. A partial leaf such as
  # build.aos-dev falls back to the build scope, so completion and filtering
  # work without evaluating unrelated check trees.
  if [[ $category == checks && $filter == *.* ]]; then
    local scope=$filter
    while :; do
      entries=$(_aos_dev_target_entries "$category" "$scope" "$cross_system")
      if [[ -n $entries || $scope != *.* ]]; then
        printf '%s\n' "$entries" | grep -F -- "$filter" || true
        return
      fi
      scope=${scope%.*}
    done
  fi

  entries=$(_aos_dev_target_entries "$category" "" "$cross_system")

  if [[ -n $filter ]]; then
    printf '%s\n' "$entries" | grep -F -- "$filter" || true
  else
    printf '%s\n' "$entries"
  fi
}

aos_dev_target_attr() {
  # Friendly target names are display-only. Map each category to its real Nix
  # attribute at the boundary so build/run/all share one spelling rule.
  local category=$1 name=$2
  case $category in
    packages) printf 'pkgs.%s' "$name" ;;
    images)
      local variant=${name%%:*} format=${name#*:}
      [[ $variant != "$format" ]] || aos_dev_error "image name must be VARIANT:FORMAT; see 'list images'"
      printf 'systems.%s.build.image.%s' "$variant" "$format"
      ;;
    containers)
      local variant=${name%%:*} kind=${name#*:}
      [[ $variant != "$kind" ]] || aos_dev_error "container name must be VARIANT:KIND; see 'list containers'"
      local prefix="containerImages.$variant"
      # The experimental image is assembled by its system module, whereas release
      # containers are exposed by the top-level containerImages attrset.
      if [[ $variant == aos-experimental || $variant == aos-experimental-staging ]]; then
        prefix="systems.$variant.build.defaultContainer"
      fi
      case $kind in
        oci) printf '%s.platforms.%s.ociLayout' "$prefix" "$aos_dev_system" ;;
        docker) printf '%s.platforms.%s.dockerArchive' "$prefix" "$aos_dev_system" ;;
        metadata) printf '%s.platforms.%s.metadata' "$prefix" "$aos_dev_system" ;;
        *) aos_dev_error "unknown container output '$kind'" ;;
      esac
      ;;
    checks|evals) printf 'checks.%s' "$name" ;;
    builds) printf 'systems.%s.build.%s' "${name%%:*}" "${name#*:}" ;;
  esac
}

aos_dev_validate_target() {
  # Most names must be listed exactly. Deep check attrs are evaluated lazily
  # by Nix and can be addressed directly without flattening the whole tree.
  local category=$1 name=$2 cross_system=${3:-}
  if [[ $category == checks && $name == *.*.* ]]; then
    return
  fi
  local entries
  # Scoped check lookup avoids forcing unrelated check groups just to validate
  # one leaf. Exact matching still rejects a completion prefix as a target.
  if [[ $category == checks ]]; then
    entries=$(_aos_dev_target_entries "$category" "$name" "$cross_system")
  else
    entries=$(aos_dev_list "$category" "" "$cross_system")
  fi
  if ! printf '%s\n' "$entries" | grep -Fxq -- "$name"; then
    printf 'aos-dev: unknown %s target: %s\n' "$category" "$name" >&2
    printf '%s\n' "$entries" | grep -iF -- "${name%%:*}" | head -8 >&2 || true
    exit 2
  fi
}
