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

aos_dev_list() {
  local category=${1:-packages}
  local filter=${2:-}
  category=$(aos_dev_category "$category") || aos_dev_error "unknown target category '$1'"

  aos_dev_require_command nix-instantiate
  local entries
  # A dotted filter descends through its parent scope. Plain names stay at
  # the root, so listing one leaf never evaluates its derivation.
  if [[ $category == checks && $filter == *.* ]]; then
    local scope=${filter%.}
    [[ $scope != "$filter" ]] || scope=${scope%.*}
    while :; do
      entries=$(cd "$aos_dev_root" && nix-instantiate --eval --raw \
        --argstr category "$category" --argstr scope "$scope" dev/targets.nix)
      if [[ -n $entries ]]; then
        printf '%s\n' "$entries" | grep -F -- "$filter" || true
        return
      fi
      [[ $scope == *.* ]] || break
      scope=${scope%.*}
    done
  fi

  entries=$(cd "$aos_dev_root" && nix-instantiate --eval --raw \
    --argstr category "$category" dev/targets.nix)

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
      # The testing image is assembled by its system module, whereas release
      # containers are exposed by the top-level containerImages attrset.
      if [[ $variant == aos-testing ]]; then
        prefix='systems.aos-testing.build.defaultContainer'
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
  local category=$1 name=$2
  # Exact check paths go straight to Nix. Listing checks first would evaluate
  # unrelated check trees before Nix evaluates the requested target.
  if [[ $category == checks ]]; then
    [[ $name =~ ^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$ ]] || \
      aos_dev_error "invalid check target '$name'"
    return
  fi

  local entries
  entries=$(aos_dev_list "$category")
  if ! printf '%s\n' "$entries" | grep -Fxq -- "$name"; then
    printf 'aos-dev: unknown %s target: %s\n' "$category" "$name" >&2
    printf '%s\n' "$entries" | grep -iF -- "${name%%:*}" | head -8 >&2 || true
    exit 2
  fi
}
