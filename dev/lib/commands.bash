aos_dev_build() {
  local category=${1:-} name=${2:-}
  [[ -n $category && -n $name ]] || aos_dev_error 'build requires a category and target name'
  shift 2
  category=$(aos_dev_category "$category") || aos_dev_error "unknown target category '$category'"
  aos_dev_validate_target "$category" "$name"

  local attr
  attr=$(aos_dev_target_attr "$category" "$name")
  aos_dev_nix_build -A "$attr" "$@"
}

aos_dev_run() {
  local category=${1:-} name=${2:-}
  [[ -n $category && -n $name ]] || aos_dev_error 'run requires a category and target name'
  shift 2
  category=$(aos_dev_category "$category") || aos_dev_error "unknown run category '$category'"

  if [[ $category == images ]]; then
    [[ $name == *:qcow2 ]] || aos_dev_error 'VM run requires a qcow2 image'
    local image
    image=$(aos_dev_build image "$name" --no-out-link)
    # The AOS VM command accepts a built disk image and its own run flags.
    local vm
    vm=$(aos_dev_nix_build -A pkgs.aos-vm --no-out-link)
    exec "$vm/bin/aos" vm run "$image/aos-${name%%:*}.qcow2" "$@"
  fi

  if [[ $category == containers ]]; then
    local variant=${name%%:*}
    local archive docker
    archive=$(aos_dev_build container "$variant:docker" --no-out-link)
    docker=$(aos_dev_nix_build -A pkgs.docker --no-out-link)
    local jq_tool reference
    jq_tool=$(aos_dev_nix_build -A pkgs.jq --no-out-link)
    reference=$("$jq_tool/bin/jq" -r '.[0].RepoTags[0]' "$archive/manifest.json")
    local -a docker_options=() command_args=()
    while (( $# > 0 )); do
      if [[ $1 == -- ]]; then
        shift
        command_args=("$@")
        break
      fi
      docker_options+=("$1")
      shift
    done
    "$docker/bin/docker" load -i "$archive/image.docker.tar" >&2
    exec "$docker/bin/docker" run --rm "${docker_options[@]}" "$reference" "${command_args[@]}"
  fi

  [[ $category == packages ]] || aos_dev_error 'run supports packages, images, and containers'
  local output
  output=$(aos_dev_build package "$name" --no-out-link)
  if [[ -x $output/bin/$name ]]; then
    exec "$output/bin/$name" "$@"
  fi

  local -a programs=("$output"/bin/*)
  [[ ${#programs[@]} == 1 && -x ${programs[0]} ]] || \
    aos_dev_error "cannot select a program in $output/bin; run an executable there explicitly"
  exec "${programs[0]}" "$@"
}

aos_dev_all() {
  local category=${1:-}
  [[ -n $category ]] || aos_dev_error 'all requires a category'
  shift
  case $category in
    packages) aos_dev_nix_build -A allPackages "$@" ;;
    checks) aos_dev_nix_build -A checks "$@" ;;
    builds) aos_dev_all_builds "$@" ;;
    format) aos_dev_fmt all --check "$@" ;;
    ci)
      aos_dev_fmt all --check
      aos_dev_nix_build -A checks.eval "$@"
      aos_dev_all_builds "$@"
      aos_dev_nix_build -A checks "$@"
      ;;
    *) aos_dev_error 'all requires packages, checks, builds, format, or ci' ;;
  esac
}

aos_dev_all_builds() {
  aos_dev_nix_build -A allPackages --no-out-link "$@"

  local target entries attr
  entries=$(aos_dev_list images)
  while IFS= read -r target; do
    [[ -n $target ]] || continue
    attr=$(aos_dev_target_attr images "$target")
    aos_dev_nix_build -A "$attr" --no-out-link "$@"
  done <<< "$entries"

  entries=$(aos_dev_list containers)
  while IFS= read -r target; do
    [[ -n $target ]] || continue
    attr=$(aos_dev_target_attr containers "$target")
    aos_dev_nix_build -A "$attr" --no-out-link "$@"
  done <<< "$entries"

  entries=$(aos_dev_list builds)
  while IFS= read -r target; do
    [[ $target == *:toplevel || $target == *:unsignedImageAssembly ]] || continue
    attr=$(aos_dev_target_attr builds "$target")
    aos_dev_nix_build -A "$attr" --no-out-link "$@"
  done <<< "$entries"
}

aos_dev_fmt() {
  local language=nix
  case ${1:-} in
    nix|rust|all) language=$1; shift ;;
  esac

  if [[ $language == nix || $language == all ]]; then
    local formatter
    formatter=$(nix-build "$aos_dev_root/default.nix" -A pkgs.alejandra --no-out-link)
    "$formatter/bin/alejandra" "$@" "$aos_dev_root"
  fi

  if [[ $language == rust || $language == all ]]; then
    local rust rust_dev
    rust=$(nix-build "$aos_dev_root/default.nix" -A pkgs.rust --no-out-link)
    rust_dev=$(nix-build "$aos_dev_root/default.nix" -A pkgs.rust.dev --no-out-link)
    PATH="$rust_dev/bin:$rust/bin:$PATH" \
      "$rust_dev/bin/cargo-fmt" --all --manifest-path "$aos_dev_root/crates/Cargo.toml" "$@"
  fi
}

aos_dev_release() {
  local cli
  cli=$(nix-build "$aos_dev_root/default.nix" -A pkgs.aos --no-out-link)
  "$cli/bin/aos" release "$@"
}

aos_dev_completion() {
  [[ ${1:-} == bash ]] || aos_dev_error 'only Bash completion is available'
  printf 'aos-dev() { bash %q "$@"; }\n' "$aos_dev_root/aos-dev"
  cat <<'COMPLETION'
_aos_dev_complete() {
  local current=${COMP_WORDS[COMP_CWORD]}
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( $(compgen -W 'list build run all fmt release cache completion help --release --no-cache' -- "$current") )
  elif (( COMP_CWORD == 2 )); then
    COMPREPLY=( $(compgen -W 'package image container check build eval packages images containers checks builds evals ci format nix rust all init doctor status usage prune clear stop' -- "$current") )
  elif (( COMP_CWORD == 3 )) && [[ ${COMP_WORDS[1]} == build || ${COMP_WORDS[1]} == run ]]; then
    COMPREPLY=( $(compgen -W "$(aos-dev list "${COMP_WORDS[2]}" 2>/dev/null)" -- "$current") )
  fi
}
complete -F _aos_dev_complete aos-dev
COMPLETION
}

aos_dev_main() {
  aos_dev_mode=development
  case ${1:-} in
    --release|--no-cache) aos_dev_mode=release; shift ;;
    --cache) shift ;;
  esac

  aos_dev_system=${AOS_DEV_SYSTEM:-$(uname -m)-linux}
  cd "$aos_dev_root" || aos_dev_error 'cannot enter the repository root'

  local command=${1:-help}
  if (( $# > 0 )); then shift; fi
  case $command in
    list) aos_dev_list "$@" ;;
    build) aos_dev_build "$@" ;;
    run) aos_dev_run "$@" ;;
    all) aos_dev_all "$@" ;;
    fmt) aos_dev_fmt "$@" ;;
    release) aos_dev_release "$@" ;;
    cache) aos_dev_cache_command "$@" ;;
    completion) aos_dev_completion "$@" ;;
    help|-h|--help) aos_dev_usage ;;
    *) aos_dev_error "unknown command '$command'; run 'bash ./aos-dev help'" ;;
  esac
}
