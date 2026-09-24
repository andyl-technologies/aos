aos_dev_cache_validate_tree() {
  # Destructive commands operate only below a complete, ordinary directory
  # tree. Refuse symlinks even when their targets are inside the cache root.
  [[ $aos_dev_cache_dir == /* ]] || aos_dev_error 'AOS_DEV_CACHE_DIR must be absolute'
  [[ $aos_dev_cache_dir != '/' && $aos_dev_cache_dir != "$HOME" && $aos_dev_cache_dir != "$HOME/.cache" ]] || \
    aos_dev_error 'AOS_DEV_CACHE_DIR is too broad for maintenance'
  [[ -d $aos_dev_cache_dir ]] || aos_dev_error 'cache directory does not exist; run cache init'

  local path
  for path in "$aos_dev_cache_dir" "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" \
      "$aos_dev_cache_dir/sccache" "$aos_dev_cache_dir/sccache/store"; do
    [[ ! -L $path ]] || aos_dev_error "cache maintenance refuses symlink: $path"
    [[ -d $path ]] || aos_dev_error "cache directory is incomplete: $path; run cache init"
  done
}

aos_dev_cache_usage() {
  aos_dev_cache_validate_tree
  local backend
  for backend in go bazel sccache; do
    if [[ -d $aos_dev_cache_dir/$backend ]]; then
      du -sh "$aos_dev_cache_dir/$backend"
    fi
  done
}

aos_dev_cache_prune() {
  aos_dev_cache_validate_tree
  local days=14 max_gib=50 dry_run=false

  while (( $# > 0 )); do
    case $1 in
      --days)
        (( $# >= 2 )) || aos_dev_error '--days requires a number'
        days=$2
        shift 2
        ;;
      --max-gib)
        (( $# >= 2 )) || aos_dev_error '--max-gib requires a number'
        max_gib=$2
        shift 2
        ;;
      --dry-run) dry_run=true; shift ;;
      *) aos_dev_error "unknown prune option '$1'" ;;
    esac
  done

  [[ $days =~ ^[0-9]+$ && $max_gib =~ ^[0-9]+$ ]] || \
    aos_dev_error 'prune limits must be nonnegative integers'
  (( max_gib > 0 )) || aos_dev_error '--max-gib must be positive'

  local -a directories=("$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel")
  local file size total max_bytes
  max_bytes=$((max_gib * 1024 * 1024 * 1024))
  total=$(du -sb "${directories[@]}" | awk '{sum += $1} END {print sum + 0}')

  # Go has its own age trimming and Bazel has idle GC. This explicit pass is
  # useful after long idle periods or when a developer needs disk immediately.
  while IFS= read -r -d '' file; do
    if [[ $dry_run == true ]]; then
      printf 'would remove %s\n' "$file"
    else
      rm -f -- "$file"
    fi
  done < <(find "${directories[@]}" -type f -mmin +"$((days * 1440))" -print0)

  if [[ $dry_run == true ]]; then
    printf 'Current Go+Bazel use: %s bytes; size cap: %s bytes\n' "$total" "$max_bytes"
    return
  fi

  total=$(du -sb "${directories[@]}" | awk '{sum += $1} END {print sum + 0}')
  # Age pruning may not reach the size cap. Remove the oldest remaining files
  # first, which preserves the recently used compilation results.
  while IFS= read -r -d '' record && (( total > max_bytes )); do
    size=${record#* }
    size=${size%% *}
    file=${record#* * }
    if [[ -f $file ]]; then
      rm -f -- "$file"
      total=$((total - size))
    fi
  done < <(find "${directories[@]}" -type f -printf '%T@ %s %p\0' | sort -zn)

  printf 'Go+Bazel cache now uses %s bytes\n' "$total"
}

aos_dev_cache_clear() {
  aos_dev_cache_validate_tree
  local backend=${1:-all}
  local -a selected=()

  case $backend in
    all) selected=(go bazel sccache) ;;
    go|bazel|sccache) selected=("$backend") ;;
    *) aos_dev_error "unknown cache backend '$backend'" ;;
  esac

  for backend in "${selected[@]}"; do
    if [[ $backend == sccache ]]; then
      # Stop the writer before deleting its store. The socket is removed too
      # so the next cache init starts a fresh server.
      aos_dev_cache_command stop
      rm -f -- "$aos_dev_cache_dir/sccache/server.sock"
      find "$aos_dev_cache_dir/sccache/store" \( -type f -o -type l \) -delete
    else
      find "$aos_dev_cache_dir/$backend" \( -type f -o -type l \) -delete
    fi
  done

  printf 'Cleared %s cache entries under %s\n' "${1:-all}" "$aos_dev_cache_dir"
}
