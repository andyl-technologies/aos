aos_dev_cache_validate_tree() {
  # Destructive commands operate only below a complete, ordinary directory
  # tree. Refuse symlinks even when their targets are inside the cache root.
  [[ $aos_dev_cache_dir == /* ]] || aos_dev_error 'AOS_DEV_CACHE_DIR must be absolute'
  [[ $aos_dev_cache_dir != '/' && $aos_dev_cache_dir != "$HOME" && $aos_dev_cache_dir != "$HOME/.cache" ]] || \
    aos_dev_error 'AOS_DEV_CACHE_DIR is too broad for maintenance'
  [[ -d $aos_dev_cache_dir ]] || aos_dev_error 'cache directory does not exist; run cache init'

  local path
  for path in "$aos_dev_cache_dir" "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" \
      "$aos_dev_cache_dir/rust"; do
    [[ ! -L $path ]] || aos_dev_error "cache maintenance refuses symlink: $path"
    [[ -d $path ]] || aos_dev_error "cache directory is incomplete: $path; run cache init"
  done
  # Older initialized caches may predate accache. Optional roots must still
  # be real directories before any command traverses them.
  for path in "$aos_dev_cache_dir/"{accache,accache-state}; do
    [[ ! -L $path ]] || aos_dev_error "cache maintenance refuses symlink: $path"
    [[ ! -e $path || -d $path ]] || aos_dev_error "cache root is not a directory: $path"
  done
}

aos_dev_cache_usage() {
  aos_dev_cache_validate_tree
  local backend
  for backend in go bazel rust accache accache-state; do
    if [[ -d $aos_dev_cache_dir/$backend ]]; then
      du -sh "$aos_dev_cache_dir/$backend"
    fi
  done
}

aos_dev_cache_prune() {
  # Apply one retention policy to every backend. Rust is always pruned by
  # whole target tree so Cargo's fingerprints and outputs stay coherent.
  local backend
  for backend in go bazel rust accache; do
    [[ -d $aos_dev_cache_dir/$backend ]] || continue
    aos_dev_cache_backend_prune "$backend" "$@"
  done
}

aos_dev_cache_backend_compact() {
  local backend=$1 dry_run=${2:-}
  [[ -z $dry_run || $dry_run == --dry-run ]] || aos_dev_error 'compact accepts only --dry-run'
  aos_dev_cache_validate_tree
  local directory=$aos_dev_cache_dir/$backend tree

  if [[ $backend == rust ]]; then
    # Never remove a directory inside an active Cargo target tree. Only an
    # empty, old top-level tree can be compacted, under the same lock as prune.
    while IFS= read -r -d '' tree; do
      if [[ $dry_run == --dry-run ]]; then
        printf '%s\n' "$tree"
      elif ! aos_dev_cache_remove_rust_tree "$tree"; then
        printf 'aos-dev: skipped active Rust target tree %s\n' "$tree" >&2
      fi
    done < <(find "$directory" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' -empty -mmin +10 -print0)
    return
  fi

  # Backend records are not ours to repack. After pruning, remove empty
  # directories old enough that an active writer is unlikely to use them.
  if [[ $dry_run == --dry-run ]]; then
    find "$directory" -mindepth 1 -depth -type d -empty -mmin +10 -print
  else
    find "$directory" -mindepth 1 -depth -type d -empty -mmin +10 -delete
  fi
}

aos_dev_cache_remove_rust_tree() {
  local tree=$1 lock fd held_fd parent_fd trash
  local -a held_fds=()
  aos_dev_require_command flock
  exec {parent_fd}>>"$aos_dev_cache_dir/rust/.aos-cache.lock"
  flock "$parent_fd"
  if [[ ! -d $tree ]]; then
    exec {parent_fd}>&-
    return 0
  fi

  # The source lock covers every aos-dev Cargo phase. Check Cargo's own
  # profile locks as well for builds started outside the wrapper.
  while IFS= read -r -d '' lock; do
    if ! exec {fd}<>"$lock"; then
      for held_fd in "${held_fds[@]}"; do exec {held_fd}>&-; done
      exec {parent_fd}>&-
      return 1
    fi
    if ! flock -n "$fd"; then
      exec {fd}>&-
      for held_fd in "${held_fds[@]}"; do exec {held_fd}>&-; done
      exec {parent_fd}>&-
      return 1
    fi
    held_fds+=("$fd")
  done < <(find "$tree" -maxdepth 2 -type f \( -name .aos-source.lock -o -name .cargo-lock \) -print0)

  # Rename under the parent lock, then do the potentially slow deletion after
  # other packages are free to start. New builds can safely recreate the key.
  trash=$(mktemp -d "$aos_dev_cache_dir/rust/.aos-trash.XXXXXXXX")
  mv -- "$tree" "$trash/tree"
  for held_fd in "${held_fds[@]}"; do exec {held_fd}>&-; done
  exec {parent_fd}>&-
  rm -rf -- "$trash"
}

aos_dev_cache_backend_prune() {
  local backend=$1
  shift
  aos_dev_cache_validate_tree
  local days=14 max_gib=50 dry_run=false compact=false before='' cutoff
  while (( $# > 0 )); do
    case $1 in
      --days|--max-gib|--before)
        (( $# >= 2 )) || aos_dev_error "$1 requires a value"
        case $1 in
          --days) days=$2 ;;
          --max-gib) max_gib=$2 ;;
          --before) before=$2 ;;
        esac
        shift 2
        ;;
      --dry-run) dry_run=true; shift ;;
      --compact) compact=true; shift ;;
      *) aos_dev_error "unknown prune option '$1'" ;;
    esac
  done
  [[ $days =~ ^[0-9]+$ && $max_gib =~ ^[1-9][0-9]*$ ]] || \
    aos_dev_error 'prune limits must be nonnegative days and a positive GiB cap'
  if [[ -n $before ]]; then
    cutoff=$(date -u -d "$before" +%s) || aos_dev_error "invalid cutoff '$before'"
  else
    cutoff=$(($(date -u +%s) - days * 86400))
  fi

  local directory=$aos_dev_cache_dir/$backend entry total limit_bytes size planned_bytes=0
  local -A planned=()
  limit_bytes=$((max_gib * 1024 * 1024 * 1024))
  if [[ $backend == rust ]]; then
    while IFS= read -r -d '' entry; do
      if [[ $dry_run == true ]]; then
        printf 'would remove %s\n' "$entry"
        size=$(du -sb "$entry" | awk '{print $1}')
        planned_bytes=$((planned_bytes + size))
        planned["$entry"]=1
      elif ! aos_dev_cache_remove_rust_tree "$entry"; then
        printf 'aos-dev: skipped active Rust target tree %s\n' "$entry" >&2
      fi
    done < <(find "$directory" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' ! -newermt "@$cutoff" -print0)
  else
    while IFS= read -r -d '' entry; do
      if [[ $dry_run == true ]]; then
        printf 'would remove %s\n' "$entry"
        size=$(stat -c %s "$entry")
        planned_bytes=$((planned_bytes + size))
        planned["$entry"]=1
      else
        rm -f -- "$entry"
      fi
    done < <(find "$directory" -type f ! -newermt "@$cutoff" -print0)
  fi

  total=$(du -sb "$directory" | awk '{print $1}')
  if [[ $dry_run == true ]]; then
    total=$((total - planned_bytes))
  fi
  if (( total > limit_bytes )); then
    # Size eviction uses the same safe unit: whole Cargo target trees or
    # individual disposable Go/Bazel records. Oldest access comes first.
    if [[ $backend == rust ]]; then
      while read -r _ entry && (( total > limit_bytes )); do
        [[ ! ${planned["$entry"]+set} ]] || continue
        if [[ $dry_run == true ]]; then
          printf 'would remove %s\n' "$entry"
          size=$(du -sb "$entry" | awk '{print $1}')
          total=$((total - size))
        else
          if ! aos_dev_cache_remove_rust_tree "$entry"; then
            printf 'aos-dev: skipped active Rust target tree %s\n' "$entry" >&2
          fi
          total=$(du -sb "$directory" | awk '{print $1}')
        fi
      done < <(find "$directory" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' -printf '%T@ %p\n' | sort -n)
    else
      while read -r _ size entry && (( total > limit_bytes )); do
        [[ ! ${planned["$entry"]+set} ]] || continue
        if [[ $dry_run == true ]]; then
          printf 'would remove %s\n' "$entry"
        else
          rm -f -- "$entry"
        fi
        total=$((total - size))
      done < <(find "$directory" -type f -printf '%T@ %s %p\n' | sort -n)
    fi
  fi

  if [[ $compact == true ]]; then
    if [[ $dry_run == true ]]; then
      aos_dev_cache_backend_compact "$backend" --dry-run
    else
      aos_dev_cache_backend_compact "$backend"
    fi
  fi
  printf '%s cache uses %s bytes (cap %s bytes)\n' "$backend" "$total" "$limit_bytes"
}

aos_dev_cache_clear() {
  aos_dev_cache_validate_tree
  local backend=${1:-all}
  local tree skipped=false
  local -a selected=()

  case $backend in
    all)
      selected=(go bazel rust)
      [[ ! -d $aos_dev_cache_dir/accache ]] || selected+=(accache)
      ;;
    go|bazel|rust|accache) selected=("$backend") ;;
    *) aos_dev_error "unknown cache backend '$backend'" ;;
  esac

  for backend in "${selected[@]}"; do
    [[ -d $aos_dev_cache_dir/$backend ]] || continue
    # accache-state is deliberately excluded: unlinking a held action lock
    # allows a new writer to lock a different inode for the same action.
    if [[ $backend == rust ]]; then
      while IFS= read -r -d '' tree; do
        if ! aos_dev_cache_remove_rust_tree "$tree"; then
          printf 'aos-dev: skipped active Rust target tree %s\n' "$tree" >&2
          skipped=true
        fi
      done < <(find "$aos_dev_cache_dir/rust" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' -print0)
      find "$aos_dev_cache_dir/rust" -mindepth 1 -maxdepth 1 ! -type d ! -name '.aos-cache.lock' -delete
    else
      # Remove directories too. A cache created before default ACL support
      # must be emptied before cache init can establish inherited permissions.
      find "$aos_dev_cache_dir/$backend" -mindepth 1 -depth -delete
    fi
  done

  printf 'Cleared %s cache entries under %s\n' "${1:-all}" "$aos_dev_cache_dir"
  [[ $skipped == false ]]
}
