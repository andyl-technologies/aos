# Cache reports intentionally describe what the backend actually exposes.
# Cargo has named target trees; Go and Bazel store content-addressed records
# whose filenames do not identify the source package or Nix derivation.
aos_dev_cache_record_builds() {
  local output_file=$1 attr=$2 output deriver timestamp backend descriptor binding expected actual
  [[ -n $attr ]] || return 0
  [[ $aos_dev_go_cache == true || $aos_dev_bazel_cache == true || \
     $aos_dev_rust_target_cache == true || ${aos_dev_accache:-false} == true ]] || return 0
  [[ ! -L $aos_dev_cache_dir/builds.tsv ]] || aos_dev_error 'cache build journal must not be a symlink'
  command -v nix-store >/dev/null 2>&1 || return 0

  timestamp=$(date -u +%FT%TZ)
  while IFS= read -r output; do
    [[ $output == /nix/store/* ]] || continue
    deriver=$(nix-store --query --deriver "$output" 2>/dev/null) || continue
    for backend in go bazel rust accache; do
      case $backend in
        accache)
          [[ ${aos_dev_accache:-false} == true ]] || continue
          binding=ACCACHE_DIR
          expected=$aos_dev_accache_path
          ;;
        go)
          [[ $aos_dev_go_cache == true ]] || continue
          binding=GOCACHE
          expected=$aos_dev_go_cache_path
          ;;
        bazel)
          [[ $aos_dev_bazel_cache == true ]] || continue
          binding=AOS_BAZEL_DISK_CACHE
          expected=$aos_dev_bazel_cache_path
          ;;
        rust)
          [[ $aos_dev_rust_target_cache == true ]] || continue
          binding=CARGO_TARGET_DIR
          expected=$aos_dev_rust_cache_path
          ;;
      esac
      actual=$(nix-store --query --binding "$binding" "$deriver" 2>/dev/null) || continue
      if [[ $backend == rust ]]; then
        [[ $actual == "$expected/"* ]] || continue
      else
        [[ $actual == "$expected" ]] || continue
      fi
      # Only record direct results whose derivation actually has this backend
      # path. Opaque individual cache records still have no such provenance.
      descriptor=$(printf '%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$backend" "$attr" "$deriver" "$output")
      if command -v flock >/dev/null 2>&1; then
        (
          flock -x 9
          printf '%s\n' "$descriptor" >&9
        ) 9>>"$aos_dev_cache_dir/builds.tsv"
      else
        printf '%s\n' "$descriptor" >> "$aos_dev_cache_dir/builds.tsv"
      fi
    done
  done < "$output_file"
}

aos_dev_cache_backend_help() {
  cat <<HELP
Usage: bash ./aos-dev cache $1 <command> [options]

Commands:
  status                 Show disk use and number of stored entries
  entries [--limit N]    Show recent target trees (Rust) or files (Go/Bazel/accache)
  intermediates [--limit N]
                         Show Rust crate fingerprints and incremental trees
  builds [--limit N]     Show aos-dev build requests made with this cache enabled
  prune [--before TIME|--days N] [--max-gib N] [--dry-run] [--compact]
                         Remove old entries; Rust removes whole target trees
  compact [--dry-run]    Remove old empty directories after pruning
  clear                  Remove this backend's disposable entries
  help                   Show this page

TIME accepts a UTC date or timestamp understood by GNU date, for example
2026-09-01 or 2026-09-01T12:00:00Z. Prune defaults to 14 days; --max-gib
defaults to 50. The build journal records direct aos-dev results and their
derivers, not a claimed mapping from every hashed cache entry to a derivation.
It cannot identify transitive builds or builds made outside aos-dev.
Compact removes empty directories (only whole empty Rust target trees);
backend cache records cannot be repacked in place. Cargo may serialize builds
that use the same target tree. Accache cleanup removes disposable action/CAS
records; its separate state directory retains locks and invocation provenance.
HELP
}

aos_dev_cache_backend_status() {
  local backend=$1 directory=$aos_dev_cache_dir/$1 entries
  aos_dev_cache_validate_tree
  if [[ $backend == rust ]]; then
    entries=$(find "$directory" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' | wc -l)
    printf '%s target trees: %s\n' "$backend" "$entries"
  else
    entries=$(find "$directory" -type f | wc -l)
    printf '%s cache files: %s\n' "$backend" "$entries"
  fi
  du -sh "$directory"
}

aos_dev_cache_backend_entries() {
  local backend=$1
  shift
  aos_dev_cache_validate_tree
  local limit=30
  if (( $# > 0 )); then
    [[ $1 == --limit && $# == 2 && $2 =~ ^[1-9][0-9]*$ ]] || \
      aos_dev_error 'entries accepts --limit followed by a positive integer'
    limit=$2
  fi

  local directory=$aos_dev_cache_dir/$backend fingerprint_count incremental_count
  if [[ $backend == rust ]]; then
    # The top-level directory name carries the package and build-contract key.
    find "$directory" -mindepth 1 -maxdepth 1 -type d ! -name '.aos-*' -printf '%T@ %p\n' |
      sort -nr | sed -n "1,${limit}p" | while read -r _ path; do
        fingerprint_count=$(find "$path" -type d -path '*/.fingerprint/*' | wc -l)
        incremental_count=$(find "$path" -type d -path '*/incremental/*' | wc -l)
        printf '%s\tfingerprints=%s\tincremental=%s\t%s\n' \
          "$(du -sh "$path" | awk '{print $1}')" "$fingerprint_count" "$incremental_count" "$path"
      done
  else
    # Go and Bazel keys are opaque. Show mtime, bytes, and the actual key path.
    find "$directory" -type f -printf '%T@ %s %p\n' |
      sort -nr | sed -n "1,${limit}p"
  fi
}

aos_dev_cache_rust_intermediates() {
  aos_dev_cache_validate_tree
  local limit=30
  if (( $# > 0 )); then
    [[ $1 == --limit && $# == 2 && $2 =~ ^[1-9][0-9]*$ ]] || \
      aos_dev_error 'intermediates accepts --limit followed by a positive integer'
    limit=$2
  fi
  # Fingerprint directory names retain crate names even though individual
  # rustc object files and incremental work products use opaque hashes.
  find "$aos_dev_cache_dir/rust" -type d -path '*/.fingerprint/*' -printf '%T@ %p\n' |
    sort -nr | sed -n "1,${limit}p"
}

aos_dev_cache_backend_builds() {
  local backend=$1
  shift
  local limit=30
  if (( $# > 0 )); then
    [[ $1 == --limit && $# == 2 && $2 =~ ^[1-9][0-9]*$ ]] || \
      aos_dev_error 'builds accepts --limit followed by a positive integer'
    limit=$2
  fi
  local journal=$aos_dev_cache_dir/builds.tsv
  [[ -f $journal ]] || return 0
  [[ ! -L $journal ]] || aos_dev_error 'cache build journal must not be a symlink'
  awk -F '\t' -v backend="$backend" '$2 == backend' "$journal" | tail -n "$limit"
}

aos_dev_cache_backend_command() {
  local backend=$1 action=${2:-help}
  shift
  (( $# > 0 )) && shift
  case $action in
    help|-h|--help) aos_dev_cache_backend_help "$backend" ;;
    status) aos_dev_cache_backend_status "$backend" ;;
    entries) aos_dev_cache_backend_entries "$backend" "$@" ;;
    intermediates)
      [[ $backend == rust ]] || aos_dev_error 'only Rust exposes named intermediate records'
      aos_dev_cache_rust_intermediates "$@"
      ;;
    builds) aos_dev_cache_backend_builds "$backend" "$@" ;;
    prune) aos_dev_cache_backend_prune "$backend" "$@" ;;
    compact) aos_dev_cache_backend_compact "$backend" "$@" ;;
    clear) aos_dev_cache_clear "$backend" ;;
    *) aos_dev_error "unknown $backend cache command '$action'" ;;
  esac
}
