# Runs inside the existing headless VM harness. Its successful exit is the
# prerequisite for the harness to publish serial.log, fc.log and a PASS result.
set -euo pipefail
umask 077
unset LD_LIBRARY_PATH

# The harness mounts /tmp as tmpfs and boots the ext4 root read-only. All
# repository, authority, source and checkout state must use the actual disk.
mount -o remount,rw /
workflow_root=/var/lib/terrane-local-workflow
mkdir -p "$workflow_root/source/nested" "$workflow_root/logs" "$workflow_root/expected"
filesystem=$(findmnt --noheadings --output FSTYPE --target "$workflow_root")
test "$filesystem" = ext4
printf 'workflow filesystem: %s\n' "$filesystem"

main_ref=refs/heads/_/main
feature_ref=refs/heads/_/feature
bucket_url=file://$workflow_root/bucket
authority_dir=$workflow_root/authority
owner_uid=$(id -u)

cli() {
    local operation=$1 label=$2
    shift 2
    local started=$SECONDS
    printf 'starting %s: %s\n' "$label" "$operation" >&2

    if ! @TERRANE@ "$operation" --bucket "$bucket_url" \
        --authority "$authority_dir" --owner-uid "$owner_uid" \
        --policy-authority "$main_ref" "$@" \
        >"$workflow_root/logs/$label.stdout" 2>"$workflow_root/logs/$label.stderr"; then
        cat "$workflow_root/logs/$label.stdout" "$workflow_root/logs/$label.stderr" >&2
        return 1
    fi

    cat "$workflow_root/logs/$label.stderr" >&2
    printf 'finished %s after %s seconds\n' "$label" "$((SECONDS - started))" >&2
    cat "$workflow_root/logs/$label.stdout"
}

require_digest() {
    [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

verify_checkout() {
    local directory=$1 has_main=$2 has_feature=$3
    local expected_count=3
    cmp "$workflow_root/expected/original" "$directory/original"
    cmp "$workflow_root/expected/executable" "$directory/nested/executable"
    test "$(readlink "$directory/link")" = original
    test "$(stat --format=%a "$directory/nested/executable")" = 750
    test "$(findmnt --noheadings --output FSTYPE --target "$directory")" = ext4

    if test "$has_main" = yes; then
        cmp "$workflow_root/expected/main" "$directory/main"
        expected_count=$((expected_count + 1))
    else
        test ! -e "$directory/main"
    fi
    if test "$has_feature" = yes; then
        cmp "$workflow_root/expected/feature" "$directory/feature"
        expected_count=$((expected_count + 1))
    else
        test ! -e "$directory/feature"
    fi

    # Include hidden entries so unexpected checkout content cannot pass merely
    # because all the expected files were also present.
    local entries
    shopt -s nullglob dotglob
    entries=("$directory"/*)
    test "${#entries[@]}" -eq "$expected_count"
    entries=("$directory/nested"/*)
    test "${#entries[@]}" -eq 1
}

not_after=$(($(date +%s) + 3600))
initialized=$(cli init initialize --not-after "$not_after")
test "$initialized" = "initialized $main_ref"
test "$(stat --format=%a "$authority_dir")" = 700
for name in issuer.seed terminal.seed token.cbor; do
    test "$(stat --format=%a "$authority_dir/$name")" = 600
    cp "$authority_dir/$name" "$workflow_root/expected/$name"
done

printf 'original content\0binary\377\n' >"$workflow_root/expected/original"
printf 'executable content\n' >"$workflow_root/expected/executable"
printf 'feature content\n' >"$workflow_root/expected/feature"
printf 'main content\n' >"$workflow_root/expected/main"
cp "$workflow_root/expected/original" "$workflow_root/source/original"
cp "$workflow_root/expected/executable" "$workflow_root/source/nested/executable"
chmod 750 "$workflow_root/source/nested/executable"
ln -s original "$workflow_root/source/link"

original=$(cli commit original "$workflow_root/source" --message 'Import directory')
require_digest "$original"
fork=$(cli fork fork "$feature_ref" --message 'Fork feature')
require_digest "$fork"

cp "$workflow_root/expected/feature" "$workflow_root/source/feature"
feature=$(cli commit feature --reference "$feature_ref" \
    "$workflow_root/source" --message 'Add feature file')
require_digest "$feature"
test "$feature" != "$fork"

rm "$workflow_root/source/feature"
cp "$workflow_root/expected/main" "$workflow_root/source/main"
main=$(cli commit main "$workflow_root/source" --message 'Add main file')
require_digest "$main"
test "$main" != "$original"
merged=$(cli merge merge "$feature_ref" --message 'Merge feature')
require_digest "$merged"
test "$merged" != "$main"
test "$merged" != "$feature"

# Every CLI command opens persisted state in a separate process. Remove the
# authoring directory before checkout so content must survive in the bucket.
rm -r "$workflow_root/source"
sync
selected=$(cli checkout merged-checkout "$main_ref" "$workflow_root/merged")
test "$selected" = "$merged"
verify_checkout "$workflow_root/merged" yes yes

selected=$(cli checkout feature-checkout --reference "$feature_ref" \
    "$feature_ref" "$workflow_root/feature")
test "$selected" = "$feature"
verify_checkout "$workflow_root/feature" no yes

selected=$(cli checkout historical-checkout "commit:$original" "$workflow_root/historical")
test "$selected" = "$original"
verify_checkout "$workflow_root/historical" no no

# Reopen the on-disk repository again after all views have been served. The
# live branch must retain its merge and the fixed target must retain its bytes.
sync
selected=$(cli checkout reopened-main "$main_ref" "$workflow_root/reopened-main")
test "$selected" = "$merged"
verify_checkout "$workflow_root/reopened-main" yes yes
selected=$(cli checkout reopened-historical "commit:$original" \
    "$workflow_root/reopened-historical")
test "$selected" = "$original"
verify_checkout "$workflow_root/reopened-historical" no no
for name in issuer.seed terminal.seed token.cbor; do
    cmp "$workflow_root/expected/$name" "$authority_dir/$name"
done

printf 'original=%s\nfeature=%s\nmain=%s\nmerged=%s\n' \
    "$original" "$feature" "$main" "$merged"
sync
printf '%s\n' 'local ext4 workflow completed'
