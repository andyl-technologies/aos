set -euo pipefail

root=$1
scratch=$2
target=$scratch/target
output=$target/release/build/example-123/out/include
cross_output=$target/x86_64-unknown-linux-gnu/debug/build/example-456/out

mkdir -p "$output" "$cross_output" "$target/release/deps"
printf 'cached header\n' > "$output/read only.h"
printf 'cached tool\n' > "$cross_output/tool"
printf 'unrelated artifact\n' > "$target/release/deps/readonly.rlib"
ln -s 'read only.h' "$output/header-link"
chmod 0444 "$output/read only.h" "$target/release/deps/readonly.rlib"
chmod 0555 "$cross_output/tool"

header_mtime=$(stat -c %Y "$output/read only.h")
header_inode=$(stat -c %i "$output/read only.h")
tool_mtime=$(stat -c %Y "$cross_output/tool")
unrelated_inode=$(stat -c %i "$target/release/deps/readonly.rlib")
export CONFIG_SHELL=${BASH}
. "$root/stdenv/cargo-target-writable.sh"
aos_prepare_cargo_build_outputs "$target"

test -w "$output/read only.h"
test "$(stat -c %i "$output/read only.h")" != "$header_inode"
test "$(stat -c %a "$output/read only.h")" = 644
test -w "$cross_output/tool"
test -x "$cross_output/tool"
test "$(stat -c %a "$cross_output/tool")" = 755
test "$(stat -c %Y "$output/read only.h")" = "$header_mtime"
test "$(stat -c %Y "$cross_output/tool")" = "$tool_mtime"
test "$(stat -c %i "$target/release/deps/readonly.rlib")" = "$unrelated_inode"
test ! -w "$target/release/deps/readonly.rlib"
test -L "$output/header-link"
test "$(cat "$output/read only.h")" = 'cached header'
test "$(cat "$cross_output/tool")" = 'cached tool'

header_inode=$(stat -c %i "$output/read only.h")
aos_prepare_cargo_build_outputs "$target"
test "$(stat -c %i "$output/read only.h")" = "$header_inode"
aos_prepare_cargo_build_outputs "$target//"

printf 'rebuilt header\n' > "$scratch/new-header"
cp "$scratch/new-header" "$output/read only.h"
test "$(cat "$output/read only.h")" = 'rebuilt header'

external=$scratch/external
symlinked_target=$scratch/symlinked-target
mkdir -p "$external/example-789/out" "$symlinked_target/release"
printf 'outside target\n' > "$external/example-789/out/untouched"
chmod 0444 "$external/example-789/out/untouched"
ln -s "$external" "$symlinked_target/release/build"

if aos_prepare_cargo_build_outputs "$symlinked_target" 2> "$scratch/symlink-error"; then
  echo 'symlinked Cargo build output was accepted' >&2
  exit 1
fi
grep -Fq 'crosses a symlink' "$scratch/symlink-error"
test ! -w "$external/example-789/out/untouched"
