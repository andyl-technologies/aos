# Exercises the actual source-built evaluator, separately from CLI transport mocks.
set -euo pipefail

root=$1
nix=$2
scratch=$3
mkdir -p "$scratch"

# Pure evaluation must not depend on an accessible host store or daemon.
export NIX_REMOTE=dummy://

if "${nix%/*}/nix-instantiate" --eval --raw --expr '"unused"' \
    >"$scratch/legacy.out" 2>"$scratch/legacy.err"; then
  echo 'legacy evaluator accepted unsupported --raw' >&2
  exit 1
fi
grep -Fq -- "unrecognised flag '--raw'" "$scratch/legacy.err"

# Attribute selection must apply top-level function inputs without quoting or
# splitting their values. Merely evaluating the function leaves it unapplied.
scope=$'vm.scoped "leaf"\\path\nsecond line'
cross_system='cross target with spaces'
entries=$("$nix" --extra-experimental-features nix-command eval --raw \
  --argstr category checks --argstr scope "$scope" \
  --argstr crossSystem "$cross_system" \
  --expr '{ category, scope, crossSystem }: {
    entries = builtins.concatStringsSep "\n" [ category scope crossSystem ];
  }' entries)
test "$entries" = "$(printf '%s\n%s\n%s' checks "$scope" "$cross_system")"

# This real target branch is lazy and needs no package build or daemon access.
entries=$("$nix" --extra-experimental-features nix-command eval --raw \
  --file "$root/tools/dev/targets.nix" --argstr category evals entries)
test "$entries" = $'eval\neval-standalone'

test "$(PATH="${nix%/*}:$PATH" "$BASH" "$root/tools/dev/aos-dev" --release list evals)" = "$entries"
printf 'PASS: actual target evaluator raw output and function arguments\n'
