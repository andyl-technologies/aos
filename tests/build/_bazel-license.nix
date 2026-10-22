##! Prohibited host/plugin links must fail analysis before executing a compiler.
{
  pkgs,
  workspace,
}:
pkgs.runCommand "aos-bazel-license-boundary-analysis" {buildDeps = [pkgs.python3];} ''
  mkdir workspace
  cp -a ${workspace.source}/. workspace/
  chmod -R u+w workspace
  cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
  mkdir -p "$out"
  for target in bad_host bad_plugin; do
    if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config ${workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/$target/bazel" --nix-sandbox \
      -- build "//tools/bazel/tests/fixture/license_negative:$target" --nobuild \
      > "$out/$target.log" 2>&1; then
      echo "prohibited license-domain link passed analysis: $target" >&2
      exit 1
    fi
    grep -F 'AOS license boundary:' "$out/$target.log"
    grep -F 'cannot link' "$out/$target.log"
  done
''
