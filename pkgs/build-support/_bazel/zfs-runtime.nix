##! Declares the OpenZFS version read by the memory-policy command at compile time.
{
  runCommand,
  zfs,
}:
runCommand "aos-bazel-zfs-runtime" {} ''
  mkdir -p "$out"
  cat > "$out/version.env" <<'ENVIRONMENT'
  AOS_ZFS_VERSION=${zfs.version}
  ENVIRONMENT
  cat > "$out/BUILD.bazel" <<'BUILD'
  exports_files(["version.env"], visibility = ["//visibility:public"])
  BUILD
  touch "$out/REPO.bazel"
''
