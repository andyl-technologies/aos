##! Target GCC shared runtimes separated from the Linux-hosted cross compiler.
{
  buildStdenv,
  buildPlatform,
  hostPlatform,
  binutils,
  gcc,
}:
(builtins.derivation {
  name = "gcc-runtime-${gcc.version}-${hostPlatform.system}";
  system = buildPlatform.system;
  builder = buildStdenv.shell;
  disallowedReferences = [gcc];
  args = [
    "-c"
    ''
      set -eu

      source_dir=${gcc}/${hostPlatform.config}/lib64
      ${buildStdenv.coreutils}/bin/mkdir -p "$out/lib"

      for family in libatomic libgcc_s libgomp libstdc++; do
        for library in "$source_dir/$family.so"*; do
          test -e "$library"
          case "$library" in
            *-gdb.py) continue ;;
          esac
          ${buildStdenv.coreutils}/bin/cp -P "$library" "$out/lib/"
        done
      done

      # GCC installs libgcc_s.so as a linker script. Strip the remaining
      # target ELF libraries so their debug tables cannot retain build inputs.
      for library in "$out/lib/"*.so.*; do
        if test ! -L "$library"; then
          ${buildStdenv.coreutils}/bin/chmod u+w "$library"
          ${binutils}/bin/strip --strip-unneeded "$library"
        fi
      done
    ''
  ];
})
// {
  inherit (gcc) version;
  passthru.evidenceSources = gcc.passthru.evidenceSources;
}
