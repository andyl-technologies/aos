##! Selects GCC-built tools explicitly while constructing public bootstrap tools.
{
  tools,
  glibc,
  bash,
  buildPlatform,
}:
builtins.derivation {
  name = "bootstrap-gcc-for-exports";
  system = buildPlatform.system;
  builder = "${tools.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${tools.coreutils}/bin:${tools.sed}/bin"
      mkdir -p "$out/bin" "$out/lib/gcc-lib/i686-unknown-linux-gnu"

      # GCC 2.95 gives its private library directory priority over some -B
      # searches. Give this build-only driver its own startup objects and tool
      # aliases instead of inheriting the TCC assembler from the original dir.
      cp -R ${tools.gcc}/lib/gcc-lib/i686-unknown-linux-gnu/2.95.3 \
        "$out/lib/gcc-lib/i686-unknown-linux-gnu/2.95.3"
      chmod -R u+w "$out/lib"
      compiler_library="$out/lib/gcc-lib/i686-unknown-linux-gnu/2.95.3"
      cp ${glibc}/lib/crt1.o ${glibc}/lib/crti.o ${glibc}/lib/crtn.o "$compiler_library/"
      cp ${glibc}/lib/libc.a "$compiler_library/"
      ln -sf ${tools.binutils}/bin/as "$compiler_library/as"
      ln -sf ${tools.binutils}/bin/ld "$compiler_library/ld"

      cat > "$out/bin/gcc" <<EOF
      #!${bash}/bin/bash
      exec ${tools.gcc}/bin/gcc-real -B$compiler_library/ -B${tools.binutils}/bin/ -isystem ${glibc}/include -isystem ${tools.linuxHeaders}/include -L${glibc}/lib -static "\$@"
      EOF
      chmod 755 "$out/bin/gcc"
      ln -s gcc "$out/bin/cc"
      ln -s ${tools.gcc}/bin/gcc-real "$out/bin/gcc-real"

      for program in as ld; do
        selected=$("$out/bin/gcc" -print-prog-name="$program")
        test "$(readlink -f "$selected")" = "$(readlink -f "${tools.binutils}/bin/$program")"
      done
    ''
  ];
}
