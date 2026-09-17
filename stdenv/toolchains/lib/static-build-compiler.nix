##! Pins cross-build generators to the preceding tier's static host toolchain.
{
  tools,
  systemHeaderFlag ? "-isystem",
}: ''
  # GMP probes and build generators can omit CFLAGS and LDFLAGS. Retain the
  # host compiler's complete invocation independently of the target compiler.
  mkdir -p "$TMPDIR/build-compiler"
  cat > "$TMPDIR/build-compiler/gcc" <<'AOS_BUILD_COMPILER'
  #!${tools.bash}/bin/bash
  exec ${tools.gcc}/bin/gcc -static ${systemHeaderFlag} ${tools.glibc}/include -L${tools.glibc}/lib "$@"
  AOS_BUILD_COMPILER
  cat > "$TMPDIR/build-compiler/g++" <<'AOS_BUILD_COMPILER'
  #!${tools.bash}/bin/bash
  exec ${tools.gcc}/bin/g++ -static ${systemHeaderFlag} ${tools.glibc}/include -L${tools.glibc}/lib "$@"
  AOS_BUILD_COMPILER
  chmod +x "$TMPDIR/build-compiler/gcc" "$TMPDIR/build-compiler/g++"

  export CC_FOR_BUILD="$TMPDIR/build-compiler/gcc"
  export CXX_FOR_BUILD="$TMPDIR/build-compiler/g++"
  export BUILD_CC="$CC_FOR_BUILD"
''
