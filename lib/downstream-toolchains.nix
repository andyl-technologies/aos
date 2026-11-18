##! Package names in the downstream toolchain set.
##!
##! A downstream workspace that takes AOS as its only input realizes these
##! packages, with every named output, as its compilers and build tools. The
##! release package matrix must publish each one's complete runtime closure on
##! both Linux platforms, so the substituted store paths are identical on
##! every machine that uses the same AOS revision. The flake exports the set
##! as `lib.<system>.toolchains`; `toolchain-cache-check` verifies that a
##! machine would download, not build, every member.
[
  # Bazel and the JDK it runs on.
  "bazel"
  "openjdk-21"

  # C and C++: the compiler wrapper AOS builders use, its GCC, binutils, and
  # C library, and the LLVM toolchain.
  "cc"
  "gcc"
  "binutils"
  "glibc"
  "llvm"

  # Language toolchains.
  "rust"
  "go"
  "nodejs"
  "pnpm"
  "python3"

  # Protocol Buffers compiler.
  "protobuf"
]
