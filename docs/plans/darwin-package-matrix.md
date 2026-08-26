# Darwin package build and publication matrix

The authoritative package inventory is
[`pkgs/_platform-support.nix`](../../pkgs/_platform-support.nix). It classifies
every package root, package expression, factory, underscore-prefixed helper,
and excluded source resource. Classification is fail-closed: adding or removing
any of them without updating the inventory makes the evaluation check fail.

This inventory describes the intended result, not the current build state. A
package marked `target` must eventually produce an executable or library for
the selected Darwin architecture. Marking it eligible does not permit stubbing
features, using a host tool, importing nixpkgs, or skipping its dependency
chain. A package marked `independent` contains no host executable and may reuse
the same store object for multiple platform entries. `build-only` roots are
Linux-native test or bootstrap artifacts. `linux-only` roots implement Linux
kernel, guest, service-manager, security or device interfaces and are never
published under a Darwin platform key.

The selector filters publication roots only. It must not filter dependencies
from a derivation. Cross builds use separate package sets so native code
generators and build tools come from the Linux build package set while headers,
libraries and final programs come from the Darwin host package set.

## Dependency waves

| Wave | Scope | Required cross-build work |
| --- | --- | --- |
| 1 | Target-independent data, leaf libraries, GNU/POSIX basics | Source SDK and sysroot, cctools/ld64, Mach-O fixup, basic Autoconf triples |
| 2 | Portable C/C++ libraries and Unix tools | Consistent build/host flags, native generators, Darwin API and library selection |
| 3 | Compilers, interpreters and build systems | Build/host/target package splicing, Canadian-cross layouts, target test deferral |
| 4 | AOS and third-party applications | Language target configuration, platform-specific runtime closures, static artifact validation |
| 5 | Bazel, Envoy and the OpenJDK ladder | Native bootstrap tools, JNI/HotSpot target builds, large target-generated source graphs |

Both matrices contain every eligible package unless upstream support is
architecture-specific. The current architecture exception inventory is
limited to Go 1.4 and OpenJDK 7 through 16, which produce x86_64 Darwin outputs;
the current Go, Rust, LLVM/Clang, GCC, Node, Python and OpenJDK packages are
required for both x86_64 Darwin and AArch64 Darwin.

## Critical toolchains

| Package | Darwin build contract |
| --- | --- |
| `cc`, `llvm` | Linux-native table generators; Darwin Clang, compiler-rt, libc++, libc++abi and linker integration |
| `gcc`, `gcc-libs` | Darwin-hosted GCC and runtimes built against the source SDK and linked through cctools/ld64 |
| `rust` | Linux build rustc/cargo; Darwin-hosted rustc/cargo and standard libraries for both architectures |
| `go` | Linux bootstrap Go; `GOOS=darwin` toolchain and standard library, with Darwin CGo compiler wiring |
| `python3` | Linux build Python for generators; Darwin interpreter, stdlib and extension modules |
| `nodejs` | Linux-native V8/Node generators; Darwin Node executable and bundled runtime libraries |
| `openjdk` | Linux build JDK; Darwin HotSpot/JDK image, using the SDK frameworks instead of Linux ALSA/X11 inputs |
| `bazel` | Linux Java/bootstrap actions; Darwin launcher/JNI outputs and Darwin toolchain configuration |

`aos` is also an explicit portability boundary. Its Darwin closure contains
construct, registry, cache and publication functions. Linux activation,
SELinux/eBPF, systemd, mount and guest-image runtime helpers must be selected at
runtime or split from the package instead of entering the Darwin closure.

## Validation

Evaluate the inventory without building packages:

```text
nix-instantiate --eval --strict -E \
  'let aos = import ./. {}; s = import ./pkgs/_platform-support.nix; \
   in s.validate (aos.pkgs.allPackageNames or aos.pkgs.packageNames)'
```

Build the focused check after it is wired into the top-level check set:

```text
nix-build -A checks.build.package-platform-support
```

Successful Linux-hosted builds prove that the target closure can be produced
and statically inspected. Runtime tests remain a separate macOS qualification
gate and must not be represented as having run during cross compilation.
