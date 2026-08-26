##! workerd (from source) — Cloudflare's Workers runtime, built hermetically.
##!
##! This is the genuinely-from-source build of `workerd` (RFC-0004 follow-on),
##! replacing the prebuilt binary seed in `workerd.nix`. It compiles workerd's
##! full Bazel graph — V8, Cap'n Proto, BoringSSL, ICU, zlib, lolhtml (Rust) —
##! against AOS-built tools only (AOS Bazel 7, AOS LLVM/clang+libc++, AOS Rust,
##! AOS Python, AOS Node is *not* required for the server binary target).
##!
##! ## Why a separate attr from `workerd.nix`
##!
##! The green `checks.vm.worker` test depends on the binary seed. This package
##! is staged as `pkgs.workerd-source` so the seed stays intact until the
##! from-source build is verified and verified in that VM test. Once green, the
##! seed can be replaced.
##!
##! ## Toolchain (the hard part)
##!
##! workerd's `.bazelrc` pins a clang + **libc++** Linux toolchain:
##!   --action_env=CC=clang / CXX=clang++ / BAZEL_COMPILER=clang
##!   -stdlib=libc++ -l:libc++.a -lm -static-libgcc
##!
##! AOS `pkgs.llvm` provides exactly this (clang, clang++, lld, libc++.a,
##! libc++abi.a, libunwind.a, libc++ headers under
##! `lib/x86_64-unknown-linux-gnu/`). But AOS clang is *not* self-contained: it
##! needs `--gcc-install-dir`, glibc headers via `-idirafter`, `-B`/`-L` for the
##! GCC install + glibc, a `-Wl,-dynamic-linker`, and rpaths. We satisfy this by
##! installing `clang`/`clang++` *wrappers* on PATH (named exactly `clang` /
##! `clang++` so Bazel's CC auto-detection finds them) that inject all the AOS
##! toolchain flags before delegating to the real `${llvm}/bin/clang`.
##!
##! ## Two-phase FOD build (mkBazelPackage)
##!
##! Like `envoy.nix`: `fetchBazelDeps` downloads the whole external graph with
##! network access into a fixed-output derivation; the offline build phase
##! patchelfs downloaded ELFs and builds against the vendored deps.
{
  mkBazelPackage,
  mkDerivation,
  stdenv,
  buildPackages,
  fetchurl,
  lib,
  bazel-7,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk,
  gcc,
  binutils,
  llvm,
  rust,
  cmake,
  ninja,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  ca-certificates,
  perl,
  gnumake,
  pkg-config,
  git,
  nodejs,
  gcc-libs,
  zlib,
  bootstrapTools,
}: let
  version = "1.20240909.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;

  # Everything Bazel executes stays on the Linux build platform.  The Darwin
  # package set is reserved for link inputs and the final workerd binary; using
  # target Bazel/JDK/Python here would either execute Mach-O during analysis or
  # recursively force the entire Darwin-hosted Java bootstrap ladder.
  buildBazel =
    if isDarwinCross
    then buildPackages.bazel-7
    else bazel-7;
  buildJdk =
    if isDarwinCross
    then buildPackages.openjdk
    else openjdk;
  buildBash =
    if isDarwinCross
    then buildPackages.bash
    else bash;
  buildCoreutils =
    if isDarwinCross
    then buildPackages.coreutils
    else coreutils;
  buildPython =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  buildLlvm =
    if isDarwinCross
    then buildPackages.llvm
    else llvm;
  buildRust =
    if isDarwinCross
    then rust.passthru.buildTool
    else rust;
  nativeRust =
    if isDarwinCross
    then buildPackages.rust
    else rust;
  buildGcc =
    if isDarwinCross
    then buildPackages.gcc
    else gcc;
  buildGccLibs =
    if isDarwinCross
    then buildPackages.gcc-libs
    else gcc-libs;
  buildZlib =
    if isDarwinCross
    then buildPackages.zlib
    else zlib;
  buildSed =
    if isDarwinCross
    then buildPackages.sed
    else sed;
  buildGawk =
    if isDarwinCross
    then buildPackages.gawk
    else gawk;
  buildGnumake =
    if isDarwinCross
    then buildPackages.gnumake
    else gnumake;
  buildNodejs =
    if isDarwinCross
    then buildPackages.nodejs
    else nodejs;
  buildCaCertificates =
    if isDarwinCross
    then buildPackages.ca-certificates
    else ca-certificates;
  buildBootstrapTools =
    if isDarwinCross
    then buildPackages.bootstrapTools
    else bootstrapTools;
  darwinBazelCpu =
    if stdenv.hostPlatform.isAarch64
    then "darwin_arm64"
    else "darwin_x86_64";
  darwinBazelCpuConstraint =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86_64";
  darwinTargetTriple = stdenv.hostPlatform.config;
  llvmMajor = builtins.head (lib.splitString "." buildLlvm.version);

  # Minimal native Tcl interpreter, built from source. workerd's vendored sqlite3
  # amalgamation generates `sqlite3.h` with a genrule that runs
  # `tclsh mksqlite3h.tcl` (a 165-line Tcl script that adds SQLITE_API/EXTERN
  # prefixes and substitutes version/source-id). Keep the historical Tcl 8.6
  # tool for native builds; cross builds must use the native package-set Tcl so
  # Bazel never attempts to execute a Darwin binary on the Linux builder.
  tcl = mkDerivation {
    pname = "tcl";
    version = "8.6.14";
    src = fetchurl {
      urls = [
        "https://prdownloads.sourceforge.net/tcl/tcl8.6.14-src.tar.gz"
        "https://downloads.sourceforge.net/tcl/tcl8.6.14-src.tar.gz"
      ];
      hash = "sha256-WIAiW6v3lUxY1PsPXPYnkQTOHNaqm3HppjIlQOHE3mY=";
    };
    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tcl8.6.14/unix
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out --disable-shared
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
          # `make install` names the binary `tclsh8.6`; sqlite3's genrule calls
          # bare `tclsh`, so add that alias.
          ln -sf "$out/bin/tclsh8.6" "$out/bin/tclsh"
        '';
      }
    ];
  };

  tclBuildPackage =
    if stdenv.isCross
    then buildPackages.tcl
    else tcl;

  # Tcl 9 intentionally installs the versioned `tclsh9.0` name, while
  # sqlite's Bazel generator invokes bare `tclsh`. Put the compatibility name
  # in an ordinary native build-tool output so Bazel's fixed action PATH sees
  # it without exposing the target package or a phase-local directory.
  tclBuildTool =
    if isDarwinCross
    then
      buildPackages.runCommand "workerd-tcl-build-tool" {} ''
        mkdir -p "$out/bin"
        test -x "${tclBuildPackage}/bin/tclsh9.0"
        ln -s "${tclBuildPackage}/bin/tclsh9.0" "$out/bin/tclsh"
      ''
    else tclBuildPackage;

  tools = [
    buildBash
    buildCoreutils
    (
      if isDarwinCross
      then buildPackages.which
      else which
    )
    (
      if isDarwinCross
      then buildPackages.zip
      else zip
    )
    (
      if isDarwinCross
      then buildPackages.unzip
      else unzip
    )
    buildGawk
    buildPython
    buildGcc
    (
      if isDarwinCross
      then buildPackages.binutils
      else binutils
    )
    buildLlvm
    buildRust
    (
      if isDarwinCross
      then buildPackages.cmake
      else cmake
    )
    (
      if isDarwinCross
      then buildPackages.ninja
      else ninja
    )
    (
      if isDarwinCross
      then buildPackages.grep
      else grep
    )
    (
      if isDarwinCross
      then buildPackages.gzip
      else gzip
    )
    (
      if isDarwinCross
      then buildPackages.patch
      else patch
    )
    (
      if isDarwinCross
      then buildPackages.diffutils
      else diffutils
    )
    (
      if isDarwinCross
      then buildPackages.findutils
      else findutils
    )
    buildSed
    (
      if isDarwinCross
      then buildPackages.tar
      else tar
    )
    (
      if isDarwinCross
      then buildPackages.xz
      else xz
    )
    (
      if isDarwinCross
      then buildPackages.file
      else file
    )
    (
      if isDarwinCross
      then buildPackages.perl
      else perl
    )
    buildGnumake
    (
      if isDarwinCross
      then buildPackages.pkg-config
      else pkg-config
    )
    # workerd fetches V8, dawn, and their deps via `git_repository` (googlesource
    # tarballs are non-deterministic, so the WORKSPACE clones over git). The FOD
    # fetch needs a real git on PATH; the build phase prepends a fake git for the
    # workspace-status command, which shadows this one there.
    (
      if isDarwinCross
      then buildPackages.git
      else git
    )
    # rules_js runs TypeScript tooling (tsc, the ts_project validator) under
    # Node during the server build's capnp->TS type generation. We wire AOS
    # Node into the rules_js node toolchain in preBazelBuild; it must be on
    # PATH for the build actions.
    buildNodejs
    # sqlite3's amalgamation genrule runs `tclsh mksqlite3h.tcl` to generate
    # sqlite3.h; provide a native from-source Tcl interpreter on PATH.
    tclBuildTool
  ];

  src = fetchurl {
    urls = [
      "https://github.com/cloudflare/workerd/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-og83fVR/VGerqMtu2qBrsP/jXJk3MtXyfqYQpv7Za8A=";
  };

  # Rewrites workerd's WORKSPACE `aspect_rules_js` http_archive to inject a
  # `patch_cmds` that (a) fixes the `/usr/bin/env bash` shebangs in the
  # downloaded rules_js tree and (b) replaces the shell-based `_exists` helper
  # in `npm/private/utils.bzl` with a pure-Starlark `rctx.path(p).exists`
  # check. rules_js's `_exists` writes `_exists.sh` (`#!/usr/bin/env bash`) and
  # execs it; in the hermetic sandbox `/usr/bin/env` is absent, so the exec
  # returns neither 0 nor 42 and trips `fail(INTERNAL_ERROR_MSG)` (the
  # `@@npm//` "rules_js internal error"). Bazel 7's `repository_ctx.path` has
  # an `exists` property, so we sidestep the shell entirely. Generated as a
  # file so the quoting survives FOD-builder embedding unchanged.
  patchWorkspacePy = builtins.toFile "patch-workspace.py" ''
    import re
    import sys

    path = sys.argv[1]
    aos_bash = sys.argv[2]

    with open(path) as f:
        src = f.read()

    # Idempotent: postPatchScript runs in both the fetch FOD and the build
    # phase (and possibly twice in the build phase), so bail out cleanly if the
    # WORKSPACE has already been rewritten. Injecting twice would produce a
    # `duplicate keyword argument: patch_cmds` Starlark error. We key on a
    # marker unique to our injection (the `_exists.sh` -> struct rewrite), since
    # workerd's WORKSPACE already uses `patch_cmds` for other http_archives.
    marker = "result = struct(return_code = 0 if rctx"
    if marker in src:
        print("AOS-DEBUG: WORKSPACE already patched; skipping")
        sys.exit(0)

    anchor = 'url = "https://github.com/aspect-build/rules_js/releases/download/v2.0.0/rules_js-v2.0.0.tar.gz",'
    assert anchor in src, "rules_js http_archive url anchor not found in WORKSPACE"

    # --- Use AOS python instead of a prebuilt CPython toolchain ----------
    # workerd's WORKSPACE calls `python_register_toolchains(name="python3_12",
    # python_version="3.12")`, which downloads a prebuilt, dynamically-linked
    # CPython whose ELF interpreter (`/lib64/ld-linux-*`) is absent in the Nix
    # sandbox -> `execvp(.../python3): No such file or directory` during
    # analysis. We drop that registration, drop the `interpreter` load it
    # feeds, and drop the `python_interpreter_target = interpreter` pins on the
    # `pip_parse` calls. rules_python then falls back to its autodetecting
    # toolchain, which resolves `python3` from PATH (AOS python3 is in `tools`).
    src = re.sub(
        r'python_register_toolchains\(\s*name = "python3_12",.*?\n\)\n',
        "",
        src,
        flags=re.DOTALL,
    )
    src = src.replace(
        'load("@python3_12//:defs.bzl", "interpreter")\n',
        "",
    )
    src = re.sub(
        r'\n[ \t]*python_interpreter_target = interpreter,',
        "",
        src,
    )

    ${
      if isDarwinCross
      then ''
        # rules_rust otherwise registers only same-platform compiler/stdlib
        # pairs.  Register the Darwin stdlib for the Linux execution compiler;
        # the build phase replaces that fetched compiler with AOS's
        # source-built native Rust build tool while preserving the generated
        # cross-toolchain metadata.
        src = src.replace(
            "extra_target_triples = [],",
            'extra_target_triples = ["${darwinTargetTriple}"],',
            1,
        )
      ''
      else ""
    }

    # patch_cmds run as shell (bash -c) after extraction, before any repo rule
    # executes. We wrap every sed program in SINGLE quotes so the embedded
    # double quotes survive the shell, and use the '@' delimiter so the '|'
    # characters in paths/regex never collide. Each entry is rendered into the
    # WORKSPACE with Python repr() so the Starlark string is exact.
    #
    # (1) Replace the shell-exec helper in _exists with a struct whose
    #     return_code mirrors rctx.path(p).exists (a Bazel 7 path property),
    #     keeping the downstream return_code == 0/42 logic valid. This is the
    #     decisive fix: it removes the `_exists.sh` exec (whose shebang can't
    #     run in the sandbox) entirely. BRE escapes: \. \[ \] for the literal
    #     dots and brackets in `rctx.execute(["./_exists.sh", str(p)])`.
    cmd_exists = (
        "sed -i "
        "'s@result = rctx\\.execute(\\[\"\\./_exists\\.sh\", str(p)\\])"
        "@result = struct(return_code = 0 if rctx\\.path(p)\\.exists else 42)@' "
        "npm/private/utils.bzl"
    )
    # (2) Belt-and-suspenders: rewrite any remaining /usr/bin/env bash shebangs
    #     to AOS bash across the tree, for any other script rules_js execs.
    cmd_shebang = (
        "find . -type f \\( -name '*.bzl' -o -name '*.sh' -o -name '*.py' "
        "-o -name '*.tpl' \\) -exec sed -i "
        ${
      if isDarwinCross
      then ''"'s@^#!/usr/bin/env bash$@#!" + aos_bash + "/bin/bash@g' {} +"''
      else ''"'s@#!/usr/bin/env bash@#!" + aos_bash + "/bin/bash@g' {} +"''
    }
    )

    patch_block = (
        anchor + "\n"
        "    patch_cmds = [\n"
        "        " + repr(cmd_exists) + ",\n"
        "        " + repr(cmd_shebang) + ",\n"
        "    ],"
    )

    src = src.replace(anchor, patch_block, 1)

    with open(path, "w") as f:
        f.write(src)

    print("AOS-DEBUG: injected rules_js patch_cmds")
  '';

  # Store path scrubbing map — shared between fetch and build phases so that
  # store paths baked into vendored files become reproducible placeholders.
  scrub = builtins.unsafeDiscardStringContext;
  scrubMap = {
    "${scrub buildPython}" = "__AOS_PYTHON__";
    "${scrub buildBash}" = "__AOS_BASH__";
    "${scrub buildCoreutils}" = "__AOS_COREUTILS__";
    "${scrub buildRust}" = "__AOS_RUST__";
    "${scrub buildLlvm}" = "__AOS_LLVM__";
    "${scrub buildGcc}" = "__AOS_GCC__";
  };

  # Build a clang/clang++ wrapper directory. AOS clang needs the GCC install dir
  # + glibc + dynamic-linker injected on every invocation; Bazel's CC toolchain
  # auto-detection just runs `clang`/`clang++` from PATH, so the wrappers carry
  # the flags. Emitted at the top of postPatch (shared fetch+build), written to
  # $SRCDIR/aos-toolchain so it survives into the build via --override flags.
  toolchainSetup = ''
    BT="${buildBootstrapTools}"
    REAL_CC=$(cat "$BT/nix-support/orig-cc")
    REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
    REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
    GCC_DIR=${
      if isDarwinCross
      then "$(dirname \"$(${buildGcc}/bin/gcc -print-libgcc-file-name)\")"
      else "$(echo \"$REAL_CC\"/lib/gcc/x86_64-unknown-linux-gnu/*)"
    }
    DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)

    mkdir -p "$SRCDIR/aos-toolchain"

    # workerd's .bazelrc forces `-stdlib=libc++` for both target and host
    # configs. AOS clang must find libc++'s C++ headers (<cstddef> etc.) for
    # that to work; with `--gcc-install-dir` present, clang would otherwise
    # search GCC's libstdc++ headers, and `-no-canonical-prefixes` stops it
    # from auto-locating its own `include/c++/v1`. Without these, capnp's
    # `kj/memory.h` fails with `no type named 'nullptr_t' in namespace 'std'`.
    # Inject the libc++ include dirs as `-isystem` (so they sort before the
    # `-idirafter` glibc headers, and `#include_next` chains stay correct).
    LIBCXX_INC="${buildLlvm}/include/c++/v1"
    LIBCXX_INC_TARGET="${buildLlvm}/include/x86_64-unknown-linux-gnu/c++/v1"

    # COMPILE *and* LINK with AOS clang/clang++ + lld, on the LLVM-native
    # runtime: compiler-rt builtins (the AOS GCC ships no static libgcc_eh.a, so
    # `--rtlib=libgcc` cannot link C++ exceptions) plus libunwind for unwinding.
    # The earlier "clang/lld is broken" diagnosis was wrong: AOS clang+lld links
    # working native binaries given a correct library search path.
    #
    # The host tools crashed at startup for a concrete, deterministic reason: the
    # AOS gcc-14 *stage2* install dir ships a stray *static* `libc.a`, and
    # `--gcc-install-dir`/`-B$GCC_DIR` puts it on the linker search path. Without
    # an *earlier* `-L` into the dynamic glibc, the implicit `-lc`/`-lm` resolve
    # to that static `libc.a` — so `libc-start.o`/`libc-tls.o` get linked
    # statically into a binary that is otherwise a dynamically-interpreted PIE.
    # That static/dynamic libc mismatch breaks `__libc_start_main`/TLS setup and
    # SIGSEGVs before `main` (which looks like a GOT-after-RELRO fault). The fix
    # is to lead the link line with `-L$REAL_LIBC/lib` so `-lc`/`-lm` bind to the
    # dynamic glibc `.so`, exactly as the cc-wrapper gcc's `cc-ldflags` do. The
    # wrapper also pins the AOS glibc dynamic linker + rpath and the libc++ rpath
    # on every link. ${bootstrapTools} (stdenv.cc) is no longer on the link path.
    LINK_COMMON="-L$REAL_LIBC/lib --gcc-install-dir=$GCC_DIR -B$REAL_LIBC/lib -B$GCC_DIR -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -L${buildLlvm}/lib/x86_64-unknown-linux-gnu -Wl,-dynamic-linker=$DL -Wl,-rpath,$REAL_LIBC/lib -Wl,-rpath,${buildLlvm}/lib/x86_64-unknown-linux-gnu"

    {
      printf '%s\n' '#!${buildBash}/bin/bash'
      printf '%s\n' 'case " $* " in'
      printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
      # Bazel can route generated C exec tools through the C wrapper while its
      # global workerd flags still request libc++. Hide GCC's libstdc++ headers
      # before adding LLVM libc++; otherwise <cmath> reaches GCC's <math.h> and
      # mixes two incompatible C++ standard-library implementations.
      printf '%s\n' "    exec ${buildLlvm}/bin/clang -nostdinc++ -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
      printf '%s\n' 'esac'
      # Bazel's generated response files can retain the auto-detected GNU C++
      # runtime even though workerd explicitly selects libc++. Remove that one
      # library before appending libc++abi/libunwind; mixing the ABI runtimes
      # produces duplicate symbols in native generators such as capnp_tool.
      printf '%s\n' 'link_args=()'
      printf '%s\n' 'for arg in "$@"; do'
      printf '%s\n' '  case "$arg" in'
      printf '%s\n' '    -lstdc++) continue ;;'
      printf '%s\n' "    @*) response_file=\"\''${arg#@}\"; if [ -f \"\$response_file\" ]; then ${buildSed}/bin/sed -i '/^[[:space:]]*-lstdc++[[:space:]]*\$/d; s/[[:space:]]-lstdc++\([[:space:]]\|\$\)/\1/g' \"\$response_file\"; fi ;;"
      printf '%s\n' '  esac'
      printf '%s\n' '  link_args+=("$arg")'
      printf '%s\n' 'done'
      printf '%s\n' "exec ${buildLlvm}/bin/clang $LINK_COMMON \"\''${link_args[@]}\""
    } > "$SRCDIR/aos-toolchain/clang"
    chmod +x "$SRCDIR/aos-toolchain/clang"

    {
      printf '%s\n' '#!${buildBash}/bin/bash'
      printf '%s\n' 'case " $* " in'
      printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
      printf '%s\n' "    exec ${buildLlvm}/bin/clang++ -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
      printf '%s\n' 'esac'
      # -nostdlib++: link the explicit static libc++ (.bazelrc -l:libc++.a) plus
      # libc++abi/libunwind appended as linkopts, never clang's default
      # libstdc++, so the two C++ runtimes never collide.
      printf '%s\n' 'link_args=()'
      printf '%s\n' 'for arg in "$@"; do'
      printf '%s\n' '  case "$arg" in'
      printf '%s\n' '    -lstdc++) continue ;;'
      printf '%s\n' "    @*) response_file=\"\''${arg#@}\"; if [ -f \"\$response_file\" ]; then ${buildSed}/bin/sed -i '/^[[:space:]]*-lstdc++[[:space:]]*\$/d; s/[[:space:]]-lstdc++\([[:space:]]\|\$\)/\1/g' \"\$response_file\"; fi ;;"
      printf '%s\n' '  esac'
      printf '%s\n' '  link_args+=("$arg")'
      printf '%s\n' 'done'
      printf '%s\n' "exec ${buildLlvm}/bin/clang++ -nostdlib++ $LINK_COMMON \"\''${link_args[@]}\""
    } > "$SRCDIR/aos-toolchain/clang++"
    chmod +x "$SRCDIR/aos-toolchain/clang++"

    # Provide the remaining LLVM binutils Bazel's clang toolchain expects.
    for t in ld.lld lld llvm-ar ar llvm-nm nm llvm-objcopy objcopy \
             llvm-objdump objdump llvm-strip strip llvm-dwp dwp \
             llvm-cov cov llvm-profdata profdata llvm-symbolizer; do
      if [ -e "${buildLlvm}/bin/$t" ]; then
        ln -sf "${buildLlvm}/bin/$t" "$SRCDIR/aos-toolchain/$t"
      fi
    done
    # Bazel's unix cc toolchain calls `ar` and the gcov tool; alias clang as cc.
    ln -sf "$SRCDIR/aos-toolchain/clang" "$SRCDIR/aos-toolchain/cc"
    ln -sf "$SRCDIR/aos-toolchain/clang++" "$SRCDIR/aos-toolchain/c++"

    ${
      if isDarwinCross
      then ''
            # Bazel itself and every exec/host action stay on the native Linux
            # toolchain above.  A separate legacy crosstool selects the AOS Darwin
            # wrapper only for target C/C++/Objective-C actions.  The compiler
            # dispatcher uses the C driver for C/ObjC compilation and the C++
            # driver for C++ compilation and all links, so libc++ is present even
            # when a link action contains only object files.
            mkdir -p "$SRCDIR/aos-darwin-toolchain"
        unzip -jo "${buildBazel.src}" \
          tools/cpp/unix_cc_toolchain_config.bzl \
          -d "$SRCDIR/aos-darwin-toolchain"
        patch "$SRCDIR/aos-darwin-toolchain/unix_cc_toolchain_config.bzl" <<'DARWIN_OBJC_PATCH_EOF'
        --- unix_cc_toolchain_config.bzl
        +++ unix_cc_toolchain_config.bzl
        @@ -142,6 +142,8 @@
         all_compile_actions = [
             ACTION_NAMES.c_compile,
             ACTION_NAMES.cpp_compile,
        +    ACTION_NAMES.objc_compile,
        +    ACTION_NAMES.objcpp_compile,
             ACTION_NAMES.linkstamp_compile,
             ACTION_NAMES.assemble,
             ACTION_NAMES.preprocess_assemble,
        @@ -154,6 +156,7 @@

         all_cpp_compile_actions = [
             ACTION_NAMES.cpp_compile,
        +    ACTION_NAMES.objcpp_compile,
             ACTION_NAMES.linkstamp_compile,
             ACTION_NAMES.cpp_header_parsing,
             ACTION_NAMES.cpp_module_compile,
        @@ -164,6 +167,8 @@
         preprocessor_compile_actions = [
             ACTION_NAMES.c_compile,
             ACTION_NAMES.cpp_compile,
        +    ACTION_NAMES.objc_compile,
        +    ACTION_NAMES.objcpp_compile,
             ACTION_NAMES.linkstamp_compile,
             ACTION_NAMES.preprocess_assemble,
             ACTION_NAMES.cpp_header_parsing,
        @@ -174,6 +179,8 @@
         codegen_compile_actions = [
             ACTION_NAMES.c_compile,
             ACTION_NAMES.cpp_compile,
        +    ACTION_NAMES.objc_compile,
        +    ACTION_NAMES.objcpp_compile,
             ACTION_NAMES.linkstamp_compile,
             ACTION_NAMES.assemble,
             ACTION_NAMES.preprocess_assemble,
        @@ -251,6 +258,35 @@

             action_configs.append(llvm_cov_action)
             action_configs.append(objcopy_action)
        +
        +    objc_compile_action = action_config(
        +        action_name = ACTION_NAMES.objc_compile,
        +        enabled = True,
        +        implies = [
        +            "compiler_input_flags",
        +            "compiler_output_flags",
        +            "preprocessor_defines",
        +            "sysroot",
        +            "unfiltered_compile_flags",
        +            "user_compile_flags",
        +        ],
        +        tools = [tool(path = "compiler")],
        +    )
        +    objcpp_compile_action = action_config(
        +        action_name = ACTION_NAMES.objcpp_compile,
        +        enabled = True,
        +        implies = [
        +            "compiler_input_flags",
        +            "compiler_output_flags",
        +            "preprocessor_defines",
        +            "sysroot",
        +            "unfiltered_compile_flags",
        +            "user_compile_flags",
        +        ],
        +        tools = [tool(path = "compiler")],
        +    )
        +    action_configs.append(objc_compile_action)
        +    action_configs.append(objcpp_compile_action)

             validate_static_library = ctx.attr.tool_paths.get("validate_static_library")
             if validate_static_library:
                 validate_static_library_action = action_config(
        DARWIN_OBJC_PATCH_EOF
        # ObjC compile actions must also receive Bazel's target defines.
        # Keep this narrowly scoped to the preprocessor-defines feature;
        # the same C++ action name appears in many unrelated features.
        sed -i '/preprocessor_defines_feature = feature/,/cs_fdo_optimize_feature/ {
          /ACTION_NAMES.cpp_compile,/a\
            ACTION_NAMES.objc_compile,\
            ACTION_NAMES.objcpp_compile,
        }' "$SRCDIR/aos-darwin-toolchain/unix_cc_toolchain_config.bzl"
        # Bazel's upstream macOS feature set omits the entire
        # preprocessor-defines feature even though Objective-C rules
        # populate it. Add the existing feature to that branch so
        # objc_library `defines` and propagated dependency defines
        # reach ObjC/ObjC++ compiler actions.
        sed -i '/^    else:/,/layering_check_features.*is_macos = True/ {
          /            default_compile_flags_feature,/a\
                    preprocessor_defines_feature,
        }' "$SRCDIR/aos-darwin-toolchain/unix_cc_toolchain_config.bzl"
        # Unlike the default compile/user-flag features, Bazel's
        # sysroot feature spells out its action list instead of using
        # all_compile_actions. Extend that list as well so Objective-C
        # framework includes resolve against the target SDK.
        sed -i '/sysroot_feature = feature/,/fdo_optimize_feature/ {
          /ACTION_NAMES.cpp_compile,/a\
            ACTION_NAMES.objc_compile,\
            ACTION_NAMES.objcpp_compile,
        }' "$SRCDIR/aos-darwin-toolchain/unix_cc_toolchain_config.bzl"
        # The generated macOS toolchain otherwise assumes its `ar` tool is
        # Apple's libtool and emits `-static -o`. AOS deliberately supplies
        # LLVM ar, whose ordinary archive action is `rcs <archive> <objects>`.
        sed -i 's/enabled = not is_linux,/enabled = False,/' \
          "$SRCDIR/aos-darwin-toolchain/unix_cc_toolchain_config.bzl"
        {
              printf '%s\n' '#!${buildBash}/bin/bash'
              printf '%s\n' 'set -eu'
              printf '%s\n' 'compiling=false'
              printf '%s\n' 'c_source=false'
              printf '%s\n' 'cxx_source=false'
              printf '%s\n' 'for arg in "$@"; do'
              printf '%s\n' '  case "$arg" in'
              printf '%s\n' '    -c|-S|-E|-M|-MM|-fsyntax-only) compiling=true ;;'
              printf '%s\n' '    *.c|*.m|*.s|*.S) c_source=true ;;'
              printf '%s\n' '    *.cc|*.cp|*.cpp|*.cxx|*.C|*.mm) cxx_source=true ;;'
              printf '%s\n' '  esac'
              printf '%s\n' 'done'
              printf '%s\n' 'if [ "$compiling" = true ] && [ "$c_source" = true ] && [ "$cxx_source" = false ]; then'
              printf '%s\n' '  exec ${stdenv.cc}/bin/cc "$@"'
              printf '%s\n' 'fi'
              printf '%s\n' 'exec ${stdenv.cc}/bin/c++ "$@"'
            } > "$SRCDIR/aos-darwin-toolchain/compiler"
            chmod +x "$SRCDIR/aos-darwin-toolchain/compiler"

            sed 's/^    //' <<'    DARWIN_TOOLCHAIN_EOF' > "$SRCDIR/aos-darwin-toolchain/BUILD.bazel"
            load(":unix_cc_toolchain_config.bzl", "cc_toolchain_config")
            load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")

            package(default_visibility = ["//visibility:public"])

            platform(
                name = "target-platform",
                constraint_values = [
                    "@platforms//cpu:${darwinBazelCpuConstraint}",
                    "@platforms//os:osx",
                ],
            )

            filegroup(name = "empty")
            filegroup(
                name = "compiler-files",
                srcs = ["compiler", "unix_cc_toolchain_config.bzl"],
            )

            cc_toolchain_suite(
                name = "toolchain",
                toolchains = {
                    "${darwinBazelCpu}": ":cc-compiler",
                    "${darwinBazelCpu}|clang": ":cc-compiler",
                },
            )

            cc_toolchain(
                name = "cc-compiler",
                toolchain_identifier = "aos-${darwinBazelCpu}",
                toolchain_config = ":config",
                all_files = ":compiler-files",
                ar_files = ":compiler-files",
                as_files = ":compiler-files",
                compiler_files = ":compiler-files",
                dwp_files = ":empty",
                linker_files = ":compiler-files",
                objcopy_files = ":compiler-files",
                strip_files = ":compiler-files",
                supports_header_parsing = 1,
                supports_param_files = 1,
            )

            toolchain(
                name = "registered-toolchain",
                exec_compatible_with = [
                    "@platforms//cpu:x86_64",
                    "@platforms//os:linux",
                ],
                target_compatible_with = [
                    "@platforms//cpu:${darwinBazelCpuConstraint}",
                    "@platforms//os:osx",
                ],
                toolchain = ":cc-compiler",
                toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
            )

            cc_toolchain_config(
                name = "config",
                cpu = "${darwinBazelCpu}",
                compiler = "clang",
                toolchain_identifier = "aos-${darwinBazelCpu}",
                host_system_name = "x86_64-unknown-linux-gnu",
                target_system_name = "${darwinTargetTriple}",
                target_libc = "macosx",
                abi_version = "darwin",
                abi_libc_version = "darwin",
                builtin_sysroot = "${stdenv.sdk}",
                cxx_builtin_include_directories = [
                    "${stdenv.darwinRuntimes}/include/c++/v1",
                    "${buildLlvm}/lib/clang/${llvmMajor}/include",
                    "${stdenv.sdk}/usr/include",
                    "${stdenv.sdk}/System/Library/Frameworks",
                ],
                tool_paths = {
                    "ar": "${stdenv.cc}/bin/ar",
                    "c++filt": "${buildLlvm}/bin/llvm-cxxfilt",
                    "cpp": "${stdenv.cc}/bin/cc",
                    "dwp": "${buildLlvm}/bin/llvm-dwp",
                    "gcc": "compiler",
                    "gcov": "${buildLlvm}/bin/llvm-cov",
                    "ld": "compiler",
                    "llvm-cov": "${buildLlvm}/bin/llvm-cov",
                    "llvm-profdata": "${buildLlvm}/bin/llvm-profdata",
                    "nm": "${stdenv.cc}/bin/nm",
                    "objcopy": "${stdenv.cc}/bin/objcopy",
                    "objdump": "${stdenv.cc}/bin/objdump",
                    "strip": "${stdenv.cc}/bin/strip",
                },
                compile_flags = [],
                dbg_compile_flags = ["-g"],
                opt_compile_flags = ["-O2", "-DNDEBUG"],
                conly_flags = [],
                cxx_flags = ["-stdlib=libc++"],
                link_flags = [],
                # Disabling the generated Apple-libtool feature selects the
                # built-in `rcs` operation. Additional flags would be parsed by
                # llvm-ar as a second, conflicting archive operation.
                archive_flags = [],
                link_libs = [],
                opt_link_flags = [],
                unfiltered_compile_flags = [],
                coverage_compile_flags = [],
                coverage_link_flags = [],
                supports_start_end_lib = False,
                extra_flags_per_feature = {},
            )
            DARWIN_TOOLCHAIN_EOF
      ''
      else ""
    }
  '';

  # Source patching — shared between fetch and build phases.
  postPatchScript = ''
    SRCDIR="$(pwd)"
    ${toolchainSetup}

    # --- Patch aspect_rules_js shebangs at extraction time ----------------
    # aspect_rules_js's repository rules write helper scripts (`_exists.sh`,
    # `_reverse_force_copy.sh`) with a `#!/usr/bin/env bash` shebang and exec
    # them via `rctx.execute([...])`. `/usr/bin/env` does not exist in the
    # hermetic Nix sandbox, so the exec fails with a return code that is
    # neither 0 nor 42, tripping `fail(INTERNAL_ERROR_MSG)` ("@@npm// rules_js
    # internal error"). We rewrite the http_archive that fetches rules_js to a
    # local `urls = ["file://..."]` pointing at our own copy AND inject a
    # `patch_cmds` that rewrites those shebangs after extraction, before any
    # repo rule runs. The Python rewriter is generated via builtins.toFile to
    # avoid heredoc-indentation pitfalls in the FOD builder.
    ${buildPython}/bin/python3 ${patchWorkspacePy} WORKSPACE "${buildBash}"
    echo "AOS-DEBUG: WORKSPACE rules_js block after patch:"
    grep -n -A8 'name = "aspect_rules_js"' WORKSPACE || true

    # Use AOS Bazel directly (drop the pinned 7.3.1 .bazelversion).
    rm -f .bazelversion

    # Drop `-D_LIBCPP_REMOVE_TRANSITIVE_INCLUDES`. workerd's .bazelrc sets it to
    # enforce IWYU against libc++, but AOS's libc++ (LLVM 22) is stricter about
    # what `<stddef.h>`/etc. re-export than the libc++ upstream CI uses, so many
    # V8/capnp headers that rely on transitive `std::vector`/`std::nullptr_t`/
    # `std::size_t` fail (`no template named 'vector' in namespace 'std'`, etc.).
    # Removing the flag restores libc++'s transitive includes — strictly more
    # lenient, so it cannot introduce errors — and matches the de-facto headers
    # the upstream build sees.
    sed -i '/-D_LIBCPP_REMOVE_TRANSITIVE_INCLUDES/d' .bazelrc

    # Drop the `-stdlib=libc++` *linkopt* (workerd's .bazelrc adds it to both
    # cxxopt and linkopt). The link wrapper passes `-nostdlib++` and links the
    # static libc++ explicitly via `-l:libc++.a`, so the link-time `-stdlib=`
    # is redundant; the *compile* `-stdlib=libc++` (cxxopt / host_cxxopt) stays,
    # so clang still builds against libc++. Likewise drop `-static-libgcc`: the
    # AOS GCC ships no static libgcc_eh.a, so the LLVM-native runtime
    # (compiler-rt + libunwind, forced by the link wrapper) handles builtins and
    # unwinding instead — `-static-libgcc` would be meaningless to it.
    sed -i "/linkopt='-stdlib=libc++'/d" .bazelrc
    sed -i "s/ --linkopt='-static-libgcc'//g; s/ --host_linkopt='-static-libgcc'//g" .bazelrc

    # Replace shebangs throughout the source tree.
    find . -type f \( -name '*.sh' -o -name '*.bzl' -o -name 'BUILD' \
         -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name '*.py' \
         -o -name '*.tpl' \) | \
      while read f; do
        ${
      if isDarwinCross
      then ''
        sed -i \
          -e "1s|^#!/usr/local/bin/bash$|#!${buildBash}/bin/bash|" \
          -e "1s|^#!/usr/bin/bash$|#!${buildBash}/bin/bash|" \
          -e "1s|^#!/bin/bash$|#!${buildBash}/bin/bash|" \
          -e "1s|^#!/usr/bin/env python3$|#!${buildPython}/bin/python3|" \
          -e "1s|^#!/usr/bin/env python$|#!${buildPython}/bin/python3|" \
          -e "1s|^#!/usr/bin/env bash$|#!${buildBash}/bin/bash|" \
          -e "1s|^#!/usr/bin/env$|#!${buildCoreutils}/bin/env|" \
          "$f" 2>/dev/null || true
      ''
      else ''
        sed -i \
          -e "s|/usr/local/bin/bash|${buildBash}/bin/bash|g" \
          -e "s|/usr/bin/bash|${buildBash}/bin/bash|g" \
          -e "s|/bin/bash|${buildBash}/bin/bash|g" \
          -e "s|/usr/bin/env python3|${buildPython}/bin/python3|g" \
          -e "s|/usr/bin/env python|${buildPython}/bin/python3|g" \
          -e "s|/usr/bin/env bash|${buildBash}/bin/bash|g" \
          -e "s|/usr/bin/env|${buildCoreutils}/bin/env|g" \
          "$f" 2>/dev/null || true
      ''
    }
      done

    # The real workspace-status script shells out to git and developer-only
    # githook checks. Replace it with a minimal stub that just emits the stable
    # version. Written *after* the shebang-rewrite loop above so the loop's
    # `s|/bin/bash|${buildBash}/bin/bash|` rule can't double-substitute the AOS bash
    # path already present here (which would corrupt the shebang and make
    # Bazel's `--workspace_status_command` exec fail with status 127). Written
    # via printf (not a heredoc) so leading indentation can't push `#!` off
    # column 0.
    mkdir -p tools/unix
    {
      printf '%s\n' '#!${buildBash}/bin/bash'
      printf '%s\n' 'echo "STABLE_VERSION ${version}"'
    } > tools/unix/workspace-status.sh
    chmod +x tools/unix/workspace-status.sh
  '';

  # PATH containing every AOS tool, with the clang wrappers in front.
  toolsBinPath = builtins.concatStringsSep ":" (builtins.map (d: "${d}/bin") tools);
in
  mkBazelPackage {
    pname = "workerd-source";
    inherit version src;

    bazel = buildBazel;
    jdk = buildJdk;
    inherit tools;
    caCertificates = buildCaCertificates;

    hardeningDisable = ["pie"];

    postPatch = postPatchScript;
    bazelTarget = "//src/workerd/server:workerd";
    bazelFlags =
      ["--noenable_bzlmod"]
      ++ lib.optionals isDarwinCross [
        "--noenable_platform_specific_config"
        "--config=macos"
        "--platforms=//aos-darwin-toolchain:target-platform"
        "--cpu=${darwinBazelCpu}"
        "--host_cpu=k8"
        "--crosstool_top=//aos-darwin-toolchain:toolchain"
        "--host_crosstool_top=@local_config_cc//:toolchain"
        "--extra_toolchains=//aos-darwin-toolchain:registered-toolchain"
      ];
    inherit scrubMap;

    # --- Fetch-specific ---
    depsHash =
      if isDarwinCross
      then
        if stdenv.hostPlatform.isAarch64
        then "sha256-6JSNdFJpprzg6Bp+h0wMKmOGiunpRke0KBcutgzUxTw="
        else "sha256-uy7rYaYP7Rz1sAadbHRG4xux2wooPXbX/pNcofL4yXE="
      else "sha256-ocxi9B0Fv1mdEGVeq6AXDuWjxdq7wKel2tDFztkeg7g=";
    fetchPostPatch = "";
    fetchEnv = {
      CARGO_BAZEL_REPIN = "true";
    };
    postFetch = ''
      # Drop prebuilt JDK/Android toolchains Bazel recreates locally.
      rm -rf "$bazelOut/external/remotejdk"* "$bazelOut/external/local_jdk"
      rm -rf "$bazelOut/external/android_tools" "$bazelOut/external/android_gmaven_r8"
      find "$bazelOut/external/repository_cache" -maxdepth 1 -type f \
        \( -iname '*remotejdk*' -o -iname '*remote_java_tools*' -o -iname '*android*' \) \
        -delete 2>/dev/null || true
    '';

    # --- Build-specific ---
    bazelBuildFlags = [
      "-c opt"
      # Per-action isolation via the process-wrapper sandbox. The vendored
      # sqlite3 genrules `cp $(SRCS) .` and run lemon/mksqlite3 in the *shared*
      # execroot CWD, and perfetto's protoc actions likewise write shared
      # scratch; under the sandbox-less `standalone` strategy concurrent actions
      # clobber each other and segfault. `processwrapper-sandbox` gives every
      # action a private symlink-tree execroot WITHOUT Linux user namespaces
      # (which `linux-sandbox` needs and the Nix build sandbox forbids), so the
      # races are eliminated at the source rather than worked around.
      # processwrapper-sandbox where possible, falling back to standalone for the
      # few genrules tagged local/no-sandbox (e.g. v8 generated_inspector_files),
      # which cannot run sandboxed. The earlier genrule "races" were really the
      # host-tool startup crash (now fixed by pinning a consistent clang+lld
      # runtime in the link wrapper), so standalone is safe for those.
      "--spawn_strategy=processwrapper-sandbox,standalone"
      # Still keep going past any straggler so one build caches everything that
      # passes and resumes converge.
      "--keep_going"
      "--extra_toolchains=@local_jdk//:all"
      "--java_runtime_version=local_jdk"
      "--tool_java_runtime_version=local_jdk"
      "--strip=always"
      "--cxxopt=-Wno-error"
      "--host_cxxopt=-Wno-error"
      "--copt=-Wno-error"
      "--host_copt=-Wno-error"
    ];
    preBazelBuild = ''
            # The build phase re-unpacks pristine src, so re-apply the source
            # mutations (clang wrappers, .bazelversion removal, shebangs) here. The
            # FOD already applied them at fetch time for dependency resolution.
            ${postPatchScript}

            # capnp's `kj/common.h` (included by all of kj/capnp) does
            # `#include <stddef.h>` and then uses `std::nullptr_t`. AOS's strict
            # libc++ `<stddef.h>` declares `nullptr_t` only in the *global*
            # namespace (libstdc++ also leaks it into `std`, which is why this
            # compiles upstream). Add `#include <cstddef>` — which puts
            # `nullptr_t` into `namespace std` — right after the `<stddef.h>`
            # include in the vendored capnp copy so kj's `std::nullptr_t` (and
            # other `std::` C-library names) resolve under libc++.
            find "$TMPDIR/repo-overrides" -type f -path '*capnp-cpp/src/kj/common.h' 2>/dev/null | \
              while read f; do
                if ! grep -q 'AOS_CSTDDEF' "$f" 2>/dev/null; then
                  sed -i 's|#include <stddef.h>|#include <stddef.h>\n#include <cstddef>  // AOS_CSTDDEF: std::nullptr_t under libc++|' "$f" 2>/dev/null || true
                fi
              done

            # Put the AOS clang/clang++ wrappers first on PATH so Bazel's CC toolchain
            # auto-detection (driven by CC=clang/CXX=clang++ in workerd's .bazelrc)
            # resolves to the AOS toolchain wrappers.
            export PATH="$PWD/aos-toolchain:$PATH"
            echo "build --action_env=PATH=$PWD/aos-toolchain:${toolsBinPath}" >> .bazelrc
            echo "build --host_action_env=PATH=$PWD/aos-toolchain:${toolsBinPath}" >> .bazelrc

            # `local_config_cc` is a repository rule: it detects the toolchain's
            # built-in include dirs by running `$CC -E -v` *at loading time*, using
            # the repo-rule environment (NOT the build action_env). Point CC/CXX at
            # the AOS wrapper absolute paths and force the C++-only auto toolchain so
            # detection runs our wrapper (with its `-idirafter <glibc>/include`) and
            # captures the AOS glibc/GCC dirs as `cxx_builtin_include_directories`.
            # Otherwise Bazel rejects the build with "absolute path inclusion(s)
            # found" when sources pull in <errno.h> from /nix/store/glibc-dev.
            export CC="$PWD/aos-toolchain/clang"
            export CXX="$PWD/aos-toolchain/clang++"
            export BAZEL_USE_CPP_ONLY_TOOLCHAIN=1
            echo "build --repo_env=CC=$PWD/aos-toolchain/clang" >> .bazelrc
            echo "build --repo_env=CXX=$PWD/aos-toolchain/clang++" >> .bazelrc
            echo "build --repo_env=BAZEL_USE_CPP_ONLY_TOOLCHAIN=1" >> .bazelrc
            ${
        if isDarwinCross
        then ''
          # The shared Bazel setup exposes Linux libpthread/libdl compatibility
          # symlinks to host actions. They must not reach the Mach-O target
          # link: ld64 rejects those ELF objects before resolving Darwin's
          # libSystem implementations. Keep the corresponding host_linkopt and
          # Cargo build flags for Linux-executed generators.
          sed -i "\\|^build --linkopt=-L$TMPDIR/rust-link-libs$|d" .bazelrc
          if grep -Fqx "build --linkopt=-L$TMPDIR/rust-link-libs" .bazelrc; then
            echo "Linux Rust compatibility libraries leaked into the Darwin target link" >&2
            exit 1
          fi

          echo "build --action_env=CC=$PWD/aos-darwin-toolchain/compiler" >> .bazelrc
          echo "build --action_env=CXX=$PWD/aos-darwin-toolchain/compiler" >> .bazelrc
          echo "build --host_action_env=CC=$PWD/aos-toolchain/clang" >> .bazelrc
          echo "build --host_action_env=CXX=$PWD/aos-toolchain/clang++" >> .bazelrc
        ''
        else ''
          echo "build --action_env=CC=$PWD/aos-toolchain/clang" >> .bazelrc
          echo "build --action_env=CXX=$PWD/aos-toolchain/clang++" >> .bazelrc
        ''
      }

            # Bazel's auto-configured CC toolchain resolves `clang` to the real
            # `${buildLlvm}/bin/clang-NN` (it canonicalizes the wrapper symlink and adds
            # `-no-canonical-prefixes`), so the AOS toolchain flags baked into the
            # wrappers never reach the actual compile/link commands — capnp's
            # `#include <unistd.h>` then fails because AOS clang has no built-in
            # glibc/GCC search path. Inject those flags directly as Bazel copts /
            # linkopts (target *and* host/exec config) so they apply no matter which
            # clang binary Bazel invokes. Paths come from the bootstrap cc-wrapper.
            BT="${buildBootstrapTools}"
            REAL_CC=$(cat "$BT/nix-support/orig-cc")
            REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
            REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
            GCC_DIR=${
        if isDarwinCross
        then "$(dirname \"$(${buildGcc}/bin/gcc -print-libgcc-file-name)\")"
        else "$(echo \"$REAL_CC\"/lib/gcc/x86_64-unknown-linux-gnu/*)"
      }
            DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)
            {
              # Compile: GCC install dir + glibc headers (via -idirafter so libc++'s
              # #include_next <stdlib.h> still finds glibc *after* the C++ headers).
              for cfg in ${
        if isDarwinCross
        then "host_copt host_conlyopt host_cxxopt"
        else "copt host_copt conlyopt host_conlyopt cxxopt host_cxxopt"
      }; do
                echo "build --$cfg=--gcc-install-dir=$GCC_DIR"
                echo "build --$cfg=-idirafter"
                echo "build --$cfg=$REAL_LIBC_DEV/include"
                echo "build --$cfg=-B$GCC_DIR"
                echo "build --$cfg=-B$REAL_LIBC/lib"
              done
              # Link: the link is routed to AOS clang++ + lld (see
              # toolchainSetup), which already pins the crt (--gcc-install-dir),
              # glibc, compiler-rt, dynamic linker, and glibc + libc++ rpaths.
              # These linkopts only need to supply the static C++ ABI runtime
              # that workerd's own .bazelrc leaves out (it relies on CI's *shared*
              # libc++ to drag them in); the -L/rpath below are belt-and-braces
              # duplicates of LINK_COMMON and harmless.
              for cfg in ${
        if isDarwinCross
        then "host_linkopt"
        else "linkopt host_linkopt"
      }; do
                # the LLVM dir holding the static libc++ runtime,
                echo "build --$cfg=-L${buildLlvm}/lib/x86_64-unknown-linux-gnu"
                echo "build --$cfg=-Wl,-rpath,${buildLlvm}/lib/x86_64-unknown-linux-gnu"
                # `--config=macos` does not activate workerd's `build:linux`
                # linkopts, even for Linux exec actions. Supply the complete
                # static libc++ stack explicitly; ABI and unwind libraries must
                # follow libc++.a so ld resolves them left-to-right.
                echo "build --$cfg=-l:libc++.a"
                echo "build --$cfg=-l:libc++abi.a"
                echo "build --$cfg=-l:libunwind.a"
              done
            } >> .bazelrc

            # Provide a fake git for the workspace status command / repo rules.
            mkdir -p "$TMPDIR/fake-bin"
            {
              printf '%s\n' '#!${buildBash}/bin/bash'
              printf '%s\n' 'case "$*" in'
              printf '%s\n' '  *rev-parse*is-inside-work-tree*) echo "false" ;;'
              printf '%s\n' '  *rev-parse*HEAD*) echo "0000000000000000000000000000000000000000" ;;'
              printf '%s\n' '  *) echo "" ;;'
              printf '%s\n' 'esac'
              printf '%s\n' 'exit 0'
            } > "$TMPDIR/fake-bin/git"
            chmod +x "$TMPDIR/fake-bin/git"
            export PATH="$TMPDIR/fake-bin:$PATH"

            # V8 defaults build-time generators such as Torque to the target
            # configuration and explicitly documents changing this selector
            # for cross compilation. Keep every such executable in Bazel's
            # native Linux exec configuration.
            v8_defs="$TMPDIR/repo-overrides/v8/bazel/defs.bzl"
            test -f "$v8_defs"
            grep -q 'return "target"' "$v8_defs"
            sed -i '/^def get_cfg()/,/^def /s/return "target"/return "exec"/' "$v8_defs"
            grep -q 'return "exec"' "$v8_defs"
            # V8 appends its own -Werror after Bazel's host copts. LLVM 22
            # diagnoses deprecations in V8's native generators that upstream's
            # older compiler accepts; keep the diagnostics without promoting
            # them to build failures.
            test "$(grep -c '^[[:space:]]*"-Werror",' "$v8_defs")" -eq 1
            sed -i 's/^\([[:space:]]*\)"-Werror",/\1"-Wno-error",/' "$v8_defs"

            # --- Wire AOS Node into the rules_js node toolchain -----------------
            # rules_js downloads a prebuilt Node (`@nodejs_linux_amd64`, node 20.14)
            # whose ELF interpreter is absent in the sandbox. The toolchain's node
            # target is `bin/nodejs/bin/node` (the raw ELF); a `bin/node` launcher
            # wraps it. Replace both with tiny wrappers that exec AOS node
            # (${buildNodejs}, node 22 — fine for tsc/validation), so every js_binary /
            # ts_project action runs the hermetic interpreter. The `repo-overrides`
            # copy is what the offline build actually uses (via --override_repository
            # from the configure phase), so patch there.
            node_repo="$TMPDIR/repo-overrides/nodejs_linux_amd64"
            if [ -d "$node_repo" ]; then
              for nodepath in "$node_repo/bin/nodejs/bin/node" "$node_repo/bin/node"; do
                if [ -e "$nodepath" ]; then
                  rm -f "$nodepath"
                  {
                    printf '%s\n' '#!${buildBash}/bin/bash'
                    printf '%s\n' 'exec ${buildNodejs}/bin/node "$@"'
                  } > "$nodepath"
                  chmod +x "$nodepath"
                fi
              done
            fi

            # rules_js's js_binary launchers (e.g. the npm_typescript `validator`)
            # and node_wrapper.sh are generated with `#!/usr/bin/env bash`, which the
            # sandbox cannot exec (`/usr/bin/env` is absent). Rewrite those shebangs
            # to AOS bash across the vendored repo-overrides. node_wrapper.sh also
            # shells out to `node`; AOS node is on PATH (tools) so it resolves.
            find "$TMPDIR/repo-overrides" -type f \
                 \( -name '*.sh' -o -name '*.sh.tpl' -o -name '*.bash' \
                 -o -name 'validator' -o -name 'node_wrapper*' \) 2>/dev/null | \
              while read f; do
                sed -i "1s|^#!/usr/bin/env bash|#!${buildBash}/bin/bash|" "$f" 2>/dev/null || true
                sed -i "s|#!/usr/bin/env bash|#!${buildBash}/bin/bash|g" "$f" 2>/dev/null || true
              done

            # rules_js runs the js_binary launcher action as `env - BAZEL_BINDIR=... \
            # <launcher>`. `env -` empties the environment, so PATH is empty and the
            # launcher's own `uname`/`dirname`/`mktemp` (coreutils) calls fail with
            # "command not found" (Exit 127). Inject a base PATH *inside* the launcher
            # template (right after its `set -o` line) — it must be set in-script,
            # since `--action_env` is wiped by `env -`. The js_binary template
            # (`js_binary.sh.tpl`) is expanded into every launcher, so patching it
            # covers the generated `validator` and friends. node_wrapper.sh gets the
            # same treatment.
            aos_launcher_path="${buildCoreutils}/bin:${buildBash}/bin:${buildSed}/bin:${buildGawk}/bin:${buildGnumake}/bin:${buildNodejs}/bin"
            find "$TMPDIR/repo-overrides" -type f \
                 \( -name 'js_binary.sh.tpl' -o -name 'node_wrapper.sh' \) 2>/dev/null | \
              while read f; do
                if ! grep -q 'AOS_LAUNCHER_PATH' "$f" 2>/dev/null; then
                  sed -i \
                    "/^set -o pipefail -o errexit -o nounset/a\\
      export PATH=\"$aos_launcher_path:\''${PATH:-}\"  # AOS_LAUNCHER_PATH" \
                    "$f" 2>/dev/null || true
                fi
              done

            # --- Supply the rules_rust execution toolchain -------------------
            # workerd's lolhtml (HTML rewriter) is Rust, so rules_rust pulls a
            # prebuilt rust toolchain (`@rust_linux_x86_64__...__stable_tools`)
            # whose ELF interpreter (`/lib64/ld-linux-x86-64.so.2`) is absent in
            # the sandbox -> `rustc: cannot execute: required file not found`.
            # Native workerd keeps the fetched toolchain self-consistent and
            # supplies only its missing ELF interpreter. Darwin cross builds
            # instead replace rustc/rustdoc/cargo and both standard-library
            # sysroots with AOS's source-built Rust 1.93 toolchains. The exec
            # repository must use the same compiler release as the Darwin
            # repository: proc-macro metadata is compiler-version-specific.
            # The generated rules_rust repositories still supply Bazel's exact
            # toolchain metadata and auxiliary rustfmt/clippy executables.
            ${
        if isDarwinCross
        then ''
          rust_cross_repo="$TMPDIR/repo-overrides/rust_linux_x86_64__${darwinTargetTriple}__stable_tools"
          if [ ! -d "$rust_cross_repo" ]; then
            echo "missing Linux-executed rules_rust repository for ${darwinTargetTriple}" >&2
            exit 1
          fi
          for rust_tool in rustc rustdoc cargo; do
            test -x "${nativeRust}/bin/$rust_tool"
            rust_tool_path="${nativeRust}/bin/$rust_tool"
            case "$rust_tool" in
              rustc|rustdoc)
                # rules_rust supplies the repository-local --sysroot after we
                # install the Darwin stdlib below. The build-tool wrappers add
                # their store sysroot themselves, which would pass the option
                # twice, so Bazel must invoke the underlying compiler here.
                rust_tool_path="${nativeRust}/bin/$rust_tool.unwrapped"
                ;;
            esac
            test -x "$rust_tool_path"
            {
              printf '%s\n' '#!${buildBash}/bin/bash'
              # The Linux host compiler loads rules_rust's native `.so` proc
              # macros while the repository-local sysroot supplies Darwin
              # target libraries. Using the same compiler as the execution
              # repository keeps proc-macro metadata and suffix conventions
              # identical across both roles.
              printf 'exec %s "$@"\n' "$rust_tool_path"
            } > "$rust_cross_repo/bin/$rust_tool"
            chmod +x "$rust_cross_repo/bin/$rust_tool"
          done
          rm -rf "$rust_cross_repo/lib/rustlib/${darwinTargetTriple}"
          mkdir -p "$rust_cross_repo/lib/rustlib/${darwinTargetTriple}"
          cp -a "${buildRust}/lib/rustlib/${darwinTargetTriple}/." \
            "$rust_cross_repo/lib/rustlib/${darwinTargetTriple}/"
          chmod -R u+w "$rust_cross_repo/lib/rustlib/${darwinTargetTriple}"

          rm -rf "$rust_cross_repo/lib/rustlib/x86_64-unknown-linux-gnu"
          mkdir -p "$rust_cross_repo/lib/rustlib/x86_64-unknown-linux-gnu"
          cp -a "${nativeRust}/lib/rustlib/x86_64-unknown-linux-gnu/." \
            "$rust_cross_repo/lib/rustlib/x86_64-unknown-linux-gnu/"
          chmod -R u+w "$rust_cross_repo/lib/rustlib/x86_64-unknown-linux-gnu"

          rust_native_repo="$TMPDIR/repo-overrides/rust_linux_x86_64__x86_64-unknown-linux-gnu__stable_tools"
          if [ ! -d "$rust_native_repo" ]; then
            echo "missing Linux-executed native rules_rust repository" >&2
            exit 1
          fi
          for rust_tool in rustc rustdoc cargo; do
            rust_tool_path="${nativeRust}/bin/$rust_tool"
            case "$rust_tool" in
              rustc|rustdoc)
                # Bazel provides the repository-local sysroot, so bypass the
                # installed wrapper that would add the store sysroot again.
                rust_tool_path="${nativeRust}/bin/$rust_tool.unwrapped"
                ;;
            esac
            test -x "$rust_tool_path"
            {
              printf '%s\n' '#!${buildBash}/bin/bash'
              printf 'exec %s "$@"\n' "$rust_tool_path"
            } > "$rust_native_repo/bin/$rust_tool"
            chmod +x "$rust_native_repo/bin/$rust_tool"
          done
          rm -rf "$rust_native_repo/lib/rustlib/x86_64-unknown-linux-gnu"
          mkdir -p "$rust_native_repo/lib/rustlib/x86_64-unknown-linux-gnu"
          cp -a "${nativeRust}/lib/rustlib/x86_64-unknown-linux-gnu/." \
            "$rust_native_repo/lib/rustlib/x86_64-unknown-linux-gnu/"
          chmod -R u+w "$rust_native_repo/lib/rustlib/x86_64-unknown-linux-gnu"
        ''
        else ""
      }

            GLIBC_RUST=$(cat "${buildBootstrapTools}/nix-support/orig-libc")
            RUST_LOADER=$(echo "$GLIBC_RUST"/lib/ld-linux-x86-64.so.*)
            for rust_repo in "$TMPDIR/repo-overrides"/rust_*__*_tools; do
              [ -d "$rust_repo" ] || continue
              # The toolchain's own shared libs live under <repo>/lib and
              # <repo>/lib/rustlib/<triple>/lib (libstd, librustc_driver,
              # libLLVM). Use absolute paths so the library-path is correct for
              # binaries at any depth (bin/, lib/rustlib/<triple>/bin/, ...).
              RUST_LIBPATH="$rust_repo/lib:$rust_repo/lib/rustlib/x86_64-unknown-linux-gnu/lib:${buildGccLibs}/lib:${buildZlib}/lib:$GLIBC_RUST/lib"
              # Wrap every dynamically-linked ELF launcher whose interpreter is
              # the (absent) /lib64 loader: rustc/cargo/rustdoc/rustfmt/clippy
              # plus the rustlib llvm-*/rust-lld tools, proactively.
              find "$rust_repo/bin" "$rust_repo/lib/rustlib" -type f 2>/dev/null | \
                while read tool; do
                  case "$tool" in *.aos-real) continue ;; esac
                  head -c 4 "$tool" 2>/dev/null | grep -qa 'ELF' 2>/dev/null || continue
                  real="$tool.aos-real"
                  mv "$tool" "$real"
                  {
                    printf '%s\n' '#!${buildBash}/bin/bash'
                    printf '%s\n' '# AOS: run prebuilt rust tool via the AOS glibc loader,'
                    printf '%s\n' '# supplying the interpreter the sandbox lacks.'
                    printf '%s\n' "exec ''${RUST_LOADER} \\"
                    printf '%s\n' "  --library-path \"$RUST_LIBPATH\" \\"
                    printf '%s\n' '  "'"$real"'" "$@"'
                  } > "$tool"
                  chmod +x "$tool"
                done
            done
    '';
    installPhase = ''
      mkdir -p $out/bin

      WORKERD_BIN=$(find $TMPDIR/output -path '*/bin/src/workerd/server/workerd' -type f 2>/dev/null | head -1)
      if [ -z "$WORKERD_BIN" ] || [ ! -f "$WORKERD_BIN" ]; then
        echo "ERROR: bazel did not produce workerd binary" >&2
        find $TMPDIR/output -name 'workerd' -type f 2>&1 | head || true
        exit 1
      fi

      cp "$WORKERD_BIN" $out/bin/workerd
      chmod +x $out/bin/workerd
    '';

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    meta = {
      description = "Cloudflare workerd Workers runtime (built from source via AOS Bazel)";
      homepage = "https://github.com/cloudflare/workerd";
      license = "Apache-2.0";
    };
  }
