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

  # Minimal Tcl interpreter, built from source. workerd's vendored sqlite3
  # amalgamation generates `sqlite3.h` with a genrule that runs
  # `tclsh mksqlite3h.tcl` (a 165-line Tcl script that adds SQLITE_API/EXTERN
  # prefixes and substitutes version/source-id). AOS has no Tcl package and the
  # script is non-trivial to reimplement, so we build a small `tclsh` here and
  # put it on the build PATH. Built into `$out` (no install of the full Tcl
  # library tree needed beyond what `make install` provides for tclsh to run).
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

  tools = [
    bash
    coreutils
    which
    zip
    unzip
    gawk
    python3
    gcc
    binutils
    llvm
    rust
    cmake
    ninja
    grep
    gzip
    patch
    diffutils
    findutils
    sed
    tar
    xz
    file
    perl
    gnumake
    pkg-config
    # workerd fetches V8, dawn, and their deps via `git_repository` (generated
    # tarballs are non-deterministic, so the WORKSPACE clones over git). The FOD
    # fetch needs a real git on PATH; the build phase prepends a fake git for the
    # workspace-status command, which shadows this one there.
    git
    # rules_js runs TypeScript tooling (tsc, the ts_project validator) under
    # Node during the server build's capnp->TS type generation. We wire AOS
    # Node into the rules_js node toolchain in preBazelBuild; it must be on
    # PATH for the build actions.
    nodejs
    # sqlite3's amalgamation genrule runs `tclsh mksqlite3h.tcl` to generate
    # sqlite3.h; provide a from-source Tcl interpreter on PATH.
    tcl
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

    # These repositories publish the same commit graphs through their official
    # GitHub mirrors. Use those mirrors so the source-only build does not add
    # redundant network origins. The Chromium-fork zlib and ICU repositories
    # intentionally stay on their canonical origin because no official GitHub
    # mirror carries those fork commits.
    git_mirrors = {
        'remote = "https://dawn.googlesource.com/dawn.git",':
            'remote = "https://github.com/google/dawn.git",',
        'remote = "https://chromium.googlesource.com/chromium/src/third_party/abseil-cpp.git",':
            'remote = "https://github.com/abseil/abseil-cpp.git",',
        'remote = "https://chromium.googlesource.com/external/github.com/Maratyszcza/FP16.git",':
            'remote = "https://github.com/Maratyszcza/FP16.git",',
    }
    for origin, mirror in git_mirrors.items():
        if origin in src:
            src = src.replace(origin, mirror, 1)
        else:
            assert mirror in src, "git_repository remote not found in WORKSPACE: " + origin

    # Idempotent: postPatchScript runs in both the fetch FOD and the build
    # phase (and possibly twice in the build phase), so bail out cleanly if the
    # WORKSPACE has already been rewritten. Injecting twice would produce a
    # `duplicate keyword argument: patch_cmds` Starlark error. We key on a
    # marker unique to our injection (the `_exists.sh` -> struct rewrite), since
    # workerd's WORKSPACE already uses `patch_cmds` for other http_archives.
    marker = "result = struct(return_code = 0 if rctx"
    if marker in src:
        with open(path, "w") as f:
            f.write(src)
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
        "'s@#!/usr/bin/env bash@#!" + aos_bash + "/bin/bash@g' {} +"
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
    "${scrub python3}" = "__AOS_PYTHON__";
    "${scrub bash}" = "__AOS_BASH__";
    "${scrub coreutils}" = "__AOS_COREUTILS__";
    "${scrub rust}" = "__AOS_RUST__";
    "${scrub llvm}" = "__AOS_LLVM__";
    "${scrub gcc}" = "__AOS_GCC__";
  };

  # Build a clang/clang++ wrapper directory. AOS clang needs the GCC install dir
  # + glibc + dynamic-linker injected on every invocation; Bazel's CC toolchain
  # auto-detection just runs `clang`/`clang++` from PATH, so the wrappers carry
  # the flags. Emitted at the top of postPatch (shared fetch+build), written to
  # $SRCDIR/aos-toolchain so it survives into the build via --override flags.
  toolchainSetup = ''
    BT="${bootstrapTools}"
    REAL_CC=$(cat "$BT/nix-support/orig-cc")
    REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
    REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
    GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
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
    LIBCXX_INC="${llvm}/include/c++/v1"
    LIBCXX_INC_TARGET="${llvm}/include/x86_64-unknown-linux-gnu/c++/v1"

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
    LINK_COMMON="-L$REAL_LIBC/lib --gcc-install-dir=$GCC_DIR -B$REAL_LIBC/lib -B$GCC_DIR -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -L${llvm}/lib/x86_64-unknown-linux-gnu -Wl,-dynamic-linker=$DL -Wl,-rpath,$REAL_LIBC/lib -Wl,-rpath,${llvm}/lib/x86_64-unknown-linux-gnu"

    {
      printf '%s\n' '#!${bash}/bin/bash'
      printf '%s\n' 'case " $* " in'
      printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
      printf '%s\n' "    exec ${llvm}/bin/clang -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
      printf '%s\n' 'esac'
      printf '%s\n' "exec ${llvm}/bin/clang $LINK_COMMON \"\$@\""
    } > "$SRCDIR/aos-toolchain/clang"
    chmod +x "$SRCDIR/aos-toolchain/clang"

    {
      printf '%s\n' '#!${bash}/bin/bash'
      printf '%s\n' 'case " $* " in'
      printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
      printf '%s\n' "    exec ${llvm}/bin/clang++ -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
      printf '%s\n' 'esac'
      # -nostdlib++: link the explicit static libc++ (.bazelrc -l:libc++.a) plus
      # libc++abi/libunwind appended as linkopts, never clang's default
      # libstdc++, so the two C++ runtimes never collide.
      printf '%s\n' "exec ${llvm}/bin/clang++ -nostdlib++ $LINK_COMMON \"\$@\""
    } > "$SRCDIR/aos-toolchain/clang++"
    chmod +x "$SRCDIR/aos-toolchain/clang++"

    # Provide the remaining LLVM binutils Bazel's clang toolchain expects.
    for t in ld.lld lld llvm-ar ar llvm-nm nm llvm-objcopy objcopy \
             llvm-objdump objdump llvm-strip strip llvm-dwp dwp \
             llvm-cov cov llvm-profdata profdata llvm-symbolizer; do
      if [ -e "${llvm}/bin/$t" ]; then
        ln -sf "${llvm}/bin/$t" "$SRCDIR/aos-toolchain/$t"
      fi
    done
    # Bazel's unix cc toolchain calls `ar` and the gcov tool; alias clang as cc.
    ln -sf "$SRCDIR/aos-toolchain/clang" "$SRCDIR/aos-toolchain/cc"
    ln -sf "$SRCDIR/aos-toolchain/clang++" "$SRCDIR/aos-toolchain/c++"
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
    ${python3}/bin/python3 ${patchWorkspacePy} WORKSPACE "${bash}"
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
        sed -i \
          -e "s|/usr/local/bin/bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/bash|${bash}/bin/bash|g" \
          -e "s|/bin/bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/env python3|${python3}/bin/python3|g" \
          -e "s|/usr/bin/env python|${python3}/bin/python3|g" \
          -e "s|/usr/bin/env bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/env|${coreutils}/bin/env|g" \
          "$f" 2>/dev/null || true
      done

    # The real workspace-status script shells out to git and developer-only
    # githook checks. Replace it with a minimal stub that just emits the stable
    # version. Written *after* the shebang-rewrite loop above so the loop's
    # `s|/bin/bash|${bash}/bin/bash|` rule can't double-substitute the AOS bash
    # path already present here (which would corrupt the shebang and make
    # Bazel's `--workspace_status_command` exec fail with status 127). Written
    # via printf (not a heredoc) so leading indentation can't push `#!` off
    # column 0.
    mkdir -p tools/unix
    {
      printf '%s\n' '#!${bash}/bin/bash'
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

    bazel = bazel-7;
    jdk = openjdk;
    inherit tools;
    caCertificates = ca-certificates;

    hardeningDisable = ["pie"];

    postPatch = postPatchScript;
    bazelTarget = "//src/workerd/server:workerd";
    bazelFlags = [
      "--noenable_bzlmod"
    ];
    # The generic fetch helper can prime Bazel's built-in module repository by
    # syncing an empty workspace. Workerd uses WORKSPACE with Bzlmod disabled,
    # so that sync only downloads unrelated cross-platform JDK and Android R8
    # repositories before the target graph is fetched.
    populateBCR = false;
    inherit scrubMap;

    # --- Fetch-specific ---
    depsHash = "sha256-D6FWYyLQWnsW06xPdBLvOj2ST/GwYU+vtSI5jaTZBY8=";
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
            echo "build --action_env=CC=$PWD/aos-toolchain/clang" >> .bazelrc
            echo "build --action_env=CXX=$PWD/aos-toolchain/clang++" >> .bazelrc

            # Bazel's auto-configured CC toolchain resolves `clang` to the real
            # `${llvm}/bin/clang-NN` (it canonicalizes the wrapper symlink and adds
            # `-no-canonical-prefixes`), so the AOS toolchain flags baked into the
            # wrappers never reach the actual compile/link commands — capnp's
            # `#include <unistd.h>` then fails because AOS clang has no built-in
            # glibc/GCC search path. Inject those flags directly as Bazel copts /
            # linkopts (target *and* host/exec config) so they apply no matter which
            # clang binary Bazel invokes. Paths come from the bootstrap cc-wrapper.
            BT="${bootstrapTools}"
            REAL_CC=$(cat "$BT/nix-support/orig-cc")
            REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
            REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
            GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
            DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)
            {
              # Compile: GCC install dir + glibc headers (via -idirafter so libc++'s
              # #include_next <stdlib.h> still finds glibc *after* the C++ headers).
              for cfg in copt host_copt conlyopt host_conlyopt cxxopt host_cxxopt; do
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
              for cfg in linkopt host_linkopt; do
                # the LLVM dir holding the static libc++ runtime,
                echo "build --$cfg=-L${llvm}/lib/x86_64-unknown-linux-gnu"
                echo "build --$cfg=-Wl,-rpath,${llvm}/lib/x86_64-unknown-linux-gnu"
                # and the static libc++abi + unwinder. workerd's .bazelrc links
                # `-l:libc++.a` but NOT libc++abi/libunwind (it relies on CI's
                # *shared* libc++ to drag those in); AOS libc++ is static, so the
                # C++ ABI runtime (`operator new`, `__cxa_*`, std::exception
                # vtables, `std::terminate`) and the unwinder must be appended
                # *after* libc++.a so ld resolves them left-to-right.
                echo "build --$cfg=-l:libc++abi.a"
                echo "build --$cfg=-l:libunwind.a"
              done
            } >> .bazelrc

            # Provide a fake git for the workspace status command / repo rules.
            mkdir -p "$TMPDIR/fake-bin"
            {
              printf '%s\n' '#!${bash}/bin/bash'
              printf '%s\n' 'case "$*" in'
              printf '%s\n' '  *rev-parse*is-inside-work-tree*) echo "false" ;;'
              printf '%s\n' '  *rev-parse*HEAD*) echo "0000000000000000000000000000000000000000" ;;'
              printf '%s\n' '  *) echo "" ;;'
              printf '%s\n' 'esac'
              printf '%s\n' 'exit 0'
            } > "$TMPDIR/fake-bin/git"
            chmod +x "$TMPDIR/fake-bin/git"
            export PATH="$TMPDIR/fake-bin:$PATH"

            # --- Wire AOS Node into the rules_js node toolchain -----------------
            # rules_js downloads a prebuilt Node (`@nodejs_linux_amd64`, node 20.14)
            # whose ELF interpreter is absent in the sandbox. The toolchain's node
            # target is `bin/nodejs/bin/node` (the raw ELF); a `bin/node` launcher
            # wraps it. Replace both with tiny wrappers that exec AOS node
            # (${nodejs}, node 22 — fine for tsc/validation), so every js_binary /
            # ts_project action runs the hermetic interpreter. The `repo-overrides`
            # copy is what the offline build actually uses (via --override_repository
            # from the configure phase), so patch there.
            node_repo="$TMPDIR/repo-overrides/nodejs_linux_amd64"
            if [ -d "$node_repo" ]; then
              for nodepath in "$node_repo/bin/nodejs/bin/node" "$node_repo/bin/node"; do
                if [ -e "$nodepath" ]; then
                  rm -f "$nodepath"
                  {
                    printf '%s\n' '#!${bash}/bin/bash'
                    printf '%s\n' 'exec ${nodejs}/bin/node "$@"'
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
                sed -i "1s|^#!/usr/bin/env bash|#!${bash}/bin/bash|" "$f" 2>/dev/null || true
                sed -i "s|#!/usr/bin/env bash|#!${bash}/bin/bash|g" "$f" 2>/dev/null || true
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
            aos_launcher_path="${coreutils}/bin:${bash}/bin:${sed}/bin:${gawk}/bin:${gnumake}/bin:${nodejs}/bin"
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

            # --- Fix the prebuilt rules_rust toolchain interpreter -----------
            # workerd's lolhtml (HTML rewriter) is Rust, so rules_rust pulls a
            # prebuilt rust toolchain (`@rust_linux_x86_64__...__stable_tools`)
            # whose ELF interpreter (`/lib64/ld-linux-x86-64.so.2`) is absent in
            # the sandbox -> `rustc: cannot execute: required file not found`.
            # We keep the prebuilt toolchain self-consistent (it depends on its
            # own `libstd-*.so` / `librustc_driver-*.so` / `libLLVM-*.so`, whose
            # exact hashes rules_rust expects) and only supply the missing
            # interpreter: wrap each binary to run via the AOS glibc loader with
            # `--library-path` covering the toolchain's own lib dir (resolved
            # relative to the wrapper so it works through the `rust_toolchain`
            # symlink), AOS glibc, and AOS libgcc_s. This is option B — safer
            # than swapping in AOS rustc, which has a different std/sysroot.
            GLIBC_RUST=$(cat "${bootstrapTools}/nix-support/orig-libc")
            RUST_LOADER=$(echo "$GLIBC_RUST"/lib/ld-linux-x86-64.so.*)
            for rust_repo in "$TMPDIR/repo-overrides"/rust_*__*_tools; do
              [ -d "$rust_repo" ] || continue
              # The toolchain's own shared libs live under <repo>/lib and
              # <repo>/lib/rustlib/<triple>/lib (libstd, librustc_driver,
              # libLLVM). Use absolute paths so the library-path is correct for
              # binaries at any depth (bin/, lib/rustlib/<triple>/bin/, ...).
              RUST_LIBPATH="$rust_repo/lib:$rust_repo/lib/rustlib/x86_64-unknown-linux-gnu/lib:${gcc-libs}/lib:${zlib}/lib:$GLIBC_RUST/lib"
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
                    printf '%s\n' '#!${bash}/bin/bash'
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
