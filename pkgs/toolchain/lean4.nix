##! lean4 — Lean 4 theorem prover and programming language, with Lake
{
  lib,
  mkDerivation,
  fetchurl,
  bash,
  cadical,
  cmake,
  git-minimal,
  gmp,
  gnumake,
  leangz,
  libuv,
  openssl,
  pkg-config,
  stdenv,
}: let
  version = "4.35.0";

  # Lean compiles mimalloc into its runtime from the source tree that its
  # CMake FetchContent declaration names. Supply that exact tag from a pinned
  # archive so the sandboxed configure step never clones it.
  mimallocVersion = "3.4.5";
  mimallocSource = fetchurl {
    urls = ["https://github.com/microsoft/mimalloc/archive/refs/tags/v${mimallocVersion}.tar.gz"];
    hash = "sha256-GaQ68GRcV9NI5ynVsx4j6RJYKRG7EEf3lXkINNNBYiE=";
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "lean4";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lean elaborates the module and evaluates the definition.";
        "files" = {
          "Qualified.lean" = "def answer : Nat := 40 + 2\ntheorem answer_eq : answer = 42 := rfl\n#eval answer\n";
        };
        "input" = "A Lean module with a definition, a proof by reflexivity, and an evaluation.";
        "operation" = "Check the module with the packaged Lean frontend.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lean"
              "Qualified.lean"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lean reports the false theorem as a type error and returns failure.";
        "files" = {
          "Invalid.lean" = "theorem wrong : 1 + 1 = 3 := rfl\n";
        };
        "input" = "A Lean module that asserts a false equation by reflexivity.";
        "operation" = "Check the invalid module with the packaged Lean frontend.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/lean\", \"Invalid.lean\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"error\" in result.stdout, result\n\nsys.stderr.write(\"lean4 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "lean4 rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # Lean's .olean format and library APIs change between releases.
    version = "=${version}";
    src = fetchurl {
      urls = ["https://github.com/leanprover/lean4/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-Z0ewmdA9NnXycW589ZJKFr+/dYIrE6PTb1H5M//MMHs=";
    };

    # The bootstrap input is the release's checked-in stage0: generated C and
    # C++ sources, not a compiler executable. The AOS C/C++ toolchain builds
    # stage0, which then compiles this release's Lean sources (Init, Std,
    # Lean, Lake, and the compiler) into the installed stage1 toolchain.
    #
    # Upstream declares its optional independent kernel checkers as
    # ExternalProject Git checkouts outside the default build. CMake requires
    # a Git executable to declare them even though none is cloned here.
    buildDeps = [cmake git-minimal gnumake pkg-config];

    # Lake links user programs with the wrapped AOS compiler by default (see
    # the InstallPath patch below), so it remains a runtime input.
    # CaDiCaL backs `bv_decide`, and leantar packs Lake cache artifacts.
    runtimeDeps = [
      bash
      cadical
      gmp
      leangz
      libuv
      openssl
      stdenv.cc
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lean4-${version}

          mkdir -p build/mimalloc/src/mimalloc
          tar xf ${mimallocSource} --strip-components=1 -C build/mimalloc/src/mimalloc

          # Build drivers, make fragments, and installed wrappers name Bash
          # through /usr/bin/env or /bin, which do not exist in the build
          # sandbox or on AOS. Use the AOS Bash in both bootstrap stages.
          interpreter_files="src/bin src/shell src/cmake src/lean.mk.in src/stdlib.make.in"
          interpreter_files="$interpreter_files stage0/src/bin stage0/src/shell"
          interpreter_files="$interpreter_files stage0/src/cmake stage0/src/lean.mk.in"
          interpreter_files="$interpreter_files stage0/src/stdlib.make.in"
          grep -rlE '/usr/bin/env bash|^#!/bin/(ba)?sh' $interpreter_files |
            while IFS= read -r script; do
              sed -i \
                -e 's|/usr/bin/env bash|${bash}/bin/bash|g' \
                -e '1s|^#!/bin/sh$|#!${bash}/bin/bash|' \
                -e '1s|^#!/bin/bash$|#!${bash}/bin/bash|' \
                "$script"
            done
          if grep -rlE '/usr/bin/env|^#!/bin/' $interpreter_files; then
            echo "unpatched host interpreter path in Lean build scripts" >&2
            exit 1
          fi

          # Without LEAN_CC or CC, Lake links user programs with whatever `cc`
          # and `ar` are first on PATH. Lean's runtime archives are compiled by
          # the AOS GCC and need its libstdc++, so default to that toolchain.
          # LEAN_CC, CC, LEAN_AR, and AR still override these defaults.
          install_path=src/lake/Lake/Config/InstallPath.lean
          sed -i \
            -e 's|return withCustomCc i "cc"$|return withCustomCc i "${stdenv.cc}/bin/cc"|' \
            -e 's|return "ar"$|return "${stdenv.cc}/bin/ar"|' \
            "$install_path"
          grep -qF 'withCustomCc i "${stdenv.cc}/bin/cc"' "$install_path"
          grep -qF 'return "${stdenv.cc}/bin/ar"' "$install_path"
        '';
      }
      {
        name = "configure";
        script = ''
          # Platform variables reach only stage0; STAGE1_ forwards the install
          # prefix to the stage that is installed. Untyped -D variables such as
          # CADICAL and LEANTAR are forwarded to both stages by upstream.
          #
          # Upstream asks the C compiler for its LLVM target triple, which GCC
          # does not answer; state it so System.Platform.target is populated.
          #
          # Lean links programs against these shared libraries by absolute
          # path but records no search path for them. The extra linker flags
          # are also the flags Lake uses for user executables, so programs
          # built with this toolchain find the same libraries at run time.
          lean_rpath=
          for library in gmp libuv libssl libcrypto; do
            lean_rpath="$lean_rpath -Wl,-rpath,$(pkg-config --variable=libdir "$library")"
          done

          cmake -S . -B build \
            -DLEAN_EXTRA_LINKER_FLAGS="$lean_rpath" \
            -DLEAN_PLATFORM_TARGET=${stdenv.hostPlatform.config} \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DSTAGE1_CMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_C_COMPILER="$CC" \
            -DCMAKE_CXX_COMPILER="$CXX" \
            -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
            -DFETCHCONTENT_SOURCE_DIR_MIMALLOC="$PWD/build/mimalloc/src/mimalloc" \
            -DCADICAL=${cadical}/bin/cadical \
            -DLEANTAR=${leangz}/bin/leantar \
            -DUSE_GITHASH=OFF \
            -DSTAGE0_USE_GITHASH=OFF \
            -DUSE_LAKE_CACHE=OFF \
            -DCCACHE=OFF
        '';
      }
      {
        name = "build";
        script = ''
          export LEAN_NUM_THREADS="$NIX_BUILD_CORES"
          make -C build -j"$NIX_BUILD_CORES" SHELL=${bash}/bin/bash
        '';
      }
      {
        name = "install";
        script = ''
          make -C build/stage1 install SHELL=${bash}/bin/bash

          # Upstream installs LICENSE and LICENSES at the prefix root; collect
          # them with the notices for components compiled into the runtime.
          mkdir -p "$out/share/licenses/lean4"
          install -m644 LICENSE LICENSES "$out/share/licenses/lean4/"
          install -m644 build/mimalloc/src/mimalloc/LICENSE \
            "$out/share/licenses/lean4/mimalloc-LICENSE"
        '';
      }
      {
        name = "check";
        script = ''
          "$out/bin/lean" --version | grep -F 'version ${version}'
          lake_version=$("$out/bin/lake" --version)
          printf '%s\n' "$lake_version"
          case $lake_version in
            *"Lean version ${version}"*) ;;
            *) echo "lake reports an unexpected Lean version" >&2; exit 1 ;;
          esac
          test -x "$out/bin/cadical"
          test -x "$out/bin/leantar"
        '';
      }
    ];

    checks = {
      self,
      pkgs,
      ...
    }: {
      lake-build = pkgs.mkDerivation {
        pname = "lean4-lake-build";
        version = "1";
        src = null;
        buildDeps = [self];
        phases = [
          {
            name = "check";
            script = ''
              cp -R ${./_lean4-lake-fixture} project
              chmod -R u+w project
              cd project

              # Lake keeps per-user state under HOME and must not touch the
              # network for a project without dependencies.
              export HOME="$TMPDIR/home"
              mkdir -p "$HOME"

              # Exercise the toolchain's default compiler, as an interactive
              # user without CC would, rather than the builder's CC.
              env -u CC -u AR -u LD_LIBRARY_PATH lake build

              # The executable must run without any library search path.
              result=$(env -u LD_LIBRARY_PATH .lake/build/bin/fixture)
              printf '%s\n' "$result"
              test "$result" = "fixture: 42 rotates to 168"

              mkdir -p "$out"
              printf '%s\n' "$result" > "$out/result"
            '';
          }
        ];
      };
    };

    meta = {
      description = "Lean 4 theorem prover and programming language, with the Lake build system";
      homepage = "https://lean-lang.org";
      license = "Apache-2.0";
      mainProgram = "lean";
    };
  }
