##! Matching libc, loader and headers for the experimental bounded-thread provider.
{
  stdenv,
  bison,
  m4,
  python3,
  perl,
  texinfo,
  linux-headers,
  gcc-libs,
}: let
  kernelHeaders = "${linux-headers}/include";

  runtime = import ../../stdenv/toolchains/gcc16/glibc.nix {
    prev =
      stdenv
      // {
        inherit bison m4 python3 perl texinfo;
        linuxHeaders = kernelHeaders;
      };
    gcc = stdenv.gcc;
    inherit (stdenv) binutils buildPlatform hostPlatform;
    linuxHeaders = kernelHeaders;
    runtimePerl = perl;
    name = "glibc-crucible-2.39";
    patches = [./glibc-patches/bounded-pthread-2.39.patch];

    # Bound each compiler/test process without borrowing memory from tmpfs.
    preConfigure = ''
      ulimit -v 2097152
      ulimit -c 0
    '';

    postBuild = ''
      qualification="$out/share/glibc-crucible/qualification"
      mkdir -p "$qualification"

      for bounded_case in \
        nptl/tst-pthread-bounded \
        nptl/tst-basic1 nptl/tst-join1 nptl/tst-join2 \
        nptl/tst-key1 nptl/tst-key3 nptl/tst-tls3 nptl/tst-attr3 \
        malloc/tst-malloc malloc/tst-calloc malloc/tst-memalign \
        malloc/tst-malloc-thread-exit
      do
        make -j1 SHELL="$CONFIG_SHELL" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true \
          MAKEINFO="${texinfo}/bin/makeinfo" \
          sysdep-library-path="${gcc-libs}/lib" test t="$bounded_case"

        # glibc's single-test target can return zero for a failing test.
        # Require the actual runner's original exit status and PASS result.
        ${python3}/bin/python3 - "$bounded_case.test-result" <<'AOS_BOUNDED_RESULT'
      import pathlib
      import sys

      result = pathlib.Path(sys.argv[1]).read_text().splitlines()
      if result != ["PASS: " + sys.argv[1].removesuffix(".test-result"),
                    "original exit status 0"]:
          raise SystemExit("bounded libc qualification failed: " + repr(result))
      AOS_BOUNDED_RESULT

        bounded_name="''${bounded_case//\//-}"
        cp "$bounded_case.test-result" "$qualification/$bounded_name.test-result"
        cp "$bounded_case.out" "$qualification/$bounded_name.out"
      done
    '';
  };
in
  runtime
  // {
    pname = "glibc-crucible";
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
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    passthru =
      runtime.passthru
      // {
        boundedPthreadVersion = 1;
        # Private TCB changes require this runtime's matching loader and headers.
        requiresMatchingLoader = true;
        sourceCommit = "dae19eda3e0ca54dc8198ef83e8ba1a6c187441e";
        evidenceSources =
          runtime.passthru.evidenceSources
          ++ [
            ./glibc-patches/LICENSES.md
          ];
      };
    meta =
      runtime.meta
      // {
        description = "GNU C Library with experimental caller-backed pthread storage";
      };
  }
