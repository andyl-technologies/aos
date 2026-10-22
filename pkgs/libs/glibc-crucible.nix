##! Matching libc, loader and headers for the experimental bounded allocation providers.
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

    # This path is an exported versioned array: embedding a store prefix changes
    # its ABI size. Keep the canonical runtime path and stage the alias separately.
    extraConfigureFlags = ["--localedir=/usr/share/locale"];
    extraInstallFlags = [''inst_localedir="$out/share/locale"''];

    # Bound each compiler/test process without borrowing memory from tmpfs.
    preConfigure = ''
      ulimit -v 2097152
      ulimit -c 0
    '';

    postBuild = ''
      qualification="$out/share/glibc-crucible/qualification"
      mkdir -p "$qualification"
      cp ../malloc/tst-malloc-bounded-glib.c "$qualification/"

      # This configured GCC carries its real unwinder in libgcc.a. Derive the
      # archive from that compiler; no fabricated libgcc_eh alias is needed.
      bounded_static_archive="$(${stdenv.gcc}/bin/gcc -print-libgcc-file-name)"
      test -f "$bounded_static_archive"
      printf '%s\n' "$bounded_static_archive" > "$qualification/static-archive.path"
      sha256sum "$bounded_static_archive" > "$qualification/static-archive.sha256"

      for bounded_case in \
        malloc/tst-malloc-bounded \
        nptl/tst-pthread-bounded \
        nptl/tst-basic1 nptl/tst-join1 nptl/tst-join2 \
        nptl/tst-key1 nptl/tst-key3 nptl/tst-tls3 nptl/tst-attr3 \
        malloc/tst-malloc malloc/tst-calloc malloc/tst-memalign \
        malloc/tst-malloc-thread-exit
      do
        make -j1 SHELL="$CONFIG_SHELL" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true \
          MAKEINFO="${texinfo}/bin/makeinfo" \
          sysdep-library-path="${gcc-libs}/lib" \
          static-gnulib-tests="$bounded_static_archive" test t="$bounded_case"

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

      # Retain the actual complete ABI outcome. The separate qualification
      # derivation fails on any negative status; a component build is no waiver.
      bounded_abi_status=0
      make -j1 SHELL="$CONFIG_SHELL" \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true \
        MAKEINFO="${texinfo}/bin/makeinfo" check-abi \
        > "$qualification/check-abi.log" 2>&1 || bounded_abi_status=$?
      printf '%s\n' "$bounded_abi_status" > "$qualification/check-abi.status"
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
        boundedApplicationVersion = 1;
        boundedProcessVersion = 1;
        boundedFailstopVersion = 1;
        # Private TCB changes require this runtime's matching loader and headers.
        requiresMatchingLoader = true;
        sourceCommit = "9ec3dc41fde9abcbd3ce3f1bf91f87fedd63ae3a";
        evidenceSources =
          runtime.passthru.evidenceSources
          ++ [
            ./glibc-patches/LICENSES.md
          ];
      };
    meta =
      runtime.meta
      // {
        description = "GNU C Library with experimental caller-backed pthread and application storage";
      };
  }
