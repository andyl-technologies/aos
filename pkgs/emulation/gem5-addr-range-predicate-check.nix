##! Direct native address-range equivalence and allocation microbenchmark
{
  mkDerivation,
  gem5,
  patch,
  python3,
}:
mkDerivation {
  pname = "gem5-addr-range-predicate-check";
  version = "1";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        cpu = ["x86_64"];
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
  src = gem5.src;
  buildDeps = [patch python3];
  runtimeDeps = [];
  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd gem5-*
        cp src/base/addr_range_map.hh src/base/addr_range_map-baseline.hh
        patch --fuzz=0 -p1 < ${./gem5-patches/addr-range-predicate-borrow.patch}
        ${python3}/bin/python3 -B - <<'PY'
        from pathlib import Path
        import re

        for name in ("addr_range_map-baseline.hh", "addr_range_map.hh"):
            source = Path("src/base", name).read_text()
            assert len(source) < 65536
            source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
            calls = list(re.finditer(r"\bfind\s*\(", source))
            definitions = list(re.finditer(r"\bfind\s*\(const AddrRange &r,", source))
            assert len(calls) == 7 and len(definitions) == 2
            assert "friend" not in source
            for definition in definitions:
                access = re.findall(r"\b(public|private|protected)\s*:", source[:definition.start()])
                assert access[-1] == "private"
            assert source.count("return find(r,") == 4
            assert source.count("const_cast<AddrRangeMap *>(this)->find(r, cond)") == 1
            assert source.count("r.isSubset(r1)") == 2
            assert source.count("r.intersects(r1)") == 2
        print("Private synchronous pure predicate caller inventory: passed")
        PY
        mkdir -p generated/config
        cat > namespace-probe.cc <<'EOF'
        namespace [[deprecated("probe")]] probe { int value; }
        EOF
        if c++ -std=c++17 -Werror -c namespace-probe.cc -o namespace-probe.o; then
          echo '#define HAVE_DEPRECATED_NAMESPACE 1' > generated/config/have_deprecated_namespace.hh
        else
          echo '#define HAVE_DEPRECATED_NAMESPACE 0' > generated/config/have_deprecated_namespace.hh
        fi
      '';
    }
    {
      name = "build";
      script = ''
        # Compile the pinned native header and its upstream test support. The
        # baseline and patched map coexist in one process with the same inputs.
        c++ -O3 -std=c++17 -pthread -Igenerated -Isrc \
          -Iext/googletest/googletest/include -Iext/googletest/googletest \
          -Iext \
          ${./_gem5/addr-range-predicate-check.cc} \
          src/base/gtest/logging.cc src/base/gtest/logging_mock.cc src/base/cprintf.cc \
          ext/googletest/googletest/src/gtest-all.cc \
          ext/googletest/googletest/src/gtest_main.cc -o addr-range-check
      '';
    }
    {
      name = "check";
      script = ''./addr-range-check > result.log 2>&1'';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/checks" "$out/share/licenses/gem5-addr-range-predicate-check"
        cp result.log "$out/share/checks/addr-range.log"
        cp LICENSE "$out/share/licenses/gem5-addr-range-predicate-check/gem5-LICENSE"
        cp ext/googletest/LICENSE "$out/share/licenses/gem5-addr-range-predicate-check/googletest-LICENSE"
        cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-addr-range-predicate-check/fixture-LICENSE"
      '';
    }
  ];
  meta = {
    description = "Proves native address-range predicate equivalence and removal of synchronous lookup allocations; no whole-boot performance claim";
    license = "BSD-3-Clause AND MIT";
  };
}
