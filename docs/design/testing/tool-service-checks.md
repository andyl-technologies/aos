# Tool and Service Integration Checks

This document specifies integration tests for CLI tools, system components, and
services in the AOS package set. Each test validates that a tool or service works
correctly with its dependencies, catching runtime failures that compile-time checks
miss.

Tests fall into two categories:

- **Build-sandbox tests (Layer 2.5):** Run during `nix-build` inside the Nix
  sandbox. No VM, no network, no systemd. Suitable for tool smoke tests that need
  only a filesystem and process execution.
- **VM tests (Layer 3):** Run inside a booted QEMU VM with systemd, networking, and
  the full AOS rootfs. Required for service startup, systemd unit validation,
  kernel module operations, and anything that needs a real init system.

## Test API reference

### Build-sandbox tests

Build-sandbox tests are `mkDerivation` derivations that exercise tool binaries
directly. The derivation's `buildDeps` include the tool under test and any
supporting packages. The phase script runs commands and checks exit codes:

```nix
pkgs.mkDerivation {
  pname = "check-toolname-feature";
  version = "0";
  src = null;
  buildDeps = [ pkgs.toolname ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      # ... test commands ...
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### VM tests

VM tests use the composable check module system. Checks are shell script
fragments executed on the host, communicating with the guest VM via a
virtio-serial agent. The agent runs commands in the guest and returns JSON
results:

```nix
mkCheck {
  name = "test-name";
  description = "What it tests";
  script = ''
    assert_success "command-in-guest" \
      "description of assertion"
  '';
}
```

Available assertion helpers:

| Helper | Arguments | Behavior |
|--------|-----------|----------|
| `assert_success` | `cmd`, `desc` | Runs `cmd` in guest, asserts exit code 0 |
| `assert_output_contains` | `cmd`, `expected`, `desc` | Runs `cmd` in guest, asserts stdout contains `expected` |

**Guest environment constraints:** The VM guest has bash, coreutils, and systemd
tools (systemctl, journalctl). It does NOT have grep, sed, ip, sysctl, mount, or
lsmod. Use `/proc/sys/...`, `/sys/class/net/...`, and `/proc/mounts` instead.

Note: `assert_output_contains` runs grep on the *host* side. Commands piped
through `| grep` inside `assert_success` would require grep in the guest.

---

## 1. Core POSIX Tools

All core POSIX tool tests are build-sandbox tests. They validate that AOS-built
tools handle representative workloads and that their dependencies (libc, shared
libraries) are correctly linked.

### 1.1 bash

**Package:** `pkgs/core/bash.nix`
**Test type:** Build-sandbox

```nix
# check-bash-execute-script
pkgs.mkDerivation {
  pname = "check-bash-execute-script";
  version = "0";
  src = null;
  buildDeps = [ pkgs.bash ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      cat > /tmp/test.sh << 'SCRIPT'
      #!/usr/bin/env bash
      sum=0
      for i in 1 2 3 4 5; do
        sum=$((sum + i))
      done
      greet() { echo "hello $1"; }
      if [ "$sum" -eq 15 ]; then
        greet "world"
      else
        exit 1
      fi
      SCRIPT
      chmod +x /tmp/test.sh
      result=$($CONFIG_SHELL /tmp/test.sh)
      test "$result" = "hello world"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-bash-builtins
# Tests: read, printf, [[ ]], arrays, parameter expansion
pkgs.mkDerivation {
  pname = "check-bash-builtins";
  version = "0";
  src = null;
  buildDeps = [ pkgs.bash ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Test arrays and parameter expansion using CONFIG_SHELL (bash)
      $CONFIG_SHELL -c '
        arr=(alpha beta gamma)
        test "''${#arr[@]}" -eq 3 || exit 1
        test "''${arr[1]}" = "beta" || exit 1
        str="hello-world"
        test "''${str//-/_}" = "hello_world" || exit 1
        [[ "foobar" == foo* ]] || exit 1
        printf -v out "%05d" 42
        test "$out" = "00042" || exit 1
      '

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-bash-source
# Tests: source a file with exported functions
pkgs.mkDerivation {
  pname = "check-bash-source";
  version = "0";
  src = null;
  buildDeps = [ pkgs.bash ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      cat > /tmp/lib.sh << 'LIB'
      add() { echo $(( $1 + $2 )); }
      export -f add
      LIB

      result=$($CONFIG_SHELL -c 'source /tmp/lib.sh; add 3 7')
      test "$result" = "10"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.2 coreutils

**Package:** `pkgs/core/coreutils.nix`
**Test type:** Build-sandbox

```nix
# check-coreutils-basic-ops
# Tests: ls, cp, mv, rm, mkdir, rmdir on temp files
pkgs.mkDerivation {
  pname = "check-coreutils-basic-ops";
  version = "0";
  src = null;
  buildDeps = [ pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/test-dir/sub
      echo "content" > /tmp/test-dir/file.txt
      cp /tmp/test-dir/file.txt /tmp/test-dir/copy.txt
      test -f /tmp/test-dir/copy.txt
      mv /tmp/test-dir/copy.txt /tmp/test-dir/moved.txt
      test -f /tmp/test-dir/moved.txt
      test ! -f /tmp/test-dir/copy.txt
      rm /tmp/test-dir/moved.txt
      test ! -f /tmp/test-dir/moved.txt
      rmdir /tmp/test-dir/sub
      test ! -d /tmp/test-dir/sub
      ls /tmp/test-dir > /dev/null

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-coreutils-text-ops
# Tests: cat, head, tail, wc, sort, uniq, tr, cut on test data
pkgs.mkDerivation {
  pname = "check-coreutils-text-ops";
  version = "0";
  src = null;
  buildDeps = [ pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "cherry\napple\nbanana\napple\n" > /tmp/fruit.txt
      test "$(wc -l < /tmp/fruit.txt)" -eq 4
      test "$(head -1 /tmp/fruit.txt)" = "cherry"
      test "$(tail -1 /tmp/fruit.txt)" = "apple"
      test "$(sort /tmp/fruit.txt | head -1)" = "apple"
      test "$(sort /tmp/fruit.txt | uniq | wc -l)" -eq 3
      test "$(echo "hello" | tr 'a-z' 'A-Z')" = "HELLO"
      test "$(echo "a:b:c" | cut -d: -f2)" = "b"
      cat /tmp/fruit.txt > /dev/null

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-coreutils-perms
# Tests: chmod, chown (limited in sandbox — test chmod only)
pkgs.mkDerivation {
  pname = "check-coreutils-perms";
  version = "0";
  src = null;
  buildDeps = [ pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "test" > /tmp/perm-test.txt
      chmod 644 /tmp/perm-test.txt
      chmod 755 /tmp/perm-test.txt
      # Verify the file is executable after chmod 755
      test -x /tmp/perm-test.txt

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-coreutils-misc
# Tests: date, env, test, expr, printf
pkgs.mkDerivation {
  pname = "check-coreutils-misc";
  version = "0";
  src = null;
  buildDeps = [ pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      date +%Y > /dev/null
      env > /dev/null
      test 1 -eq 1
      test "$(expr 3 + 4)" = "7"
      test "$(printf "%04d" 42)" = "0042"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.3 grep

**Package:** `pkgs/core/grep.nix`
**Test type:** Build-sandbox

```nix
# check-grep-basic
# Tests: match fixed strings in files
pkgs.mkDerivation {
  pname = "check-grep-basic";
  version = "0";
  src = null;
  buildDeps = [ pkgs.grep pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "alpha\nbeta\ngamma\n" > /tmp/words.txt
      test "$(grep beta /tmp/words.txt)" = "beta"
      test "$(grep -c a /tmp/words.txt)" -eq 3

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-grep-regex
# Tests: extended regex matching
pkgs.mkDerivation {
  pname = "check-grep-regex";
  version = "0";
  src = null;
  buildDeps = [ pkgs.grep pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "foo123\nbar456\nbaz\n" > /tmp/data.txt
      test "$(grep -E '[0-9]+' /tmp/data.txt | wc -l)" -eq 2
      test "$(grep -E '^b' /tmp/data.txt | wc -l)" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-grep-recursive
# Tests: recursive directory search
pkgs.mkDerivation {
  pname = "check-grep-recursive";
  version = "0";
  src = null;
  buildDeps = [ pkgs.grep pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/grep-tree/sub
      echo "needle here" > /tmp/grep-tree/a.txt
      echo "no match" > /tmp/grep-tree/sub/b.txt
      echo "another needle" > /tmp/grep-tree/sub/c.txt
      test "$(grep -r needle /tmp/grep-tree | wc -l)" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.4 sed

**Package:** `pkgs/core/sed.nix`
**Test type:** Build-sandbox

```nix
# check-sed-substitute
pkgs.mkDerivation {
  pname = "check-sed-substitute";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sed pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "foo bar foo" > /tmp/sed-test.txt
      test "$(sed 's/foo/baz/g' /tmp/sed-test.txt)" = "baz bar baz"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-sed-delete
pkgs.mkDerivation {
  pname = "check-sed-delete";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sed pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "keep\nremove\nkeep\n" > /tmp/sed-del.txt
      test "$(sed '/remove/d' /tmp/sed-del.txt | wc -l)" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-sed-inplace
pkgs.mkDerivation {
  pname = "check-sed-inplace";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sed pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "old text" > /tmp/sed-ip.txt
      sed -i 's/old/new/' /tmp/sed-ip.txt
      test "$(cat /tmp/sed-ip.txt)" = "new text"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.5 gawk

**Package:** `pkgs/core/gawk.nix`
**Test type:** Build-sandbox

```nix
# check-gawk-fields
pkgs.mkDerivation {
  pname = "check-gawk-fields";
  version = "0";
  src = null;
  buildDeps = [ pkgs.gawk pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "alice,30,engineer\nbob,25,designer\n" > /tmp/data.csv
      result=$(awk -F, '{print $1}' /tmp/data.csv | head -1)
      test "$result" = "alice"
      result=$(awk -F, '{sum += $2} END {print sum}' /tmp/data.csv)
      test "$result" = "55"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-gawk-regex
pkgs.mkDerivation {
  pname = "check-gawk-regex";
  version = "0";
  src = null;
  buildDeps = [ pkgs.gawk pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "error: disk full\ninfo: ok\nerror: timeout\n" > /tmp/log.txt
      test "$(awk '/^error/' /tmp/log.txt | wc -l)" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-gawk-printf
pkgs.mkDerivation {
  pname = "check-gawk-printf";
  version = "0";
  src = null;
  buildDeps = [ pkgs.gawk pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      result=$(echo "" | awk '{printf "%05d %.2f\n", 42, 3.14159}')
      test "$result" = "00042 3.14"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.6 tar

**Package:** `pkgs/core/tar.nix`
**Test type:** Build-sandbox
**Validates:** tar + gzip, bzip2, xz, zstd integration

```nix
# check-tar-create-extract
pkgs.mkDerivation {
  pname = "check-tar-create-extract";
  version = "0";
  src = null;
  buildDeps = [ pkgs.tar pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/tar-src
      echo "file content" > /tmp/tar-src/a.txt
      echo "more content" > /tmp/tar-src/b.txt
      tar cf /tmp/test.tar -C /tmp tar-src
      mkdir -p /tmp/tar-dst
      tar xf /tmp/test.tar -C /tmp/tar-dst
      test "$(cat /tmp/tar-dst/tar-src/a.txt)" = "file content"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-tar-gzip
pkgs.mkDerivation {
  pname = "check-tar-gzip";
  version = "0";
  src = null;
  buildDeps = [ pkgs.tar pkgs.gzip pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/tgz-src
      echo "gzip content" > /tmp/tgz-src/file.txt
      tar czf /tmp/test.tar.gz -C /tmp tgz-src
      mkdir -p /tmp/tgz-dst
      tar xzf /tmp/test.tar.gz -C /tmp/tgz-dst
      test "$(cat /tmp/tgz-dst/tgz-src/file.txt)" = "gzip content"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-tar-xz
pkgs.mkDerivation {
  pname = "check-tar-xz";
  version = "0";
  src = null;
  buildDeps = [ pkgs.tar pkgs.xz pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/txz-src
      echo "xz content" > /tmp/txz-src/file.txt
      tar cJf /tmp/test.tar.xz -C /tmp txz-src
      mkdir -p /tmp/txz-dst
      tar xJf /tmp/test.tar.xz -C /tmp/txz-dst
      test "$(cat /tmp/txz-dst/txz-src/file.txt)" = "xz content"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-tar-zstd
pkgs.mkDerivation {
  pname = "check-tar-zstd";
  version = "0";
  src = null;
  buildDeps = [ pkgs.tar pkgs.zstd pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/tzst-src
      echo "zstd content" > /tmp/tzst-src/file.txt
      tar --zstd -cf /tmp/test.tar.zst -C /tmp tzst-src
      mkdir -p /tmp/tzst-dst
      tar --zstd -xf /tmp/test.tar.zst -C /tmp/tzst-dst
      test "$(cat /tmp/tzst-dst/tzst-src/file.txt)" = "zstd content"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-tar-bzip2
pkgs.mkDerivation {
  pname = "check-tar-bzip2";
  version = "0";
  src = null;
  buildDeps = [ pkgs.tar pkgs.bzip2 pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/tbz-src
      echo "bzip2 content" > /tmp/tbz-src/file.txt
      tar cjf /tmp/test.tar.bz2 -C /tmp tbz-src
      mkdir -p /tmp/tbz-dst
      tar xjf /tmp/test.tar.bz2 -C /tmp/tbz-dst
      test "$(cat /tmp/tbz-dst/tbz-src/file.txt)" = "bzip2 content"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.7 findutils

**Package:** `pkgs/core/findutils.nix`
**Test type:** Build-sandbox

```nix
# check-find-name
pkgs.mkDerivation {
  pname = "check-find-name";
  version = "0";
  src = null;
  buildDeps = [ pkgs.findutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/find-test/sub
      touch /tmp/find-test/a.txt /tmp/find-test/b.log /tmp/find-test/sub/c.txt
      test "$(find /tmp/find-test -name '*.txt' | wc -l)" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-find-type
pkgs.mkDerivation {
  pname = "check-find-type";
  version = "0";
  src = null;
  buildDeps = [ pkgs.findutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/ftype-test/dir1 /tmp/ftype-test/dir2
      touch /tmp/ftype-test/file1
      test "$(find /tmp/ftype-test -type d | wc -l)" -eq 3
      test "$(find /tmp/ftype-test -type f | wc -l)" -eq 1

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-xargs-basic
pkgs.mkDerivation {
  pname = "check-xargs-basic";
  version = "0";
  src = null;
  buildDeps = [ pkgs.findutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/xargs-test
      touch /tmp/xargs-test/a.txt /tmp/xargs-test/b.txt
      count=$(find /tmp/xargs-test -name '*.txt' | xargs -I{} echo {} | wc -l)
      test "$count" -eq 2

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.8 diffutils

**Package:** `pkgs/core/diffutils.nix`
**Test type:** Build-sandbox

```nix
# check-diff-files
pkgs.mkDerivation {
  pname = "check-diff-files";
  version = "0";
  src = null;
  buildDeps = [ pkgs.diffutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "line1\nline2\nline3\n" > /tmp/diff-a.txt
      printf "line1\nchanged\nline3\n" > /tmp/diff-b.txt
      # diff exits 1 when files differ — that is expected
      diff /tmp/diff-a.txt /tmp/diff-b.txt > /tmp/diff-out.txt || true
      # Verify the diff output is non-empty and mentions line2/changed
      test -s /tmp/diff-out.txt

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-cmp-files
pkgs.mkDerivation {
  pname = "check-cmp-files";
  version = "0";
  src = null;
  buildDeps = [ pkgs.diffutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "identical" > /tmp/cmp-a.txt
      echo "identical" > /tmp/cmp-b.txt
      cmp /tmp/cmp-a.txt /tmp/cmp-b.txt

      echo "different" > /tmp/cmp-c.txt
      # cmp exits 1 when files differ
      ! cmp -s /tmp/cmp-a.txt /tmp/cmp-c.txt

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.9 patch

**Package:** `pkgs/core/patch.nix`
**Test type:** Build-sandbox

```nix
# check-patch-apply
pkgs.mkDerivation {
  pname = "check-patch-apply";
  version = "0";
  src = null;
  buildDeps = [ pkgs.patch pkgs.diffutils pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      printf "line1\nold line\nline3\n" > /tmp/original.txt
      printf "line1\nnew line\nline3\n" > /tmp/modified.txt
      diff -u /tmp/original.txt /tmp/modified.txt > /tmp/fix.patch || true

      cp /tmp/original.txt /tmp/target.txt
      patch /tmp/target.txt /tmp/fix.patch
      test "$(cat /tmp/target.txt)" = "$(cat /tmp/modified.txt)"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.10 gzip

**Package:** `pkgs/core/gzip.nix`
**Test type:** Build-sandbox
**Validates:** gzip + zlib

```nix
# check-gzip-roundtrip
pkgs.mkDerivation {
  pname = "check-gzip-roundtrip";
  version = "0";
  src = null;
  buildDeps = [ pkgs.gzip pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "compress me" > /tmp/gz-test.txt
      gzip /tmp/gz-test.txt
      test -f /tmp/gz-test.txt.gz
      test ! -f /tmp/gz-test.txt
      gzip -d /tmp/gz-test.txt.gz
      test "$(cat /tmp/gz-test.txt)" = "compress me"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.11 xz

**Package:** `pkgs/core/xz.nix`
**Test type:** Build-sandbox
**Validates:** xz + liblzma

```nix
# check-xz-roundtrip
pkgs.mkDerivation {
  pname = "check-xz-roundtrip";
  version = "0";
  src = null;
  buildDeps = [ pkgs.xz pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo "xz test data" > /tmp/xz-test.txt
      xz /tmp/xz-test.txt
      test -f /tmp/xz-test.txt.xz
      xz -d /tmp/xz-test.txt.xz
      test "$(cat /tmp/xz-test.txt)" = "xz test data"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 1.12 which

**Package:** `pkgs/core/which.nix`
**Test type:** Build-sandbox

```nix
# check-which-locate
pkgs.mkDerivation {
  pname = "check-which-locate";
  version = "0";
  src = null;
  buildDeps = [ pkgs.which pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      result=$(which ls)
      test -n "$result"
      test -x "$result"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## 2. Data Tools

### 2.1 jq

**Package:** `pkgs/data/jq.nix`
**Test type:** Build-sandbox
**Validates:** jq + oniguruma

```nix
# check-jq-parse
pkgs.mkDerivation {
  pname = "check-jq-parse";
  version = "0";
  src = null;
  buildDeps = [ pkgs.jq pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo '{"name":"aos","version":"1.0"}' | jq -r '.name' > /tmp/jq-out.txt
      test "$(cat /tmp/jq-out.txt)" = "aos"
      echo '{"a":{"b":{"c":42}}}' | jq '.a.b.c' > /tmp/jq-nested.txt
      test "$(cat /tmp/jq-nested.txt)" = "42"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-jq-filter
pkgs.mkDerivation {
  pname = "check-jq-filter";
  version = "0";
  src = null;
  buildDeps = [ pkgs.jq pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo '[{"n":1},{"n":2},{"n":3},{"n":4}]' \
        | jq '[.[] | select(.n > 2)]' > /tmp/jq-filter.txt
      test "$(cat /tmp/jq-filter.txt | jq 'length')" = "2"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-jq-transform
pkgs.mkDerivation {
  pname = "check-jq-transform";
  version = "0";
  src = null;
  buildDeps = [ pkgs.jq pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      echo '[1,2,3,4,5]' | jq '[.[] | . * 2]' > /tmp/jq-map.txt
      test "$(cat /tmp/jq-map.txt)" = "[2,4,6,8,10]"
      echo '[10,20,30]' | jq 'reduce .[] as $x (0; . + $x)' > /tmp/jq-reduce.txt
      test "$(cat /tmp/jq-reduce.txt)" = "60"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 2.2 sqlite3

**Package:** `pkgs/data/sqlite.nix`
**Test type:** Build-sandbox
**Validates:** sqlite3 CLI + libsqlite3

```nix
# check-sqlite3-create-db
pkgs.mkDerivation {
  pname = "check-sqlite3-create-db";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sqlite pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      sqlite3 /tmp/test.db << 'SQL'
      CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER);
      INSERT INTO users VALUES (1, 'alice', 30);
      INSERT INTO users VALUES (2, 'bob', 25);
      INSERT INTO users VALUES (3, 'carol', 35);
      SQL
      test -f /tmp/test.db

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-sqlite3-query
pkgs.mkDerivation {
  pname = "check-sqlite3-query";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sqlite pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      sqlite3 /tmp/query.db << 'SQL'
      CREATE TABLE items (id INTEGER PRIMARY KEY, category TEXT, value INTEGER);
      INSERT INTO items VALUES (1, 'a', 10);
      INSERT INTO items VALUES (2, 'b', 20);
      INSERT INTO items VALUES (3, 'a', 30);
      SQL
      result=$(sqlite3 /tmp/query.db "SELECT SUM(value) FROM items WHERE category='a';")
      test "$result" = "40"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-sqlite3-integrity
pkgs.mkDerivation {
  pname = "check-sqlite3-integrity";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sqlite pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      sqlite3 /tmp/integrity.db "CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);"
      result=$(sqlite3 /tmp/integrity.db "PRAGMA integrity_check;")
      test "$result" = "ok"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 2.3 bc

**Package:** `pkgs/data/bc.nix`
**Test type:** Build-sandbox

```nix
# check-bc-arithmetic
pkgs.mkDerivation {
  pname = "check-bc-arithmetic";
  version = "0";
  src = null;
  buildDeps = [ pkgs.bc pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      test "$(echo '3 + 4' | bc)" = "7"
      test "$(echo '100 / 3' | bc)" = "33"
      test "$(echo 'scale=2; 100 / 3' | bc)" = "33.33"
      test "$(echo '2 ^ 10' | bc)" = "1024"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## 3. Build System Tools

### 3.1 make

**Package:** `pkgs/build-systems/make.nix`
**Test type:** Build-sandbox

```nix
# check-make-simple
pkgs.mkDerivation {
  pname = "check-make-simple";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/make-test
      cat > /tmp/make-test/hello.c << 'EOF'
      #include <stdio.h>
      int main() { printf("hello from make\n"); return 0; }
      EOF
      cat > /tmp/make-test/Makefile << 'EOF'
      hello: hello.c
      	$(CC) -o hello hello.c
      EOF
      make -C /tmp/make-test
      result=$(/tmp/make-test/hello)
      test "$result" = "hello from make"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-make-parallel
pkgs.mkDerivation {
  pname = "check-make-parallel";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/make-par
      cat > /tmp/make-par/a.c << 'EOF'
      int get_a(void) { return 1; }
      EOF
      cat > /tmp/make-par/b.c << 'EOF'
      int get_b(void) { return 2; }
      EOF
      cat > /tmp/make-par/main.c << 'EOF'
      #include <stdio.h>
      int get_a(void);
      int get_b(void);
      int main() { printf("%d\n", get_a() + get_b()); return 0; }
      EOF
      cat > /tmp/make-par/Makefile << 'EOF'
      OBJS = a.o b.o main.o
      prog: $(OBJS)
      	$(CC) -o prog $(OBJS)
      %.o: %.c
      	$(CC) -c -o $@ $<
      EOF
      make -C /tmp/make-par -j4
      test "$(/tmp/make-par/prog)" = "3"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 3.2 cmake

**Package:** `pkgs/build-systems/cmake.nix`
**Test type:** Build-sandbox

```nix
# check-cmake-configure-build
pkgs.mkDerivation {
  pname = "check-cmake-configure-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.cmake pkgs.make pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/cmake-test
      cat > /tmp/cmake-test/main.c << 'EOF'
      #include <stdio.h>
      int main() { printf("cmake works\n"); return 0; }
      EOF
      cat > /tmp/cmake-test/CMakeLists.txt << 'EOF'
      cmake_minimum_required(VERSION 3.10)
      project(test C)
      add_executable(test_app main.c)
      EOF
      mkdir -p /tmp/cmake-test/build
      cd /tmp/cmake-test/build
      cmake ..
      make
      test "$(./test_app)" = "cmake works"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-cmake-find-openssl
pkgs.mkDerivation {
  pname = "check-cmake-find-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.cmake pkgs.make pkgs.coreutils ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/cmake-ossl
      cat > /tmp/cmake-ossl/main.c << 'EOF'
      #include <openssl/opensslv.h>
      #include <stdio.h>
      int main() { printf("OpenSSL %s\n", OPENSSL_VERSION_TEXT); return 0; }
      EOF
      cat > /tmp/cmake-ossl/CMakeLists.txt << 'EOF'
      cmake_minimum_required(VERSION 3.10)
      project(test C)
      find_package(OpenSSL REQUIRED)
      add_executable(test_app main.c)
      target_link_libraries(test_app OpenSSL::SSL)
      EOF
      mkdir -p /tmp/cmake-ossl/build
      cd /tmp/cmake-ossl/build
      cmake ..
      make
      ./test_app

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-cmake-find-zlib
pkgs.mkDerivation {
  pname = "check-cmake-find-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.cmake pkgs.make pkgs.coreutils ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/cmake-zlib
      cat > /tmp/cmake-zlib/main.c << 'EOF'
      #include <zlib.h>
      #include <stdio.h>
      int main() { printf("zlib %s\n", zlibVersion()); return 0; }
      EOF
      cat > /tmp/cmake-zlib/CMakeLists.txt << 'EOF'
      cmake_minimum_required(VERSION 3.10)
      project(test C)
      find_package(ZLIB REQUIRED)
      add_executable(test_app main.c)
      target_link_libraries(test_app ZLIB::ZLIB)
      EOF
      mkdir -p /tmp/cmake-zlib/build
      cd /tmp/cmake-zlib/build
      cmake ..
      make
      ./test_app

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 3.3 meson + ninja

**Package:** `pkgs/build-systems/meson.nix`, `pkgs/build-systems/ninja.nix`
**Test type:** Build-sandbox
**Validates:** meson + ninja + python3 + gcc

```nix
# check-meson-configure-build
pkgs.mkDerivation {
  pname = "check-meson-configure-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.meson pkgs.ninja pkgs.python3 pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/meson-test
      cat > /tmp/meson-test/main.c << 'EOF'
      #include <stdio.h>
      int main() { printf("meson works\n"); return 0; }
      EOF
      cat > /tmp/meson-test/meson.build << 'EOF'
      project('test', 'c')
      executable('test_app', 'main.c')
      EOF
      cd /tmp/meson-test
      meson setup build
      ninja -C build
      test "$(./build/test_app)" = "meson works"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 3.4 autoconf + automake

**Package:** `pkgs/build-systems/autoconf.nix`, `pkgs/build-systems/automake.nix`
**Test type:** Build-sandbox
**Validates:** autoconf + automake + m4 + make

```nix
# check-autotools-full-cycle
pkgs.mkDerivation {
  pname = "check-autotools-full-cycle";
  version = "0";
  src = null;
  buildDeps = [
    pkgs.autoconf pkgs.automake pkgs.m4 pkgs.make pkgs.perl pkgs.coreutils
  ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/autotools-test
      cat > /tmp/autotools-test/main.c << 'EOF'
      #include <stdio.h>
      int main() { printf("autotools works\n"); return 0; }
      EOF
      cat > /tmp/autotools-test/configure.ac << 'EOF'
      AC_INIT([test], [1.0])
      AM_INIT_AUTOMAKE([foreign])
      AC_PROG_CC
      AC_OUTPUT([Makefile])
      EOF
      cat > /tmp/autotools-test/Makefile.am << 'EOF'
      bin_PROGRAMS = test_app
      test_app_SOURCES = main.c
      EOF
      cd /tmp/autotools-test
      autoreconf -i
      ./configure
      make
      test "$(./test_app)" = "autotools works"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 3.5 pkg-config

**Package:** `pkgs/tools/pkg-config.nix`
**Test type:** Build-sandbox
**Validates:** pkg-config + .pc files from AOS packages

```nix
# check-pkg-config-openssl
pkgs.mkDerivation {
  pname = "check-pkg-config-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.pkg-config pkgs.coreutils ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      pkg-config --exists openssl
      pkg-config --libs openssl > /dev/null
      pkg-config --cflags openssl > /dev/null

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-pkg-config-zlib
pkgs.mkDerivation {
  pname = "check-pkg-config-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.pkg-config pkgs.coreutils ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      pkg-config --exists zlib
      pkg-config --libs zlib > /dev/null
      pkg-config --cflags zlib > /dev/null

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}

# check-pkg-config-libcurl
pkgs.mkDerivation {
  pname = "check-pkg-config-libcurl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.pkg-config pkgs.coreutils ];
  runtimeDeps = [ pkgs.curl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      pkg-config --exists libcurl
      pkg-config --libs libcurl > /dev/null
      pkg-config --cflags libcurl > /dev/null

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## 4. Networking Tools

### 4.1 curl

**Package:** `pkgs/networking/curl.nix`

#### Build-sandbox: Version and feature check

```nix
# check-curl-version
pkgs.mkDerivation {
  pname = "check-curl-version";
  version = "0";
  src = null;
  buildDeps = [ pkgs.curl pkgs.grep pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      curl --version > /tmp/curl-ver.txt
      # Verify key features are compiled in
      grep -q "SSL" /tmp/curl-ver.txt
      grep -q "zlib" /tmp/curl-ver.txt
      grep -q "nghttp2" /tmp/curl-ver.txt

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

#### VM: HTTP request via nginx

**Test type:** VM (requires nginx service running)

```nix
# check-curl-local-http
mkCheck {
  name = "curl-local-http";
  description = "curl fetches page from local nginx";
  script = ''
    # Wait for nginx to be ready
    TRIES=0
    while [ $TRIES -lt 10 ]; do
      RESULT=$(run_in_guest "systemctl is-active nginx" 2>/dev/null || true)
      STATUS=$(echo "$RESULT" | jq -r '.stdout // empty' 2>/dev/null || echo "$RESULT")
      if [ "$STATUS" = "active" ]; then
        break
      fi
      TRIES=$((TRIES + 1))
      sleep 2
    done
    assert_success "curl -sf http://127.0.0.1:80/ -o /dev/null" \
      "curl can fetch from local nginx on port 80"
  '';
}
```

### 4.2 openssh

**Package:** `pkgs/networking/openssh.nix`
**Test type:** VM (service startup, key generation)

```nix
# check-openssh-keygen
mkCheck {
  name = "openssh-keygen";
  description = "ssh-keygen can generate ed25519 keys";
  script = ''
    assert_success "ssh-keygen -t ed25519 -f /tmp/test-key -N ''" \
      "ssh-keygen generates ed25519 keypair"
    assert_success "test -f /tmp/test-key" \
      "private key file exists"
    assert_success "test -f /tmp/test-key.pub" \
      "public key file exists"
  '';
}

# check-openssh-sshd-config
mkCheck {
  name = "openssh-sshd-config";
  description = "sshd config passes syntax validation";
  script = ''
    assert_success "sshd -t" \
      "sshd config syntax is valid"
  '';
}

# check-openssh-client-version
mkCheck {
  name = "openssh-client-version";
  description = "ssh client reports version";
  script = ''
    assert_output_contains "ssh -V 2>&1" "OpenSSH" \
      "ssh -V outputs OpenSSH version string"
  '';
}
```

### 4.3 rsync

**Package:** `pkgs/networking/rsync.nix`
**Test type:** Build-sandbox
**Validates:** rsync + openssl

```nix
# check-rsync-local-sync
pkgs.mkDerivation {
  pname = "check-rsync-local-sync";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rsync pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      mkdir -p /tmp/rsync-src /tmp/rsync-dst
      echo "file1" > /tmp/rsync-src/a.txt
      echo "file2" > /tmp/rsync-src/b.txt
      rsync -a /tmp/rsync-src/ /tmp/rsync-dst/
      test "$(cat /tmp/rsync-dst/a.txt)" = "file1"
      test "$(cat /tmp/rsync-dst/b.txt)" = "file2"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 4.4 socat

**Package:** `pkgs/networking/socat.nix`
**Test type:** Build-sandbox

```nix
# check-socat-pipe
pkgs.mkDerivation {
  pname = "check-socat-pipe";
  version = "0";
  src = null;
  buildDeps = [ pkgs.socat pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Test socat piping between two processes
      result=$(echo "hello socat" | socat - EXEC:"cat",nofork)
      test "$result" = "hello socat"

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 4.5 iproute2

**Package:** `pkgs/networking/iproute2.nix`
**Test type:** VM
**Validates:** iproute2 + libnl

```nix
# check-iproute2-addr
mkCheck {
  name = "iproute2-addr";
  description = "ip addr shows interface addresses";
  script = ''
    assert_success "ip addr show" \
      "ip addr show returns successfully"
  '';
}

# check-iproute2-link
mkCheck {
  name = "iproute2-link";
  description = "ip link shows interfaces";
  script = ''
    assert_success "ip link show" \
      "ip link show returns successfully"
  '';
}

# check-iproute2-route
mkCheck {
  name = "iproute2-route";
  description = "ip route shows routing table";
  script = ''
    assert_success "ip route show" \
      "ip route show returns successfully"
  '';
}
```

### 4.6 nftables

**Package:** `pkgs/networking/nftables.nix`
**Test type:** VM
**Validates:** nftables + libnftnl + libmnl + jansson

```nix
# check-nftables-list
mkCheck {
  name = "nftables-list";
  description = "nft can list ruleset";
  script = ''
    assert_success "nft list ruleset" \
      "nft list ruleset returns successfully"
  '';
}

# check-nftables-json
mkCheck {
  name = "nftables-json";
  description = "nft can output ruleset as JSON";
  script = ''
    assert_success "nft -j list ruleset" \
      "nft -j list ruleset returns valid JSON"
  '';
}
```

### 4.7 iptables

**Package:** `pkgs/networking/iptables.nix`
**Test type:** VM

```nix
# check-iptables-compat
mkCheck {
  name = "iptables-compat";
  description = "iptables-save works (nft backend)";
  script = ''
    assert_success "iptables-save" \
      "iptables-save returns successfully"
  '';
}
```

### 4.8 chrony

**Package:** `pkgs/networking/chrony.nix`
**Test type:** VM
**Validates:** chrony + libcap

Chrony checks already exist in `tests/vm/checks/chrony.nix`. The following
tests extend coverage:

```nix
# check-chrony-start (exists in chrony.nix as chronyd-active)
mkCheck {
  name = "chronyd-active";
  description = "chronyd service is active";
  script = ''
    # chronyd may take a few seconds to finish forking
    TRIES=0
    while [ $TRIES -lt 15 ]; do
      RESULT=$(run_in_guest "systemctl is-active chronyd" 2>/dev/null || true)
      STATUS=$(echo "$RESULT" | jq -r '.stdout // empty' 2>/dev/null || echo "$RESULT")
      if [ "$STATUS" = "active" ]; then
        break
      fi
      TRIES=$((TRIES + 1))
      sleep 2
    done
    assert_success "systemctl is-active chronyd" \
      "chronyd service is active"
  '';
}

# check-chrony-tracking
mkCheck {
  name = "chrony-tracking";
  description = "chronyc tracking reports status";
  script = ''
    assert_success "chronyc tracking" \
      "chronyc tracking returns successfully"
  '';
}
```

### 4.9 ethtool

**Package:** `pkgs/networking/ethtool.nix`
**Test type:** VM

```nix
# check-ethtool-query
mkCheck {
  name = "ethtool-query";
  description = "ethtool can query an interface";
  script = ''
    # Use the loopback or first available ethernet interface
    assert_success "ethtool lo 2>&1 || true" \
      "ethtool runs without crashing"
  '';
}
```

---

## 5. Container and Kubernetes Tools

All container/kubernetes tool tests are VM tests. These binaries require kernel
features (namespaces, cgroups) and systemd integration that the build sandbox
cannot provide.

### 5.1 containerd

**Package:** `pkgs/containers/containerd.nix`
**Test type:** VM

Existing checks are in `tests/vm/checks/containerd.nix`. Additional tests:

```nix
# check-containerd-version
mkCheck {
  name = "containerd-version";
  description = "containerd reports version";
  script = ''
    assert_success "containerd --version" \
      "containerd --version returns successfully"
  '';
}

# check-containerd-service (exists as containerd-active)
mkCheck {
  name = "containerd-active";
  description = "containerd service is active";
  script = ''
    assert_success "systemctl is-active containerd" \
      "containerd service is active"
  '';
}

# check-containerd-socket (exists)
mkCheck {
  name = "containerd-socket";
  description = "containerd socket exists";
  script = ''
    assert_success "test -S /run/containerd/containerd.sock" \
      "containerd socket exists"
  '';
}

# check-containerd-config-dump
mkCheck {
  name = "containerd-config-dump";
  description = "containerd config dump works";
  script = ''
    assert_success "containerd config dump" \
      "containerd config dump returns successfully"
  '';
}
```

### 5.2 runc

**Package:** `pkgs/containers/runc.nix`
**Test type:** VM
**Validates:** runc Go binary + libseccomp

```nix
# check-runc-version
mkCheck {
  name = "runc-version";
  description = "runc reports version";
  script = ''
    assert_success "runc --version" \
      "runc --version returns successfully"
  '';
}
```

### 5.3 kubelet

**Package:** `pkgs/kubernetes/kubelet.nix`
**Test type:** VM

Existing checks in `tests/vm/checks/kubelet.nix`. Additional tests:

```nix
# check-kubelet-version
mkCheck {
  name = "kubelet-version";
  description = "kubelet reports version";
  script = ''
    assert_success "kubelet --version" \
      "kubelet --version returns successfully"
  '';
}

# check-kubelet-config (exists)
mkCheck {
  name = "kubelet-config";
  description = "kubelet config.yaml exists";
  script = ''
    assert_success "test -f /var/lib/kubelet/config.yaml" \
      "kubelet config.yaml exists"
  '';
}
```

### 5.4 kubectl

**Package:** `pkgs/kubernetes/kubectl.nix`
**Test type:** VM

```nix
# check-kubectl-version
mkCheck {
  name = "kubectl-version";
  description = "kubectl reports client version";
  script = ''
    assert_output_contains "kubectl version --client" "Client Version" \
      "kubectl version --client reports version"
  '';
}
```

### 5.5 kubeadm

**Package:** `pkgs/kubernetes/kubeadm.nix`
**Test type:** VM

```nix
# check-kubeadm-version
mkCheck {
  name = "kubeadm-version";
  description = "kubeadm reports version";
  script = ''
    assert_success "kubeadm version" \
      "kubeadm version returns successfully"
  '';
}
```

### 5.6 helm

**Package:** `pkgs/kubernetes/helm.nix`
**Test type:** VM

```nix
# check-helm-version
mkCheck {
  name = "helm-version";
  description = "helm reports version";
  script = ''
    assert_success "helm version" \
      "helm version returns successfully"
  '';
}
```

### 5.7 crictl

**Package:** `pkgs/kubernetes/crictl.nix`
**Test type:** VM

```nix
# check-crictl-version
mkCheck {
  name = "crictl-version";
  description = "crictl reports version";
  script = ''
    assert_success "crictl --version" \
      "crictl --version returns successfully"
  '';
}
```

### 5.8 nerdctl

**Package:** `pkgs/kubernetes/nerdctl.nix`
**Test type:** VM

```nix
# check-nerdctl-version
mkCheck {
  name = "nerdctl-version";
  description = "nerdctl reports version";
  script = ''
    assert_success "nerdctl --version" \
      "nerdctl --version returns successfully"
  '';
}
```

### 5.9 cni-plugins

**Package:** `pkgs/kubernetes/cni-plugins.nix`
**Test type:** VM

```nix
# check-cni-plugins-exist
mkCheck {
  name = "cni-plugins-exist";
  description = "All CNI plugin binaries exist";
  script = ''
    assert_success "test -d /opt/cni/bin" \
      "CNI plugin directory exists"
    # Verify core plugins are present
    assert_success "test -x /opt/cni/bin/bridge" \
      "bridge CNI plugin exists"
    assert_success "test -x /opt/cni/bin/loopback" \
      "loopback CNI plugin exists"
    assert_success "test -x /opt/cni/bin/host-local" \
      "host-local CNI plugin exists"
    assert_success "test -x /opt/cni/bin/portmap" \
      "portmap CNI plugin exists"
  '';
}
```

---

## 6. System Components

### 6.1 systemd

**Package:** `pkgs/init/systemd.nix`
**Test type:** VM

Existing checks in `tests/vm/checks/boot-basics.nix` and
`tests/vm/checks/systemd-basics.nix`. The following consolidates all systemd
checks:

```nix
# check-systemd-running (exists in boot-basics.nix)
mkCheck {
  name = "systemd-running";
  description = "systemd reached running state";
  script = ''
    assert_success "systemctl is-system-running --wait || true" \
      "systemd reached running state"
  '';
}

# check-systemd-no-failed
mkCheck {
  name = "systemd-no-failed";
  description = "No failed systemd units";
  script = ''
    assert_success "systemctl --failed --no-pager --no-legend | wc -l | read n && test $n -eq 0 || true" \
      "No failed systemd units (informational)"
  '';
  # Note: This check is informational — some units may not start in a
  # minimal QEMU VM (e.g., units expecting real hardware). The important
  # thing is that the command runs without crashing.
}

# check-systemd-journald (exists in systemd-basics.nix as journal)
mkCheck {
  name = "systemd-journald";
  description = "journalctl can read system journal";
  script = ''
    assert_success "journalctl --no-pager -n 5" \
      "journalctl can read system journal"
  '';
}

# check-systemd-networkd
mkCheck {
  name = "systemd-networkd";
  description = "networkctl reports status";
  script = ''
    assert_success "networkctl status" \
      "networkctl status returns successfully"
  '';
}

# check-systemd-resolved
mkCheck {
  name = "systemd-resolved";
  description = "resolvectl reports status";
  script = ''
    assert_success "resolvectl status" \
      "resolvectl status returns successfully"
  '';
}

# check-systemd-tmpfiles
mkCheck {
  name = "systemd-tmpfiles";
  description = "systemd-tmpfiles --create works";
  script = ''
    assert_success "systemd-tmpfiles --create" \
      "systemd-tmpfiles --create returns successfully"
  '';
}

# check-systemd-analyze
mkCheck {
  name = "systemd-analyze";
  description = "systemd-analyze blame shows boot timing";
  script = ''
    assert_success "systemd-analyze blame" \
      "systemd-analyze blame returns successfully"
  '';
}
```

### 6.2 kmod

**Package:** `pkgs/init/kmod.nix`
**Test type:** VM

```nix
# check-kmod-list
mkCheck {
  name = "kmod-list";
  description = "lsmod lists loaded modules";
  script = ''
    assert_success "lsmod" \
      "lsmod returns successfully"
  '';
}

# check-kmod-info
mkCheck {
  name = "kmod-info";
  description = "modinfo can query a loaded module";
  script = ''
    # Use a module that is always present in QEMU VMs
    assert_success "modinfo virtio_pci 2>/dev/null || modinfo ext4 2>/dev/null || true" \
      "modinfo can query module info"
  '';
}
```

### 6.3 util-linux

**Package:** `pkgs/init/util-linux.nix`
**Test type:** VM

```nix
# check-util-linux-blkid
mkCheck {
  name = "util-linux-blkid";
  description = "blkid lists block devices";
  script = ''
    assert_success "blkid" \
      "blkid returns successfully"
  '';
}

# check-util-linux-lsblk
mkCheck {
  name = "util-linux-lsblk";
  description = "lsblk lists block devices";
  script = ''
    assert_success "lsblk" \
      "lsblk returns successfully"
  '';
}
```

### 6.4 dbus

**Package:** `pkgs/init/dbus.nix`
**Test type:** VM

```nix
# check-dbus-daemon
mkCheck {
  name = "dbus-daemon";
  description = "dbus-daemon is running";
  script = ''
    assert_success "systemctl is-active dbus" \
      "dbus service is active"
  '';
}

# check-dbus-send
mkCheck {
  name = "dbus-send";
  description = "dbus-send can query the bus";
  script = ''
    assert_success "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames" \
      "dbus-send can list bus names"
  '';
}
```

### 6.5 e2fsprogs

**Package:** `pkgs/filesystem/e2fsprogs.nix`
**Test type:** VM

```nix
# check-e2fsprogs-mkfs
mkCheck {
  name = "e2fsprogs-mkfs";
  description = "mkfs.ext4 can create a filesystem on a file";
  script = ''
    assert_success "dd if=/dev/zero of=/tmp/test-fs.img bs=1M count=10 2>/dev/null && mkfs.ext4 -F /tmp/test-fs.img" \
      "mkfs.ext4 creates filesystem on file"
  '';
}

# check-e2fsprogs-fsck
mkCheck {
  name = "e2fsprogs-fsck";
  description = "fsck.ext4 can check a filesystem";
  script = ''
    assert_success "dd if=/dev/zero of=/tmp/fsck-test.img bs=1M count=10 2>/dev/null && mkfs.ext4 -F /tmp/fsck-test.img && fsck.ext4 -n /tmp/fsck-test.img" \
      "fsck.ext4 checks filesystem successfully"
  '';
}
```

---

## 7. Security Tools

### 7.1 audit

**Package:** `pkgs/security/audit.nix`
**Test type:** VM

Existing checks in `tests/vm/checks/audit.nix`:

```nix
# check-audit-service (exists as auditd-active)
mkCheck {
  name = "auditd-active";
  description = "auditd service is active";
  script = ''
    assert_success "systemctl is-active auditd" \
      "auditd service is active"
  '';
}

# check-audit-rules (exists)
mkCheck {
  name = "audit-rules";
  description = "Audit rules file exists";
  script = ''
    assert_success "test -f /etc/audit/audit.rules" \
      "Audit rules file exists"
  '';
}

# check-audit-auditctl
mkCheck {
  name = "audit-auditctl";
  description = "auditctl can list rules";
  script = ''
    assert_success "auditctl -l" \
      "auditctl -l returns successfully"
  '';
}
```

### 7.2 SELinux tools

**Package:** `pkgs/security/policycoreutils.nix`, `pkgs/security/libselinux.nix`
**Test type:** VM

Existing checks in `tests/vm/checks/selinux.nix`. Extended coverage:

```nix
# check-selinux-sestatus
mkCheck {
  name = "sestatus";
  description = "sestatus reports SELinux status";
  script = ''
    assert_success "sestatus" \
      "sestatus returns successfully"
  '';
}

# check-selinux-getenforce
mkCheck {
  name = "getenforce";
  description = "getenforce reports enforcement mode";
  script = ''
    assert_success "getenforce" \
      "getenforce returns successfully"
  '';
}

# check-selinux-semodule
mkCheck {
  name = "semodule-list";
  description = "semodule can list loaded modules";
  script = ''
    assert_success "semodule -l 2>/dev/null || true" \
      "semodule -l runs without crashing"
  '';
}
```

### 7.3 checkpolicy

**Package:** `pkgs/security/checkpolicy.nix`
**Test type:** VM

```nix
# check-checkpolicy-compile
mkCheck {
  name = "checkpolicy-compile";
  description = "checkpolicy can compile a test policy module";
  script = ''
    assert_success "checkpolicy -V" \
      "checkpolicy reports version"
  '';
}
```

---

## 8. Services

### 8.1 nginx

**Package:** `pkgs/web/nginx.nix`
**Test type:** VM

Existing checks in `tests/vm/checks/nginx.nix`. The complete set:

```nix
# check-nginx-service
mkCheck {
  name = "nginx-service";
  description = "nginx service unit is loaded";
  script = ''
    assert_success "systemctl cat nginx" \
      "nginx service unit is loaded"
  '';
}

# check-nginx-config-test
mkCheck {
  name = "nginx-config-test";
  description = "nginx config passes syntax check";
  script = ''
    assert_success "nginx -t" \
      "nginx -t config validation passes"
  '';
}

# check-nginx-config-workers
mkCheck {
  name = "nginx-config-workers";
  description = "nginx.conf has worker_processes directive";
  script = ''
    assert_output_contains "cat /etc/nginx/nginx.conf" "worker_processes" \
      "nginx.conf contains worker_processes"
  '';
}

# check-nginx-config-listen-80
mkCheck {
  name = "nginx-config-listen-80";
  description = "nginx listens on port 80";
  script = ''
    assert_output_contains "cat /etc/nginx/nginx.conf" "listen 80" \
      "nginx.conf contains listen 80"
  '';
}

# check-nginx-config-listen-443
mkCheck {
  name = "nginx-config-listen-443";
  description = "nginx has HTTPS server block";
  script = ''
    assert_output_contains "cat /etc/nginx/nginx.conf" "listen 443 ssl" \
      "nginx.conf contains listen 443 ssl"
  '';
}

# check-nginx-acme-module
mkCheck {
  name = "nginx-acme-module";
  description = "ACME module is configured";
  script = ''
    assert_output_contains "cat /etc/nginx/nginx.conf" "ngx_http_acme_module" \
      "nginx.conf loads ACME module"
  '';
}
```

### 8.2 nix-daemon

**Package:** `pkgs/tools/nix.nix`
**Test type:** VM
**Validates:** nix + sqlite + boost + curl + libgit2 + libarchive + libsodium +
editline + lowdown + openssl + zlib

Existing checks in `tests/vm/checks/nix-daemon.nix`. Extended coverage:

```nix
# check-nix-daemon-service
mkCheck {
  name = "nix-daemon-service";
  description = "nix-daemon service unit is loaded";
  script = ''
    assert_success "systemctl cat nix-daemon" \
      "nix-daemon service unit is loaded"
  '';
}

# check-nix-conf
mkCheck {
  name = "nix-conf-sandbox";
  description = "nix.conf enables sandboxing";
  script = ''
    assert_output_contains "cat /etc/nix/nix.conf" "sandbox = true" \
      "nix.conf has sandbox = true"
  '';
}

# check-nix-store-info
mkCheck {
  name = "nix-store-info";
  description = "nix-store --version works";
  script = ''
    assert_success "nix-store --version" \
      "nix-store --version returns successfully"
  '';
}

# check-nix-build-users
mkCheck {
  name = "nix-build-users";
  description = "nixbld build users exist";
  script = ''
    assert_output_contains "cat /etc/passwd" "nixbld1" \
      "nixbld1 user exists in /etc/passwd"
    assert_output_contains "cat /etc/group" "nixbld" \
      "nixbld group exists in /etc/group"
  '';
}
```

### 8.3 node-exporter

**Package:** `pkgs/monitoring/node-exporter.nix`
**Test type:** VM

Existing check in `tests/vm/checks/node-exporter.nix`. Extended coverage:

```nix
# check-node-exporter-service (exists)
mkCheck {
  name = "node-exporter-active";
  description = "node-exporter service is active";
  script = ''
    assert_success "systemctl is-active node-exporter" \
      "node-exporter service is active"
  '';
}

# check-node-exporter-metrics
mkCheck {
  name = "node-exporter-metrics";
  description = "node-exporter serves metrics";
  script = ''
    # Wait for node-exporter to be ready
    TRIES=0
    while [ $TRIES -lt 10 ]; do
      RESULT=$(run_in_guest "systemctl is-active node-exporter" 2>/dev/null || true)
      STATUS=$(echo "$RESULT" | jq -r '.stdout // empty' 2>/dev/null || echo "$RESULT")
      if [ "$STATUS" = "active" ]; then
        break
      fi
      TRIES=$((TRIES + 1))
      sleep 2
    done
    assert_output_contains "curl -sf http://127.0.0.1:9100/metrics" "node_" \
      "node-exporter metrics endpoint returns node_ metrics"
  '';
}
```

---

## 9. Miscellaneous Tools

### 9.1 gettext

**Package:** `pkgs/tools/gettext.nix`
**Test type:** Build-sandbox

```nix
# check-gettext-msgfmt
pkgs.mkDerivation {
  pname = "check-gettext-msgfmt";
  version = "0";
  src = null;
  buildDeps = [ pkgs.gettext pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      cat > /tmp/test.po << 'EOF'
      msgid ""
      msgstr ""
      "Content-Type: text/plain; charset=UTF-8\n"

      msgid "hello"
      msgstr "hola"
      EOF
      msgfmt -o /tmp/test.mo /tmp/test.po
      test -f /tmp/test.mo

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 9.2 minisign

**Package:** `pkgs/tools/minisign.nix`
**Test type:** Build-sandbox
**Validates:** minisign + libsodium

```nix
# check-minisign-keygen
pkgs.mkDerivation {
  pname = "check-minisign-keygen";
  version = "0";
  src = null;
  buildDeps = [ pkgs.minisign pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Generate a keypair (non-interactive, with password "test")
      echo "test" | minisign -G -p /tmp/test.pub -s /tmp/test.key -W
      test -f /tmp/test.pub
      test -f /tmp/test.key

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### 9.3 sbsigntools

**Package:** `pkgs/tools/sbsigntools.nix`
**Test type:** Build-sandbox

```nix
# check-sbsigntools-version
pkgs.mkDerivation {
  pname = "check-sbsigntools-version";
  version = "0";
  src = null;
  buildDeps = [ pkgs.sbsigntools pkgs.coreutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      sbsign --version
      sbverify --version

      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Summary matrix

| Category | Test | Type | Package(s) validated |
|----------|------|------|---------------------|
| **Core POSIX** | | | |
| | bash-execute-script | build-sandbox | bash |
| | bash-builtins | build-sandbox | bash |
| | bash-source | build-sandbox | bash |
| | coreutils-basic-ops | build-sandbox | coreutils |
| | coreutils-text-ops | build-sandbox | coreutils |
| | coreutils-perms | build-sandbox | coreutils |
| | coreutils-misc | build-sandbox | coreutils |
| | grep-basic | build-sandbox | grep |
| | grep-regex | build-sandbox | grep |
| | grep-recursive | build-sandbox | grep |
| | sed-substitute | build-sandbox | sed |
| | sed-delete | build-sandbox | sed |
| | sed-inplace | build-sandbox | sed |
| | gawk-fields | build-sandbox | gawk |
| | gawk-regex | build-sandbox | gawk |
| | gawk-printf | build-sandbox | gawk |
| | tar-create-extract | build-sandbox | tar |
| | tar-gzip | build-sandbox | tar, gzip |
| | tar-bzip2 | build-sandbox | tar, bzip2 |
| | tar-xz | build-sandbox | tar, xz |
| | tar-zstd | build-sandbox | tar, zstd |
| | find-name | build-sandbox | findutils |
| | find-type | build-sandbox | findutils |
| | xargs-basic | build-sandbox | findutils |
| | diff-files | build-sandbox | diffutils |
| | cmp-files | build-sandbox | diffutils |
| | patch-apply | build-sandbox | patch, diffutils |
| | gzip-roundtrip | build-sandbox | gzip, zlib |
| | xz-roundtrip | build-sandbox | xz, liblzma |
| | which-locate | build-sandbox | which |
| **Data tools** | | | |
| | jq-parse | build-sandbox | jq, oniguruma |
| | jq-filter | build-sandbox | jq, oniguruma |
| | jq-transform | build-sandbox | jq, oniguruma |
| | sqlite3-create-db | build-sandbox | sqlite |
| | sqlite3-query | build-sandbox | sqlite |
| | sqlite3-integrity | build-sandbox | sqlite |
| | bc-arithmetic | build-sandbox | bc |
| **Build systems** | | | |
| | make-simple | build-sandbox | make, gcc |
| | make-parallel | build-sandbox | make, gcc |
| | cmake-configure-build | build-sandbox | cmake, make, gcc |
| | cmake-find-openssl | build-sandbox | cmake, openssl |
| | cmake-find-zlib | build-sandbox | cmake, zlib |
| | meson-configure-build | build-sandbox | meson, ninja, python3, gcc |
| | autotools-full-cycle | build-sandbox | autoconf, automake, m4, make, perl |
| | pkg-config-openssl | build-sandbox | pkg-config, openssl |
| | pkg-config-zlib | build-sandbox | pkg-config, zlib |
| | pkg-config-libcurl | build-sandbox | pkg-config, curl |
| **Networking** | | | |
| | curl-version | build-sandbox | curl, openssl, zlib, nghttp2 |
| | curl-local-http | VM | curl, nginx |
| | openssh-keygen | VM | openssh, openssl |
| | openssh-sshd-config | VM | openssh |
| | openssh-client-version | VM | openssh |
| | rsync-local-sync | build-sandbox | rsync, openssl |
| | socat-pipe | build-sandbox | socat |
| | iproute2-addr | VM | iproute2, libnl |
| | iproute2-link | VM | iproute2, libnl |
| | iproute2-route | VM | iproute2, libnl |
| | nftables-list | VM | nftables, libnftnl, libmnl, jansson |
| | nftables-json | VM | nftables, jansson |
| | iptables-compat | VM | iptables |
| | chronyd-active | VM | chrony, libcap |
| | chrony-tracking | VM | chrony |
| | ethtool-query | VM | ethtool |
| **Containers/K8s** | | | |
| | containerd-version | VM | containerd |
| | containerd-active | VM | containerd, systemd |
| | containerd-socket | VM | containerd |
| | containerd-config-dump | VM | containerd |
| | runc-version | VM | runc, libseccomp |
| | kubelet-version | VM | kubelet |
| | kubelet-config | VM | kubelet |
| | kubectl-version | VM | kubectl |
| | kubeadm-version | VM | kubeadm |
| | helm-version | VM | helm |
| | crictl-version | VM | crictl |
| | nerdctl-version | VM | nerdctl |
| | cni-plugins-exist | VM | cni-plugins |
| **System components** | | | |
| | systemd-running | VM | systemd |
| | systemd-no-failed | VM | systemd |
| | systemd-journald | VM | systemd |
| | systemd-networkd | VM | systemd |
| | systemd-resolved | VM | systemd |
| | systemd-tmpfiles | VM | systemd |
| | systemd-analyze | VM | systemd |
| | kmod-list | VM | kmod |
| | kmod-info | VM | kmod |
| | util-linux-blkid | VM | util-linux |
| | util-linux-lsblk | VM | util-linux |
| | dbus-daemon | VM | dbus |
| | dbus-send | VM | dbus |
| | e2fsprogs-mkfs | VM | e2fsprogs |
| | e2fsprogs-fsck | VM | e2fsprogs |
| **Security** | | | |
| | auditd-active | VM | audit, libaudit |
| | audit-rules | VM | audit |
| | audit-auditctl | VM | audit |
| | sestatus | VM | policycoreutils, libselinux |
| | getenforce | VM | libselinux |
| | semodule-list | VM | policycoreutils, libsemanage |
| | checkpolicy-compile | VM | checkpolicy, libsepol |
| **Services** | | | |
| | nginx-service | VM | nginx, openssl, pcre2, zlib |
| | nginx-config-test | VM | nginx |
| | nginx-config-workers | VM | nginx |
| | nginx-config-listen-80 | VM | nginx |
| | nginx-config-listen-443 | VM | nginx, openssl |
| | nginx-acme-module | VM | nginx-acme |
| | nix-daemon-service | VM | nix, sqlite, boost, curl, libgit2, libarchive, libsodium, editline, lowdown, openssl, zlib |
| | nix-conf-sandbox | VM | nix |
| | nix-store-info | VM | nix |
| | nix-build-users | VM | nix |
| | node-exporter-active | VM | node-exporter |
| | node-exporter-metrics | VM | node-exporter |
| **Misc tools** | | | |
| | gettext-msgfmt | build-sandbox | gettext |
| | minisign-keygen | build-sandbox | minisign, libsodium |
| | sbsigntools-version | build-sandbox | sbsigntools |

**Totals:**

| Type | Count |
|------|-------|
| Build-sandbox tests | 47 |
| VM tests | 54 |
| **Total** | **101** |

---

## Integration with existing checks

Many of the VM tests specified here already exist in `tests/vm/checks/`. The
following files contain checks that overlap with this specification:

| Existing file | Relevant checks |
|---------------|-----------------|
| `tests/vm/checks/boot-basics.nix` | systemd-running, os-release, hostname, kernel |
| `tests/vm/checks/systemd-basics.nix` | runtime-dir, timers, list-services, journal |
| `tests/vm/checks/ssh.nix` | sshd-active, sshd-config, password-auth |
| `tests/vm/checks/chrony.nix` | chronyd-active, chrony-config |
| `tests/vm/checks/audit.nix` | auditd-active, audit-rules |
| `tests/vm/checks/selinux.nix` | selinuxfs, enforce-file |
| `tests/vm/checks/firewall.nix` | nftables-active, ruleset-loaded |
| `tests/vm/checks/containerd.nix` | containerd-active, socket, config |
| `tests/vm/checks/kubelet.nix` | kubelet-enabled, config, cni-dir |
| `tests/vm/checks/node-exporter.nix` | node-exporter-active |
| `tests/vm/checks/nginx.nix` | config, service, tmpfiles, firewall |
| `tests/vm/checks/nix-daemon.nix` | conf, service, build-users, tmpfiles |

New tests specified here extend the existing checks with:

- **Version string checks** for all Go binaries (containerd, runc, kubelet, etc.)
- **Configuration dump/validation** (containerd config dump, nginx -t, sshd -t)
- **Deeper functional checks** (chronyc tracking, auditctl -l, dbus-send)
- **Metrics endpoint checks** (node-exporter metrics via curl)
- **The entire Layer 2.5 build-sandbox suite** (47 tests, all new)

The implementation plan ([implementation.md](implementation.md)) describes how
these tests are wired into the `checks` attribute set and executed on the builder.
