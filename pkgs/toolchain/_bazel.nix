##! Shared builder for Bazel versions.
##! Underscore prefix = not auto-discovered. Imported by bazel-N.nix files.
##!
##! Three-stage bootstrap: (1) binary bazel-bootstrap vendors external deps
##! into a fixed-output derivation, (2) compile.sh builds a minimal Bazel
##! from javac, (3) that minimal Bazel builds the real Bazel using vendored
##! deps with --repository_disable_download.
{
  mkDerivation,
  fetchurl,
  lib,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk-21,
  gcc,
  binutils,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  patchelf,
  bazel-bootstrap,
  bootstrapTools,
  gcc-libs,
}: {
  version,
  srcHash,
  vendorDepsHash,
  # Major version string for the version check test (e.g. "7.7", "8.6", "9.0")
  versionCheck ? builtins.substring 0 3 version,
}: let
  # Python script to repackage a self-extracting ELF+zip Bazel binary after
  # patchelf. Patchelf changes the ELF portion's size, corrupting the zip
  # central directory offsets. This script splits, patches, and recombines.
  repackBazelPy = builtins.toFile "repack_bazel.py" ''
    import zipfile, os, sys, subprocess, tempfile, shutil

    bazel_path = sys.argv[1]
    interp = sys.argv[2]
    rpath = sys.argv[3]
    patchelf_bin = sys.argv[4]
    output_path = sys.argv[5]

    with open(bazel_path, 'rb') as f:
        data = f.read()

    zf = zipfile.ZipFile(bazel_path, 'r')
    first_offset = min(zi.header_offset for zi in zf.infolist())
    elf_prefix = data[:first_offset]

    flags = set(sys.argv[6:])
    patch_elf_prefix = '--no-patch-elf-prefix' not in flags

    # Optionally patch LD_PRELOAD string in ELF prefix (for bootstrap wrapper)
    if '--patch-ld-preload' in flags:
        elf_prefix = elf_prefix.replace(b'LD_PRELOAD', b'XX_PRELOAD')

    tmpdir = tempfile.mkdtemp()
    if patch_elf_prefix:
        # Write ELF prefix to temp file, patchelf it, read back.
        elf_tmp = os.path.join(tmpdir, 'elf_prefix')
        with open(elf_tmp, 'wb') as f:
            f.write(elf_prefix)
        os.chmod(elf_tmp, 0o755)
        subprocess.run([patchelf_bin, '--set-interpreter', interp, '--set-rpath', rpath, elf_tmp], check=True)
        with open(elf_tmp, 'rb') as f:
            patched_prefix = f.read()
    else:
        patched_prefix = elf_prefix

    # Extract, patchelf ELF binaries in the zip payload
    extract_dir = os.path.join(tmpdir, 'zip_contents')
    os.makedirs(extract_dir)
    zf.extractall(extract_dir)

    for name in os.listdir(extract_dir):
        fpath = os.path.join(extract_dir, name)
        if not os.path.isfile(fpath):
            continue
        with open(fpath, 'rb') as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            continue
        try:
            result = subprocess.run([patchelf_bin, '--print-interpreter', fpath], capture_output=True, text=True)
            if '/lib64/ld-linux-x86-64.so.2' in result.stdout:
                os.chmod(fpath, 0o755)
                subprocess.run([patchelf_bin, '--set-interpreter', interp, '--set-rpath', rpath, fpath], check=True)
                print(f"Patched zip entry: {name}")
        except Exception as e:
            print(f"Skipping {name}: {e}")

    # Repackage directly after the ELF prefix. Bazel's embedded zip reader
    # expects central-directory offsets to be relative to the whole file, while
    # a separately generated payload zip would record offsets from byte 0 of the
    # payload and only work with zip readers that compensate for SFX prefixes.
    with open(output_path, 'wb') as f:
        f.write(patched_prefix)
        new_zf = zipfile.ZipFile(f, 'w')
        for zi in zf.infolist():
            fpath = os.path.join(extract_dir, zi.filename)
            if os.path.isfile(fpath):
                with open(fpath, 'rb') as entry:
                    file_data = entry.read()
                new_zi = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                new_zi.compress_type = zi.compress_type
                new_zi.external_attr = zi.external_attr
                new_zf.writestr(new_zi, file_data)
        new_zf.close()
    zf.close()

    # Python's zip writer can leave inherited/trailing bytes when writing after
    # an SFX prefix. Bazel's reader requires the EOCD comment to end exactly at
    # EOF, so trim anything after the declared EOCD end.
    with open(output_path, 'r+b') as f:
        out_data = f.read()
        sig = b'PK\x05\x06'
        max_delta = 0xffff + 22
        start = max(0, len(out_data) - max_delta - 1024)
        for pos in range(len(out_data) - 22, start - 1, -1):
            if out_data[pos:pos + 4] != sig:
                continue
            comment_length = int.from_bytes(out_data[pos + 20:pos + 22], 'little')
            expected_end = pos + 22 + comment_length
            if expected_end <= len(out_data):
                f.truncate(expected_end)
                break

    os.chmod(output_path, 0o755)
    shutil.rmtree(tmpdir)
    print("Repackaged bazel binary")
  '';

  # All tools Bazel needs in PATH during build and at runtime
  toolsPath = lib.makeBinPath [
    bash
    coreutils
    which
    zip
    unzip
    gawk
    python3
    gcc
    binutils
    grep
    gzip
    patch
    diffutils
    findutils
    sed
    tar
    xz
    file
  ];

  src = fetchurl {
    urls = [
      "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel-${version}-dist.zip"
    ];
    hash = srcHash;
  };

  # Fixed-output derivation: vendor all external dependencies using
  # bazel-bootstrap in --batch mode.
  vendorDeps = builtins.derivation {
    name = "bazel-vendor-deps-${version}";
    system = lib.system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
                set -eu
                export PATH="${toolsPath}:${openjdk-21}/bin:${patchelf}/bin:$PATH"
                export HOME="$TMPDIR/home"
                mkdir -p "$HOME"
                export JAVA_HOME="${openjdk-21}"

                INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
                BT_LIB=$(dirname "$INTERP")

                # Repackage the bootstrap Bazel binary with patchelf'd ELF files.
                # The bazel binary is a self-extracting ELF+zip — patchelf changes
                # the ELF size, corrupting zip offsets. Use the shared repack script.
                RPATH="$BT_LIB:${gcc-libs}/lib"
                python3 ${repackBazelPy} \
                  "${bazel-bootstrap}/lib/bazel-real" \
                  "$INTERP" \
                  "$RPATH" \
                  "${patchelf}/bin/patchelf" \
                  "$TMPDIR/bazel-patched" \
                  --no-patch-elf-prefix

                # Create wrapper script (still need proc_self_exe_fix for
                # /proc/self/exe since we invoke via explicit ld.so)
                cat > "$TMPDIR/bazel" << BWRAP
        #!${bash}/bin/bash
        export BAZEL_REAL_PATH="$TMPDIR/bazel-patched"
        export LD_PRELOAD="${bazel-bootstrap}/lib/proc_self_exe_fix.so"
        export LD_LIBRARY_PATH="${gcc-libs}/lib:$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
        exec $INTERP "$TMPDIR/bazel-patched" "\$@"
        BWRAP
                chmod +x "$TMPDIR/bazel"
                export PATH="$TMPDIR:$PATH"

                # Extract dist zip
                mkdir -p "$TMPDIR/bazel_src"
                cd "$TMPDIR/bazel_src"
                unzip -q ${src}

                # Apply reproducibility patch when the target test file exists.
                if [ -f src/test/shell/bazel/list_source_repository.bzl ]; then
                  patch --batch -p1 < ${./bazel-patches/test_source_sort.patch} || true
                fi

                # Remove .bazelrc — it may contain options (e.g. --downloader_config)
                # that the bootstrap bazel (older version) doesn't understand.
                rm -f .bazelrc

                # Remove rules_python toolchain/pip registrations from MODULE.bazel.
                # rules_python's repository rule calls repository_ctx.execute() which
                # requires process-wrapper (a pre-built ELF with /lib64 interpreter
                # that doesn't exist in the Nix sandbox). The actual build target
                # (//src:bazel_nojdk) doesn't need a Python toolchain for vendoring.
                cat > "$TMPDIR/fix_module.py" << 'PYEOF'
        import re, sys
        with open(sys.argv[1], 'r') as f:
            lines = f.readlines()
        # Remove lines related to python/pip extensions that trigger process-wrapper
        skip = False
        result = []
        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(p) for p in [
                'python = use_extension(', 'python.toolchain(',
                'pip = use_extension(', 'pip.parse(',
                'use_repo(pip,',
            ]):
                skip = True
            if skip:
                if stripped == ')' or stripped.startswith('use_repo(pip,'):
                    skip = False
                    continue
                continue
            result.append(line)
        with open(sys.argv[1], 'w') as f:
            f.writelines(result)
        PYEOF
                python3 "$TMPDIR/fix_module.py" MODULE.bazel 2>/dev/null || true

                # Also strip pip/python references from src/BUILD since we removed
                # the pip extension from MODULE.bazel. The load() and requirement()
                # calls would fail because @bazel_pip_dev_deps no longer exists.
                sed -i '/bazel_pip_dev_deps/d' src/BUILD 2>/dev/null || true
                sed -i '/requirement("bazel-runfiles")/d' src/BUILD 2>/dev/null || true

                # Ensure BUILD files exist for directories referenced by MODULE.bazel
                # (Bazel 8+ references src/test/shell/bazel:list_source_repository.bzl)
                mkdir -p src/test/shell/bazel
                touch src/test/shell/bazel/BUILD
                # Create a stub .bzl file if missing (dist zip may omit test files)
                if [ ! -f src/test/shell/bazel/list_source_repository.bzl ]; then
                  echo 'list_source_repository = repository_rule(implementation = lambda ctx: None, attrs = {})' \
                    > src/test/shell/bazel/list_source_repository.bzl
                fi

                # Common vendor flags:
                # --check_direct_dependencies=off: bootstrap version resolves different BCR versions
                # --check_bazel_compatibility=off: bootstrap version may be older than required
                VENDOR_FLAGS="--check_direct_dependencies=off --check_bazel_compatibility=off"

                # Fetch module metadata first — triggers rules_java repo setup so
                # we can patch _detect_java_version before the actual vendor step.
                bazel --batch --ignore_all_rc_files \
                  --output_user_root="$TMPDIR/bazel_cache" \
                  --server_javabase="${openjdk-21}" \
                  mod deps --curses=no \
                  $VENDOR_FLAGS 2>&1 || true

                # Patch rules_java: replace _detect_java_version to read release file
                # instead of running java -XshowSettings:properties (which fails under
                # repository_ctx.execute in the bootstrap bazel sandbox).
                cat > "$TMPDIR/patch_detect.py" << 'PYEOF'
        import re, sys
        filepath = sys.argv[1]
        with open(filepath, 'r') as fh:
            content = fh.read()
        new_func = (
            'def _detect_java_version(repository_ctx, java_bin):\n'
            '    release_path = java_bin.dirname.dirname.get_child("release")\n'
            '    if release_path.exists:\n'
            '        for line in repository_ctx.read(release_path).splitlines():\n'
            '            if line.startswith("JAVA_VERSION="):\n'
            '                version = line.split("=", 1)[1].strip().replace(\'"\', "")\n'
            '                parts = version.split(".")\n'
            '                major = parts[0]\n'
            '                if major == "1" and len(parts) > 1:\n'
            '                    return parts[1]\n'
            '                return major\n'
            '    return None\n\n'
        )
        content = re.sub(
            r'def _detect_java_version\(.*?\n(?=def )',
            new_func,
            content,
            count=1,
            flags=re.DOTALL
        )
        with open(filepath, 'w') as fh:
            fh.write(content)
        PYEOF
                for f in $(find "$TMPDIR/bazel_cache" -path "*/external/rules_java*/local_java_repository.bzl" 2>/dev/null); do
                  chmod u+w "$f" 2>/dev/null || true
                  python3 "$TMPDIR/patch_detect.py" "$f"
                done

                # Vendor all external dependencies
                bazel --batch --ignore_all_rc_files \
                  --output_user_root="$TMPDIR/bazel_cache" \
                  --server_javabase="${openjdk-21}" \
                  vendor //src:bazel_nojdk \
                  --curses=no \
                  --vendor_dir="$out" \
                  --verbose_failures \
                  $VENDOR_FLAGS

                # Clean non-reproducible artifacts
                find "$out" -name "*.pyc" -type f -delete
                rm -rf "$out/gazelle~~non_module_deps~bazel_gazelle_go_repository_cache/gocache" 2>/dev/null || true
                rm -f "$out/rules_go~~go_sdk~go_default_sdk/versions.json" 2>/dev/null || true
                rm -f "$out/bazel-external" 2>/dev/null || true

                # The generated Maven maintenance helper records HTTP proxy
                # arguments, including ephemeral relay ports, but is not used by
                # offline consumers of the vendor tree. Remove it so identical
                # dependencies produce identical fixed-output contents.
                rm -f "$out/rules_jvm_external~~maven~maven/outdated.sh"

                # Remove files/directories that reference Nix store paths.
                # FODs must not contain store path references. Marker files from
                # rules_python and similar repo rules record the build environment
                # (PATH, JAVA_HOME, etc.) which contains store paths. Remove them.
                # Keep rules_python~ source (needed by rules_pkg's py_binary) but
                # delete generated Python toolchain/pip repos that contain store paths.
                find "$out" -name "*.marker" -delete 2>/dev/null || true
                rm -rf "$out/rules_python"*pip* 2>/dev/null || true
                rm -rf "$out/rules_python"*python* 2>/dev/null || true
                rm -rf "$out/rules_python"*pythons* 2>/dev/null || true

                # Scan for any remaining store path references and remove them
                find "$out" -type f | while read f; do
                  if grep -qI '/nix/store/' "$f" 2>/dev/null; then
                    echo "WARNING: removing file with store path refs: ''${f#$out/}"
                    rm -f "$f"
                  fi
                done
      ''
    ];

    outputHash = vendorDepsHash;
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };
in
  mkDerivation {
    pname = "bazel";
    inherit version;

    # The binary is an ELF+zip self-extractor. Generic ELF mutation and
    # line-oriented reference scrubbing both corrupt the appended zip payload.
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    inherit src;

    buildDeps = [
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk-21
      gcc
      binutils
      grep
      gzip
      patch
      diffutils
      findutils
      sed
      tar
      xz
      file
      patchelf
    ];
    runtimeDeps = [
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk-21
      findutils
      file
      gcc-libs
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          # Bazel source is a zip, not a tarball
          mkdir bazel_src
          cd bazel_src
          unzip -q $src
        '';
      }
      {
        name = "patch";
        script = ''
                  # Apply patches (|| true — patches may not apply to all versions)
                  patch --batch -p1 < ${./bazel-patches/java_toolchain.patch} || true
                  if [ -f src/test/shell/bazel/list_source_repository.bzl ]; then
                    patch --batch -p1 < ${./bazel-patches/test_source_sort.patch} || true
                  fi

                  # Replace hardcoded paths throughout the source tree
                  find . -type f \( -name '*.sh' -o -name '*.bzl' -o -name 'BUILD' \
                       -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name '*.py' \
                       -o -name '*.java' -o -name '*.cc' -o -name '*.tpl' \
                       -o -name '*.txt' \) | \
                    while read f; do
                      sed -i \
                        -e "s|/usr/local/bin/bash|${bash}/bin/bash|g" \
                        -e "s|/usr/bin/bash|${bash}/bin/bash|g" \
                        -e "s|/bin/bash|${bash}/bin/bash|g" \
                        -e "s|/usr/bin/env python|${python3}/bin/python3|g" \
                        -e "s|/usr/bin/env bash|${bash}/bin/bash|g" \
                        -e "s|/usr/bin/env|${coreutils}/bin/env|g" \
                        -e "s|/bin/true|${coreutils}/bin/true|g" \
                        "$f" 2>/dev/null || true
                    done

                  # Patch Python bootstrap template shebang placeholder
                  sed -i "s|%shebang%|#!${python3}/bin/python3|" \
                    tools/python/python_bootstrap_template.txt 2>/dev/null || true

                  # Apply strict_action_env patch (substitute placeholder with AOS tool paths)
                  patch --batch -p1 < ${./bazel-patches/strict_action_env.patch} || true
                  sed -i "s|@strictActionEnvPatch@|${toolsPath}|g" \
                    src/main/java/com/google/devtools/build/lib/bazel/rules/BazelRuleClassProvider.java

                  # Apply bazel_rc patch and substitute placeholder
                  patch --batch -p1 < ${./bazel-patches/bazel_rc.patch} || true
                  sed -i "s|@bazelSystemBazelRCPath@|/dev/null|g" \
                    src/main/cpp/option_processor.cc

                  # Strip rules_python toolchain/pip registrations from MODULE.bazel
                  # (same as vendor FOD step — prevents downloading pre-built Python)
                  cat > /tmp/fix_module.py << 'PYEOF'
          import re, sys
          with open(sys.argv[1], 'r') as f:
              lines = f.readlines()
          skip = False
          result = []
          for line in lines:
              stripped = line.strip()
              if any(stripped.startswith(p) for p in [
                  'python = use_extension(', 'python.toolchain(',
                  'pip = use_extension(', 'pip.parse(',
                  'use_repo(pip,',
              ]):
                  skip = True
              if skip:
                  if stripped == ')' or stripped.startswith('use_repo(pip,'):
                      skip = False
                      continue
                  continue
              result.append(line)
          with open(sys.argv[1], 'w') as f:
              f.writelines(result)
          PYEOF
                  python3 /tmp/fix_module.py MODULE.bazel 2>/dev/null || true

                  # Strip pip/python references from src/BUILD
                  sed -i '/bazel_pip_dev_deps/d' src/BUILD 2>/dev/null || true
                  sed -i '/requirement("bazel-runfiles")/d' src/BUILD 2>/dev/null || true
        '';
      }
      {
        name = "build";
        script = ''
          # Set up vendor directory from FOD output
          cp -a ${vendorDeps} ../vendor_dir
          chmod -R u+w ../vendor_dir

          # Bazel 7 (bootstrap) uses ~ in canonical repo names, but Bazel 8+
          # uses + as the separator. Rename vendored directories and update
          # file contents to match the target Bazel version's convention.
          MAJOR=$(echo "${version}" | cut -d. -f1)
          if [ "$MAJOR" -ge 8 ]; then
            # Rename directories: ~ → +
            for dir in ../vendor_dir/*~*; do
              [ -e "$dir" ] || continue
              newdir=$(echo "$dir" | sed 's/~/_TILDE_/g' | sed 's/_TILDE_/+/g')
              if [ "$dir" != "$newdir" ]; then
                mv "$dir" "$newdir"
              fi
            done
            # Update references inside files: replace ~ separator with + in repo names.
            # Patterns: ~~ → ++, name~name → name+name, name~// → name+// (path separator),
            # name~" → name+" (end of string), name~' → name+' (end of string)
            find ../vendor_dir -type f \( -name '*.bzl' -o -name '*.bazel' -o -name 'BUILD' -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name 'MODULE.bazel' \) | \
              while read f; do
                sed -i \
                  -e 's/~~/++/g' \
                  -e 's/\([a-z0-9_]\)~\([a-z0-9]\)/\1+\2/g' \
                  -e 's/\([a-z0-9_]\)~\//\1+\//g' \
                  -e "s/\([a-z0-9_]\)~\"/\1+\"/g" \
                  -e "s/\([a-z0-9_]\)~'/\1+'/g" \
                  "$f" 2>/dev/null || true
              done
          fi

          # Remove generated repos that depend on the Bazel version's built-in
          # symbols (they were generated by the bootstrap Bazel 7 and may have
          # wrong symbol definitions for the target version).
          rm -rf ../vendor_dir/*bazel_features_globals* 2>/dev/null || true
          rm -rf ../vendor_dir/*version_extension* 2>/dev/null || true

          # Regenerate VENDOR.bazel — only pin directories that exist in the
          # vendor dir. Repos with local=True (e.g. bazel_features globals_repo)
          # are NOT in the vendor dir, so they won't be pinned and will
          # regenerate dynamically under the bootstrap Bazel.
          rm -f ../vendor_dir/VENDOR.bazel
          find ../vendor_dir -maxdepth 1 -mindepth 1 -type d -printf 'pin("@@%P")\n' > ../vendor_dir/VENDOR.bazel

          # Fix for bootstrap Bazel: the javac-compiled bootstrap Bazel reports
          # an empty native.bazel_version. bazel_features' parse_version treats
          # empty strings as "dev" (999999.999999.999999). Patch to report the
          # actual target version so bazel_features generates correct globals.
          sed -i 's|v = "999999.999999.999999"|v = "${version}"|' \
            ../vendor_dir/bazel_features+/private/parse.bzl 2>/dev/null || true
          sed -i 's|v = "999999.999999.999999"|v = "${version}"|' \
            ../vendor_dir/bazel_features~/private/parse.bzl 2>/dev/null || true

          # Patch shebangs and interpreter paths in vendored deps.
          # Also patches DEFAULT_STUB_SHEBANG in rules_python .bzl files
          # and stage1_bootstrap_template.sh since /usr/bin/env and /bin/bash
          # don't exist in the Nix sandbox.
          # Order matters: replace longer/more-specific paths first to avoid
          # double-substitution. "/bin/bash" must come BEFORE "/usr/bin/env bash"
          # because the replacement contains "/bin/bash" as a substring.
          find ../vendor_dir -type f \( -name '*.py' -o -name '*.txt' -o -name '*.tpl' -o -name '*.bzl' -o -name '*.sh' \) | \
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

          # Derive bootstrapTools lib path from CONFIG_SHELL (set by mkDerivation)
          BT_LIB=$(dirname "$(dirname "$CONFIG_SHELL")")/lib

          # Create a bash wrapper that always sets PATH and LD_LIBRARY_PATH.
          # Bazel genrules use `exec env -` which strips all vars including PATH.
          # The --action_env flags don't work with the javac-compiled bootstrap
          # Bazel for genrules. We use --shell_executable to point to this wrapper.
          mkdir -p ../tools
          cat > ../tools/bash-with-path << BASHWRAP
          #!${bash}/bin/bash
          export PATH="${toolsPath}:\$PATH"
          export LD_LIBRARY_PATH="$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
          exec ${bash}/bin/bash "\$@"
          BASHWRAP
          chmod +x ../tools/bash-with-path

          export HOME=$(mktemp -d)
          export JAVA_HOME="${openjdk-21}"
          export EMBED_LABEL="${version}- (@non-git)"
          export PATH="${toolsPath}:$PATH"

          # Unset C_INCLUDE_PATH so Bazel's CC toolchain auto-detection doesn't
          # pick up bootstrapTools/include as a -I flag, which breaks
          # #include_next <stdlib.h> in the C++ standard library headers.
          # The cc-wrapper's built-in -isystem flag provides glibc headers.
          unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH

          # Fix shebangs in compile.sh and bootstrap scripts
          sed -i "s|#!/bin/bash|#!${bash}/bin/bash|g" compile.sh
          sed -i "s|#!/bin/bash|#!${bash}/bin/bash|g" scripts/bootstrap/compile.sh
          sed -i "s|shasum -a 256|sha256sum|g" scripts/bootstrap/compile.sh

          # Patch compile.sh: remove --action_env=PATH (inherit from host, which
          # is empty under env -). Our EXTRA_BAZEL_ARGS provides an explicit
          # --action_env=PATH=${toolsPath} instead. Also fix --build_python_zip.
          sed -i '/--action_env=PATH/d' compile.sh
          sed -i "s|--build_python_zip|--nobuild_python_zip|g" scripts/bootstrap/compile.sh

          # Set EXTRA_BAZEL_ARGS which gets included in _BAZEL_ARGS in bootstrap.sh.
          # --vendor_dir provides all vendored deps from the FOD.
          # --repository_disable_download prevents any network access.
          VENDOR_ABS="$(cd ../vendor_dir && pwd)"

          export EXTRA_BAZEL_ARGS="
            --verbose_failures
            --curses=no
            --tool_java_runtime_version=local_jdk_21
            --java_runtime_version=local_jdk_21
            --tool_java_language_version=21
            --java_language_version=21
            --extra_toolchains=@bazel_tools//tools/jdk:all
            --vendor_dir=$VENDOR_ABS
            --repository_disable_download
            --nobuild_python_zip
            --incompatible_strict_action_env
            --action_env=PATH=${toolsPath}
            --host_action_env=PATH=${toolsPath}
            --action_env=LD_LIBRARY_PATH=$BT_LIB
            --host_action_env=LD_LIBRARY_PATH=$BT_LIB
            --shell_executable=$(cd ../tools && pwd)/bash-with-path
            --python_path=${python3}/bin/python3
          "

          # Run the bootstrap build
          ${bash}/bin/bash ./compile.sh
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share

          # Create bazelrc with AOS defaults
          cat > $out/share/bazel.bazelrc << BAZELRC
          startup --server_javabase=${openjdk-21}
          build --extra_toolchains=@bazel_tools//tools/jdk:all
          build --tool_java_runtime_version=local_jdk
          build --java_runtime_version=local_jdk
          try-import /etc/bazel.bazelrc
          BAZELRC

          BAZEL_BIN=output/bazel
          if [ ! -f "$BAZEL_BIN" ]; then
            echo "ERROR: compile.sh did not produce output/bazel" >&2
            exit 1
          fi

          # The output binary is a self-extracting ELF+zip. Patchelf changes the
          # ELF portion's size, corrupting the zip central directory offsets.
          # Use the shared repack script.
          INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
          BT_LIB=$(dirname "$INTERP")
          RPATH="$BT_LIB:${gcc-libs}/lib"

          python3 ${repackBazelPy} \
            "$BAZEL_BIN" "$INTERP" "$RPATH" \
            "${patchelf}/bin/patchelf" \
            "$out/bin/bazel-real"

          # Create wrapper script
          cat > $out/bin/bazel << WRAPPER
          #!${bash}/bin/bash
          export PATH="${toolsPath}:\$PATH"
          export JAVA_HOME="${openjdk-21}"
          exec $out/bin/bazel-real "\$@"
          WRAPPER
          chmod +x $out/bin/bazel

          # Save references for Nix's scanner
          mkdir -p $out/nix-support
          echo "${toolsPath}" >> $out/nix-support/depends
        '';
      }
    ];

    meta = {
      description = "Bazel ${version} — build and test tool built from source";
      homepage = "https://bazel.build";
      license = "Apache-2.0";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkVMTest {
        name = "build-systems-bazel-${version}-version";
        rootfsDeps = [self];
        testScript = ''
          OUTPUT=$(bazel --version 2>&1)
          case "$OUTPUT" in
            *"${versionCheck}"*)
              echo "==> bazel version: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected bazel version: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };
    };
  }
