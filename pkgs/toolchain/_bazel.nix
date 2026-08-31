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
  stdenv,
  buildPackages,
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
  llvm,
}: {
  version,
  srcHash,
  vendorDepsHash,
  # Major version string for the version check test (e.g. "7.7", "8.6", "9.0")
  versionCheck ? builtins.substring 0 3 version,
}: let
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  needsDarwinMdns = builtins.compareVersions version "8.0.0" >= 0;
  needsRulesJavaRuntime = builtins.compareVersions version "9.0.0" >= 0;
  darwinIOKitUserSrc =
    if isDarwinCross
    then
      fetchurl {
        urls = [
          "https://github.com/apple-oss-distributions/IOKitUser/archive/323ead896d04424f87184d8f6ff0cce811aab106.tar.gz"
        ];
        hash = "sha256-Gg76WBI81dEDJ1pd+vLXXjoKVjhHXS17tXPdBL/zD8w=";
      }
    else null;
  darwinXnuSrc =
    if isDarwinCross
    then
      fetchurl {
        urls = [
          "https://github.com/apple-oss-distributions/xnu/archive/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea.tar.gz"
        ];
        hash = "sha256-B2MUbStUWbBw2AKqupUmzq1/sNVdDVG6AGmBgDAVCxU=";
      }
    else null;
  darwinLibnotifySrc =
    if isDarwinCross
    then
      fetchurl {
        urls = [
          "https://github.com/apple-oss-distributions/Libnotify/archive/715d461778f6b93c821d99390a0078bd6f6d8c04.tar.gz"
        ];
        hash = "sha256-3Y5oYWjcpcOLtnDDn00x8JLjfdbaOwMy9S4ywbjuMws=";
      }
    else null;
  darwinMdnsResponderSrc =
    if isDarwinCross && needsDarwinMdns
    then
      fetchurl {
        urls = [
          "https://github.com/darlinghq/darling-mDNSResponder/archive/7e38ef562b4f3d41bffabb3e30d844d8042d3bbd.tar.gz"
        ];
        hash = "sha256-hPVgEJgzqCQA0xNHfdnwSIhKHaVFMHONnKY72L2Rk5c=";
      }
    else null;
  buildBash =
    if isDarwinCross
    then buildPackages.bash
    else bash;
  buildCoreutils =
    if isDarwinCross
    then buildPackages.coreutils
    else coreutils;
  buildWhich =
    if isDarwinCross
    then buildPackages.which
    else which;
  buildZip =
    if isDarwinCross
    then buildPackages.zip
    else zip;
  buildUnzip =
    if isDarwinCross
    then buildPackages.unzip
    else unzip;
  buildGawk =
    if isDarwinCross
    then buildPackages.gawk
    else gawk;
  buildPython3 =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  buildOpenjdk =
    if isDarwinCross
    then buildPackages.openjdk-21
    else openjdk-21;
  buildGcc =
    if isDarwinCross
    then buildPackages.gcc
    else gcc;
  buildBinutils =
    if isDarwinCross
    then buildPackages.binutils
    else binutils;
  buildGrep =
    if isDarwinCross
    then buildPackages.grep
    else grep;
  buildGzip =
    if isDarwinCross
    then buildPackages.gzip
    else gzip;
  buildPatch =
    if isDarwinCross
    then buildPackages.patch
    else patch;
  buildDiffutils =
    if isDarwinCross
    then buildPackages.diffutils
    else diffutils;
  buildFindutils =
    if isDarwinCross
    then buildPackages.findutils
    else findutils;
  buildSed =
    if isDarwinCross
    then buildPackages.sed
    else sed;
  buildTar =
    if isDarwinCross
    then buildPackages.tar
    else tar;
  buildXz =
    if isDarwinCross
    then buildPackages.xz
    else xz;
  buildFile =
    if isDarwinCross
    then buildPackages.file
    else file;
  buildPatchelf =
    if isDarwinCross
    then buildPackages.patchelf
    else patchelf;
  buildBazelBootstrap =
    if isDarwinCross
    then buildPackages.bazel-bootstrap
    else bazel-bootstrap;
  buildBootstrapTools =
    if isDarwinCross
    then buildPackages.bootstrapTools
    else bootstrapTools;
  buildGccLibs =
    if isDarwinCross
    then buildPackages.gcc-libs
    else gcc-libs;
  buildLlvm =
    if isDarwinCross
    then buildPackages.llvm
    else llvm;
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

  # Darwin launchers cannot be executed or mutated with patchelf on Linux.
  # Rebuild only their appended ZIP payload, translating native build-tool
  # paths to the corresponding Darwin runtime paths. Nested JAR/ZIP payloads
  # are rewritten structurally so changing store-name lengths never corrupts
  # central-directory offsets.
  crossRepackBazelPy = builtins.toFile "repack_bazel_cross.py" ''
    import io
    import os
    import sys
    import zipfile

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    raw_pairs = sys.argv[3:]
    if len(raw_pairs) % 2:
        raise SystemExit("cross Bazel rewrite requires old/new path pairs")

    replacements = [
        (raw_pairs[index].encode(), raw_pairs[index + 1].encode())
        for index in range(0, len(raw_pairs), 2)
        if raw_pairs[index] != raw_pairs[index + 1]
    ]

    def replace_plain(data):
        for old, new in replacements:
            data = data.replace(old, new)
        return data.replace(b"/build/", b"/aos__/")

    def rewrite_zip(data):
        source = io.BytesIO(data)
        try:
            archive = zipfile.ZipFile(source, "r")
            entries = archive.infolist()
        except zipfile.BadZipFile:
            return replace_plain(data)

        target = io.BytesIO()
        with archive, zipfile.ZipFile(target, "w") as rewritten:
            rewritten.comment = replace_plain(archive.comment)
            for entry in entries:
                payload = archive.read(entry.filename)
                # Some Java dependencies bundle Linux async-profiler variants
                # alongside their Darwin library. They are unusable on the
                # target host and must not leak ELF into a Darwin cache root.
                if payload.startswith(bytes.fromhex("7f454c46")):
                    continue
                if zipfile.is_zipfile(io.BytesIO(payload)):
                    payload = rewrite_zip(payload)
                else:
                    payload = replace_plain(payload)
                entry.filename = replace_plain(entry.filename.encode()).decode()
                entry.orig_filename = entry.filename
                entry.comment = replace_plain(entry.comment)
                entry.extra = replace_plain(entry.extra)
                rewritten.writestr(entry, payload)
        return target.getvalue()

    def assert_plain_clean(data, label):
        if data.startswith(bytes.fromhex("7f454c46")):
            raise SystemExit("ELF executable remains in cross Bazel payload " + label)
        for old, _new in replacements:
            if old in data:
                raise SystemExit(
                    "native build path remains in cross Bazel payload "
                    + label
                    + ": "
                    + old.decode(errors="replace")
                )
        if b"/build/" in data:
            raise SystemExit("ephemeral /build path remains in cross Bazel payload " + label)

    def assert_clean(data, label):
        source = io.BytesIO(data)
        if not zipfile.is_zipfile(source):
            assert_plain_clean(data, label)
            return
        with zipfile.ZipFile(source, "r") as archive:
            assert_plain_clean(archive.comment, label + ":comment")
            for entry in archive.infolist():
                entry_label = label + ":" + entry.filename
                assert_plain_clean(entry.filename.encode(), entry_label + ":filename")
                assert_plain_clean(entry.comment, entry_label + ":comment")
                assert_plain_clean(entry.extra, entry_label + ":extra")
                assert_clean(archive.read(entry.filename), label + ":" + entry.filename)

    with open(input_path, "rb") as source_file:
        bazel = source_file.read()

    with zipfile.ZipFile(io.BytesIO(bazel), "r") as archive:
        first_offset = min(entry.header_offset for entry in archive.infolist())
    macho_prefix = replace_plain(bazel[:first_offset])
    assert_clean(macho_prefix, "Mach-O prefix")

    payload = rewrite_zip(bazel)
    assert_clean(payload, "ZIP")

    with open(output_path, "wb") as output_file:
        output_file.write(macho_prefix)
        # A separately generated ZIP records offsets from byte zero. Re-emit
        # entries after the Mach-O prefix so Bazel's SFX reader sees absolute
        # offsets, matching the native repack path above.
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            with zipfile.ZipFile(output_file, "w") as rewritten:
                rewritten.comment = archive.comment
                for entry in archive.infolist():
                    rewritten.writestr(entry, archive.read(entry.filename))

    os.chmod(output_path, 0o755)
    print("Repackaged Darwin Bazel binary")
  '';

  # All tools Bazel needs in PATH during build and at runtime. A Darwin client
  # can re-evaluate the embedded xcode-locator genrule, so retain a real
  # Darwin-hosted Clang instead of the Linux cross wrapper used at bootstrap.
  toolsPath = lib.makeBinPath (
    [
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
    ]
    ++ lib.optional isDarwinCross llvm
  );
  buildToolsPath =
    if isDarwinCross
    then
      lib.makeBinPath [
        buildBash
        buildCoreutils
        buildWhich
        buildZip
        buildUnzip
        buildGawk
        buildPython3
        buildGcc
        buildBinutils
        buildGrep
        buildGzip
        buildPatch
        buildDiffutils
        buildFindutils
        buildSed
        buildTar
        buildXz
        buildFile
      ]
    else toolsPath;

  # Cross builds keep the javac bootstrap and execution actions on Linux. A
  # separate Darwin crosstool is selected only for target C/C++ actions,
  # including the launcher, JNI library, process-wrapper, and build-runfiles
  # payloads.
  darwinBuildPrefix = ''
    # Leave BAZEL unset so compile.sh creates its Java bootstrap runner with
    # the native JDK. That runner understands this dist archive's exact vendor
    # layout and remains Linux-hosted while it builds the Darwin target.
    unset BAZEL
    export CC="${buildPackages.cc}/bin/cc"
    export CXX="${buildPackages.cc}/bin/c++"

    mkdir -p aos-darwin-toolchain aos-linux-toolchain
    unix_cc_toolchain_config=tools/cpp/unix_cc_toolchain_config.bzl
    if grep -q '_cc_toolchain_config = "cc_toolchain_config"' \
      "$unix_cc_toolchain_config"; then
      # Bazel 8+ leaves only a compatibility forwarding module in the dist
      # archive. Copy the pinned rules_cc implementation so this package-local
      # toolchain can adjust its Darwin archiver without modifying the vendor
      # fixed-output derivation.
      unix_cc_toolchain_config=${vendorDeps}/rules_cc~/cc/private/toolchain/unix_cc_toolchain_config.bzl
      if [ ! -f "$unix_cc_toolchain_config" ]; then
        echo "Bazel ${version}: vendored Unix C++ toolchain config is missing" >&2
        exit 1
      fi
    fi
    cp "$unix_cc_toolchain_config" \
      aos-darwin-toolchain/unix_cc_toolchain_config.bzl
    cp "$unix_cc_toolchain_config" \
      aos-linux-toolchain/unix_cc_toolchain_config.bzl

    # The generated macOS feature assumes `ar` is Apple's libtool and emits
    # `-static -o`. AOS supplies LLVM ar, whose archive operation is `rcs`.
    if ! grep -q 'enabled = not is_linux,' \
      aos-darwin-toolchain/unix_cc_toolchain_config.bzl; then
      echo "Bazel ${version}: macOS libtool feature anchor is missing" >&2
      exit 1
    fi
    sed -i 's/enabled = not is_linux,/enabled = False,/' \
      aos-darwin-toolchain/unix_cc_toolchain_config.bzl

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
    } > aos-darwin-toolchain/compiler
    chmod +x aos-darwin-toolchain/compiler

    # Keep host/exec C++ actions on a fully declared native toolchain. Bazel's
    # Java bootstrap otherwise loses the auto-configured builtin include list
    # when a distinct target platform is selected, and its include scanner
    # rejects every GCC/glibc system header as an undeclared absolute include.
    cp aos-darwin-toolchain/compiler aos-linux-toolchain/compiler
    sed -i \
      -e 's|${stdenv.cc}/bin/cc|${buildPackages.cc}/bin/cc|g' \
      -e 's|${stdenv.cc}/bin/c++|${buildPackages.cc}/bin/c++|g' \
      aos-linux-toolchain/compiler
    sed -i '/^set -eu$/a unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_CXXFLAGS_COMPILE NIX_LDFLAGS SDKROOT' \
      aos-linux-toolchain/compiler

    : > aos-linux-toolchain/include-dirs
    for language in xc xc++; do
      ./aos-linux-toolchain/compiler -E -"$language" - -v \
        </dev/null >/dev/null 2> aos-linux-toolchain/include-search
      ${buildGawk}/bin/awk '
        /#include <\.\.\.> search starts here:/ { capture = 1; next }
        /End of search list\./ { capture = 0 }
        capture { sub(/^[[:space:]]+/, ""); print }
      ' aos-linux-toolchain/include-search \
        | while IFS= read -r include_dir; do
            ${buildCoreutils}/bin/realpath "$include_dir"
          done >> aos-linux-toolchain/include-dirs
    done
    sort -u -o aos-linux-toolchain/include-dirs \
      aos-linux-toolchain/include-dirs
    {
      printf '%s\n' 'HOST_BUILTIN_INCLUDE_DIRECTORIES = ['
      while IFS= read -r include_dir; do
        printf '    "%s",\n' "$include_dir"
      done < aos-linux-toolchain/include-dirs
      printf '%s\n' ']'
    } > aos-linux-toolchain/host_builtin_dirs.bzl

    # The redistributable AOS SDK intentionally exposes only the Foundation
    # declarations needed by the existing package set. Bazel's real Xcode
    # locator uses a few more public selectors. Overlay those declarations for
    # this one toolchain rather than replacing the locator with a reduced stub.
    mkdir -p aos-darwin-toolchain/include/Foundation
    cp ${stdenv.sdk}/System/Library/Frameworks/Foundation.framework/Headers/Foundation.h \
      aos-darwin-toolchain/include/Foundation/Foundation.h
    sed -i \
      -e 's/id \*itemsPtr;/id __unsafe_unretained *itemsPtr;/' \
      -e 's/objects:(id \[\])buffer/objects:(id __unsafe_unretained [])buffer/' \
      aos-darwin-toolchain/include/Foundation/Foundation.h
    cat <<'BAZEL_FOUNDATION_EOF' > aos-darwin-toolchain/AOSBazelFoundation.h
    #import <Foundation/Foundation.h>

    enum { NSNumericSearch = 64 };
    #define CFBridgingRelease(value) (__bridge_transfer id)(value)

    @interface NSString (AOSBazelXcodeLocator)
    - (NSArray<NSString *> *)componentsSeparatedByString:(NSString *)separator;
    - (NSComparisonResult)compare:(NSString *)string options:(NSUInteger)options;
    @end

    @interface NSArray (AOSBazelXcodeLocator)
    - (NSString *)componentsJoinedByString:(NSString *)separator;
    @end

    @interface NSFileManager (AOSBazelXcodeLocator)
    - (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url
                        includingPropertiesForKeys:(NSArray<NSString *> *)keys
                                           options:(NSUInteger)mask
                                             error:(NSError **)error;
    @end

    @interface NSBundle (AOSBazelXcodeLocator)
    @property(readonly, copy) NSDictionary *infoDictionary;
    @end

    @interface NSURL (AOSBazelXcodeLocator)
    - (NSURL *)URLByAppendingPathComponent:(NSString *)pathComponent;
    @property(readonly) const char *fileSystemRepresentation;
    @end

    @interface NSDictionary (AOSBazelXcodeLocator)
    - (instancetype)initWithContentsOfURL:(NSURL *)url;
    @end

    @interface NSMutableDictionary (AOSBazelXcodeLocator)
    - (void)enumerateKeysAndObjectsUsingBlock:(void (^)(id key, id object, BOOL *stop))block;
    @end

    @interface NSMutableSet<ObjectType> (AOSBazelXcodeLocator)
    - (NSArray<ObjectType> *)allObjects;
    @end
    BAZEL_FOUNDATION_EOF

    # Bazel 7 still uses the public run-loop FSEvents API. The compact AOS SDK
    # carries the matching schedule call but omits its legacy unschedule peer
    # from both the header and text stub, even though Darwin exports it.
    mkdir -p aos-darwin-toolchain/include/CoreServices
    cp ${stdenv.sdk}/System/Library/Frameworks/CoreServices.framework/Headers/CoreServices.h \
      aos-darwin-toolchain/include/CoreServices/CoreServices.h
    if ! grep -q '^Boolean FSEventStreamStart' \
      aos-darwin-toolchain/include/CoreServices/CoreServices.h; then
      echo "Bazel ${version}: FSEvents header anchor is missing" >&2
      exit 1
    fi
    sed -i '/^Boolean FSEventStreamStart/i\void FSEventStreamUnscheduleFromRunLoop(FSEventStreamRef streamRef, CFRunLoopRef runLoop, CFStringRef runLoopMode);' \
      aos-darwin-toolchain/include/CoreServices/CoreServices.h${lib.optionalString needsRulesJavaRuntime ''

      sed -i '/^Boolean FSEventStreamStart/i\Boolean FSEventStreamSetExclusionPaths(FSEventStreamRef streamRef, CFArrayRef pathsToExclude);' \
        aos-darwin-toolchain/include/CoreServices/CoreServices.h''}

    mkdir -p aos-darwin-toolchain/include/pthread
    cat <<'BAZEL_PTHREAD_SPAWN_EOF' > aos-darwin-toolchain/include/pthread/spawn.h
    #ifndef AOS_BAZEL_PTHREAD_SPAWN_H
    #define AOS_BAZEL_PTHREAD_SPAWN_H
    #include <spawn.h>
    #include <sys/qos.h>

    __BEGIN_DECLS
    int posix_spawnattr_set_qos_class_np(posix_spawnattr_t *attr,
                                         qos_class_t qos_class);
    __END_DECLS
    #endif
    BAZEL_PTHREAD_SPAWN_EOF
    ${buildTar}/bin/tar -xOf ${darwinLibnotifySrc} \
      --wildcards '*/notify_keys.h' \
      > aos-darwin-toolchain/include/notify_keys.h
    ${lib.optionalString needsDarwinMdns ''
      # Bazel 8+ includes gRPC's CoreFoundation event engine, which uses
      # Bonjour's public DNS Service Discovery API. The compact SDK already
      # exports these libSystem symbols, but omits Apple's declaration header.
      ${buildTar}/bin/tar -xOf ${darwinMdnsResponderSrc} \
        --wildcards '*/mDNSShared/dns_sd.h' \
        > aos-darwin-toolchain/include/dns_sd.h
    ''}mkdir -p aos-darwin-toolchain/include/IOKit/pwr_mgt
    ${buildTar}/bin/tar -xOf ${darwinIOKitUserSrc} \
      --wildcards '*/pwr_mgt.subproj/IOPMLib.h' \
      > aos-darwin-toolchain/include/IOKit/pwr_mgt/IOPMLib.h
    ${buildTar}/bin/tar -xOf ${darwinIOKitUserSrc} \
      --wildcards '*/pwr_mgt.subproj/IOPMKeys.h' \
      > aos-darwin-toolchain/include/IOKit/pwr_mgt/IOPMKeys.h
    ${buildTar}/bin/tar -xOf ${darwinXnuSrc} \
      --wildcards '*/iokit/IOKit/pwr_mgt/IOPMLibDefs.h' \
      > aos-darwin-toolchain/include/IOKit/pwr_mgt/IOPMLibDefs.h
    ${buildTar}/bin/tar -xOf ${darwinXnuSrc} \
      --wildcards '*/iokit/IOKit/pwr_mgt/IOPM.h' \
      > aos-darwin-toolchain/include/IOKit/pwr_mgt/IOPM.h
    ${buildTar}/bin/tar -xOf ${darwinXnuSrc} \
      --wildcards '*/iokit/IOKit/IOMessage.h' \
      > aos-darwin-toolchain/include/IOKit/IOMessage.h

    # The SDK's IOKit link surface currently contains only the package-set
    # symbols. Preserve that surface and add the public power-management
    # functions consumed by Bazel's CPU and suspension-monitor JNI code.
    mkdir -p aos-darwin-toolchain/frameworks/IOKit.framework
    cp ${stdenv.sdk}/System/Library/Frameworks/IOKit.framework/IOKit.tbd \
      aos-darwin-toolchain/frameworks/IOKit.framework/IOKit.tbd
    sed -i '/      - _kIOMasterPortDefault/a\      - _IOAllowPowerChange\n      - _IONotificationPortSetDispatchQueue\n      - _IOPMAssertionCreateWithName\n      - _IOPMAssertionRelease\n      - _IOPMCopyCPUPowerStatus\n      - _IORegisterForSystemPower' \
      aos-darwin-toolchain/frameworks/IOKit.framework/IOKit.tbd
    mkdir -p aos-darwin-toolchain/frameworks/CoreServices.framework
    cp ${stdenv.sdk}/System/Library/Frameworks/CoreServices.framework/CoreServices.tbd \
      aos-darwin-toolchain/frameworks/CoreServices.framework/CoreServices.tbd
    if ! grep -q '      - _FSEventStreamStart' \
      aos-darwin-toolchain/frameworks/CoreServices.framework/CoreServices.tbd; then
      echo "Bazel ${version}: FSEvents text-stub anchor is missing" >&2
      exit 1
    fi
    sed -i '/      - _FSEventStreamStart/a\      - _FSEventStreamUnscheduleFromRunLoop' \
      aos-darwin-toolchain/frameworks/CoreServices.framework/CoreServices.tbd${lib.optionalString needsRulesJavaRuntime ''

      sed -i '/      - _FSEventStreamStart/a\      - _FSEventStreamSetExclusionPaths' \
        aos-darwin-toolchain/frameworks/CoreServices.framework/CoreServices.tbd''}

    # The client asks CoreFoundation for filesystem properties when warning
    # about remote volumes and excluding Bazel state from backups. Its headers
    # expose these APIs, so extend the package-local link surface to match.
    mkdir -p aos-darwin-toolchain/frameworks/CoreFoundation.framework
    cp ${stdenv.sdk}/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd \
      aos-darwin-toolchain/frameworks/CoreFoundation.framework/CoreFoundation.tbd
    if ! grep -q '      - _CFDataCreateMutable' \
      aos-darwin-toolchain/frameworks/CoreFoundation.framework/CoreFoundation.tbd; then
      echo "Bazel ${version}: CoreFoundation text-stub anchor is missing" >&2
      exit 1
    fi
    sed -i '/      - _CFDataCreateMutable/a\      - _CFErrorCopyDescription\n      - _CFURLCopyResourcePropertyForKey\n      - _kCFURLIsExcludedFromBackupKey\n      - _kCFURLVolumeIsLocalKey' \
      aos-darwin-toolchain/frameworks/CoreFoundation.framework/CoreFoundation.tbd

    cat <<'LINUX_TOOLCHAIN_EOF' > aos-linux-toolchain/BUILD.bazel
    load(":host_builtin_dirs.bzl", "HOST_BUILTIN_INCLUDE_DIRECTORIES")
    load(":unix_cc_toolchain_config.bzl", "cc_toolchain_config")
    load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")

    package(default_visibility = ["//visibility:public"])

    filegroup(name = "empty")
    filegroup(
        name = "compiler-files",
        srcs = [
            "compiler",
            "host_builtin_dirs.bzl",
            "unix_cc_toolchain_config.bzl",
        ],
    )

    cc_toolchain_suite(
        name = "toolchain",
        toolchains = {
            "k8": ":cc-compiler",
            "k8|gcc": ":cc-compiler",
        },
    )

    cc_toolchain(
        name = "cc-compiler",
        toolchain_identifier = "aos-linux-k8",
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
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        toolchain = ":cc-compiler",
        toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    )

    cc_toolchain_config(
        name = "config",
        cpu = "k8",
        compiler = "gcc",
        toolchain_identifier = "aos-linux-k8",
        host_system_name = "x86_64-unknown-linux-gnu",
        target_system_name = "x86_64-unknown-linux-gnu",
        target_libc = "glibc",
        abi_version = "local",
        abi_libc_version = "local",
        builtin_sysroot = "",
        cxx_builtin_include_directories = HOST_BUILTIN_INCLUDE_DIRECTORIES,
        tool_paths = {
            "ar": "${buildPackages.cc}/bin/ar",
            "c++filt": "${buildBinutils}/bin/c++filt",
            "cpp": "${buildPackages.cc}/bin/cc",
            "dwp": "${buildLlvm}/bin/llvm-dwp",
            "gcc": "compiler",
            "gcov": "${buildGcc}/bin/gcov",
            "ld": "compiler",
            "llvm-cov": "${buildLlvm}/bin/llvm-cov",
            "llvm-profdata": "${buildLlvm}/bin/llvm-profdata",
            "nm": "${buildPackages.cc}/bin/nm",
            "objcopy": "${buildPackages.cc}/bin/objcopy",
            "objdump": "${buildPackages.cc}/bin/objdump",
            "strip": "${buildPackages.cc}/bin/strip",
        },
        compile_flags = ["-fno-omit-frame-pointer"],
        dbg_compile_flags = ["-g"],
        opt_compile_flags = ["-O2", "-DNDEBUG"],
        conly_flags = [],
        cxx_flags = [],
        link_flags = [],
        archive_flags = [],
        link_libs = [],
        opt_link_flags = [],
        unfiltered_compile_flags = [],
        coverage_compile_flags = ["--coverage"],
        coverage_link_flags = ["--coverage"],
        # AOS's native GNU ld does not implement the LLVM/lld --start-lib
        # extension. Advertising it makes Bazel pass the option while linking
        # execution-platform helpers such as singlejar.
        supports_start_end_lib = False,
        extra_flags_per_feature = {},
    )
    LINUX_TOOLCHAIN_EOF

    cat <<'DARWIN_TOOLCHAIN_EOF' > aos-darwin-toolchain/BUILD.bazel
    load(":unix_cc_toolchain_config.bzl", "cc_toolchain_config")
    load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
    ${lib.optionalString needsRulesJavaRuntime ''
      # Bazel 9 migrated java_runtime from the native compatibility shell to
      # rules_java. Load the real implementation so its runtime attributes
      # and JavaRuntimeInfo provider remain available during bootstrap.
      load("@rules_java//java/common/rules:java_runtime.bzl", "java_runtime")
    ''}
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
        srcs = [
            "AOSBazelFoundation.h",
            "compiler",
            "unix_cc_toolchain_config.bzl",
        ] + glob([
            "frameworks/**",
            "include/**",
        ]),
    )

    # Java compilation executes with @local_jdk on Linux, but java_binary
    # analysis also requires a runtime compatible with the Darwin target.
    # bazel_nojdk never embeds this JDK; the installed bazelrc selects the AOS
    # Darwin JDK when the resulting Bazel runs on its host.
    java_runtime(
        name = "darwin-java-runtime",
        java_home = "${openjdk-21}",
        version = 21,
    )
    config_setting(
        name = "darwin-java-runtime-setting",
        values = {"java_runtime_version": "local_jdk_21"},
    )
    toolchain(
        name = "darwin-java-runtime-toolchain",
        target_compatible_with = [
            "@platforms//cpu:${darwinBazelCpuConstraint}",
            "@platforms//os:osx",
        ],
        target_settings = [":darwin-java-runtime-setting"],
        toolchain = ":darwin-java-runtime",
        toolchain_type = "@bazel_tools//tools/jdk:runtime_toolchain_type",
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
            "${stdenv.cc}/lib/clang/aos-darwin/include",
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
        compile_flags = ["-Iaos-darwin-toolchain/include"${lib.optionalString needsDarwinMdns '', "-D__HAS_DISPATCH__=1", "-faligned-allocation"''}],
        dbg_compile_flags = ["-g"],
        opt_compile_flags = ["-O2", "-DNDEBUG"],
        conly_flags = [],
        cxx_flags = ["-stdlib=libc++"],
        link_flags = ["-Faos-darwin-toolchain/frameworks"],
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

    # Darwin selects commands that normally require Xcode and BSD md5. The
    # AOS compiler wrapper and native coreutils provide the same operations.
    sed -i \
      's|/usr/bin/xcrun --sdk macosx clang -mmacosx-version-min=10.13 -fobjc-arc -framework CoreServices \\|${stdenv.cc}/bin/cc -Iaos-darwin-toolchain/include -include aos-darwin-toolchain/AOSBazelFoundation.h -fobjc-arc -framework ApplicationServices -framework CoreServices \\|' \
      tools/osx/BUILD
    sed -i \
      's| -arch arm64 -arch x86_64 -o \$@ \$<| -o $@ $(location xcode_locator.m)|' \
      tools/osx/BUILD
    sed -i \
      's|"//src/conditions:darwin": \["xcode_locator.m"\],|"//src/conditions:darwin": ["xcode_locator.m", "//aos-darwin-toolchain:compiler-files"],|' \
      tools/osx/BUILD
    sed -i \
      's|md5_cmd % ("/sbin/md5", "/sbin/md5", "head -c 32")|md5_cmd % ("${buildCoreutils}/bin/md5sum", "${buildCoreutils}/bin/md5sum", "head -c 32")|' \
      src/BUILD

    # compile.sh explicitly resets both platforms to @platforms//host. Keep
    # the Linux host platform, but replace the target and select the split
    # crosstools after every common bootstrap flag.
    if ! grep -q -- '--platforms=@platforms//host' compile.sh; then
      echo "Bazel ${version}: compile.sh host-platform anchor is missing" >&2
      exit 1
    fi
    sed -i \
      's|--platforms=@platforms//host \\|--platforms=//aos-darwin-toolchain:target-platform --cpu=${darwinBazelCpu} --host_cpu=k8 --crosstool_top=//aos-darwin-toolchain:toolchain --host_crosstool_top=//aos-linux-toolchain:toolchain --extra_toolchains=//aos-linux-toolchain:registered-toolchain --extra_toolchains=//aos-darwin-toolchain:registered-toolchain --extra_toolchains=//aos-darwin-toolchain:darwin-java-runtime-toolchain --noenable_platform_specific_config \\|' \
      compile.sh

    # compile.sh locates the completed binary with a separate `bazel info`
    # invocation. Give that query the same target CPU so it looks in the
    # Darwin configuration directory instead of the Linux k8 directory.
    if ! grep -q '_run_bootstrapping_bazel info "bazel-bin"' \
      scripts/bootstrap/bootstrap.sh; then
      echo "Bazel ${version}: bazel-bin lookup anchor is missing" >&2
      exit 1
    fi
    sed -i \
      's|_run_bootstrapping_bazel info "bazel-bin"|_run_bootstrapping_bazel info "bazel-bin" --platforms=//aos-darwin-toolchain:target-platform --cpu=${darwinBazelCpu} --noenable_platform_specific_config|' \
      scripts/bootstrap/bootstrap.sh
  '';

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
    builder = "${buildBash}/bin/bash";
    args = [
      "-c"
      ''
                set -eu
                export PATH="${buildToolsPath}:${buildOpenjdk}/bin:${buildPatchelf}/bin:$PATH"
                export HOME="$TMPDIR/home"
                mkdir -p "$HOME"
                export JAVA_HOME="${buildOpenjdk}"

                INTERP=$(cat "${buildBootstrapTools}/nix-support/dynamic-linker")
                BT_LIB=$(dirname "$INTERP")

                # Repackage the bootstrap Bazel binary with patchelf'd ELF files.
                # The bazel binary is a self-extracting ELF+zip — patchelf changes
                # the ELF size, corrupting zip offsets. Use the shared repack script.
                RPATH="$BT_LIB:${buildGccLibs}/lib"
                python3 ${repackBazelPy} \
                  "${buildBazelBootstrap}/lib/bazel-real" \
                  "$INTERP" \
                  "$RPATH" \
                  "${buildPatchelf}/bin/patchelf" \
                  "$TMPDIR/bazel-patched" \
                  --no-patch-elf-prefix

                # Create wrapper script (still need proc_self_exe_fix for
                # /proc/self/exe since we invoke via explicit ld.so)
                cat > "$TMPDIR/bazel" << BWRAP
        #!${buildBash}/bin/bash
        export BAZEL_REAL_PATH="$TMPDIR/bazel-patched"
        export LD_PRELOAD="${buildBazelBootstrap}/lib/proc_self_exe_fix.so"
        export LD_LIBRARY_PATH="${buildGccLibs}/lib:$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
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
                  --server_javabase="${buildOpenjdk}" \
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
                  --server_javabase="${buildOpenjdk}" \
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
    runtimeDeps =
      [
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
      ]
      ++ lib.optional isDarwinCross llvm;
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
                        -e "s|/usr/local/bin/bash|${buildBash}/bin/bash|g" \
                        -e "s|/usr/bin/bash|${buildBash}/bin/bash|g" \
                        -e "s|/bin/bash|${buildBash}/bin/bash|g" \
                        -e "s|/usr/bin/env python|${buildPython3}/bin/python3|g" \
                        -e "s|/usr/bin/env bash|${buildBash}/bin/bash|g" \
                        -e "s|/usr/bin/env|${buildCoreutils}/bin/env|g" \
                        -e "s|/bin/true|${buildCoreutils}/bin/true|g" \
                        "$f" 2>/dev/null || true
                    done

                  # Patch Python bootstrap template shebang placeholder
                  sed -i "s|%shebang%|#!${buildPython3}/bin/python3|" \
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
        script =
          (lib.optionalString isDarwinCross darwinBuildPrefix)
          + ''
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
                  -e "s|/usr/local/bin/bash|${buildBash}/bin/bash|g" \
                  -e "s|/usr/bin/bash|${buildBash}/bin/bash|g" \
                  -e "s|/bin/bash|${buildBash}/bin/bash|g" \
                  -e "s|/usr/bin/env python3|${buildPython3}/bin/python3|g" \
                  -e "s|/usr/bin/env python|${buildPython3}/bin/python3|g" \
                  -e "s|/usr/bin/env bash|${buildBash}/bin/bash|g" \
                  -e "s|/usr/bin/env|${buildCoreutils}/bin/env|g" \
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
            #!${buildBash}/bin/bash
            export PATH="${buildToolsPath}:\$PATH"
            export LD_LIBRARY_PATH="$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
            exec ${buildBash}/bin/bash "\$@"
            BASHWRAP
            chmod +x ../tools/bash-with-path

            export HOME=$(mktemp -d)
            export JAVA_HOME="${buildOpenjdk}"
            export EMBED_LABEL="${version}- (@non-git)"
            export PATH="${lib.optionalString isDarwinCross "${buildPackages.cc}/bin:"}${buildToolsPath}:$PATH"

            # Unset C_INCLUDE_PATH so Bazel's CC toolchain auto-detection doesn't
            # pick up bootstrapTools/include as a -I flag, which breaks
            # #include_next <stdlib.h> in the C++ standard library headers.
            # The cc-wrapper's built-in -isystem flag provides glibc headers.
            unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH

            # Fix shebangs in compile.sh and bootstrap scripts
            sed -i "s|#!/bin/bash|#!${buildBash}/bin/bash|g" compile.sh
            sed -i "s|#!/bin/bash|#!${buildBash}/bin/bash|g" scripts/bootstrap/compile.sh
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
              --action_env=PATH=${buildToolsPath}
              --host_action_env=PATH=${buildToolsPath}
              --action_env=LD_LIBRARY_PATH=$BT_LIB
              --host_action_env=LD_LIBRARY_PATH=$BT_LIB
              --shell_executable=$(cd ../tools && pwd)/bash-with-path
              --python_path=${buildPython3}/bin/python3
            "

            # Run the bootstrap build
            ${buildBash}/bin/bash ./compile.sh
          '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out/bin $out/share

            # The installed wrapper and all runtime defaults belong to the
            # Darwin host, even though their build-time counterparts executed
            # on Linux.
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

            ${buildPython3}/bin/python3 ${crossRepackBazelPy} \
              "$BAZEL_BIN" "$out/bin/bazel-real" \
              "${stdenv.cc}/bin/cc" "${llvm}/bin/clang" \
              "${buildBash}" "${bash}" \
              "${buildCoreutils}" "${coreutils}" \
              "${buildWhich}" "${which}" \
              "${buildZip}" "${zip}" \
              "${buildUnzip}" "${unzip}" \
              "${buildGawk}" "${gawk}" \
              "${buildPython3}" "${python3}" \
              "${buildOpenjdk}" "${openjdk-21}" \
              "${buildGcc}" "${gcc}" \
              "${buildBinutils}" "${binutils}" \
              "${buildGrep}" "${grep}" \
              "${buildGzip}" "${gzip}" \
              "${buildPatch}" "${patch}" \
              "${buildDiffutils}" "${diffutils}" \
              "${buildFindutils}" "${findutils}" \
              "${buildSed}" "${sed}" \
              "${buildTar}" "${tar}" \
              "${buildXz}" "${xz}" \
              "${buildFile}" "${file}" \
              "${buildPatchelf}" "${patchelf}" \
              "${buildBootstrapTools}" "${bootstrapTools}" \
              "${buildGccLibs}" "${gcc-libs}" \
              "${buildLlvm}" "${llvm}"

            cat > $out/bin/bazel << WRAPPER
            #!${bash}/bin/bash
            export PATH="${toolsPath}:\$PATH"
            export JAVA_HOME="${openjdk-21}"
            exec $out/bin/bazel-real "\$@"
            WRAPPER
            chmod +x $out/bin/bazel

            mkdir -p $out/nix-support
            echo "${toolsPath}" >> $out/nix-support/depends
          ''
          else ''
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
