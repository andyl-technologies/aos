##! Complete, sharded build validation for the advertised Darwin package set.
##!
##! Every publication root and every named output is realized through a
##! publication-wave check. The checks inspect Darwin artifacts from Linux;
##! they never execute a target binary.
{pkgs}: let
  lib = pkgs.lib;
  support = import ../../pkgs/_platform-support.nix;
  buildSystem = pkgs.stdenv.buildPlatform.system;
  waves = [1 2 3 4 5];

  targetSystems = {
    x86_64-darwin = {
      expectedCpu = "X86_64";
      expectedElfArch = "x86_64";
      expectedElfFormat = "elf64-x86-64";
    };
    aarch64-darwin = {
      expectedCpu = "ARM64";
      expectedElfArch = "aarch64";
      expectedElfFormat = "elf64-littleaarch64";
    };
  };

  nativeToolNames = [
    "autoconf"
    "automake"
    "bash"
    "binutils"
    "bison"
    "cc"
    "cmake"
    "coreutils"
    "diffutils"
    "file"
    "findutils"
    "flex"
    "gawk"
    "gcc"
    "gcc-libs"
    "gccUnwrapped"
    "git-minimal"
    "gnumake"
    "go"
    "gperf"
    "grep"
    "llvm"
    "m4"
    "meson"
    "ninja"
    "nix"
    "nodejs"
    "patch"
    "perl"
    "pkg-config"
    "python3"
    "rust"
    "sed"
    "tar"
    "texinfo"
    "which"
  ];

  packageOutputs = packageName: package:
    builtins.map (outputName: {
      inherit packageName outputName;
      isPrimary = outputName == (package.outputName or "out");
      path = builtins.getAttr outputName package;
    }) (package.outputs or ["out"]);

  outputPaths = packages:
    lib.concatMap (
      name: builtins.map (entry: entry.path) (packageOutputs name packages.${name})
    ) (builtins.attrNames packages);

  nativeToolPackages =
    builtins.map (name: builtins.getAttr name pkgs) (
      builtins.filter (name: builtins.hasAttr name pkgs) nativeToolNames
    )
    ++ builtins.filter (
      package: builtins.isAttrs package && package ? outPath
    ) [
      pkgs.bootstrapTools
      pkgs.stdenv
    ];

  nativeToolOutputPaths = lib.unique (
    lib.concatMap (
      package:
        builtins.map (
          # These are blacklist keys for the structured target graph, not
          # inputs to the check itself. Discard string context so every shard
          # does not realize the complete native compiler/tool inventory just
          # to compare store-path names.
          outputName:
            builtins.unsafeDiscardStringContext (
              toString (builtins.getAttr outputName package)
            )
        ) (package.outputs or ["out"])
    )
    nativeToolPackages
  );

  mkAggregate = name: checks:
    pkgs.mkDerivation {
      pname = "darwin-package-matrix-${name}";
      version = "0";
      src = null;
      buildDeps = checks;
      dontStrip = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "aggregate";
          script = ''
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    };

  mkTargetChecks = targetSystem: targetConfig: let
    cross = import ../.. {
      system = buildSystem;
      crossSystem = targetSystem;
    };
    targetPackages = cross.pkgs.targetPackagesFor targetSystem;
    targetNames = cross.pkgs.targetPackageNamesFor targetSystem;
    compilerSdkPath = toString cross.pkgs.stdenv.cc.passthru.sdk;
    namesForWave = wave:
      builtins.filter (
        name: (support.packageSupport name).wave == wave
      )
      targetNames;
    partitionedNames = lib.concatMap namesForWave waves;
    partitionCounts =
      builtins.foldl' (
        counts: name:
          counts
          // {
            ${name} = (counts.${name} or 0) + 1;
          }
      ) {}
      partitionedNames;
    invalidPartition =
      builtins.filter (
        name: partitionCounts.${name} or 0 != 1
      )
      targetNames;
    partitionIsExact =
      builtins.length partitionedNames
      == builtins.length targetNames
      && invalidPartition == [];
    allTargetOutputPaths = builtins.map toString (outputPaths targetPackages);
    prohibitedNativePaths =
      builtins.filter (
        path: !(builtins.elem path allTargetOutputPaths)
      )
      nativeToolOutputPaths;

    mkWave = wave: let
      waveNames = namesForWave wave;
      wavePackages = builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = targetPackages.${name};
        })
        waveNames
      );
      waveOutputs =
        lib.concatMap (
          name: packageOutputs name wavePackages.${name}
        )
        waveNames;
      rootPaths = builtins.map (entry: entry.path) waveOutputs;
      auditCalls =
        lib.concatMapStringsSep "\n" (entry: ''
          audit_output \
            ${lib.escapeShellArg entry.packageName} \
            ${lib.escapeShellArg entry.outputName} \
            ${lib.escapeShellArg (
            if entry.isPrimary
            then "1"
            else "0"
          )} \
            ${lib.escapeShellArg (toString entry.path)}
        '')
        waveOutputs;
      prohibitedChecks =
        lib.concatMapStringsSep "\n" (path: ''
          if grep -F -x -q ${lib.escapeShellArg path} audited-closure-paths; then
            printf '%s\n' ${lib.escapeShellArg path} >> prohibited-native-paths
          fi
        '')
        prohibitedNativePaths;
    in
      pkgs.mkDerivation {
        pname = "darwin-package-matrix-${targetSystem}-wave-${toString wave}";
        version = "0";
        src = null;

        # The structured graph realizes and describes the target outputs
        # without passing them through buildDeps, whose package-set splicing
        # would correctly replace executable dependencies with Linux tools.
        outputChecks = {};
        exportReferencesGraph.matrix = rootPaths;
        buildDeps = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gawk
          pkgs.grep
          pkgs.jq
          pkgs.llvm
        ];
        dontStrip = true;
        dontNukeRefs = true;

        phases = [
          {
            name = "audit";
            script = ''
              set -eu

              expected_platform=${lib.escapeShellArg targetSystem}
              expected_build_platform=${lib.escapeShellArg buildSystem}
              compiler_sdk_path=${lib.escapeShellArg compilerSdkPath}
              expected_cpu=${lib.escapeShellArg targetConfig.expectedCpu}
              expected_elf_arch=${lib.escapeShellArg targetConfig.expectedElfArch}
              expected_elf_format=${lib.escapeShellArg targetConfig.expectedElfFormat}
              mkdir -p "$out"
              : > "$out/outputs.tsv"

              audit_build_path() {
                file=$1
                # Match the sandbox root as a path boundary. Package sources
                # legitimately contain components such as src/go/build/;
                # treating every `/build/` component as ephemeral rejects
                # canonical language package names rather than build roots.
                if ${pkgs.llvm}/bin/llvm-strings -a "$file" \
                  | grep -E '(^|[[:space:]"=:(;,])/build/' >/dev/null; then
                  echo "ephemeral /build path in Darwin output: $file" >&2
                  exit 1
                fi
              }

              audit_gnu_efi() {
                root=$1

                unexpected=$(find "$root" -type f \( \
                     -perm /111 \
                  -o -name '*.dylib' -o -name '*.dylib.*' \
                  -o -name '*.so' -o -name '*.so.*' \
                  -o -name '*.bundle' -o -name '*.node' -o -name '*.jnilib' \
                  \) -print -quit)
                if [ -n "$unexpected" ]; then
                  echo "gnu-efi published an executable or shared artifact: $unexpected" >&2
                  exit 1
                fi

                crt_files=$(find "$root" -type f -name 'crt*.o' -print)
                if [ -z "$crt_files" ]; then
                  echo "gnu-efi published no EFI CRT objects" >&2
                  exit 1
                fi
                for crt in $crt_files; do
                  audit_build_path "$crt"
                  header=$(${pkgs.llvm}/bin/llvm-readobj --file-headers "$crt")
                  if ! printf '%s\n' "$header" | grep -F -q "Format: $expected_elf_format" \
                    || ! printf '%s\n' "$header" | grep -F -q "Arch: $expected_elf_arch" \
                    || ! printf '%s\n' "$header" | grep -F -q 'Type: Relocatable'; then
                    echo "gnu-efi CRT is not matching ELF relocatable code: $crt" >&2
                    printf '%s\n' "$header" >&2
                    exit 1
                  fi
                done

                archives=$(find "$root" -type f -name '*.a' -print)
                if [ -z "$archives" ]; then
                  echo "gnu-efi published no EFI static archives" >&2
                  exit 1
                fi
                for archive in $archives; do
                  audit_build_path "$archive"
                  member_count=$(${pkgs.llvm}/bin/llvm-ar t "$archive" | wc -l)
                  if [ "$member_count" -eq 0 ]; then
                    echo "gnu-efi published an empty archive: $archive" >&2
                    exit 1
                  fi

                  headers=$(${pkgs.llvm}/bin/llvm-readobj --file-headers "$archive")
                  header_count=$(printf '%s\n' "$headers" | awk '/^File: / { count++ } END { print count + 0 }')
                  format_count=$(printf '%s\n' "$headers" | grep -F -c "Format: $expected_elf_format" || true)
                  arch_count=$(printf '%s\n' "$headers" | grep -F -c "Arch: $expected_elf_arch" || true)
                  relocatable_count=$(printf '%s\n' "$headers" | grep -F -c 'Type: Relocatable' || true)
                  if [ "$header_count" -ne "$member_count" ] \
                    || [ "$format_count" -ne "$member_count" ] \
                    || [ "$arch_count" -ne "$member_count" ] \
                    || [ "$relocatable_count" -ne "$member_count" ]; then
                    echo "gnu-efi archive contains a non-matching member: $archive" >&2
                    printf '%s\n' "$headers" >&2
                    exit 1
                  fi
                done
              }

              audit_output() {
                package=$1
                output_name=$2
                is_primary=$3
                root=$4

                printf '%s\t%s\t%s\n' "$package" "$output_name" "$root" \
                  >> "$out/outputs.tsv"

                if [ -d "$root" ] && [ ! -L "$root" ]; then
                  marker="$root/nix-support/aos-target-platform"
                  if [ ! -f "$marker" ]; then
                    echo "missing target-platform marker: $package.$output_name ($root)" >&2
                    exit 1
                  fi
                  actual_platform=$(cat "$marker")
                  if [ "$actual_platform" != "$expected_platform" ]; then
                    echo "wrong target-platform marker on $package.$output_name: $actual_platform" >&2
                    exit 1
                  fi
                elif [ "$is_primary" = 1 ]; then
                  echo "advertised package root is not a directory: $package ($root)" >&2
                  exit 1
                elif [ ! -e "$root" ]; then
                  echo "missing secondary output: $package.$output_name ($root)" >&2
                  exit 1
                else
                  return
                fi

                if [ "$package" = gnu-efi ]; then
                  audit_gnu_efi "$root"
                fi

                # Inspect only files whose format carries an execution
                # contract. Static archives and relocatable objects are
                # deliberately excluded: gnu-efi, for example, publishes
                # architecture-specific ELF development artifacts for later
                # firmware links from a Darwin package set.
                find "$root" -type f \( \
                     -perm /111 \
                  -o -name '*.dylib' -o -name '*.dylib.*' \
                  -o -name '*.so' -o -name '*.so.*' \
                  -o -name '*.bundle' -o -name '*.node' -o -name '*.jnilib' \
                  \) -print | while IFS= read -r file; do
                    audit_build_path "$file"

                    # GDB auto-load helpers and dSYM relocation maps
                    # conventionally include the full shared-library name in
                    # their source or metadata basename. Audit their text for
                    # build paths, but do not classify them as shared objects.
                    case "$file" in
                      *-gdb.py) continue ;;
                      *.dSYM/Contents/Resources/Relocations/*/*.dylib.yml) continue ;;
                    esac

                    magic=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
                    case "$magic" in
                      cffaedfe|feedfacf|cefaedfe|feedface|cafebabe|bebafeca|cafebabf|bfbafeca)
                        is_macho=1
                        ;;
                      *)
                        is_macho=0
                        ;;
                    esac

                    if [ "$is_macho" = 1 ]; then
                      header=$(${pkgs.llvm}/bin/llvm-objdump --macho --private-header "$file")
                      if ! printf '%s\n' "$header" | grep -q "$expected_cpu"; then
                        echo "wrong Mach-O CPU in $file: expected $expected_cpu" >&2
                        printf '%s\n' "$header" >&2
                        exit 1
                      fi
                      continue
                    fi

                    if [ "$magic" = 7f454c46 ]; then
                      echo "ELF executable or shared library in Darwin output: $file" >&2
                      exit 1
                    fi

                    case "$file" in
                      *.dylib|*.dylib.*|*.so|*.so.*|*.bundle|*.node|*.jnilib)
                        echo "non-Mach-O shared library in Darwin output: $file" >&2
                        exit 1
                        ;;
                    esac
                  done

                # Metadata that feeds downstream builds must not retain a
                # sandbox location even though it has no executable format.
                find "$root" -type f \( \
                     -name '*.pc' -o -name '*.la' -o -name '*.cmake' \
                  -o -name Makefile -o -name '_sysconfigdata*.py' \
                  -o -name '_sysconfig_vars*.json' \
                  \) -print | while IFS= read -r file; do
                    audit_build_path "$file"
                  done
              }

              ${auditCalls}

              ${pkgs.jq}/bin/jq -r '.matrix[].path' "$NIX_ATTRS_JSON_FILE" \
                | sort -u > closure-paths

              # The public SDK and compiler publications deliberately retain
              # their Linux-hosted compiler SDK and wrapper so downstream cross
              # compilers can consume them.
              # Perl's dev output is likewise an explicitly forensic copy of
              # its unsanitized build configuration; the runnable output is
              # scrubbed and remains subject to the complete closure audit.
              # Exclude only those documented publication roots so unrelated
              # native-tool leaks remain visible.
              : > audited-closure-paths
              while IFS="$(printf '\t')" read -r package output_name root; do
                if [ "$package" = darwin-sdk ] \
                  || [ "$package" = cc ] \
                  || [ "$package" = gcc ] \
                  || [ "$package" = gcc-libs ] \
                  || [ "$package" = gccUnwrapped ] \
                  || { [ "$package" = perl ] && [ "$output_name" = dev ]; }; then
                  continue
                fi
                ${pkgs.jq}/bin/jq -r --arg root "$root" '
                  .matrix as $nodes
                  | ($nodes | map({key: .path, value: .references}) | from_entries) as $refs
                  | def walk($path; $seen):
                      if $seen | index($path) then
                        empty
                      else
                        $path,
                        (($refs[$path] // [])[] | walk(.; $seen + [$path]))
                      end;
                    walk($root; [])
                ' "$NIX_ATTRS_JSON_FILE" >> audited-closure-paths
              done < "$out/outputs.tsv"
              sort -u -o audited-closure-paths audited-closure-paths

              # Any marked object in a Darwin runtime closure must carry the
              # same target. Unmarked fixed-output sources remain valid, then
              # the explicit native-tool blacklist covers compiler and build
              # tooling outputs that predate the marker contract.
              : > wrong-platform-paths
              while IFS= read -r path; do
                marker="$path/nix-support/aos-target-platform"
                if [ -f "$marker" ]; then
                  marked_platform=$(cat "$marker")
                  if [ "$marked_platform" != "$expected_platform" ]; then
                    # The compiler SDK is a Linux-hosted publication consumed
                    # as immutable target data. Exempt only this exact role and
                    # path; every other marked closure member must match the
                    # Darwin target.
                    if [ "$path" = "$compiler_sdk_path" ] \
                      && [ "$marked_platform" = "$expected_build_platform" ]; then
                      continue
                    fi
                    printf '%s\n' "$path" >> wrong-platform-paths
                  fi
                fi
              done < audited-closure-paths
              if [ -s wrong-platform-paths ]; then
                echo "Darwin closure contains outputs marked for another platform:" >&2
                sort -u wrong-platform-paths >&2
                exit 1
              fi

              : > prohibited-native-paths
              ${prohibitedChecks}
              if [ -s prohibited-native-paths ]; then
                echo "Darwin closure retains prohibited native build/toolchain outputs:" >&2
                sort -u prohibited-native-paths >&2
                exit 1
              fi

              package_count=${toString (builtins.length waveNames)}
              output_count=${toString (builtins.length waveOutputs)}
              closure_count=$(${pkgs.jq}/bin/jq '.matrix | length' "$NIX_ATTRS_JSON_FILE")
              {
                printf 'schema=aos.darwin-package-matrix/v1\n'
                printf 'platform=%s\n' "$expected_platform"
                printf 'wave=%s\n' ${lib.escapeShellArg (toString wave)}
                printf 'packages=%s\n' "$package_count"
                printf 'outputs=%s\n' "$output_count"
                printf 'closure-paths=%s\n' "$closure_count"
                printf 'result=PASS\n'
              } > "$out/result"
            '';
          }
        ];

        passthru = {
          inherit targetSystem wave waveNames;
          packageCount = builtins.length waveNames;
          outputCount = builtins.length waveOutputs;
        };
      };

    waveChecks = builtins.listToAttrs (
      builtins.map (wave: {
        name = "wave${toString wave}";
        value = mkWave wave;
      })
      waves
    );
  in
    assert partitionIsExact;
      waveChecks
      // {
        all = mkAggregate targetSystem (builtins.attrValues waveChecks);
      };

  matrices = builtins.mapAttrs mkTargetChecks targetSystems;
in
  matrices
  // {
    all = mkAggregate "all" (
      builtins.map (targetSystem: matrices.${targetSystem}.all) (
        builtins.attrNames targetSystems
      )
    );
  }
