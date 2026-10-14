##! Source-built direct native x86 CPUID handler bounds and tuple regression
{
  gem5,
  python3-3_12,
  grep,
}: let
  registration = ''
    GTest('cpuid_boundary.test', 'cpuid_boundary.test.cc', 'cpuid.cc',
          '../../sim/cur_tick.cc', '../../base/debug.cc',
          '../../base/trace.cc', '../../base/match.cc', '../../base/str.cc',
          '../../base/atomicio.cc', '../../sim/backtrace_glibc.cc')
  '';
in
  # This builds the handler regression, not another installed simulator.
  gem5.passthru.nativeCompiler.overrideAttrs (previous: {
    pname = "gem5-cpuid-boundary-check";
    version = "1";
    cpuidSourceRecord = builtins.toJSON {
      schema = "crucible.gem5.cpuid-handler-source.v1";
      recipeSha256 = builtins.hashFile "sha256" ./gem5-cpuid-boundary-check.nix;
      witnessSha256 = builtins.hashFile "sha256" ./_gem5/cpuid-boundary-check.cc;
      guardPatchSha256 = builtins.hashFile "sha256" ./gem5-patches/x86-cpuid-subleaf-bounds.patch;
      registrationSha256 = builtins.hashString "sha256" registration;
      buildTarget = "build/ALL/arch/x86/cpuid_boundary.test.opt";
      sourceSnapshot = "after-handler-guard-and-witness-registration-before-defconfig";
      inheritedInputs = "build/foundation-native-compiler-inputs.json";
      actualCommands = "build/invoked-builder.sh";
      simulatorQualified = false;
    };
    passAsFile = previous.passAsFile ++ ["cpuidSourceRecord"];
    # Reuse the exact source-built foundation environment and source patches.
    # The witness links the real handler and upstream GoogleTest harness.
    phases = [
      (builtins.head previous.phases)
      {
        name = "configure";
        script = ''
          if patch --fuzz=0 --dry-run -p1 < ${./gem5-patches/x86-cpuid-subleaf-bounds.patch}; then
            patch --fuzz=0 -p1 < ${./gem5-patches/x86-cpuid-subleaf-bounds.patch}
          else
            # A foundation containing this exact patch needs no second apply.
            patch --fuzz=0 --dry-run --reverse -p1 < ${./gem5-patches/x86-cpuid-subleaf-bounds.patch}
          fi
          cp ${./_gem5/cpuid-boundary-check.cc} src/arch/x86/cpuid_boundary.test.cc
          cat >> src/arch/x86/SConscript <<'EOF'
          ${registration}
          EOF
          # Snapshot the actual handler/witness registration before SCons writes
          # generated files. The inherited specification describes the foundation;
          # this check's executed builder and record identify its own commands.
          ${(builtins.head (builtins.filter (phase: phase.name == "native-corresponding-source") previous.phases)).script}
          mv "$source/build/native-compiler-inputs.json" \
            "$source/build/foundation-native-compiler-inputs.json"
          cp "$cpuidSourceRecordPath" "$source/build/cpuid-handler-source.json"
          cp ${./gem5-cpuid-boundary-check.nix} "$source/build/recipes/gem5-cpuid-boundary-check.nix"
          cp ${./_gem5/cpuid-boundary-check.cc} "$source/build/cpuid-boundary-check.cc"
          # The inherited patch roster already retains the applied CPUID guard.
          cat > "$source/build/cpuid-registration.scons" <<'EOF'
          ${registration}
          EOF
          export CPATH="$C_INCLUDE_PATH"
          ${python3-3_12}/bin/python3 -m SCons --ignore-style --no-colors \
            defconfig build/ALL build_opts/ALL
        '';
      }
      {
        name = "build";
        script = ''
          export CPATH="$C_INCLUDE_PATH"
          ${python3-3_12}/bin/python3 -m SCons --ignore-style --no-colors \
            -j"$NIX_BUILD_CORES" build/ALL/arch/x86/cpuid_boundary.test.opt
        '';
      }
      {
        name = "check";
        script = ''
          build/ALL/arch/x86/cpuid_boundary.test.opt
          mkdir -p "$out/share"
          cat > "$out/share/result.json" <<'EOF'
          {"schema":"crucible.gem5.cpuid-native-check.v1","actualNativeHandler":true,"configuredTuplesPreserved":64,"unavailableSubleafsZero":true,"preMultiplyBounds":true,"ordinaryLeavesIgnoreIndex":true,"fullSystemQualified":false}
          EOF
        '';
      }
    ];
    meta.description = "Exercises the actual source-built native CPUID handler with valid, partial and overflow-index tuples";
  })
