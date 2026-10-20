##! Mandatory native diagnostic controls against the full ALL source foundation
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  python3-3_12,
  coreutils,
  grep,
  tar,
}: let
  foundation = gem5-native-original-scope-foundation;
  source = foundation.source;
  nativeCheck = ./_gem5/native-original-scope-check.py;
  diagnosticGuest = ./_gem5/native-diagnostic-guest.py;
  lruBankCheck = ./_gem5/lru-constructor-births-check.cc;
  tableBankCheck = ./_gem5/selected-table-banks-check.cc;
  tableMethodsWriter = ./_gem5/selected-table-methods.py;
  walkerStateCheck = ./_gem5/arm-walker-source-state-check.cc;
  walkerMethodsWriter = ./_gem5/arm-walker-source-state-methods.py;
  facadeWriter = ./_gem5/replacement-data-facade.py;
  evidenceWriter = ./_gem5/native-original-scope-evidence.py;
in
  mkDerivation {
    pname = "gem5-native-original-scope-check";
    version = "1";

    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
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

    buildDeps = [python3-3_12 coreutils grep tar];
    runtimeDeps = [foundation source];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out/share/gem5/checks" native-source
          ${tar}/bin/tar --no-same-owner -xf ${source}/gem5-patched-source.tar \
            -C native-source ./src/sim/crucible_lru_births.hh \
            ./src/sim/crucible_native_scope.hh ./src/sim/crucible_native_scope.cc \
            ./src/sim/crucible_native_cut.hh \
            ./src/sim/crucible_kernel_process.hh \
            ./src/arch/arm/table_walker.cc \
            ./src/mem/cache/replacement_policies/replaceable_entry.hh
          ${python3-3_12}/bin/python3 ${facadeWriter} \
            native-source/src/mem/cache/replacement_policies/replaceable_entry.hh \
            replacement-data.facade.hh
          # These data-only controls exercise the actual fixed bank/header with
          # the complete upstream base declaration, not a configured LRU TU.
          "$CXX" -std=c++17 -O2 -UNDEBUG -I. -Inative-source/src -MD \
            -MF lru-constructor-births.d ${lruBankCheck} -o lru-constructor-births-check
          ./lru-constructor-births-check > "$out/share/gem5/checks/lru-constructor-births.log"
          cat "$out/share/gem5/checks/lru-constructor-births.log"
          test "$(grep -c '^PASS ' "$out/share/gem5/checks/lru-constructor-births.log")" -eq 9
          cp lru-constructor-births.d replacement-data.facade.source.json \
            "$out/share/gem5/checks/"
          # These exact source methods use fixture pointer identities only;
          # configured native translation units and graph ownership stay separate.
          ${python3-3_12}/bin/python3 ${tableMethodsWriter} \
            native-source/src/sim/crucible_native_scope.cc selected-table-methods.hh
          "$CXX" -std=c++17 -O2 -UNDEBUG -I. -Inative-source/src -MD \
            -MF selected-table-banks.d ${tableBankCheck} -o selected-table-banks-check
          ./selected-table-banks-check > "$out/share/gem5/checks/selected-table-banks.log"
          cat "$out/share/gem5/checks/selected-table-banks.log"
          test "$(grep -c '^PASS ' "$out/share/gem5/checks/selected-table-banks.log")" -eq 9
          cp selected-table-banks.d selected-table-methods.source.json \
            "$out/share/gem5/checks/"
          # Literal walker methods and birth expressions use modeled partners;
          # the production ALL build compiles the complete native constructor.
          ${python3-3_12}/bin/python3 ${walkerMethodsWriter} \
            native-source/src/arch/arm/table_walker.cc arm-walker-source-state-methods.hh
          "$CXX" -std=c++17 -O2 -UNDEBUG -I. -MD \
            -MF arm-walker-source-state.d ${walkerStateCheck} -o arm-walker-source-state-check
          ./arm-walker-source-state-check > "$out/share/gem5/checks/arm-walker-source-state.log"
          cat "$out/share/gem5/checks/arm-walker-source-state.log"
          test "$(grep -c '^PASS ' "$out/share/gem5/checks/arm-walker-source-state.log")" -eq 9
          cp arm-walker-source-state.d arm-walker-source-state-methods.source.json \
            "$out/share/gem5/checks/"

          # A counter-only real native callback leaves its cached value stale
          # at a nonzero tick, so accidental observer normalization is visible.
          ${foundation}/bin/gem5 --listener-mode=off --outdir=counter-observation \
            ${./_gem5/system-counter-observation-check.py} \
            > counter-observation.log 2>&1
          cat counter-observation.log
          grep '"schema":"crucible.gem5.system-counter-observation-mechanism.v1"' \
            counter-observation.log > "$out/share/gem5/checks/counter-observation.json"

          ${python3-3_12}/bin/python3 ${diagnosticGuest} diagnostic-fixed-loop.elf
          for mode in owned unknown-bus changed-clock foreign-helper unarmed counter-owned counter-pending counter-invalid-table; do
            status=0
            ${foundation}/bin/gem5 --listener-mode=off --outdir="native-scope-$mode" \
              ${nativeCheck} diagnostic-fixed-loop.elf "$mode" \
              > "native-scope-$mode.log" 2>&1 || status=$?
            # Preserve the actual error even if Nix removes this failed tree.
            cat "native-scope-$mode.log"
            printf '%s\n' "$status" > "native-scope-$mode.status"
            if [ "$mode" = unarmed ]; then
              test "$status" -eq 126
            else
              test "$status" -eq 0
            fi
            grep '"schema":"crucible.gem5.diagnostic-original-native-ownership.v1"' \
              "native-scope-$mode.log" > "$out/share/gem5/checks/native-scope-$mode.json"
          done

          ${python3-3_12}/bin/python3 ${evidenceWriter} \
            ${foundation} ${source} ${./gem5-native-original-scope-check.nix} \
            ${nativeCheck} ${diagnosticGuest} "$out/share/gem5/checks/source-binding.json"
          # The mandatory check's closure co-retains both the actual ELF and
          # its complete matching source; these links grant no node authority.
          ln -s ${foundation} "$out/share/gem5/foundation"
          ln -s ${source} "$out/share/gem5/corresponding-source"
        '';
      }
    ];

    meta = {
      description = "Runs eight source-bound native diagnostic graph controls including real stopped counter callbacks without granting source issuance, restore adoption or node readiness";
      license = "MIT";
    };
  }
