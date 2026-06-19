{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-phase0-risk-register-gate";
  version = "0";
  src = builtins.path {
    path = ../../docs/rfcs/0010-crucible;
    name = "crucible-rfc0010-docs";
  };

  buildDeps = [
    pkgs.coreutils
    pkgs.gawk
    pkgs.grep
  ];

  phases = [
    {
      name = "check-risk-register";
      script = ''
        set -eu

        cp -r "$src" source
        chmod -R u+w source
        cd source

        risk_doc="30-risks-spikes.md"
        decision_doc="31-decision-register.md"

        fail() {
          echo "FAIL: $*" >&2
          exit 1
        }

        require_fixed() {
          file="$1"
          text="$2"
          grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
        }

        {
          printf '%s\n' T-RISK-8
          printf '%s\n' T-RISK-11
          printf '%s\n' T-RISK-12
          printf '%s\n' T-RISK-13
          printf '%s\n' T-RISK-14
          printf '%s\n' T-RISK-15
          printf '%s\n' T-RISK-16
          printf '%s\n' T-RISK-17
        } > expected-checked-tasks.txt

        gawk '
          /^- \[x\] \*\*T-/ {
            if (match($0, /T-[A-Z]+-[0-9]+/)) {
              print substr($0, RSTART, RLENGTH)
            }
          }
        ' ./*.md | sort > checked-tasks.txt

        sort expected-checked-tasks.txt > expected-checked-tasks.sorted
        checked_count=$(wc -l < checked-tasks.txt)
        [ "$checked_count" -eq 8 ] || fail "expected 8 checked risk tasks, found $checked_count"
        while read -r task; do
          grep -F -x -q -- "$task" checked-tasks.txt || fail "missing checked task $task"
        done < expected-checked-tasks.sorted
        while read -r task; do
          grep -F -x -q -- "$task" expected-checked-tasks.sorted || fail "unexpected checked task $task"
        done < checked-tasks.txt

        require_fixed "$risk_doc" "- [ ] **T-RISK-1**"
        require_fixed "$risk_doc" "- [ ] **T-RISK-2**"
        require_fixed "$risk_doc" "- [ ] **T-RISK-3**"
        require_fixed "$risk_doc" "- [ ] **T-RISK-4**"

        require_fixed "$risk_doc" "**RISK-15** is retired by \`T-RISK-8\`"
        require_fixed "$risk_doc" "**RISK-18** is retired by \`T-RISK-11\`"
        require_fixed "$risk_doc" "**RISK-19** is retired by \`T-RISK-12\`"
        require_fixed "$risk_doc" "**RISK-20** is retired by \`T-RISK-13\`"
        require_fixed "$risk_doc" "**RISK-21** is retired by \`T-RISK-14\`"
        require_fixed "$risk_doc" "**RISK-22** is retired by \`T-RISK-15\`"
        require_fixed "$risk_doc" "**RISK-23 / RISK-24** are enforced as a Phase-0 checklist guard by \`T-RISK-16\`"
        require_fixed "$risk_doc" "**RISK-25** is retired by \`T-RISK-17\`"

        require_fixed "$decision_doc" "RISK-15 / T-RISK-8"
        require_fixed "$decision_doc" "RISK-18 / T-RISK-11"
        require_fixed "$decision_doc" "RISK-19 / T-RISK-12"
        require_fixed "$decision_doc" "RISK-20 / T-RISK-13"
        require_fixed "$decision_doc" "RISK-21 / T-RISK-14"
        require_fixed "$decision_doc" "RISK-22 / T-RISK-15"
        require_fixed "$decision_doc" "RISK-23 / RISK-24 / T-RISK-16"
        require_fixed "$decision_doc" "RISK-25 / T-RISK-17"

        require_fixed "$decision_doc" "checks.crucible.phase0.coverageOverhead"
        require_fixed "$decision_doc" "checks.crucible.phase0.abiDrift"
        require_fixed "$decision_doc" "checks.crucible.phase0.futexStress"
        require_fixed "$decision_doc" "checks.crucible.phase0.lifecycle"
        require_fixed "$decision_doc" "checks.crucible.phase0.searchTreeGrowth"
        require_fixed "$decision_doc" "checks.crucible.phase0.multiVmParallelism"
        require_fixed "$decision_doc" "checks.crucible.phase0.riskRegisterGate"
        require_fixed "$decision_doc" "checks.crucible.phase0.s11MultiVcpuFingerprint"

        mkdir -p "$out"
        {
          echo PASS
          echo spike=risk-register-checklist-guard
          echo checked_risk_tasks=8
          echo retired_decision_entries=8
          echo phase0_foundational_blockers_open=4
          echo unexpected_checked_nonrisk_tasks=0
          echo phase1_plus_checked_tasks=0
        } > "$out/result"
        cp "$risk_doc" "$out/30-risks-spikes.md"
        cp "$decision_doc" "$out/31-decision-register.md"
      '';
    }
  ];

  meta = {
    description = "Crucible Phase 0 risk-register and checklist-guard consistency check";
  };
}
