{
  pkgs,
  lib,
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  claude = builtins.readFile ../../CLAUDE.md;
  agents = builtins.readFile ../../AGENTS.md;
  standards = builtins.readFile ../../docs/rfcs/0010-crucible/28-engineering-standards.md;
  documentationHygieneRust =
    builtins.readFile ../../crates/crucible-harness/tests/documentation_hygiene.rs;
  rfcConsistencyRust =
    builtins.readFile ../../crates/crucible-harness/tests/rfc_consistency.rs;
  rfcConsistencyTasks =
    builtins.readFile ../../crates/crucible-harness/tests/support/rfc_consistency_tasks.rs;
  rfcConsistencyMisc =
    builtins.readFile ../../crates/crucible-harness/tests/support/rfc_consistency_misc.rs;
  gateCatalogRust = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  crucibleSourceNix = builtins.readFile ../../pkgs/tools/crucible/_source.nix;
  defaultNix = builtins.readFile ./default.nix;
  rfcConsistencyNix = builtins.readFile ./phase1-rfc-consistency.nix;
  phaseGateWiringNix = builtins.readFile ./phase1-phase-gate-wiring.nix;

  commentsOnlyTerms = [
    "comments-only"
    "never reorder"
    "rename, or reformat code in a docs pass"
    "doc claim contradicts"
  ];

  std30Terms = [
    "Documenting existing code is comments-only"
    "NOT reorder, rename, or reformat code"
    "observed"
    "flagged in the PR"
  ];

  std31Terms = [
    "Doc-lint and the gate catalog"
    "referenced-but-undefined gate"
    "defined-but-unreferenced gate"
    "drifted"
  ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (index:
        builtins.substring index needleLen haystack == needle)
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceBetween = startNeedle: endNeedle: content: let
    start = indexOf startNeedle content;
    afterStart =
      if start == null
      then ""
      else builtins.substring start (builtins.stringLength content - start) content;
    end = indexOf endNeedle afterStart;
  in
    if start == null || end == null
    then ""
    else builtins.substring 0 end afterStart;

  missingTerms = label: content: terms:
    lib.concatMap (
      term:
        lib.optionals (!(hasInfix term content)) [
          "${label}: missing `${term}`"
        ]
    )
    terms;

  isCommentOnlyLine = line: let
    trimmed = lib.trim line;
  in
    trimmed == ""
    || lib.hasPrefix "//!" trimmed
    || lib.hasPrefix "///" trimmed
    || lib.hasPrefix "// SAFETY:" trimmed;

  nonCommentCode = content:
    builtins.concatStringsSep "\n" (
      builtins.filter (line: !(isCommentOnlyLine line)) (lib.splitString "\n" content)
    );

  commentsOnlyDiffFailures = label: before: after:
    lib.optionals (nonCommentCode before != nonCommentCode after) [
      "${label}: non-comment code drift in documentation-only diff"
    ];

  expectCommentsOnlyClean = label: before: after:
    commentsOnlyDiffFailures label before after;

  expectCommentsOnlyRejected = label: before: after:
    lib.optionals (commentsOnlyDiffFailures label before after == []) [
      "${label}: comments-only classifier accepted non-comment code drift"
    ];

  rfcConsistencyBody = sliceBetween
    "fn rfc_0010_consistency_lint_is_clean"
    "\n#[test]\nfn rfc_consistency_rules"
    rfcConsistencyRust;
  taskSyncBody = sliceBetween
    "pub(super) fn task_sync_failures"
    "\npub(super) fn task_order_failures"
    rfcConsistencyTasks;

  failures =
    missingTerms "CLAUDE.md" claude commentsOnlyTerms
    ++ missingTerms "AGENTS.md" agents commentsOnlyTerms
    ++ missingTerms "28-engineering-standards.md STD-30" standards std30Terms
    ++ missingTerms "28-engineering-standards.md STD-31" standards std31Terms
    ++ missingTerms "documentation_hygiene.rs" documentationHygieneRust [
      "comments_only_documentation_policy_matches_root_guidance"
      "doc_lint_and_gate_catalog_checks_remain_wired"
      "comments_only_diff_classifier_rejects_code_motion_and_formatting"
      "documentation_only_workspace_diff_is_comments_only_when_requested"
      "CRUCIBLE_DOCUMENTATION_ONLY_DIFF"
    ]
    ++ missingTerms "rfc_0010_consistency_lint_is_clean" rfcConsistencyBody [
      "failures.extend(task_sync_failures(&docs, &tasks, &phase_plan_order));"
      "failures.extend(gate_reference_failures(&gate_catalog, &referenced_gates));"
      "failures.extend(banned_name_failures(&root)?);"
    ]
    ++ missingTerms "task_sync_failures" taskSyncBody [
      "task_order_failures(tasks, phase_plan_order)"
      "task_manifest_digest_failures"
    ]
    ++ missingTerms "support/rfc_consistency_misc.rs" rfcConsistencyMisc [
      "gate_catalog"
      "referenced_gate_names"
      "gate_reference_failures"
    ]
    ++ missingTerms "gate_catalog.rs" gateCatalogRust [
      "canonical_gate_catalog_matches_rfc_table_and_references"
    ]
    ++ missingTerms "tests/crucible/default.nix" defaultNix [
      "documentationHygiene = import ./phase1-documentation-hygiene.nix"
      "phaseGateWiring = import ./phase1-phase-gate-wiring.nix"
      "rfcConsistency = import ./phase1-rfc-consistency.nix"
    ]
    ++ missingTerms "phase1-rfc-consistency.nix" rfcConsistencyNix [
      "tasks=T-PLAN-1,T-PLAN-2,T-STD-12"
    ]
    ++ missingTerms "pkgs/tools/crucible/_source.nix" crucibleSourceNix [
      ''pathString == "''${repoRootString}/CLAUDE.md"''
      ''pathString == "''${repoRootString}/AGENTS.md"''
    ]
    ++ missingTerms "phase1-phase-gate-wiring.nix" phaseGateWiringNix [
      "missingCatalogWiring"
      "unknownPhaseGates"
      "catalog gate is not assigned to a phase exit target"
      "phase exit target is not in the canonical gate catalog"
      "check=checks.crucible.phase1.phaseGateWiring"
    ]
    ++ expectCommentsOnlyClean "synthetic comment-only rust docs"
    "pub fn run() {}\n"
    "//! Module docs.\n/// Runs the operation.\npub fn run() {}\n"
    ++ expectCommentsOnlyClean "synthetic safety comment"
    "unsafe { call_raw() };\n"
    "// SAFETY: synthetic invariant.\nunsafe { call_raw() };\n"
    ++ expectCommentsOnlyRejected "synthetic ordinary comment"
    "pub fn run() {}\n"
    "// Incidental note.\npub fn run() {}\n"
    ++ expectCommentsOnlyRejected "synthetic rename"
    "pub fn run() {}\n"
    "/// Runs the operation.\npub fn execute() {}\n"
    ++ expectCommentsOnlyRejected "synthetic reorder"
    "fn first() {}\nfn second() {}\n"
    "/// Second docs.\nfn second() {}\nfn first() {}\n"
    ++ expectCommentsOnlyRejected "synthetic reformat"
    "pub fn run(){call();}\n"
    "/// Runs the operation.\npub fn run() { call(); }\n";
in
  if failures != []
  then throw "crucible phase1 documentation hygiene lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-documentation-hygiene";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            test -f ${crucibleSrc}/CLAUDE.md
            test -f ${crucibleSrc}/AGENTS.md
            test -f ${crucibleSrc}/docs/rfcs/0010-crucible/28-engineering-standards.md
            test -f ${crucibleSrc}/crates/crucible-harness/tests/documentation_hygiene.rs
            test -f ${crucibleSrc}/tests/crucible/phase1-documentation-hygiene.nix
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.documentationHygiene
            tasks=T-STD-12
            comments_only_policy=CLAUDE.md,AGENTS.md,28-engineering-standards.md
            source_filter=CLAUDE.md,AGENTS.md,documentation_hygiene.rs,phase1-documentation-hygiene.nix
            rfc_consistency_check=checks.crucible.phase1.rfcConsistency
            phase_gate_wiring_check=checks.crucible.phase1.phaseGateWiring
            RESULT
          '';
        }
      ];
    }
