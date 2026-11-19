{
  pkgs,
  lib,
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  agents = builtins.readFile ../../AGENTS.md;
  standards = builtins.readFile ../../docs/engineering/crucible/engineering-standards.md;
  documentationHygieneRust =
    builtins.readFile ../../crates/crucible/crucible-test-support/tests/documentation_hygiene.rs;
  gateCatalogRust = builtins.readFile ../../crates/crucible/crucible-test-support/tests/gate_catalog.rs;
  crucibleSourceNix = builtins.readFile ../../pkgs/tools/crucible/_source.nix;
  defaultNix = builtins.readFile ./default.nix;
  phaseGateWiringNix = builtins.readFile ./phase1-phase-gate-wiring.nix;

  commentsOnlyTerms = [
    "comments-only"
    "never reorder"
    "rename, or reformat code in a docs pass"
    "doc claim contradicts"
  ];

  commentsOnlyRuleTerms = [
    "Documenting existing code is comments-only"
    "NOT reorder, rename, or reformat code"
    "observed"
    "flagged in the PR"
  ];

  docLintRuleTerms = [
    "Doc-lint and the gate catalog"
    "referenced-but-undefined gate"
    "defined-but-unreferenced gate"
    "drifted"
  ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

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
    trimmed
    == ""
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

  failures =
    missingTerms "AGENTS.md" agents commentsOnlyTerms
    ++ missingTerms "engineering-standards.md comments-only rule" standards commentsOnlyRuleTerms
    ++ missingTerms "engineering-standards.md doc-lint rule" standards docLintRuleTerms
    ++ missingTerms "documentation_hygiene.rs" documentationHygieneRust [
      "comments_only_documentation_policy_matches_root_guidance"
      "doc_lint_and_gate_catalog_checks_remain_wired"
      "comments_only_diff_classifier_rejects_code_motion_and_formatting"
      "documentation_only_workspace_diff_is_comments_only_when_requested"
      "CRUCIBLE_DOCUMENTATION_ONLY_DIFF"
    ]
    ++ missingTerms "gate_catalog.rs" gateCatalogRust [
      "canonical_gate_catalog_matches_documented_table_and_references"
      "fn referenced_gate_names"
    ]
    ++ missingTerms "tests/crucible/default.nix" defaultNix [
      "documentationHygiene = import ./phase1-documentation-hygiene.nix"
      "phaseGateWiring = import ./phase1-phase-gate-wiring.nix"
      "gateCatalog = import ./phase1-gate-catalog.nix"
    ]
    ++ missingTerms "pkgs/tools/crucible/_source.nix" crucibleSourceNix [
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
            test -f ${crucibleSrc}/AGENTS.md
            test -f ${crucibleSrc}/docs/engineering/crucible/engineering-standards.md
            test -f ${crucibleSrc}/crates/crucible/crucible-test-support/tests/documentation_hygiene.rs
            test -f ${crucibleSrc}/tests/crucible/phase1-documentation-hygiene.nix
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.documentationHygiene
            comments_only_policy=AGENTS.md,engineering-standards.md
            source_filter=AGENTS.md,documentation_hygiene.rs,phase1-documentation-hygiene.nix
            gate_catalog_check=checks.crucible.phase1.gateCatalog
            phase_gate_wiring_check=checks.crucible.phase1.phaseGateWiring
            RESULT
          '';
        }
      ];
    }
