{
  pkgs,
  lib,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  standards = builtins.readFile ../../docs/rfcs/0010-crucible/28-engineering-standards.md;
  reviewRust = builtins.readFile ../../crates/crucible-harness/tests/determinism_review.rs;
  defaultNix = builtins.readFile ./default.nix;
  expectedDeterminismChecklistItems = 15;

  rfcTerms = [
    "[STD-32]"
    "DETERMINISM REVIEW CHECKLIST"
    "any PR touching an engine/scheduler/transport crate"
    "MUST block the PR on"
    "completed checklist is recorded in the PR description"
    "or review."
    "[STD-33]"
    "fix MUST be at the"
    "source"
    "never a workaround"
    "retry"
    "jitter tolerance"
    "fudge factor"
    "papers over a determinism leak"
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
    matches = builtins.filter (index:
      builtins.substring index needleLen haystack == needle)
    indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceBetween = label: startNeedle: endNeedle: content: let
    start = indexOf startNeedle content;
    afterStart =
      if start == null
      then ""
      else builtins.substring (start + builtins.stringLength startNeedle) (builtins.stringLength content - start) content;
    end = indexOf endNeedle afterStart;
  in
    if start == null || end == null
    then {
      inherit label;
      missing = true;
      value = "";
    }
    else {
      inherit label;
      missing = false;
      value = builtins.substring 0 end afterStart;
    };

  missingTerms = label: content: terms:
    lib.concatMap (
      term:
        lib.optionals (!(hasInfix term content)) [
          "${label}: missing `${term}`"
        ]
    )
    terms;

  normalizeItem = item:
    builtins.concatStringsSep " " (
      builtins.filter (part: part != "") (
        lib.splitString " " (
          builtins.replaceStrings ["`" "—" "–" "⇒"] ["" "-" "-" "=>"] (lib.trim item)
        )
      )
    );

  pushCurrent = state:
    if lib.trim state.current == ""
    then
      state
      // {
        current = "";
        currentOpen = false;
      }
    else {
      items = state.items ++ [(normalizeItem state.current)];
      current = "";
      currentOpen = false;
    };

  checkboxItems = prefix: section: let
    step = state: line: let
      trimmed = lib.trim line;
    in
      if lib.hasPrefix prefix trimmed
      then
        (pushCurrent state)
        // {
          current = lib.removePrefix prefix trimmed;
          currentOpen = true;
        }
      else if trimmed == ""
      then pushCurrent state
      else if state.currentOpen
      then
        state
        // {
          current = state.current + " " + trimmed;
        }
      else state;
    folded = builtins.foldl' step {
      items = [];
      current = "";
      currentOpen = false;
    } (lib.splitString "\n" section);
  in
    (pushCurrent folded).items;

  rfcChecklistSection =
    sliceBetween
    "RFC determinism checklist block"
    "```text\nDETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)"
    "\n```"
    standards;
  rfcChecklistItems = checkboxItems "[ ] " rfcChecklistSection.value;

  checklistStructureFailures =
    lib.optionals rfcChecklistSection.missing [
      "${rfcChecklistSection.label}: missing section markers"
    ]
    ++ lib.optionals (builtins.length rfcChecklistItems != expectedDeterminismChecklistItems) [
      "28-engineering-standards.md: expected ${builtins.toString expectedDeterminismChecklistItems} RFC checklist items, found ${builtins.toString (builtins.length rfcChecklistItems)}"
    ];

  failures =
    missingTerms "28-engineering-standards.md STD-32/STD-33" standards rfcTerms
    ++ checklistStructureFailures
    ++ missingTerms "determinism_review.rs" reviewRust [
      "determinism_review_policy_matches_rfc"
      "determinism_review_rules_reject_missing_checklist_structure"
      "rfc_structure_failures"
      "rfc_checklist_items"
      "DETERMINISM_CHECKLIST_COUNT"
      "failures.extend(rfc_structure_failures(&standards)?)"
    ]
    ++ missingTerms "tests/crucible/default.nix" defaultNix [
      "determinismReview = import ./phase1-determinism-review.nix"
    ];
in
  if failures != []
  then throw "crucible phase1 determinism review lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-determinism-review";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            test -f ${crucibleSrc}/docs/rfcs/0010-crucible/28-engineering-standards.md
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.determinismReview
            tasks=T-STD-13
            review_checklist=docs/rfcs/0010-crucible/28-engineering-standards.md
            root_cause_rule=source-only
            RESULT
          '';
        }
      ];
    }
