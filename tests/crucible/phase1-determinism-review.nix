{
  pkgs,
  lib,
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  template = builtins.readFile ../../.github/pull_request_template.md;
  standards = builtins.readFile ../../docs/rfcs/0010-crucible/28-engineering-standards.md;
  reviewRust =
    builtins.readFile ../../crates/crucible-harness/tests/determinism_review.rs;
  defaultNix = builtins.readFile ./default.nix;
  sourceNix = builtins.readFile ../../pkgs/tools/crucible/_source.nix;
  expectedTemplateCheckboxes = 18;
  expectedApplicabilityCheckboxes = [
    "Not applicable: this PR does not touch engine, scheduler, transport, or ordering-significant host code."
    "Applicable: every relevant item in the determinism review checklist below is checked or explicitly justified in this PR."
  ];
  expectedApplicabilityCheckboxItems = builtins.map normalizeItem expectedApplicabilityCheckboxes;
  expectedDeterminismChecklistItems = 15;
  expectedRootCauseCheckboxes = 1;
  expectedRootCauseCheckbox = "Any discovered determinism leak was fixed at source, or no leak was discovered.";

  templateTerms = [
    "DETERMINISM REVIEW CHECKLIST"
    "engine, scheduler, transport"
    "ordering-significant host code"
    "Reviewers must block merge on any unchecked applicable item"
    "crucible-sim"
    "crucible-assert"
    "crucible-shmem"
    "crucible-protocol"
    "crucible-device"
    "crucible"
    "Ordering"
    "Time, randomness, numerics"
    "State purity & content addressing"
    "ABI, unsafe, errors"
    "Tests & gates"
    "gate:harness-lint"
    "gate:adversarial-determinism"
    "Root-Cause Fix Rule"
    "fixed at source"
    "retry logic"
    "quarantine"
    "jitter tolerance"
    "fudge-factor"
    "paper over the leak"
  ];

  templateScopeLines = [
    "- L0: `crucible-sim`, `crucible-assert`"
    "- L1: `crucible-shmem`, `crucible-protocol`, `crucible-device`"
    "- L3: `crucible`"
  ];

  rfcTerms = [
    "[STD-32]"
    "DETERMINISM REVIEW CHECKLIST"
    "any PR touching an engine/scheduler/transport crate"
    "MUST block the PR on"
    "recorded in the PR (a template)"
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
    matches =
      builtins.filter (index:
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

  sliceAfter = label: startNeedle: content: let
    start = indexOf startNeedle content;
  in
    if start == null
    then {
      inherit label;
      missing = true;
      value = "";
    }
    else {
      inherit label;
      missing = false;
      value = builtins.substring (start + builtins.stringLength startNeedle) (builtins.stringLength content - start) content;
    };

  missingTerms = label: content: terms:
    lib.concatMap (
      term:
        lib.optionals (!(hasInfix term content)) [
          "${label}: missing `${term}`"
        ]
    )
    terms;

  forbiddenTerms = label: content: terms:
    lib.concatMap (
      term:
        lib.optionals (hasInfix term content) [
          "${label}: forbidden `${term}`"
        ]
    )
    terms;

  checkboxCount = content:
    builtins.length (
      builtins.filter (line: lib.hasPrefix "- [ ] " (lib.trim line)) (lib.splitString "\n" content)
    );

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
    then state // {current = ""; currentOpen = false;}
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
    folded =
      builtins.foldl' step {
        items = [];
        current = "";
        currentOpen = false;
      } (lib.splitString "\n" section);
  in
    (pushCurrent folded).items;

  templateChecklistSection = sliceBetween
    "template determinism checklist section"
    "### DETERMINISM REVIEW CHECKLIST"
    "### Root-Cause Fix Rule"
    template;
  rfcChecklistSection = sliceBetween
    "RFC determinism checklist block"
    "```text\nDETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)"
    "\n```"
    standards;
  rootCauseSection = sliceAfter
    "template root-cause fix rule section"
    "### Root-Cause Fix Rule"
    template;
  applicabilitySection = sliceBetween
    "template applicability section"
    "Reviewers must block merge on any unchecked applicable item."
    "### DETERMINISM REVIEW CHECKLIST"
    template;
  applicabilityChecklistItems = checkboxItems "- [ ] " applicabilitySection.value;
  templateChecklistItems = checkboxItems "- [ ] " templateChecklistSection.value;
  rfcChecklistItems = checkboxItems "[ ] " rfcChecklistSection.value;
  rootCauseChecklistItems = checkboxItems "- [ ] " rootCauseSection.value;

  checklistStructureFailures =
    lib.optionals (checkboxCount template != expectedTemplateCheckboxes) [
      ".github/pull_request_template.md: expected ${builtins.toString expectedTemplateCheckboxes} checkboxes, found ${builtins.toString (checkboxCount template)}"
    ]
    ++ lib.optionals templateChecklistSection.missing [
      "${templateChecklistSection.label}: missing section markers"
    ]
    ++ lib.optionals rfcChecklistSection.missing [
      "${rfcChecklistSection.label}: missing section markers"
    ]
    ++ lib.optionals rootCauseSection.missing [
      "${rootCauseSection.label}: missing section marker"
    ]
    ++ lib.optionals applicabilitySection.missing [
      "${applicabilitySection.label}: missing section markers"
    ]
    ++ lib.optionals (builtins.length applicabilityChecklistItems != builtins.length expectedApplicabilityCheckboxItems) [
      ".github/pull_request_template.md: expected ${builtins.toString (builtins.length expectedApplicabilityCheckboxItems)} applicability checkboxes, found ${builtins.toString (builtins.length applicabilityChecklistItems)}"
    ]
    ++ lib.optionals (applicabilityChecklistItems != expectedApplicabilityCheckboxItems) [
      ".github/pull_request_template.md: applicability checkbox text drifts from STD-32 scope rule"
    ]
    ++ lib.optionals (builtins.length templateChecklistItems != expectedDeterminismChecklistItems) [
      ".github/pull_request_template.md: expected ${builtins.toString expectedDeterminismChecklistItems} determinism checklist items, found ${builtins.toString (builtins.length templateChecklistItems)}"
    ]
    ++ lib.optionals (builtins.length rfcChecklistItems != expectedDeterminismChecklistItems) [
      "28-engineering-standards.md: expected ${builtins.toString expectedDeterminismChecklistItems} RFC checklist items, found ${builtins.toString (builtins.length rfcChecklistItems)}"
    ]
    ++ lib.optionals (templateChecklistItems != rfcChecklistItems) [
      ".github/pull_request_template.md: determinism checklist item text drifts from RFC STD-32 checklist"
    ]
    ++ lib.optionals (builtins.length rootCauseChecklistItems != expectedRootCauseCheckboxes) [
      ".github/pull_request_template.md: expected ${builtins.toString expectedRootCauseCheckboxes} root-cause checkbox, found ${builtins.toString (builtins.length rootCauseChecklistItems)}"
    ]
    ++ lib.optionals (rootCauseChecklistItems != [(normalizeItem expectedRootCauseCheckbox)]) [
      ".github/pull_request_template.md: root-cause checkbox drifts from STD-33 source-fix rule"
    ];

  failures =
    missingTerms ".github/pull_request_template.md" template templateTerms
    ++ missingTerms ".github/pull_request_template.md scope" template templateScopeLines
    ++ checklistStructureFailures
    ++ missingTerms "28-engineering-standards.md STD-32/STD-33" standards rfcTerms
    ++ missingTerms "determinism_review.rs" reviewRust [
      "determinism_review_template_matches_rfc_policy"
      "determinism_review_template_rules_reject_missing_checklist_structure"
      "template_structure_failures"
      "template_applicability_items"
      "template_checklist_items"
      "rfc_checklist_items"
      "root_cause_checklist_items"
      "TEMPLATE_CHECKBOX_COUNT"
      "APPLICABILITY_CHECKBOX_COUNT"
      "APPLICABILITY_CHECKBOXES"
      "DETERMINISM_CHECKLIST_COUNT"
      "ROOT_CAUSE_CHECKBOX_COUNT"
      "ROOT_CAUSE_CHECKBOX"
      "failures.extend(template_structure_failures(&template, &standards)?)"
    ]
    ++ missingTerms "tests/crucible/default.nix" defaultNix [
      "determinismReview = import ./phase1-determinism-review.nix"
    ]
    ++ missingTerms "pkgs/tools/crucible/_source.nix" sourceNix [
      ''pathString == "''${repoRootString}/.github"''
      ''pathString == "''${repoRootString}/.github/pull_request_template.md"''
    ]
    ++ forbiddenTerms "pkgs/tools/crucible/_source.nix" sourceNix [
      ''lib.hasPrefix "''${repoRootString}/.github" pathString''
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
            test -f ${crucibleSrc}/.github/pull_request_template.md
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.determinismReview
            tasks=T-STD-13
            review_template=.github/pull_request_template.md
            root_cause_rule=source-only
            RESULT
          '';
        }
      ];
    }
