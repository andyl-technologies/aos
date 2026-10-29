##! Keeps the retired RFC series out of the repository.
##!
##! Design decisions live in the `docs/engineering/` page for the affected
##! component. This check fails when the old RFC directory under `docs/`
##! exists, when a file names a path inside it, or when a file cites an AOS RFC
##! number. AOS numbered its records with four zero-padded digits below 0100,
##! so only that form is flagged; external standards stay citable in their
##! usual unpadded form (`RFC 9110`, `NixOS RFC 42`). The rule is documented in
##! `docs/engineering/code-style.md`.
{
  pkgs,
  lib,
}: let
  repoRoot = ../..;
  repoRootString = toString repoRoot;
  # Concatenated so the source of this check does not match its own rule.
  retiredDirectory = "docs/" + "rfcs";

  # Version-control metadata, agent checkouts, and build or runtime state are
  # not repository content. The names mirror `.gitignore`, so a working-tree
  # evaluation scans the same files as the flake's Git-filtered source.
  ignoredNames = [
    ".git"
    ".direnv"
    ".worktrees"
    ".wrangler"
    ".crucible"
    ".aos-hub"
    ".aos-doc-cache.json"
    "__pycache__"
    "result"
  ];
  ignoredPaths = [
    ".claude"
    "output"
    "mirror"
    "cli/target"
    "crates/target"
    "crates/crucible/crucible-daemon/run-state"
    "tests/ignition-test.json"
  ];

  isIgnored = path: type: let
    base = baseNameOf path;
    relative = lib.removePrefix "${repoRootString}/" (toString path);
  in
    builtins.elem base ignoredNames
    || lib.hasPrefix "result-" base
    || lib.hasSuffix ".pyc" base
    || (type == "directory" && (base == "target" || lib.hasPrefix "target-" base))
    || builtins.elem relative ignoredPaths;

  source = builtins.path {
    path = repoRoot;
    name = "aos-design-record-reference-source";
    filter = path: type: !(isIgnored path type);
  };

  # Bracketed letters keep each pattern from matching its own source text.
  # Paths into the retired directory appear either rooted at `docs/` or
  # relative to a sibling documentation section.
  retiredDirectoryPatterns = [
    "docs/rfc[s]"
    "\\.\\./rfc[s]([/)#]|$)"
    "rfc[s]/00[0-9][0-9]"
  ];
  # An AOS record citation is `RFC` with an optional `-`, `_`, or space
  # separator and a zero-padded number from 0000 through 0099, as in an
  # identifier, a heading, or prose.
  citationPattern = "(^|[^[:alnum:]])rfc[-_ ]?00[0-9][0-9]([^0-9]|$)";

  grepPatternArguments =
    lib.concatMapStringsSep " " (pattern: "-e ${lib.escapeShellArg pattern}")
    (retiredDirectoryPatterns ++ [citationPattern]);
in
  pkgs.mkDerivation {
    pname = "aos-design-record-references-check";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils pkgs.grep];

    phases = [
      {
        name = "check";
        script = ''
          failed=0
          cd ${source}

          if [ -e ${retiredDirectory} ]; then
            echo "FAIL: ${retiredDirectory} exists; record designs in docs/engineering/ instead" >&2
            failed=1
          fi

          # -I skips binary files; -i applies the rule in any letter case.
          if grep -r -n -I -i -E ${grepPatternArguments} . > "$TMPDIR/matches"; then
            echo "FAIL: retired RFC references found:" >&2
            head -n 200 "$TMPDIR/matches" >&2
            echo "($(wc -l < "$TMPDIR/matches") matching lines)" >&2
            echo "Cite the docs/engineering/ page instead; write external RFC numbers without leading zeros." >&2
            failed=1
          fi

          if [ "$failed" -ne 0 ]; then
            exit 1
          fi

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
