# Review inventory only. Discovering an ID or naming a case is not execution
# evidence and never enables a backend, lifecycle, or resource capability.
{
  lib,
  caseBindings ? [],
}: let
  chapter = file: owner: gates: {
    inherit file owner gates;
    path = ../../docs/rfcs/0021-crucible-paged-ram + "/${file}";
  };
  chapters = [
    (chapter "00-goals-and-invariants.md" "crucible-harness" ["gate:ram-guest-transparency" "gate:ram-determinism"])
    (chapter "02-logical-ram-and-merkle-format.md" "crucible-ram" ["gate:ram-format" "gate:ram-merkle-oracle"])
    (chapter "03-write-tracking-and-fingerprints.md" "crucible-qemu" ["gate:ram-dirty-epochs" "gate:ram-merkle-oracle" "gate:ram-determinism"])
    (chapter "04-host-paging.md" "crucible-qemu-plugin" ["gate:ram-paging" "gate:ram-fault-progress" "gate:ram-guest-transparency"])
    (chapter "05-runtime-policy-and-supervision.md" "crucible-qemu" ["gate:ram-runtime-policy" "gate:ram-policy-history" "gate:ram-supervision"])
    (chapter "06-hot-fork-and-lifecycle.md" "crucible-qemu" ["gate:ram-continuation" "gate:ram-fork-residency"])
    (chapter "07-checkpoints-and-storage.md" "crucible-cas" ["gate:ram-continuation" "gate:ram-store-transfer"])
    (chapter "08-state-transfer.md" "crucible-cas" ["gate:ram-store-transfer" "gate:ram-continuation"])
    (chapter "09-security-and-cutover.md" "crucible-harness" ["gate:ram-cutover" "gate:ram-store-transfer" "gate:ram-paging"])
    (chapter "10-validation-and-performance.md" "crucible-harness" ["gate:ram-performance"])
    (chapter "11-implementation-plan.md" "crucible-harness" [])
    (chapter "12-decisions-and-open-questions.md" "crucible-ram" ["gate:ram-performance"])
  ];
  discover = entry: let
    lines = lib.splitString "\n" (builtins.readFile entry.path);
    scan = index: let
      line = builtins.elemAt lines index;
      matched = builtins.match ".*[*][*][[]([A-Z]+-[0-9]+)[]].*" line;
    in
      if matched == null
      then []
      else [
        {
          id = builtins.head matched;
          source = "docs/rfcs/0021-crucible-paged-ram/${entry.file}";
          line = index + 1;
          owner = entry.owner;
          candidateGates = entry.gates;
          text = line;
        }
      ];
  in
    builtins.concatLists (builtins.genList scan (builtins.length lines));
  discovered = lib.concatMap discover chapters;
  ids = map (requirement: requirement.id) discovered;
  # Some normative performance obligations are prose rather than numbered IDs.
  # Retain their exact source anchors and scoped evidence alongside the ID table.
  proseReference = file: marker: let
    path = ../../docs/rfcs/0021-crucible-paged-ram + "/${file}";
    lines = lib.splitString "\n" (builtins.readFile path);
    matches = builtins.filter (index: lib.hasPrefix marker (builtins.elemAt lines index)) (builtins.genList (index: index) (builtins.length lines));
  in
    if builtins.length matches != 1
    then throw "Unnumbered RAM obligation must retain exactly one descriptive source anchor"
    else {
      source = "docs/rfcs/0021-crucible-paged-ram/${file}";
      line = builtins.head matches + 1;
      text = builtins.elemAt lines (builtins.head matches);
    };
  evidenceFile = relative: {
    path = relative;
    sha256 = builtins.hashFile "sha256" (../.. + "/${relative}");
  };
  unnumberedRequirements = [
    {
      name = "offline-canonical-ram-hash-comparison";
      sourceReferences = [
        (proseReference "10-validation-and-performance.md" "Hash measurements MUST include 4 KiB page preimages")
        (proseReference "12-decisions-and-open-questions.md" "Measurements must cover 4 KiB page preimages")
      ];
      owner = "crucible-ram";
      evidenceClass = "performance";
      executable = {
        package = "crucible-ram";
        example = "ram-hash-benchmark";
        features = ["test-support"];
      };
      evidenceFiles = map evidenceFile [
        "crates/crucible-ram/examples/ram_hash_benchmark.rs"
        "crates/crucible-ram/Cargo.toml"
        "docs/rfcs/0021-crucible-paged-ram/measurements/host-hashing/README.md"
        "docs/rfcs/0021-crucible-paged-ram/measurements/host-hashing/receipt.json"
        "docs/rfcs/0021-crucible-paged-ram/measurements/host-hashing/measurements.csv"
      ];
      coverage = "offline-host-measurement-recorded";
      scope = "The retained 130 warm host-side samples compare declared Rust BLAKE3 AVX2/SSE4.1 and accelerated x86 SHA-256 over full and final partial page preimages, small typed node/root preimages, and sparse/dense changed-page ancestor unions at two logical sizes. The receipt records the actual host and paths; it does not time native C hashing, persistent-tree allocation or metadata COW, paging, whole-VM throughput or physical peaks. No portable threshold or runtime capability follows from this run.";
      qualified = false;
      advertisedCapabilities = [];
    }
  ];
  bindingsFor = id: builtins.filter (binding: builtins.elem id binding.requirementIds) caseBindings;
  invalidBindings =
    builtins.filter (
      binding:
        binding.requirementIds
        == []
        || !(builtins.all (id: builtins.elem id ids) binding.requirementIds)
        || !(builtins.elem binding.role ["positive" "adversarial"])
        || !(builtins.elem binding.evidenceClass ["format" "model" "live-vm" "packaged" "performance"])
    )
    caseBindings;
  requirements =
    map (
      requirement: let
        bindings = bindingsFor requirement.id;
        hasRole = role: builtins.any (binding: binding.role == role) bindings;
      in
        requirement
        // {
          componentCases = bindings;
          coverage =
            if hasRole "positive" && hasRole "adversarial"
            then "cases-bound-not-qualified"
            else if bindings != []
            then "partial-case-bindings"
            else "uncovered";
          qualified = false;
          advertisedCapabilities = [];
        }
    )
    discovered;
in
  if builtins.length ids != builtins.length (lib.unique ids)
  then throw "Normative RAM requirement IDs must be unique before recording coverage"
  else if invalidBindings != []
  then throw "RAM coverage case bindings must name current normative IDs, evidence classes, and real test roles"
  else {
    schema = "crucible.ram-coverage-inventory.v1";
    kind = "review-inventory";
    qualification = "not-execution-evidence";
    advertisedCapabilities = [];
    inherit requirements unnumberedRequirements;
    requirementCount = builtins.length requirements;
    uncovered = map (requirement: requirement.id) (builtins.filter (requirement: requirement.coverage == "uncovered") requirements);
    sourceDigests =
      map (entry: {
        source = "docs/rfcs/0021-crucible-paged-ram/${entry.file}";
        sha256 = builtins.hashFile "sha256" entry.path;
      })
      chapters;
  }
