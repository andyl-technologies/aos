{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  crateUnsafeFenceRust = builtins.readFile ../../crates/crucible-harness/tests/crate_unsafe_fence.rs;
  crateUnsafeFenceSupport = builtins.readFile ../../crates/crucible-harness/tests/support/crate_unsafe_fence.rs;
  crateUnsafeFenceHarness = crateUnsafeFenceRust + "\n" + crateUnsafeFenceSupport;
  safeFence = "#![forbid(unsafe_code)]";
  unsafeFence = "#![deny(unsafe_op_in_unsafe_fn)]";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  stripLineComment = line: lib.trim (builtins.elemAt (lib.splitString "//" line) 0);

  normalize = value: builtins.replaceStrings [" " "\t" "\r"] ["" "" ""] value;

  scrubLineStrings = line: let
    chars = builtins.genList (index: builtins.substring index 1 line) (builtins.stringLength line);
    step = state: ch:
      if state.inString
      then
        if state.escape
        then
          state
          // {
            out = state.out + " ";
            escape = false;
          }
        else if ch == "\\"
        then
          state
          // {
            out = state.out + " ";
            escape = true;
          }
        else if ch == "\""
        then {
          out = state.out + " ";
          inString = false;
          escape = false;
        }
        else
          state
          // {
            out = state.out + " ";
          }
      else if ch == "\""
      then {
        out = state.out + " ";
        inString = true;
        escape = false;
      }
      else
        state
        // {
          out = state.out + ch;
        };
    result =
      builtins.foldl' step {
        out = "";
        inString = false;
        escape = false;
      }
      chars;
  in
    result.out;

  crateRootInnerAttributes = content: let
    lines = lib.splitString "\n" content;
    step = state: line:
      if state.done
      then state
      else let
        trimmed = lib.trim line;
      in
        if state.inBlockComment
        then
          state
          // {
            inBlockComment = !(hasInfix "*/" trimmed);
          }
        else if trimmed == "" || lib.hasPrefix "//!" trimmed
        then state
        else if lib.hasPrefix "//" trimmed
        then state
        else if lib.hasPrefix "/*" trimmed
        then
          state
          // {
            inBlockComment = !(hasInfix "*/" trimmed);
          }
        else if lib.hasPrefix "#![" trimmed
        then
          state
          // {
            attrs = state.attrs ++ [(stripLineComment trimmed)];
          }
        else
          state
          // {
            done = true;
          };
    result =
      builtins.foldl' step {
        attrs = [];
        done = false;
        inBlockComment = false;
      }
      lines;
  in
    result.attrs;

  uncommentCodeLines = content: let
    lines = lib.splitString "\n" content;
    step = state: line: let
      trimmed = lib.trim line;
    in
      if state.inBlockComment
      then
        state
        // {
          lines = state.lines ++ [""];
          inBlockComment = !(hasInfix "*/" trimmed);
        }
      else if trimmed == "" || lib.hasPrefix "//" trimmed
      then
        state
        // {
          lines = state.lines ++ [""];
        }
      else if lib.hasPrefix "/*" trimmed
      then
        state
        // {
          lines = state.lines ++ [""];
          inBlockComment = !(hasInfix "*/" trimmed);
        }
      else
        state
        // {
          lines = state.lines ++ [(scrubLineStrings (stripLineComment line))];
        };
    result =
      builtins.foldl' step {
        lines = [];
        inBlockComment = false;
      }
      lines;
  in
    result.lines;

  # Accepts a SAFETY comment that is adjacent to the unsafe line, mirroring the
  # authoritative Rust scanner's `has_adjacent_safety_comment`: the comment may be
  # (a) the last line of a preceding `//` comment block that opened with
  # `// SAFETY:`, or (b) a `// SAFETY:` line immediately inside/after the
  # `unsafe {` block. A previous version only inspected the single line directly
  # above the unsafe, so it rejected the multi-line preceding comments and the
  # inside-block SAFETY comments the codebase actually uses.
  safetyLineStatesInvariant = line: let
    prefix = "// SAFETY:";
    trimmed = lib.trim line;
    invariant = lib.trim (builtins.substring (builtins.stringLength prefix) (builtins.stringLength trimmed) trimmed);
  in
    lib.hasPrefix prefix trimmed && invariant != "";
  # Walks up over a contiguous `//` comment block ending on line `above` and
  # returns whether the block opened with a non-empty `// SAFETY:` line.
  precedingSafetySection = rawLines: above:
    if above < 1
    then false
    else let
      line = lib.trim (builtins.elemAt rawLines (above - 1));
    in
      if safetyLineStatesInvariant line
      then true
      else if lib.hasPrefix "//" line
      then precedingSafetySection rawLines (above - 1)
      else false;
  safetyCommentStatesInvariant = rawLines: lineNumber: let
    lineCount = builtins.length rawLines;
    following =
      lineNumber
      < lineCount
      && safetyLineStatesInvariant (builtins.elemAt rawLines lineNumber);
  in
    (lineNumber >= 2 && precedingSafetySection rawLines (lineNumber - 1)) || following;
  precedingSafetyDocSection = rawLines: above:
    if above < 1
    then false
    else let
      line = lib.trim (builtins.elemAt rawLines (above - 1));
    in
      if lib.hasPrefix "///" line && hasInfix "# Safety" line
      then true
      else if lib.hasPrefix "///" line || lib.hasPrefix "#[" line || line == ""
      then precedingSafetyDocSection rawLines (above - 1)
      else false;

  rustSources = dir: displayPrefix: let
    entries = builtins.readDir dir;
    names = lib.sort builtins.lessThan (builtins.attrNames entries);
  in
    lib.concatMap (
      name: let
        path = dir + "/${name}";
        display = "${displayPrefix}/${name}";
        kind = entries.${name};
      in
        if kind == "directory"
        then rustSources path display
        else if kind == "regular" && lib.hasSuffix ".rs" name
        then [{inherit path display;}]
        else []
    )
    names;

  unsafeSourceFailuresForContent = spec: display: content: let
    rawLines = lib.splitString "\n" content;
    codeLines = uncommentCodeLines content;
    indexes = builtins.genList (index: index) (builtins.length codeLines);
    unsafePatterns = [
      "unsafe{"
      "unsafefn"
      "unsafetrait"
      "unsafeimpl"
      "unsafeextern"
    ];
    step = state: index: let
      line = builtins.elemAt codeLines index;
      compact = normalize line;
      lineNumber = index + 1;
      linePrefix = "${display}:${builtins.toString lineNumber}";
      startsUnsafeExternBlock = hasInfix "unsafeextern" compact && hasInfix "{" compact && !(hasInfix "unsafeexternfn" compact);
      inUnsafeExternBlock = state.inUnsafeExternBlock || startsUnsafeExternBlock;
      closesUnsafeExternBlock = inUnsafeExternBlock && hasInfix "}" compact;
      safeCrateFailures =
        if spec.unsafeBoundary
        then []
        else
          lib.concatMap (
            pattern:
              lib.optionals (hasInfix pattern compact) [
                "${linePrefix}: banned unsafe keyword outside enumerated unsafe-boundary crate pattern `${pattern}`"
              ]
          )
          unsafePatterns;
      unsafeBlockFailures =
        lib.optionals (
          spec.unsafeBoundary
          && hasInfix "unsafe{" compact
          && !(safetyCommentStatesInvariant rawLines lineNumber)
        ) [
          "${linePrefix}: banned bare unsafe block pattern `unsafe`"
        ];
      unsafeImplFailures =
        lib.optionals (
          spec.unsafeBoundary
          && hasInfix "unsafeimpl" compact
          && !(safetyCommentStatesInvariant rawLines lineNumber)
        ) [
          "${linePrefix}: banned unsafe impl without SAFETY pattern `unsafe impl`"
        ];
      unsafeCallableFailures =
        lib.optionals (
          spec.unsafeBoundary
          && (hasInfix "unsafefn" compact || hasInfix "unsafetrait" compact || hasInfix "unsafeexternfn" compact)
          && !(precedingSafetyDocSection rawLines (lineNumber - 1))
        ) [
          "${linePrefix}: banned unsafe item pattern `unsafe`"
        ];
      publicUnsafeExternFailures =
        lib.optionals (
          spec.unsafeBoundary
          && inUnsafeExternBlock
          && lib.hasPrefix "pub" compact
        ) [
          "${linePrefix}: banned public unsafe extern item pattern `pub item`"
        ];
    in {
      inUnsafeExternBlock = inUnsafeExternBlock && !closesUnsafeExternBlock;
      failures = state.failures ++ safeCrateFailures ++ unsafeBlockFailures ++ unsafeImplFailures ++ unsafeCallableFailures ++ publicUnsafeExternFailures;
    };
    result =
      builtins.foldl' step {
        inUnsafeExternBlock = false;
        failures = [];
      }
      indexes;
  in
    result.failures;

  unsafeSourceFailuresForSpec = spec:
    lib.concatMap (
      source:
        unsafeSourceFailuresForContent spec source.display (builtins.readFile source.path)
    ) (rustSources (cratesDir + "/${spec.package}/src") "crates/${spec.package}/src");

  specs = [
    {
      package = "crucible-cas";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-sim";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-assert";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-shmem";
      root = "src/lib.rs";
      unsafeBoundary = true;
      safeWrapperContract = [
        "Unsafe boundary discipline:"
        "safe typed region accessors"
        "safe SPSC push/pop"
        "wrappers that uphold alignment"
      ];
    }
    {
      package = "crucible-protocol";
      root = "src/lib.rs";
      unsafeBoundary = true;
      safeWrapperContract = [
        "Unsafe boundary discipline:"
        "public callers use safe setup descriptor handover wrappers"
        "validate the fixed two-fd order and descriptor count"
      ];
    }
    {
      package = "crucible-device";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-qemu";
      root = "src/lib.rs";
      unsafeBoundary = true;
      safeWrapperContract = [
        "Unsafe boundary discipline:"
        "public callers use a safe host-driver API"
        "validates process and mapping invariants"
      ];
    }
    {
      package = "crucible-qemu-plugin";
      root = "src/lib.rs";
      unsafeBoundary = true;
      safeWrapperContract = [
        "Unsafe boundary discipline:"
        "validate raw QEMU"
        "delegate to safe Rust shims"
      ];
    }
    {
      package = "crucible-debug-gateway";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-guest";
      root = "src/lib.rs";
      unsafeBoundary = true;
      safeWrapperContract = [
        "Unsafe boundary discipline:"
        "public callers use safe doorbell and marker accessors"
        "guest/register and shared-region invariants"
      ];
    }
    {
      package = "crucible";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-session";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-api";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-daemon";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-cli";
      root = "src/main.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
    {
      package = "crucible-harness";
      root = "src/lib.rs";
      unsafeBoundary = false;
      safeWrapperContract = [];
    }
  ];

  expectedPackages = lib.sort builtins.lessThan (map (spec: spec.package) specs);
  foundPackages = lib.sort builtins.lessThan (
    builtins.filter (
      name:
        lib.hasPrefix "crucible" name
        && builtins.pathExists (cratesDir + "/${name}/Cargo.toml")
    ) (builtins.attrNames (builtins.readDir cratesDir))
  );

  packageSetFailures =
    if foundPackages == expectedPackages
    then []
    else [
      "crucible package set mismatch: expected [${builtins.concatStringsSep ", " expectedPackages}], found [${builtins.concatStringsSep ", " foundPackages}]"
    ];

  scannerRegressionFailures = let
    activeAttrs = crateRootInnerAttributes ''
      //! ${safeFence}
      /*
      ${safeFence}
      */
      // ${safeFence}
      ${unsafeFence}

      fn later_item() {}
      ${safeFence}
    '';
  in
    if activeAttrs == [unsafeFence]
    then []
    else [
      "crate-root attribute scanner accepted inactive fence text: [${builtins.concatStringsSep ", " activeAttrs}]"
    ];

  checkSpec = spec: let
    rootPath = cratesDir + "/${spec.package}/${spec.root}";
    content = builtins.readFile rootPath;
    activeAttrs = crateRootInnerAttributes content;
    required =
      if spec.unsafeBoundary
      then unsafeFence
      else safeFence;
    rejected =
      if spec.unsafeBoundary
      then safeFence
      else unsafeFence;
    displayPath = "crates/${spec.package}/${spec.root}";
    contractFailures =
      if spec.unsafeBoundary && spec.safeWrapperContract == []
      then [
        "${displayPath}: unsafe boundary has no safe-wrapper contract"
      ]
      else
        lib.concatMap (
          phrase:
            lib.optionals (!(hasInfix phrase content)) [
              "${displayPath}: missing safe-wrapper contract phrase `${phrase}`"
            ]
        )
        spec.safeWrapperContract;
  in
    (lib.optionals (!(builtins.elem required activeAttrs)) [
      "${displayPath}: missing required crate-root fence `${required}`"
    ])
    ++ (lib.optionals (builtins.elem rejected activeAttrs) [
      "${displayPath}: carries contradictory crate-root fence `${rejected}`"
    ])
    ++ contractFailures;

  rustHarnessFailures = let
    requiredRustText = [
      "unsafe_boundary_crates_document_safe_wrapper_contracts"
      "unsafe_usage_is_confined_to_safe_wrapper_boundaries"
      "unsafe_source_scanner_rejects_boundary_drift"
      "unsafe_source_failures"
      "unsafe_callable_item_at"
      "unsafe_impl_at"
      "unsafe_extern_function_at"
      "public_unsafe_api_at"
      "public_unsafe_extern_item_failures"
      "outside enumerated unsafe-boundary crate"
      "has_preceding_safety_comment"
      "safety_comment_states_invariant"
      "safe-wrapper contract"
      "unsafe item"
      "unsafe impl without SAFETY"
      "public unsafe API"
      "public unsafe extern item"
    ];
  in
    lib.concatMap (
      required:
        lib.optionals (!(hasInfix required crateUnsafeFenceHarness)) [
          "crates/crucible-harness/tests/crate_unsafe_fence.rs: missing unsafe-fence scanner wiring `${required}`"
        ]
    )
    requiredRustText;

  unsafeSourceFailures = lib.concatMap unsafeSourceFailuresForSpec specs;

  unsafeSourceRegressionFailures = let
    safeCrateFindings =
      unsafeSourceFailuresForContent {
        package = "crucible";
        unsafeBoundary = false;
      } "safe-regression.rs" ''
        fn bad() {
          unsafe {}
        }
      '';
    unsafeBoundaryFindings =
      unsafeSourceFailuresForContent {
        package = "crucible-shmem";
        unsafeBoundary = true;
      } "unsafe-boundary-regression.rs" ''
        pub unsafe fn leaky_public_api() {}

        unsafe impl Send for LeakyRing {}

        unsafe extern "C" {
          pub static mut RAW_STATE: u8;
        }

        fn empty_safety_comment() {
          // SAFETY:
          unsafe {}
        }
      '';
    allowedBoundaryFindings =
      unsafeSourceFailuresForContent {
        package = "crucible-shmem";
        unsafeBoundary = true;
      } "allowed-boundary-regression.rs" ''
        pub fn safe_wrapper() {
          // SAFETY: the wrapper validates the pointer before dereference.
          unsafe {}
        }

        unsafe extern "C" {
          fn private_raw_ffi_import();
          fn publish_event();
        }

        // SAFETY: the ring wrapper owns the producer/consumer invariants.
        unsafe impl Send for PrivateRing {}

        const SAMPLE: &str = "unsafe {";
      '';
    hasFinding = reason: findings: builtins.any (finding: hasInfix reason finding) findings;
  in
    (lib.optionals (!(hasFinding "outside enumerated unsafe-boundary crate" safeCrateFindings)) [
      "unsafe-source scanner regression failed to reject unsafe in a SAFE crate"
    ])
    ++ (lib.optionals (!(hasFinding "unsafe item" unsafeBoundaryFindings)) [
      "unsafe-source scanner regression failed to reject unsafe callable items"
    ])
    ++ (lib.optionals (!(hasFinding "unsafe impl without SAFETY" unsafeBoundaryFindings)) [
      "unsafe-source scanner regression failed to reject undocumented unsafe impl"
    ])
    ++ (lib.optionals (!(hasFinding "public unsafe extern item" unsafeBoundaryFindings)) [
      "unsafe-source scanner regression failed to reject public unsafe extern items"
    ])
    ++ (lib.optionals (!(hasFinding "bare unsafe block" unsafeBoundaryFindings)) [
      "unsafe-source scanner regression failed to reject empty SAFETY comments"
    ])
    ++ (lib.optionals (allowedBoundaryFindings != []) [
      "unsafe-source scanner regression rejected allowed safe-wrapper sample: ${builtins.concatStringsSep "; " allowedBoundaryFindings}"
    ]);

  failures = packageSetFailures ++ scannerRegressionFailures ++ rustHarnessFailures ++ unsafeSourceRegressionFailures ++ unsafeSourceFailures ++ lib.concatMap checkSpec specs;
in
  if failures != []
  then throw "crucible phase1 crate unsafe-fence lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-crate-unsafe-fence";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.crateUnsafeFence
            gate=gate:harness-lint
            tasks=T-CRATE-2,T-STD-7
            runtime_safe_crates=9
            runtime_unsafe_boundary_crates=5
            test_only_safe_crates=1
            unsafe_policy=root-fences,no-fifth-unsafe-crate,immediate-safety-invariants,no-unsafe-callable-items,no-public-unsafe-api,safe-wrapper-contracts
            RESULT
          '';
        }
      ];
    }
