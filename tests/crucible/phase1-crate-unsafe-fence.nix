{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  safeFence = "#![forbid(unsafe_code)]";
  unsafeFence = "#![deny(unsafe_op_in_unsafe_fn)]";

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (i: i) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  stripLineComment = line: lib.trim (builtins.elemAt (lib.splitString "//" line) 0);

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

  specs = [
    {
      package = "crucible-sim";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-assert";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-shmem";
      root = "src/lib.rs";
      unsafeBoundary = true;
    }
    {
      package = "crucible-protocol";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-device";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-qemu";
      root = "src/lib.rs";
      unsafeBoundary = true;
    }
    {
      package = "crucible-qemu-plugin";
      root = "src/lib.rs";
      unsafeBoundary = true;
    }
    {
      package = "crucible-guest";
      root = "src/lib.rs";
      unsafeBoundary = true;
    }
    {
      package = "crucible";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-session";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-api";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-daemon";
      root = "src/lib.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-cli";
      root = "src/main.rs";
      unsafeBoundary = false;
    }
    {
      package = "crucible-harness";
      root = "src/lib.rs";
      unsafeBoundary = false;
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
  in
    (lib.optionals (!(builtins.elem required activeAttrs)) [
      "${displayPath}: missing required crate-root fence `${required}`"
    ])
    ++ (lib.optionals (builtins.elem rejected activeAttrs) [
      "${displayPath}: carries contradictory crate-root fence `${rejected}`"
    ]);

  failures = packageSetFailures ++ scannerRegressionFailures ++ lib.concatMap checkSpec specs;
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
            task=T-CRATE-2
            runtime_safe_crates=9
            runtime_unsafe_boundary_crates=4
            test_only_safe_crates=1
            RESULT
          '';
        }
      ];
    }
