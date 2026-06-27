{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ninePWireAbi",
  taskIds ? ["T-IO-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  ninepSubnode = builtins.readFile ../../crates/crucible/src/ninep_subnode.rs;
  wireTest = builtins.readFile ../../crates/crucible/tests/ninep_wire_abi.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  abiConformanceGate = builtins.readFile ./phase2-abi-conformance.nix;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-8 checked off";
        needle = "- [x] **T-IO-8**";
      }
      {
        label = "T-IO-8 completion note";
        needle = "Completed by `checks.crucible.phase3.ninePWireAbi`";
      }
      {
        label = "wire golden note";
        needle = "exact 9P2000.L wire golden vectors";
      }
      {
        label = "wire fuzz note";
        needle = "deterministic arbitrary-byte fuzz coverage";
      }
    ]
    ++ failuresFor "crates/crucible/src/ninep_subnode.rs" ninepSubnode [
      {
        label = "wire entrypoint";
        needle = "pub fn handle_wire_request";
      }
      {
        label = "wire decoder";
        needle = "fn decode_wire_request";
      }
      {
        label = "wire cursor";
        needle = "struct NinePWireCursor";
      }
      {
        label = "wire encoder";
        needle = "fn encode_wire_response";
      }
      {
        label = "wire error encoder";
        needle = "fn encode_wire_error";
      }
      {
        label = "size mismatch guard";
        needle = "if declared_size != actual_size";
      }
      {
        label = "wire msize guard";
        needle = "if declared_size > negotiated_msize";
      }
      {
        label = "wire response msize guard";
        needle = "fn encode_wire_response_limited";
      }
      {
        label = "fallible wire response limiter";
        needle = "fn try_encode_wire_response_limited";
      }
      {
        label = "transactional wire trial";
        needle = "let mut trial = self.clone();";
      }
      {
        label = "commit only after encodable response";
        needle = "*self = trial;";
      }
      {
        label = "success response type guard";
        needle = "fn success_wire_response_type";
      }
      {
        label = "canonical version tag guard";
        needle = "if tag != NINEP_NOTAG";
      }
      {
        label = "write-open flag guard";
        needle = "fn open_flags_request_write";
      }
      {
        label = "fallible string encoder";
        needle = "fn append_wire_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ()>";
      }
      {
        label = "unknown type maps ENOSYS";
        needle = "message_type: unknown";
      }
      {
        label = "rlerror type";
        needle = "const NINEP_RLERROR: u8 = 7";
      }
      {
        label = "readdir wire encoder";
        needle = "wire_message(NINEP_RREADDIR";
      }
      {
        label = "getattr wire encoder";
        needle = "wire_message(NINEP_RGETATTR";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/ninep_subnode.rs" ninepSubnode [
      {
        label = "host filesystem API";
        needle = "std::fs";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "wall-clock API";
        needle = "SystemTime";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "panic unwrap";
        needle = ".unwrap()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/ninep_wire_abi.rs" wireTest [
      {
        label = "wire ABI test header";
        needle = "T-IO-8 9P2000.L wire golden vectors";
      }
      {
        label = "golden vector test";
        needle = "wire_golden_vectors_cover_read_traverse_and_error_responses";
      }
      {
        label = "response msize and string test";
        needle = "wire_response_msize_and_string_failures_return_well_formed_errors";
      }
      {
        label = "fuzzer test";
        needle = "wire_fuzzer_never_panics_and_returns_structurally_valid_response";
      }
      {
        label = "panic catcher";
        needle = "std::panic::catch_unwind";
      }
      {
        label = "well formed response assertion";
        needle = "assert_well_formed_response";
      }
      {
        label = "exact read golden";
        needle = "message(RREAD, 5, expected_read_body)";
      }
      {
        label = "valid frame fuzz inputs";
        needle = "message(TVERSION, NOTAG, version_request_body(64))";
      }
      {
        label = "response body parser";
        needle = "match message_type";
      }
      {
        label = "overflow walk does not create new fid";
        needle = ".any(|snapshot| snapshot.fid == 2)";
      }
      {
        label = "overflow lopen does not open fid";
        needle = "fid 1 should remain attached";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "canonical ABI gate target";
        needle = ''
          gate: "gate:abi-conformance",
                  package: "crucible",
                  test_target: "ninep_wire_abi",
                  required_features: &["test-double"],
                  placeholder: false,'';
      }
    ]
    ++ failuresFor "tests/crucible/phase2-abi-conformance.nix" abiConformanceGate [
      {
        label = "phase2 ABI gate runs 9p wire ABI";
        needle = "--test ninep_wire_abi";
      }
      {
        label = "phase2 ABI gate checks 9p wire ABI";
        needle = "crucibleNinePWireAbiTest";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/ninep_wire_abi.rs" wireTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes 9p wire ABI check";
        needle = "ninePWireAbi = import ./phase3-ninep-wire-abi.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 9p wire ABI check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-ninep-wire-abi";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        "unpackPhase"
        "buildPhase"
        "installPhase"
      ];

      buildPhase = ''
        runHook preBuild

        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"

        export CARGO_HOME="$TMPDIR/cargo-home"
        mkdir -p "$CARGO_HOME"
        ln -s ${cargoDeps} "$CARGO_HOME/vendor"

        cat > "$CARGO_HOME/config.toml" <<'CONFIG'
        [source.crates-io]
        replace-with = "vendored-sources"

        [source.vendored-sources]
        directory = "__CARGO_VENDOR__"

        [net]
        offline = true
        CONFIG
        ${pkgs.sed}/bin/sed -i "s#__CARGO_VENDOR__#${cargoDeps}#g" "$CARGO_HOME/config.toml"

        cd crates
        ${pkgs.rust}/bin/cargo test --offline -p crucible --features test-double --test ninep_wire_abi -- --test-threads=1

        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        cat > "$out/result.txt" <<EOF
        ${attrPath}: ${taskList}
        EOF
        runHook postInstall
      '';
    }
