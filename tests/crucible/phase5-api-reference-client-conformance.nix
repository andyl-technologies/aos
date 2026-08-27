{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiReferenceClientConformance",
  taskIds ? ["T-API-13"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiCargo = builtins.readFile ../../crates/crucible-api/Cargo.toml;
  controlClientTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/tests/gate_control_client.rs;
  };
  abiTest = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  qemuNode = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu/src/node.rs)
    (import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible-qemu/src/node_tests.rs;
    })
  ];
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-13 completion note";
        needle = "Completed by `checks.crucible.phase5.apiReferenceClientConformance`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API reference client status note";
        needle = "`T-API-13` is green through";
      }
    ]
    ++ failuresFor "crates/crucible-api/Cargo.toml" apiCargo [
      {
        label = "QEMU backend contract dev dependency";
        needle = ''crucible-qemu = { path = "../crucible-qemu" }'';
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client*.rs" controlClientTest [
      {
        label = "reference client conformance test";
        needle = "reference_client_conformance_drives_full_lifecycle_across_transports_with_simdouble_backend";
      }
      {
        label = "RPC wire contract snapshots";
        needle = "rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants";
      }
      {
        label = "reference conformance driver";
        needle = "run_reference_client_conformance";
      }
      {
        label = "in-process lifecycle reference client";
        needle = "InProcessLifecycleClient";
      }
      {
        label = "HTTP/2 RPC reference client";
        needle = "RpcControlClient";
      }
      {
        label = "control attach stream path";
        needle = "ClientControlStream";
      }
      {
        label = "watch attach stream path";
        needle = "ClientWatchStream";
      }
      {
        label = "SimDouble backend lane";
        needle = "ReferenceSimDoubleLoop";
      }
      {
        label = "SimDouble backend stepping";
        needle = "SimulationBackend::step_to(&mut self.backend";
      }
      {
        label = "QEMU backend trait assertion";
        needle = "assert_qemu_node_implements_simulation_backend_contract";
      }
      {
        label = "QemuNode implements SimulationBackend";
        needle = "assert_qemu_node_implements_simulation_backend_contract";
      }
      {
        label = "scenario-ref create session";
        needle = "CreateSessionRequest::scenario_ref";
      }
      {
        label = "inline create session";
        needle = "CreateSessionRequest::inline";
      }
      {
        label = "destroy session coverage";
        needle = "DestroySessionRequest::new";
      }
      {
        label = "GetReproduction coverage";
        needle = "GetReproductionRequest::new";
      }
      {
        label = "epoch guard rejection";
        needle = "epoch-guard-rejection";
      }
      {
        label = "set breakpoint lifecycle command";
        needle = "SessionCommandKind::SetBreakpoint";
      }
      {
        label = "remove breakpoint lifecycle command";
        needle = "SessionCommandKind::RemoveBreakpoint";
      }
      {
        label = "savepoint lifecycle command";
        needle = "SessionCommandKind::CreateSavepoint";
      }
      {
        label = "fork lifecycle command";
        needle = "SessionCommandKind::Fork";
      }
      {
        label = "query lifecycle command";
        needle = "SessionCommandKind::Query";
      }
      {
        label = "transport equivalence assertion";
        needle = "assert_reference_conformance_equivalent";
      }
      {
        label = "hello response wire snapshot";
        needle = "hello-response";
      }
      {
        label = "list scenarios wire snapshot";
        needle = "list-scenarios-request";
      }
      {
        label = "attach request wire snapshot";
        needle = "attach-request";
      }
      {
        label = "send request wire snapshot";
        needle = "send-request";
      }
      {
        label = "get reproduction response wire snapshot";
        needle = "get-reproduction-response";
      }
      {
        label = "scenario-ref create wire snapshot";
        needle = "create-session-ref-request";
      }
      {
        label = "inline create wire snapshot";
        needle = "create-session-inline-request";
      }
      {
        label = "list sessions wire snapshot";
        needle = "list-sessions-response";
      }
      {
        label = "destroy wire snapshot";
        needle = "destroy-session-response";
      }
      {
        label = "attach wire snapshot";
        needle = "attached-response";
      }
      {
        label = "accepted send response wire snapshot";
        needle = "send-response-accepted";
      }
      {
        label = "rejected send response wire snapshot";
        needle = "send-response-rejected";
      }
      {
        label = "event frame wire snapshot";
        needle = "event-frame";
      }
      {
        label = "state update frame wire snapshot";
        needle = "state-update-frame";
      }
      {
        label = "typed RPC error wire snapshot";
        needle = "rpc-error";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" abiTest [
      {
        label = "contract snapshot covers HelloRequest";
        needle = "saw_hello_request";
      }
      {
        label = "contract snapshot covers HelloResponse";
        needle = "saw_hello_response";
      }
      {
        label = "contract snapshot covers Attached";
        needle = "saw_attached";
      }
      {
        label = "contract snapshot covers AttachedWithReproduction";
        needle = "saw_attached_with_reproduction";
      }
      {
        label = "contract snapshot covers GetReproductionRequest";
        needle = "saw_get_reproduction_request";
      }
      {
        label = "contract snapshot covers GetReproductionResponse";
        needle = "saw_get_reproduction_response";
      }
      {
        label = "contract snapshot covers CommandRequest";
        needle = "saw_command_request";
      }
      {
        label = "contract snapshot covers CommandResponse";
        needle = "saw_command_response";
      }
      {
        label = "contract snapshot covers RpcError";
        needle = "saw_rpc_error";
      }
      {
        label = "contract snapshot covers Event";
        needle = "saw_event";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "QemuNode SimulationBackend focused test";
        needle = "qemu_node_satisfies_simulation_backend_trait";
      }
      {
        label = "QemuNode backend step_to coverage";
        needle = "SimulationBackend::step_to(&mut node";
      }
      {
        label = "QemuNode backend apply coverage";
        needle = "SimulationBackend::apply(";
      }
      {
        label = "QemuNode backend snapshot coverage";
        needle = "SimulationBackend::snapshot(&mut node)";
      }
      {
        label = "QemuNode backend restore coverage";
        needle = "SimulationBackend::restore(";
      }
      {
        label = "QemuNode backend shutdown coverage";
        needle = "SimulationBackend::shutdown(&mut node)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API reference client conformance check";
        needle = "apiReferenceClientConformance = import ./phase5-api-reference-client-conformance.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-reference-client-conformance";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_13_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-phase5-api-reference-client-conformance";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_13_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_13_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_control_client \
            -- --list \
            > "$TMPDIR/reference-client-tests.list"
          grep -Fxq \
            'contract_tests::transport_conformance::reference_client_conformance_drives_full_lifecycle_across_transports_with_simdouble_backend: test' \
            "$TMPDIR/reference-client-tests.list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_control_client \
            contract_tests::transport_conformance::reference_client_conformance_drives_full_lifecycle_across_transports_with_simdouble_backend \
            -- --exact --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_control_client \
            -- --list \
            > "$TMPDIR/reference-client-tests.list"
          grep -Fxq \
            'contract_tests::rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants: test' \
            "$TMPDIR/reference-client-tests.list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_control_client \
            contract_tests::rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants \
            -- --exact --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_abi_conformance \
            -- --list \
            > "$TMPDIR/abi-conformance-tests.list"
          grep -Fxq \
            'rpc_golden_vectors_cover_requests_responses_events_and_payload_kinds: test' \
            "$TMPDIR/abi-conformance-tests.list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-api \
            --test gate_abi_conformance \
            rpc_golden_vectors_cover_requests_responses_events_and_payload_kinds \
            -- --exact --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-qemu \
            --lib \
            -- --list \
            > "$TMPDIR/qemu-library-tests.list"
          grep -Fxq \
            'node::tests::exact_lifecycle::qemu_node_satisfies_simulation_backend_trait: test' \
            "$TMPDIR/qemu-library-tests.list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-reference-client-conformance-target" \
            -p crucible-qemu \
            node::tests::exact_lifecycle::qemu_node_satisfies_simulation_backend_trait \
            -- --exact --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 API reference client conformance gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
