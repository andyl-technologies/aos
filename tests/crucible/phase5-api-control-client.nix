{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiControlClient",
  taskIds ? ["T-API-1"],
  dependencies ? [],
}: let
  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiCargo = builtins.readFile ../../crates/crucible-api/Cargo.toml;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  rpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  apiGateTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-1 checked off";
        needle = "- [x] **T-API-1**";
      }
      {
        label = "T-API-1 completion note";
        needle = "Completed by `checks.crucible.phase5.apiControlClient`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API control-client status note";
        needle = "`T-API-1` is green through `checks.crucible.phase5.apiControlClient`";
      }
    ]
    ++ failuresFor "crates/crucible-api/Cargo.toml" apiCargo [
      {
        label = "reqwest HTTP/2 client dependency";
        needle = ''reqwest = { workspace = true, features = ["http2"] }'';
      }
      {
        label = "axum HTTP/2 gate dependency";
        needle = "axum = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "client module exported";
        needle = "pub mod client";
      }
      {
        label = "ControlClient re-export";
        needle = "ControlClient";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" rpcAbi [
      {
        label = "typed hello request encoder";
        needle = "pub fn encode_rpc_hello_request";
      }
      {
        label = "typed hello response encoder";
        needle = "pub fn encode_rpc_hello_response";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "async typed client trait";
        needle = "pub trait ControlClient";
      }
      {
        label = "boxed async client future";
        needle = "ControlClientFuture";
      }
      {
        label = "same-process client";
        needle = "pub struct InProcessControlClient";
      }
      {
        label = "same-process actor mailbox";
        needle = "mpsc::Sender<SessionCommand>";
      }
      {
        label = "same-process live mirror";
        needle = "Arc<LiveSnapshot>";
      }
      {
        label = "no serialization marker";
        needle = "reaches_same_process_actor_without_serialization";
      }
      {
        label = "HTTP/2 RPC client";
        needle = "pub struct RpcControlClient";
      }
      {
        label = "HTTP/2 endpoint";
        needle = "RpcTransportProtocol::Http2";
      }
      {
        label = "shared wire model";
        needle = "pub struct ControlWireModel";
      }
      {
        label = "shared wire-model assertion";
        needle = "assert_shared_wire_model";
      }
      {
        label = "typed request wire encoder";
        needle = "encode_rpc_hello_request(&request.client_name, request.version)";
      }
      {
        label = "typed response wire encoder";
        needle = "encode_rpc_hello_response(";
      }
      {
        label = "HTTP/2 client builder";
        needle = ".http2_prior_knowledge()";
      }
      {
        label = "HTTP/2 hello RPC path";
        needle = ".post(self.endpoint.rpc_url(HELLO_RPC_PATH))";
      }
      {
        label = "HTTP/2 RPC content type";
        needle = ".header(reqwest::header::CONTENT_TYPE, RPC_CONTENT_TYPE)";
      }
      {
        label = "HTTP/2 response decoder";
        needle = "decode_hello_response(&body, self.transport())";
      }
      {
        label = "hello negotiates RPC protocol";
        needle = "negotiate_rpc_protocol(request.version)";
      }
      {
        label = "HTTP/2 request error";
        needle = "HttpRequest";
      }
      {
        label = "HTTP/2 status error";
        needle = "HttpStatus";
      }
      {
        label = "RPC decode error";
        needle = "RpcDecode";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" apiGateTest [
      {
        label = "trait transport-agnostic test";
        needle = "control_client_trait_is_transport_agnostic_over_in_process_and_rpc";
      }
      {
        label = "in-process client constructed";
        needle = "InProcessControlClient::new";
      }
      {
        label = "HTTP/2 RPC endpoint constructed";
        needle = "RpcEndpoint::http2";
      }
      {
        label = "shared wire model asserted";
        needle = "assert_shared_wire_model";
      }
      {
        label = "typed hello request encoder asserted";
        needle = ''encode_rpc_hello_request("api-control-client-test"'';
      }
      {
        label = "typed hello response encoder asserted";
        needle = "encode_rpc_hello_response(";
      }
      {
        label = "local HTTP/2 server fixture";
        needle = "spawn_http2_hello_server";
      }
      {
        label = "HTTP/2 request observed";
        needle = "Version::HTTP_2";
      }
      {
        label = "HTTP/2 route";
        needle = ''"/crucible.rpc/hello"'';
      }
      {
        label = "HTTP/2 assertion";
        needle = "saw_http2_request";
      }
      {
        label = "major mismatch on both transports";
        needle = "control_client_rejects_rpc_major_version_mismatch_on_both_transports";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API control-client check";
        needle = "apiControlClient = import ./phase5-api-control-client.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-control-client";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils];

    CRUCIBLE_T_API_1_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "run-phase5-api-control-client";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_1_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_1_FAILURES" >&2
            exit 1
          fi

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'control_client_trait=async_typed\n'
            printf 'in_process_transport=same_process_actor_no_serialization\n'
            printf 'rpc_transport=http2\n'
            printf 'wire_model=shared_rpc_abi_encoder\n'
          } > "$out/result"
        '';
      }
    ];
  }
