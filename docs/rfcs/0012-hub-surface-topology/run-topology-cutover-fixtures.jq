include "validate-topology-cutover";

# This JQ runner is a portable diagnostic for semantic fixtures. The Rust
# verifier remains normative because schema, signature, bundle-closure, and
# running-executable byte-identity stages require authenticated bundle bytes.

def pointer_tokens($pointer):
  if ($pointer | startswith("/")) | not then
    error("fixture pointer must be absolute")
  else
    $pointer[1:] | split("/")
    | map(gsub("~1"; "/") | gsub("~0"; "~")
          | if test("^(0|[1-9][0-9]*)$") then tonumber else . end)
  end;

def add_value($document; $tokens; $value):
  if $tokens[-1] == "-" then
    ($tokens[0:-1]) as $parent
    | $document | setpath($parent; (getpath($parent) + [$value]))
  else
    $document | setpath($tokens; $value)
  end;

def apply_mutation($document; $mutation):
  ($mutation.pointer | pointer_tokens(.)) as $tokens
  | if $mutation.operation == "add" then
      add_value($document; $tokens; $mutation.value)
    elif $mutation.operation == "replace" then
      $document | setpath($tokens; $mutation.value)
    elif $mutation.operation == "remove" then
      $document | delpaths([$tokens])
    elif $mutation.operation == "copy" then
      ($mutation.from_pointer | pointer_tokens(.)) as $source
      | add_value($document; $tokens; ($document | getpath($source)))
    else
      error("unsupported fixture operation: \($mutation.operation)")
    end;

def apply_case($base; $case):
  reduce $case.mutations[] as $mutation
    ($base;
     .[$mutation.target] =
       apply_mutation(.[$mutation.target]; $mutation));

def bundle_reference_errors($materialized):
  ($recipe[0].layout) as $entries
  | ({"schema/bundle":"bundle_schema",
      "schema/bundle-generation":"bundle_generation_schema",
      "schema/fixtures":"fixture_schema",
      "schema/plan":"plan_schema",
      "schema/report":"report_schema",
      "schema/signature-envelope":"signature_envelope_schema",
      "schema/signer-key-map":"signer_key_map_schema",
      "schema/verification":"verification_schema"}) as $schema_roles
  | ({"document/plan":"plan_payload",
      "document/report":"report_payload",
      "document/verification":"verification_payload"}) as $document_roles
  | ($materialized.plan.backup
     | map({key:.destination_artifact_node_id, value:.expected_media_type})
     | from_entries) as $backup_media
  | ([$materialized.plan, $materialized.report, $materialized.verification]
     | [.. | objects | to_entries[]?
        | select(.key | endswith("node_id"))
        | select(.value | type == "string"
                 and test("^(artifact|evidence|manifest|ruleset|schema|verifier)/"))]) as $references
  | ([ $references[] as $reference
       | ([$entries[] | select(.node_id == $reference.value)]) as $actual
       | if ($actual|length) != 1 then true
         elif $backup_media[$reference.value] != null then
           ($actual[0].kind != "evidence" or $actual[0].role != "evidence"
            or $actual[0].media_type != $backup_media[$reference.value])
         elif (($reference.key | endswith("artifact_node_id"))
               or ($reference.key | endswith("evidence_node_id"))) then
           ($actual[0].kind != "evidence" or $actual[0].role != "evidence"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "transformer_node_id" then
           ($actual[0].kind != "tool" or $actual[0].role != "tool"
            or $actual[0].media_type != "application/octet-stream")
         elif $reference.key == "source_export_node_id" then
           ($actual[0].kind != "source_export" or $actual[0].role != "source_export"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "api_manifest_node_id" then
           ($actual[0].kind != "interface_manifest" or $actual[0].role != "api_manifest"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "cli_manifest_node_id" then
           ($actual[0].kind != "interface_manifest" or $actual[0].role != "cli_manifest"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "route_manifest_node_id" then
           ($actual[0].kind != "interface_manifest" or $actual[0].role != "route_manifest"
            or $actual[0].media_type != "text/markdown")
         elif $reference.key == "verification_query_set_node_id" then
           ($actual[0].kind != "ruleset" or $actual[0].role != "ruleset"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "bundle_node_id" then
           ($actual[0].kind != "tool" or $actual[0].role != "verifier"
            or $actual[0].media_type != "application/octet-stream")
         elif $reference.key == "manifest_node_id" then
           ($actual[0].kind != "fixture_manifest" or $actual[0].role != "fixture_manifest"
            or $actual[0].media_type != "application/json")
         elif $reference.key == "metaschema_node_id" then
           ($actual[0].kind != "metaschema" or $actual[0].role != "dialect_metaschema"
            or $actual[0].media_type != "application/json")
         else false end
       | select(.) ] | length) > 0 as $invalid
  | ($materialized.verification.schema_validation.validated_schema_node_ids) as $validated_schemas
  | ([ $validated_schemas[] as $node_id
       | [$entries[] | select(.node_id == $node_id)] as $actual
       | select(($actual|length) != 1
                or $schema_roles[$node_id] == null
                or $actual[0].kind != "schema"
                or $actual[0].role != $schema_roles[$node_id]
                or $actual[0].media_type != "application/json") ] | length) > 0 as $invalid_schemas
  | ($materialized.verification.schema_validation.validated_document_node_ids) as $validated_documents
  | ([ $validated_documents[] as $node_id
       | [$entries[] | select(.node_id == $node_id)] as $actual
       | select(($actual|length) != 1
                or $document_roles[$node_id] == null
                or $actual[0].kind != "document"
                or $actual[0].role != $document_roles[$node_id]
                or $actual[0].media_type != "application/json") ] | length) > 0 as $invalid_documents
  | if ($invalid
        or $invalid_schemas
        or $invalid_documents
        or $validated_schemas != ($schema_roles | keys)
        or $validated_documents != ($document_roles | keys)) then
      [{code:"reference_contract_invalid",path:"/bundle-references"}]
    else [] end;

def fixture_count_errors($materialized):
  ($fixtures[0].cases | length) as $expected
  | if ($materialized.verification.fixture_validation.case_count == $expected
        and $materialized.verification.fixture_validation.passed_count == $expected
        and $materialized.verification.fixture_validation.failed_count == 0)
    then []
    else [{code:"verification_contract_invalid",path:"/fixture_validation"}]
    end;

def canonical_manifest_errors:
  ($fixtures[0].cases | map(.case_id)) as $case_ids
  | ($recipe[0].layout | map(.node_id)) as $layout_ids
  | ($recipe[0].edges | map([.from_node_id, .relation, .to_node_id])) as $edge_ids
  | if ($case_ids == ($case_ids | sort | unique)
        and $layout_ids == ($layout_ids | sort | unique)
        and $edge_ids == ($edge_ids | sort | unique))
    then []
    else [{code:"canonical_order_invalid",path:"/authenticated-manifests"}]
    end;

def evaluate_semantic($base; $case):
  apply_case($base; $case) as $materialized
  | (validate($materialized.plan;
              $materialized.report;
              $materialized.verification)
     + bundle_reference_errors($materialized)
     + fixture_count_errors($materialized)
     + canonical_manifest_errors) as $errors
  | {
      case_id: $case.case_id,
      evaluation_stage: $case.evaluation_stage,
      expected_result: $case.expected_result,
      expected_code: $case.expected_code,
      observed_result: (if $errors == [] then "pass" else "fail" end),
      observed_codes: [$errors[].code],
      matched:
        (if $case.expected_result == "pass" then $errors == []
         else any($errors[]; .code == $case.expected_code)
         end)
    };

{
  plan: $plan[0],
  report: $report[0],
  verification:
    ($verification[0]
     # The authenticated verifier proves this equality from actual bytes.
     # The JQ-only diagnostic has no executable byte input.
     | .verifier_identity.current_exe_sha256 =
         .verifier_identity.bundle_entry_sha256)
} as $base
| [
    $fixtures[0].cases[] as $case
    | if $case.evaluation_stage == "semantic" then
        evaluate_semantic($base; $case)
      else
        {
          case_id: $case.case_id,
          evaluation_stage: $case.evaluation_stage,
          expected_result: $case.expected_result,
          expected_code: $case.expected_code,
          observed_result: "delegated",
          observed_codes: [],
          matched: true
        }
      end
  ]
