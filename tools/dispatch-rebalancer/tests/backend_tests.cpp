#include "dispatch/backend.h"

#include <folly/init/Init.h>
#include <folly/logging/Init.h>

#include <array>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {

using dispatch::backend::Json;
namespace wire = dispatch::backend::wire;

void require(bool condition, const char* detail) {
  if (!condition) {
    throw std::runtime_error(detail);
  }
}

Json rational(int value) {
  return Json{{"numerator", std::to_string(value)}, {"denominator", "1"}};
}

void add_tier(Json& problem, const std::string& id, const Json& metric) {
  const Json term{{"id", id + "_term"}, {"direction", "minimize"},
                  {"weight", rational(1)}, {"normalizer", rational(1)}, {"metric", metric}};
  problem["objectives"].push_back(Json{{"id", id}, {"terms", Json::array({term})}});
}

Json fixture() {
  const Json dimension{{"unit", "bytes"}, {"quantum", "1"}};
  const Json target{{"capacities", {{"bytes", {{"kind", "finite"}, {"limit", "4"}}}}},
                    {"fixed_load", {{"bytes", "0"}}}};
  const Json item{{"domain", "hosts"}, {"deferrable", false},
                  {"demands", {{"bytes", {{"default", "2"}, {"overrides", Json::object()}}}}}};
  const Json observed{{"binding", {{"kind", "target"}, {"target", "a"}}},
                      {"charges", {{"bytes", "2"}}}};
  const Json costs{{"default", rational(1)}, {"targets", {{"b", rational(0)}}},
                   {"deferred", rational(0)}};
  Json problem{{"model_version", "1"}, {"observation_basis", Json::object()},
               {"items", {{"first", item}, {"second", item}}},
               {"targets", {{"a", target}, {"b", target}}},
               {"dimensions", {{"bytes", dimension}}}, {"domains", {{"hosts", {"a", "b"}}}},
               {"groups", {{"all", {"first", "second"}}}},
               {"target_sets", {{"a", {"a"}}, {"b", {"b"}}, {"all", {"a", "b"}}}},
               {"scope_families", {{"hosts", {{"a", {"a"}}, {"b", {"b"}}}}}},
               {"observed", {{"first", observed}, {"second", observed}}},
               {"holdings", Json::array()}, {"constraints", Json::array()},
               {"objectives", Json::array()}};
  for (const auto* target_id : {"a", "b"}) {
    problem["constraints"].push_back(
        {{"id", std::string("capacity_") + target_id}, {"enforcement", "hard"},
         {"rule", {{"kind", "capacity"}, {"target_set", target_id}, {"dimension", "bytes"},
                   {"phase", "final"}, {"limit", "4"}}}});
  }
  problem["objectives"].push_back(
      {{"id", "prefer_b"},
       {"terms", {{{"id", "cost"}, {"direction", "minimize"}, {"weight", rational(1)},
                   {"normalizer", rational(1)},
                   {"metric", {{"kind", "assignment_cost"},
                               {"costs", {{"first", costs}, {"second", costs}}}}}}}}});
  return problem;
}

wire::SolveOptions options(wire::SearchMode mode) {
  wire::SolveOptions value;
  value.set_mode(mode);
  value.set_threads(1);
  value.set_wall_time_millis(5000);
  return value;
}

void native_search_assigns_items() {
  auto problem = fixture();
  const Json movement_costs{{"default", rational(2)}, {"targets", Json::object()},
                            {"deferred", rational(1)}};
  const Json policy{{"unit", "bytes"}, {"categories", {"relocation", "retirement"}},
                    {"costs", {{"first", movement_costs}, {"second", movement_costs}}}};
  add_tier(problem, "physical_movement",
           Json{{"kind", "movement_cost"}, {"items", {"first", "second"}}, {"costs", policy}});
  const auto model = dispatch::backend::parse_model(problem.dump());
  for (const auto mode : {wire::SEARCH_MODE_LOCAL_SEARCH, wire::SEARCH_MODE_MIP}) {
    const auto result = dispatch::backend::solve_model(model, options(mode), "", "conformance");
    require(result.evidence == wire::EVIDENCE_KIND_NONE, "native result must not claim exact search evidence");
    require(result.assignment.at("bindings").size() == 2, "native result must cover all items");
    for (const auto& binding : result.assignment.at("bindings")) {
      require(binding.at("kind") == "target" && binding.at("target") == "b",
              "native engine must improve the declared assignment cost");
    }
  }
}

void rejects_unit_ambiguous_native_comparisons() {
  auto problem = fixture();
  problem["constraints"][0]["rule"]["limit"] = "2251799813685248";
  const auto model = dispatch::backend::parse_model(problem.dump());

  try {
    dispatch::backend::solve_model(model, options(wire::SEARCH_MODE_LOCAL_SEARCH), "", "comparison_guard");
    throw std::runtime_error("native comparison outside precision profile was accepted");
  } catch (const dispatch::backend::Error& error) {
    require(error.code() == wire::ERROR_CODE_UNSUPPORTED_MODEL,
            "precision-profile rejection must remain distinct from infeasibility");
  }
}

void immutable_overlap_charges_bound_placement() {
  auto problem = fixture();
  problem["observed"]["first"]["charges"]["bytes"] = "3";
  problem["observed"]["second"]["charges"]["bytes"] = "3";
  problem["constraints"].push_back(
      {{"id", "overlap"}, {"enforcement", "hard"},
       {"rule", {{"kind", "capacity"}, {"target_set", "all"}, {"dimension", "bytes"},
                 {"phase", "overlap"}, {"limit", "6"}}}});
  const auto model = dispatch::backend::parse_model(problem.dump());
  for (const auto mode : {wire::SEARCH_MODE_LOCAL_SEARCH, wire::SEARCH_MODE_MIP}) {
    const auto result = dispatch::backend::solve_model(model, options(mode), "", "overlap_conformance");
    for (const auto& binding : result.assignment.at("bindings")) {
      require(binding.at("target") == "a", "overlap must retain immutable source charges while charging a destination");
    }
  }
}

void topology_and_utilization_use_zero_weight_anchors() {
  auto problem = fixture();
  problem["objectives"] = Json::array();
  const Json members = Json::array({
      Json{{"id", "a"}, {"target_set", "a"}, {"dimension", "bytes"}, {"phase", "final"}, {"capacity", "4"}},
      Json{{"id", "b"}, {"target_set", "b"}, {"dimension", "bytes"}, {"phase", "final"}, {"capacity", "4"}}});
  add_tier(problem, "balance", Json{{"kind", "maximum_utilization"}, {"members", members}});
  problem["constraints"].push_back(
      {{"id", "spread"}, {"enforcement", "hard"},
       {"rule", {{"kind", "spread"}, {"group", "all"}, {"family", "hosts"},
                 {"minimum", "2"}, {"maximum_per_member", "1"}, {"when_admitted", false}}}});
  const auto model = dispatch::backend::parse_model(problem.dump());
  for (const auto mode : {wire::SEARCH_MODE_LOCAL_SEARCH, wire::SEARCH_MODE_MIP}) {
    const auto result = dispatch::backend::solve_model(model, options(mode), "", "topology_conformance");
    require(result.assignment.at("bindings").at("first").at("target") !=
                result.assignment.at("bindings").at("second").at("target"),
            "topology must count actual group items rather than accounting anchors");
  }

  auto seeded = options(wire::SEARCH_MODE_MIP);
  seeded.set_threads(2);
  seeded.set_seed(17);
  require(dispatch::backend::solve_model(model, seeded, "", "changed_threads").assignment.at("bindings").size() == 2,
          "warm native MIP must accept changed threads and an explicit seed");
}

void utilization_extremes_balance_load_in_both_search_modes() {
  const Json members = Json::array({
      Json{{"id", "a"}, {"target_set", "a"}, {"dimension", "bytes"}, {"phase", "final"}, {"capacity", "4"}},
      Json{{"id", "b"}, {"target_set", "b"}, {"dimension", "bytes"}, {"phase", "final"}, {"capacity", "4"}}});
  for (const auto* kind : {"maximum_utilization", "utilization_range"}) {
    auto problem = fixture();
    problem["objectives"] = Json::array();
    add_tier(problem, "balance", Json{{"kind", kind}, {"members", members}});
    const auto model = dispatch::backend::parse_model(problem.dump());

    for (const auto mode : {wire::SEARCH_MODE_LOCAL_SEARCH, wire::SEARCH_MODE_MIP}) {
      const auto result = dispatch::backend::solve_model(model, options(mode), "", "utilization_extremes");
      require(result.assignment.at("bindings").at("first").at("target") !=
                  result.assignment.at("bindings").at("second").at("target"),
              "utilization objective must attain peak one-half or range zero without a spread constraint");
    }
  }
}

void empty_conditional_spread_has_no_minimum_debt() {
  auto problem = fixture();
  problem["groups"]["empty"] = Json::array();
  problem["constraints"].push_back(
      {{"id", "empty_spread"}, {"enforcement", "repair"},
       {"rule", {{"kind", "spread"}, {"group", "empty"}, {"family", "hosts"},
                 {"minimum", "2"}, {"maximum_per_member", nullptr}, {"when_admitted", true}}}});
  const Json components = Json::array({Json{{"constraint", "empty_spread"}, {"component", "minimum"}}});
  add_tier(problem, "empty_debt", Json{{"kind", "repair_debt"}, {"components", components}});
  const auto model = dispatch::backend::parse_model(problem.dump());
  require(dispatch::backend::solve_model(model, options(wire::SEARCH_MODE_MIP), "", "empty_spread")
              .assignment.at("bindings").size() == 2,
          "empty conditional group must not create a positive minimum constraint or debt");
}

void rejects_lossy_numeric_compilation() {
  auto problem = fixture();
  problem["items"]["first"]["demands"]["bytes"]["default"] = "9007199254740992";
  bool rejected = false;
  try {
    dispatch::backend::parse_model(problem.dump());
  } catch (const dispatch::backend::Error& error) {
    rejected = error.code() == wire::ERROR_CODE_UNSUPPORTED_MODEL;
  }
  require(rejected, "quantities outside exact binary64 range must be rejected");

  problem = fixture();
  problem["objectives"][0]["terms"][0]["metric"] =
      Json{{"kind", "unknown_objective"}, {"items", {"first", "second"}}};
  rejected = false;
  try {
    dispatch::backend::check_model_support(dispatch::backend::parse_model(problem.dump()));
  } catch (const dispatch::backend::Error& error) {
    rejected = error.code() == wire::ERROR_CODE_UNSUPPORTED_MODEL;
  }
  require(rejected, "unsupported metrics must be rejected rather than replaced by a surrogate");
}

void portable_names_and_reduced_rationals_are_distinct() {
  auto problem = fixture();
  problem["observation_basis"] = Json{{"capacity", "revision-v1"}, {"numerator", "observation-v2"}};
  dispatch::backend::check_model_support(dispatch::backend::parse_model(problem.dump()));

  problem["objectives"][0]["terms"][0]["weight"] =
      Json{{"numerator", "2"}, {"denominator", "2"}};
  bool rejected = false;
  try {
    dispatch::backend::check_model_support(dispatch::backend::parse_model(problem.dump()));
  } catch (const dispatch::backend::Error& error) {
    rejected = error.code() == wire::ERROR_CODE_UNSUPPORTED_MODEL;
  }
  require(rejected, "portable rational pairs must already be reduced");

  rejected = false;
  try {
    dispatch::backend::parse_model("{\"model_version\":\"1\",\"model_version\":\"1\"}");
  } catch (const dispatch::backend::Error& error) {
    rejected = error.code() == wire::ERROR_CODE_UNSUPPORTED_MODEL;
  }
  require(rejected, "duplicate JSON fields must fail closed");
}

void protobuf_serialization_matches_cross_language_vector() {
  wire::WorkerEnvelope hello;
  hello.mutable_protocol_version()->set_major(1);
  hello.set_session_generation(1);
  hello.set_worker_generation(2);
  hello.set_request_id(3);
  hello.mutable_hello();
  const std::string expected("\x0a\x02\x08\x01\x10\x01\x18\x02\x20\x03\x52\x00", 12);
  require(hello.SerializeAsString() == expected, "native protobuf must match the published cross-language vector");
}

void append_frame(std::ostream& stream, const wire::WorkerEnvelope& envelope) {
  const auto bytes = envelope.SerializeAsString();
  const auto length = static_cast<std::uint32_t>(bytes.size());
  const std::array<char, 4> header{static_cast<char>(length >> 24), static_cast<char>(length >> 16),
                                   static_cast<char>(length >> 8), static_cast<char>(length)};
  stream.write(header.data(), header.size());
  stream.write(bytes.data(), bytes.size());
}

wire::WorkerEnvelope read_response(std::istream& stream) {
  std::array<unsigned char, 4> header{};
  stream.read(reinterpret_cast<char*>(header.data()), header.size());
  require(stream.gcount() == 4, "worker response header is missing");
  const std::uint32_t length = (std::uint32_t{header[0]} << 24) |
                               (std::uint32_t{header[1]} << 16) |
                               (std::uint32_t{header[2]} << 8) | header[3];
  std::string payload(length, '\0');
  stream.read(payload.data(), payload.size());
  wire::WorkerEnvelope result;
  require(result.ParseFromString(payload), "worker response protobuf is invalid");
  return result;
}

wire::WorkerEnvelope envelope(std::uint64_t request_id) {
  wire::WorkerEnvelope result;
  result.mutable_protocol_version()->set_major(1);
  result.set_session_generation(7);
  result.set_worker_generation(11);
  result.set_request_id(request_id);
  return result;
}

void prepared_inputs_and_replay_are_session_bound() {
  std::stringstream requests;
  auto hello = envelope(1);
  hello.mutable_hello()->add_protocol_versions()->set_major(1);
  hello.mutable_hello()->add_model_versions()->set_major(1);
  *hello.mutable_hello()->mutable_limits() = dispatch::backend::capabilities().limits();
  append_frame(requests, hello);

  auto prepare = envelope(2);
  prepare.mutable_prepare()->set_problem_json(fixture().dump());
  prepare.mutable_prepare()->set_model_digest(std::string(32, 'm'));
  append_frame(requests, prepare);

  auto solve = envelope(3);
  solve.mutable_solve()->set_prepared_handle("11:1");
  solve.mutable_solve()->set_model_digest(std::string(32, 'm'));
  solve.mutable_solve()->set_request_digest(std::string(32, 'r'));
  *solve.mutable_solve()->mutable_options() = options(wire::SEARCH_MODE_LOCAL_SEARCH);
  append_frame(requests, solve);
  append_frame(requests, solve);

  auto release = envelope(4);
  release.mutable_release()->set_handle("11:1");
  append_frame(requests, release);
  solve.set_request_id(5);
  append_frame(requests, solve);

  std::stringstream responses;
  require(dispatch::backend::run_worker(requests, responses) == 0, "warm worker failed");
  require(read_response(responses).has_capabilities(), "Hello must negotiate capabilities");
  require(read_response(responses).prepared().handle() == "11:1", "prepared handle must bind worker generation");
  require(read_response(responses).has_finished(), "prepared native solve must finish");
  require(read_response(responses).error().code() == wire::ERROR_CODE_INVALID_MESSAGE, "replayed id must fail closed");
  require(read_response(responses).has_released(), "prepared model must be releasable");
  require(read_response(responses).error().code() == wire::ERROR_CODE_STALE_HANDLE, "released prepared handle must be stale");
}

}  // namespace

int main(int argc, char** argv) {
  folly::Init initialize(&argc, &argv);
  folly::initLoggingOrDie("ERR");
  try {
    rejects_lossy_numeric_compilation();
    portable_names_and_reduced_rationals_are_distinct();
    protobuf_serialization_matches_cross_language_vector();
    rejects_unit_ambiguous_native_comparisons();
    native_search_assigns_items();
    immutable_overlap_charges_bound_placement();
    topology_and_utilization_use_zero_weight_anchors();
    utilization_extremes_balance_load_in_both_search_modes();
    empty_conditional_spread_has_no_minimum_debt();
    prepared_inputs_and_replay_are_session_bound();
    std::cout << "native backend conformance passed\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
