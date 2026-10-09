#include "dispatch/backend.h"
#include "dispatch/numbers.h"

#include <algorithm>
#include <set>

namespace dispatch::backend {
namespace {

[[noreturn]] void unsupported(const std::string& detail) {
  throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, detail);
}

void require_fields(const Json& object, std::initializer_list<const char*> fields) {
  if (!object.is_object() || object.size() != fields.size()) {
    unsupported("model object has missing or unknown fields");
  }
  for (const auto* field : fields) {
    if (!object.contains(field)) {
      unsupported(std::string("missing model field: ") + field);
    }
  }
}

void reference(const Json& definitions, const std::string& id, const char* kind) {
  if (!definitions.contains(id)) {
    unsupported(std::string("unknown ") + kind + ": " + id);
  }
}

void references(const Json& definitions, const Json& values, const char* kind) {
  if (!values.is_array()) {
    unsupported(std::string(kind) + " selection must be an array");
  }
  std::set<std::string> seen;
  for (const auto& value : values) {
    const auto id = value.get<std::string>();
    reference(definitions, id, kind);
    if (!seen.insert(id).second) {
      unsupported(std::string("duplicate ") + kind + " selection");
    }
  }
}

void check_assignment_costs(const Model& model, const std::string& id, const Json& costs,
                             const std::set<std::string>* categories = nullptr) {
  reference(model.source.at("items"), id, "cost item");
  require_fields(costs, {"default", "targets", "deferred"});
  const auto check = [&](const Json& value) {
    const auto number = rational(value);
    if (categories != nullptr && number.numerator < 0) {
      unsupported("physical movement costs must be nonnegative");
    }
  };
  if (!costs.at("default").is_null()) {
    check(costs.at("default"));
  }
  check(costs.at("deferred"));
  for (const auto& [target, value] : costs.at("targets").items()) {
    reference(model.source.at("targets"), target, "cost target");
    check(value);
  }
  const auto& item = model.items.at(model.item_indices.at(id));
  for (const auto& target : item.eligible) {
    const bool charged = categories == nullptr ||
                         (item.observed_target.empty() && categories->contains("new_placement")) ||
                         (!item.observed_target.empty() && item.observed_target != target &&
                          categories->contains("relocation"));
    if (charged && costs.at("default").is_null() && !costs.at("targets").contains(target)) {
      unsupported("eligible charged destination lacks an explicit cost");
    }
  }
}

void check_movement_costs(const Model& model, const Json& items, const Json& policy) {
  require_fields(policy, {"unit", "categories", "costs"});
  if (!policy.at("unit").is_string()) {
    unsupported("movement policy needs an explicit cost unit");
  }
  std::set<std::string> categories;
  for (const auto& value : policy.at("categories")) {
    const auto category = value.get<std::string>();
    if ((category != "new_placement" && category != "relocation" && category != "retirement") ||
        !categories.insert(category).second) {
      unsupported("movement categories must be known and unique");
    }
  }
  const auto selected = items.get<std::set<std::string>>();
  if (selected.size() != policy.at("costs").size()) {
    unsupported("movement cost table must cover exactly the selected items");
  }
  for (const auto& id : selected) {
    reference(policy.at("costs"), id, "movement cost entry");
    check_assignment_costs(model, id, policy.at("costs").at(id), &categories);
  }
}

}  // namespace

Model parse_model(const std::string& source) {
  try {
    Model model;
    std::map<int, std::set<std::string>> object_keys;
    std::uint64_t decoded_bound = 0;
    model.source = Json::parse(source, [&](int depth, Json::parse_event_t event, Json& value) {
      if (depth > 32 ||
          ((event == Json::parse_event_t::object_start || event == Json::parse_event_t::array_start) &&
           depth >= 32)) {
        throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model nesting exceeds native bound");
      }
      decoded_bound += 64;
      if (value.is_string()) {
        const auto& text = value.get_ref<const std::string&>();
        if (text.size() > 4096) {
          throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model string exceeds native bound");
        }
        decoded_bound += text.size();
      }
      if (decoded_bound > 128 * 1024 * 1024) {
        throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model decoded size exceeds native bound");
      }
      if (event == Json::parse_event_t::object_start) {
        object_keys[depth].clear();
      } else if (event == Json::parse_event_t::key &&
                 !object_keys[depth - 1].insert(value.get<std::string>()).second) {
        unsupported("duplicate JSON model field");
      } else if (event == Json::parse_event_t::object_end) {
        object_keys.erase(depth);
      }
      return true;
    });
    const auto& problem = model.source;
    require_fields(problem, {"model_version", "observation_basis", "items", "targets",
                             "dimensions", "domains", "groups", "target_sets",
                             "scope_families", "observed", "holdings", "constraints",
                             "objectives"});
    if (problem.at("model_version") != "1") {
      unsupported("unsupported semantic model version");
    }
    for (const auto* field : {"observation_basis", "items", "targets", "dimensions",
                              "domains", "groups", "target_sets", "scope_families", "observed"}) {
      if (!problem.at(field).is_object()) {
        unsupported(std::string(field) + " must be an object");
      }
    }
    for (const auto* field : {"holdings", "constraints", "objectives"}) {
      if (!problem.at(field).is_array()) {
        unsupported(std::string(field) + " must be an array");
      }
    }
    for (const auto& revision : problem.at("observation_basis")) {
      if (!revision.is_string()) {
        unsupported("observation revisions must be opaque strings");
      }
    }
    for (const auto& [dimension, definition] : problem.at("dimensions").items()) {
      require_fields(definition, {"unit", "quantum"});
      exact_double(decimal(definition.at("quantum")));
      if (decimal(definition.at("quantum")) == 0 || !definition.at("unit").is_string()) {
        unsupported("dimension needs a positive quantum and explicit unit");
      }
    }

    for (const auto& [id, target] : problem.at("targets").items()) {
      require_fields(target, {"capacities", "fixed_load"});
      if (target.at("capacities").size() != problem.at("dimensions").size() ||
          target.at("fixed_load").size() != problem.at("dimensions").size()) {
        unsupported("target accounting must cover exactly every dimension");
      }
      for (const auto& [dimension, capacity] : target.at("capacities").items()) {
        reference(problem.at("dimensions"), dimension, "capacity dimension");
        if (capacity.at("kind") == "finite") {
          require_fields(capacity, {"kind", "limit"});
          exact_double(decimal(capacity.at("limit")));
        } else if (capacity.at("kind") == "unbounded") {
          require_fields(capacity, {"kind"});
        } else {
          unsupported("unknown declared capacity kind");
        }
      }
      model.target_indices.emplace(id, model.targets.size());
      model.targets.push_back(id);
      for (const auto& [dimension, value] : target.at("fixed_load").items()) {
        reference(problem.at("dimensions"), dimension, "dimension");
        exact_double(decimal(value));
      }
    }
    for (const auto& [id, domain] : problem.at("domains").items()) {
      references(problem.at("targets"), domain, "target");
    }
    for (const auto& [id, item] : problem.at("items").items()) {
      require_fields(item, {"domain", "deferrable", "demands"});
      const auto domain = item.at("domain").get<std::string>();
      reference(problem.at("domains"), domain, "domain");
      if (!item.at("deferrable").is_boolean()) {
        unsupported("deferrable must be a boolean");
      }
      Item parsed{id, item.at("deferrable").get<bool>(),
                  problem.at("domains").at(domain).get<std::vector<std::string>>(), ""};
      reference(problem.at("observed"), id, "observation");
      const auto& observation = problem.at("observed").at(id);
      require_fields(observation, {"binding", "charges"});
      if (item.at("demands").size() != problem.at("dimensions").size() ||
          observation.at("charges").size() != problem.at("dimensions").size()) {
        unsupported("item accounting must cover exactly every dimension");
      }
      const auto& binding = observation.at("binding");
      if (binding.at("kind") == "target") {
        require_fields(binding, {"kind", "target"});
        parsed.observed_target = binding.at("target").get<std::string>();
        reference(problem.at("targets"), parsed.observed_target, "historical target");
      } else if (binding.at("kind") == "unplaced") {
        require_fields(binding, {"kind"});
      } else {
        unsupported("unknown historical binding");
      }
      for (const auto& [dimension, definition] : problem.at("dimensions").items()) {
        reference(item.at("demands"), dimension, "item demand");
        reference(observation.at("charges"), dimension, "observed charge");
        exact_double(decimal(observation.at("charges").at(dimension)));
        if (parsed.observed_target.empty() && decimal(observation.at("charges").at(dimension)) != 0) {
          unsupported("unplaced observation cannot carry ordinary resource charges");
        }
        const auto& demand = item.at("demands").at(dimension);
        require_fields(demand, {"default", "overrides"});
        if (!demand.at("default").is_null()) {
          exact_double(decimal(demand.at("default")));
        }
        for (const auto& [target, value] : demand.at("overrides").items()) {
          reference(problem.at("targets"), target, "demand target");
          exact_double(decimal(value));
        }
        for (const auto& target : parsed.eligible) {
          if (demand.at("default").is_null() && !demand.at("overrides").contains(target)) {
            unsupported("eligible target lacks explicit resource demand");
          }
        }
      }
      model.item_indices.emplace(id, model.items.size());
      model.items.push_back(std::move(parsed));
    }
    if (problem.at("observed").size() != model.items.size()) {
      unsupported("observations must cover exactly the modeled items");
    }
    for (const auto& [id, members] : problem.at("groups").items()) {
      references(problem.at("items"), members, "item");
    }
    for (const auto& [id, members] : problem.at("target_sets").items()) {
      references(problem.at("targets"), members, "target");
    }
    for (const auto& [id, family] : problem.at("scope_families").items()) {
      std::set<std::string> seen;
      for (const auto& [member, targets] : family.items()) {
        references(problem.at("targets"), targets, "target");
        for (const auto& target : targets) {
          if (!seen.insert(target.get<std::string>()).second) {
            unsupported("scope family members overlap");
          }
        }
      }
      if (seen.size() != model.targets.size()) {
        unsupported("scope family must partition every real target");
      }
    }
    std::set<std::string> holding_ids;
    std::map<std::pair<std::string, std::string>, Integer> fragments;
    for (const auto& holding : problem.at("holdings")) {
      require_fields(holding, {"id", "target", "dimension", "quantity", "kind"});
      exact_double(decimal(holding.at("quantity")));
      const auto id = holding.at("id").get<std::string>();
      if (!holding_ids.insert(id).second) {
        unsupported("duplicate holding identifier");
      }
      const auto target = holding.at("target").get<std::string>();
      const auto dimension = holding.at("dimension").get<std::string>();
      reference(problem.at("targets"), target, "holding target");
      reference(problem.at("dimensions"), dimension, "holding dimension");
      const auto& kind = holding.at("kind");
      if (kind.at("kind") == "ordinary") {
        require_fields(kind, {"kind", "item"});
        const auto item = kind.at("item").get<std::string>();
        reference(problem.at("items"), item, "holding item");
        const auto& observed = problem.at("observed").at(item);
        if (observed.at("binding").at("kind") != "target" ||
            observed.at("binding").at("target") != target) {
          unsupported("ordinary holding must fragment its item's observed target charge");
        }
        const auto component = std::make_pair(item, dimension);
        fragments[component] += decimal(holding.at("quantity"));
        if (fragments[component] > decimal(observed.at("charges").at(dimension))) {
          unsupported("ordinary holding fragments exceed the observed charge");
        }
      } else if (kind.at("kind") == "additional") {
        require_fields(kind, {"kind", "retained_at_final"});
        if (!kind.at("retained_at_final").is_boolean()) {
          unsupported("holding retention flag must be boolean");
        }
      } else {
        unsupported("unknown holding accounting kind");
      }
    }
    for (const auto& [component, quantity] : fragments) {
      if (quantity != decimal(problem.at("observed").at(component.first).at("charges").at(component.second))) {
        unsupported("ordinary holding fragments must fully account for the observed charge");
      }
    }
    return model;
  } catch (const Error&) {
    throw;
  } catch (const Json::exception& error) {
    unsupported(std::string("invalid portable model: ") + error.what());
  }
}

static void check_model_support_impl(const Model& model) {
  if (model.items.size() > 1000000 / (model.targets.size() + 1)) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT,
                "native compilation exceeds one million item/destination coefficient entries");
  }
  static const std::set<std::string> constraint_kinds{
      "eligibility", "fixed_placement", "capacity", "admission", "atomic_admission",
      "co_location", "spread", "movement_budget"};
  static const std::set<std::string> objective_kinds{
      "admitted_count", "admitted_priority", "assignment_cost", "movement_cost",
      "used_targets", "maximum_utilization", "utilization_range", "total_absolute_deviation", "repair_debt"};
  std::set<std::string> constraint_ids;
  for (const auto& constraint : model.source.at("constraints")) {
    require_fields(constraint, {"id", "enforcement", "rule"});
    const auto id = constraint.at("id").get<std::string>();
    if (id.empty() || id.starts_with('$') || !constraint_ids.insert(id).second) {
      unsupported("constraint identifiers must be unique, nonempty, and unreserved");
    }
    const auto& rule = constraint.at("rule");
    const auto kind = rule.at("kind").get<std::string>();
    if (!constraint_kinds.contains(kind)) {
      unsupported("unsupported constraint kind: " + kind);
    }
    if (kind == "eligibility") {
      require_fields(rule, {"kind", "items", "targets"});
      references(model.source.at("items"), rule.at("items"), "eligibility item");
      references(model.source.at("targets"), rule.at("targets"), "eligibility target");
    } else if (kind == "fixed_placement") {
      require_fields(rule, {"kind", "bindings"});
      for (const auto& [item, binding] : rule.at("bindings").items()) {
        reference(model.source.at("items"), item, "fixed item");
        if (binding.at("kind") == "target") {
          require_fields(binding, {"kind", "target"});
          reference(model.source.at("targets"), binding.at("target").get<std::string>(), "fixed target");
        } else if (binding.at("kind") == "deferred") {
          require_fields(binding, {"kind"});
        } else {
          unsupported("unknown fixed binding kind");
        }
      }
    } else if (kind == "capacity") {
      require_fields(rule, {"kind", "target_set", "dimension", "phase", "limit"});
      reference(model.source.at("target_sets"), rule.at("target_set").get<std::string>(), "capacity set");
      reference(model.source.at("dimensions"), rule.at("dimension").get<std::string>(), "capacity dimension");
      if (rule.at("phase") != "final" && rule.at("phase") != "overlap") {
        unsupported("unknown accounting phase");
      }
      exact_double(decimal(rule.at("limit")));
    } else if (kind == "admission") {
      require_fields(rule, {"kind", "group", "minimum", "maximum"});
      if (decimal(rule.at("minimum")) > decimal(rule.at("maximum"))) {
        unsupported("admission minimum exceeds maximum");
      }
      exact_double(decimal(rule.at("minimum")));
      exact_double(decimal(rule.at("maximum")));
    } else if (kind == "atomic_admission") {
      require_fields(rule, {"kind", "group"});
    } else if (kind == "co_location") {
      require_fields(rule, {"kind", "group", "family"});
    } else if (kind == "spread") {
      require_fields(rule, {"kind", "group", "family", "minimum", "maximum_per_member", "when_admitted"});
      exact_double(decimal(rule.at("minimum")));
      if (!rule.at("maximum_per_member").is_null()) {
        exact_double(decimal(rule.at("maximum_per_member")));
      }
    } else if (kind == "movement_budget") {
      require_fields(rule, {"kind", "items", "costs", "limit"});
      references(model.source.at("items"), rule.at("items"), "movement item");
      check_movement_costs(model, rule.at("items"), rule.at("costs"));
      if (rational(rule.at("limit")).numerator < 0) {
        unsupported("movement ceiling must be nonnegative");
      }
    }
    if (rule.contains("group")) {
      reference(model.source.at("groups"), rule.at("group").get<std::string>(), "constraint group");
    }
    if (rule.contains("family")) {
      reference(model.source.at("scope_families"), rule.at("family").get<std::string>(), "constraint family");
    }
    const auto enforcement = constraint.at("enforcement").get<std::string>();
    if (enforcement != "hard" && enforcement != "repair") {
      unsupported("unknown enforcement policy");
    }
    if (enforcement == "repair" && kind != "capacity" && kind != "admission" &&
        kind != "spread") {
      unsupported("repair is unsupported for constraint kind: " + kind);
    }
    if (kind == "spread" && rule.at("when_admitted").get<bool>() &&
        decimal(rule.at("minimum")) != 0) {
      const auto& group = model.source.at("groups").at(rule.at("group").get<std::string>());
      for (const auto& id : group) {
        if (model.items.at(model.item_indices.at(id.get<std::string>())).deferrable) {
          unsupported("conditional spread with deferrable items is not representable by this backend");
        }
      }
    }
  }
  std::set<std::string> tier_ids;
  std::set<std::string> term_ids;
  for (const auto& tier : model.source.at("objectives")) {
    require_fields(tier, {"id", "terms"});
    if (!tier_ids.insert(tier.at("id").get<std::string>()).second) {
      unsupported("objective tier identifiers must be unique");
    }
    for (const auto& term : tier.at("terms")) {
      require_fields(term, {"id", "direction", "weight", "normalizer", "metric"});
      if (!term_ids.insert(term.at("id").get<std::string>()).second) {
        unsupported("objective term identifiers must be globally unique");
      }
      if (rational(term.at("weight")).numerator < 0 || rational(term.at("normalizer")).numerator <= 0) {
        unsupported("objective weight must be nonnegative and normalizer positive");
      }
      const auto kind = term.at("metric").at("kind").get<std::string>();
      if (!objective_kinds.contains(kind)) {
        unsupported("unsupported objective kind: " + kind);
      }
      const auto& metric = term.at("metric");
      if (kind == "admitted_count" || kind == "used_targets") {
        require_fields(metric, {"kind", "items"});
        references(model.source.at("items"), metric.at("items"), "objective item");
      } else if (kind == "admitted_priority") {
        require_fields(metric, {"kind", "priorities"});
        for (const auto& [item, priority] : metric.at("priorities").items()) {
          reference(model.source.at("items"), item, "priority item");
          if (rational(priority).numerator < 0) {
            unsupported("admission priorities must be nonnegative");
          }
        }
      } else if (kind == "assignment_cost") {
        require_fields(metric, {"kind", "costs"});
        for (const auto& [item, costs] : metric.at("costs").items()) {
          check_assignment_costs(model, item, costs);
        }
      } else if (kind == "movement_cost") {
        require_fields(metric, {"kind", "items", "costs"});
        references(model.source.at("items"), metric.at("items"), "movement objective item");
        check_movement_costs(model, metric.at("items"), metric.at("costs"));
      } else if (kind == "repair_debt") {
        require_fields(metric, {"kind", "components"});
        for (const auto& component : metric.at("components")) {
          require_fields(component, {"constraint", "component"});
        }
      } else {
        require_fields(metric, {"kind", "members"});
        for (const auto& entry : metric.at("members")) {
          const auto& member = kind == "total_absolute_deviation" ? entry.at("member") : entry;
          if (kind == "total_absolute_deviation") {
            require_fields(entry, {"member", "reference"});
            rational(entry.at("reference"));
          }
          require_fields(member, {"id", "target_set", "dimension", "phase", "capacity"});
          reference(model.source.at("target_sets"), member.at("target_set").get<std::string>(), "utilization set");
          reference(model.source.at("dimensions"), member.at("dimension").get<std::string>(), "utilization dimension");
          if (member.at("phase") != "final" && member.at("phase") != "overlap") {
            unsupported("unknown utilization accounting phase");
          }
          if (decimal(member.at("capacity")) == 0) {
            unsupported("utilization denominator must be positive");
          }
          exact_double(decimal(member.at("capacity")));
        }
      }
    }
  }
}

void check_model_support(const Model& model) {
  try {
    check_model_support_impl(model);
  } catch (const Error&) {
    throw;
  } catch (const Json::exception& error) {
    unsupported(std::string("invalid portable policy: ") + error.what());
  }
}

wire::Capabilities capabilities() {
  wire::Capabilities result;
  result.mutable_protocol_version()->set_major(1);
  result.add_model_versions()->set_major(1);
  result.set_backend_name("rebalancer");
  result.set_backend_build_id(backend_build_id());
  result.set_maximum_exact_integer(kMaximumExactInteger);
  result.add_search_modes(wire::SEARCH_MODE_LOCAL_SEARCH);
  result.add_search_modes(wire::SEARCH_MODE_MIP);
  result.set_seed_supported(true);
  for (const auto* feature : {"final_result", "prepared_input", "hard_constraints",
                             "lexicographic_objectives", "explicit_physical_movement",
                             "target_dependent_demands", "deferral", "overlap_accounting",
                             "profile.rebalancer.v1", "repair.capacity_admission_spread",
                             "spread.positive_conditional_minimum_requires_mandatory_or_empty",
                             "utilization.maximum_range_disjoint_single_dimension_phase",
                             "compilation.maximum_item_destination_pairs.1000000",
                             "compilation.maximum_nonzero_entries.4000000",
                             "objective.maximum_scaled_tier_magnitude.2251799813685247",
                             "comparison.maximum_scaled_magnitude.2251799813685247",
                             "control.seed_signed32", "control.iterations.unsupported",
                             "control.maximum_threads.128", "control.mip_minimum_wall_time_millis.1000",
                             "assignment_hint.unsupported", "prepared.portable_input_only"}) {
    result.add_capabilities(feature);
  }
  for (const auto* kind : {"eligibility", "fixed_placement", "capacity", "admission",
                          "atomic_admission", "co_location", "spread", "movement_budget"}) {
    result.add_constraint_kinds(kind);
  }
  for (const auto* kind : {"admitted_count", "admitted_priority", "assignment_cost", "movement_cost",
                          "used_targets", "maximum_utilization", "utilization_range", "total_absolute_deviation", "repair_debt"}) {
    result.add_objective_kinds(kind);
  }
  auto* limits = result.mutable_limits();
  limits->set_max_frame_bytes(kMaximumFrameBytes);
  limits->set_max_problem_bytes(12 * 1024 * 1024);
  limits->set_max_decoded_bytes(128 * 1024 * 1024);
  limits->set_max_items(100000);
  limits->set_max_targets(10000);
  limits->set_max_dimensions(128);
  limits->set_max_memberships(1000000);
  limits->set_max_domain_entries(1000000);
  limits->set_max_overrides(1000000);
  limits->set_max_constraints(10000);
  limits->set_max_objectives(10000);
  limits->set_max_nesting(32);
  limits->set_max_string_bytes(4096);
  limits->set_max_prepared(16);
  limits->set_max_prepared_bytes(64 * 1024 * 1024);
  limits->set_max_diagnostic_bytes(4096);
  return result;
}

}  // namespace dispatch::backend
