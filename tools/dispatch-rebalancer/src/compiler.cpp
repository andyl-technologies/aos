#include "dispatch/backend.h"
#include "dispatch/numbers.h"

#include <algopt/rebalancer/interface/ProblemSolverFactory.h>
#include <Highs.h>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace dispatch::backend {
namespace {

namespace native = facebook::rebalancer::interface;
using Coefficients = std::vector<std::vector<Rational>>;
using GoalSpec = std::variant<native::CapacitySpec, native::AggregatedGroupSpec,
                              native::MinimizeNthLargestUtilizationSpec, native::ColocateGroupsSpec>;

struct DeferredGoal {
  GoalSpec spec;
  Rational weight;
  Integer bound;
};

struct ResourceDimension {
  std::string name;
  Integer bound;
};

struct FamilyScope {
  std::string name;
  std::map<std::string, std::string> member_names;
  std::map<std::string, std::string> target_members;
};

struct ScopeSelection {
  std::string name;
  std::vector<std::string> items;
};

constexpr const char* kSink = "dispatch_deferred";
constexpr const char* kContainerScope = "container";

double comparison_double(const Integer& value) {
  // Upstream compares 2*abs(a-b)/(abs(a)+abs(b)) against machine epsilon.
  // Below 2^51, its relative tolerance is below half an integer quantum;
  // the absolute tolerance is also below one quantum. Representation alone
  // would allow larger integers whose one-unit differences compare equal.
  if (absolute(value) > kMaximumComparisonMagnitude) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                "native comparison magnitude exceeds the integer precision profile");
  }
  return exact_double(value);
}

std::string object_name(std::size_t index) {
  return "item_" + std::to_string(index);
}

std::string target_name(std::size_t index) {
  return "target_" + std::to_string(index);
}

std::string anchor_name(std::size_t index) {
  return "anchor_" + std::to_string(index);
}

std::set<std::string> string_set(const Json& values) {
  return values.get<std::set<std::string>>();
}

Integer demand(const Model& model, std::size_t item, const std::string& dimension,
               const std::string& target) {
  const auto& definition = model.source.at("items").at(model.items[item].id)
                               .at("demands").at(dimension);
  if (definition.at("overrides").contains(target)) {
    return decimal(definition.at("overrides").at(target));
  }
  if (!definition.at("default").is_null()) {
    return decimal(definition.at("default"));
  }
  // Missing demand is permitted only at an ineligible destination. Its value
  // cannot affect an accepted assignment because the domain is a hard rule.
  return 0;
}

Integer observed_charge(const Model& model, std::size_t item, const std::string& dimension) {
  return decimal(model.source.at("observed").at(model.items[item].id).at("charges").at(dimension));
}

Rational assignment_cost(const Json& costs, const std::string& target) {
  if (target.empty()) {
    return rational(costs.at("deferred"));
  }
  if (costs.at("targets").contains(target)) {
    return rational(costs.at("targets").at(target));
  }
  if (costs.at("default").is_null()) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "eligible assignment lacks explicit cost");
  }
  return rational(costs.at("default"));
}

Rational movement_cost(const Model& model, std::size_t index, const Json& policy,
                       const std::string& destination) {
  const auto& item = model.items[index];
  if (item.observed_target == destination) {
    return {};
  }
  const auto category = item.observed_target.empty() ? "new_placement"
                       : destination.empty() ? "retirement" : "relocation";
  const auto categories = string_set(policy.at("categories"));
  if (!categories.contains(category)) {
    return {};
  }
  const auto& costs = policy.at("costs").at(item.id);
  if (!destination.empty() && costs.at("default").is_null() &&
      !costs.at("targets").contains(destination) &&
      std::find(item.eligible.begin(), item.eligible.end(), destination) == item.eligible.end()) {
    return {};
  }
  auto value = assignment_cost(costs, destination);
  if (value.numerator < 0) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "movement costs must be nonnegative");
  }
  return value;
}

class Compiler {
 public:
  Compiler(const Model& model, std::string run_id, unsigned threads)
      : model_(model),
        solver_(native::ProblemSolverFactory::makeProblemSolver(
            native::ProblemSolver::makeCPUThreadPoolExecutor("dispatch", threads),
            "dispatch", "assignment")) {
    solver_->setRunId(std::move(run_id));
    solver_->setObjectName("item");
    solver_->setContainerName(kContainerScope);
    solver_->setConstraintPolicy(native::ConstraintPolicy::HARD);
    facebook::algopt::common::thrift::PrecisionTolerances precision;
    *precision.absolute() = 1e-10;
    *precision.relative() = std::numeric_limits<double>::epsilon();
    solver_->setPrecision(precision);
    solver_->disableLogging();
    solver_->disableSolutionSummary();

    std::map<std::string, std::vector<std::string>> assignment;
    assignment[kSink] = {};
    for (std::size_t index = 0; index < model_.targets.size(); ++index) {
      assignment[target_name(index)] = {anchor_name(index)};
    }
    for (std::size_t index = 0; index < model_.items.size(); ++index) {
      const auto& source = model_.items[index].observed_target;
      const auto container = source.empty() ? kSink : target_name(model_.target_indices.at(source));
      assignment[container].push_back(object_name(index));
    }
    solver_->setAssignment(assignment);

    native::AvoidMovingSpec anchors;
    *anchors.name() = "fixed_accounting_anchors";
    for (std::size_t index = 0; index < model_.targets.size(); ++index) {
      anchors.objects()->push_back(anchor_name(index));
    }
    solver_->addConstraint(anchors);
    compile_domains();
  }

  void compile() {
    for (const auto& constraint : model_.source.at("constraints")) {
      compile_constraint(constraint);
    }
    for (const auto& tier : model_.source.at("objectives")) {
      compile_tier(tier);
      solver_->addGoalBoundary();
    }
  }

  native::ProblemSolver& solver() {
    return *solver_;
  }

 private:
  void admit_compiled_entry() {
    if (++compiled_entries_ > 4000000) {
      throw Error(wire::ERROR_CODE_RESOURCE_LIMIT,
                  "native compilation exceeds four million nonzero dimension and objective entries");
    }
  }

  std::string fresh(const char* prefix) {
    return std::string(prefix) + "_" + std::to_string(next_identifier_++);
  }

  Coefficients coefficients() const {
    return Coefficients(model_.items.size(), std::vector<Rational>(model_.targets.size() + 1));
  }

  ScopeSelection aggregate_scope(const std::set<std::string>& targets) {
    if (targets.size() == 1) {
      return {kContainerScope, {target_name(model_.target_indices.at(*targets.begin()))}};
    }
    if (const auto found = aggregate_scopes_.find(targets); found != aggregate_scopes_.end()) {
      return found->second;
    }
    const auto scope = fresh("aggregate");
    std::map<std::string, std::vector<std::string>> membership{{"selected", {}}, {"outside", {kSink}}};
    for (std::size_t index = 0; index < model_.targets.size(); ++index) {
      membership[targets.contains(model_.targets[index]) ? "selected" : "outside"].push_back(target_name(index));
    }
    solver_->addScope(scope, membership);
    ScopeSelection selection{scope, {"selected"}};
    aggregate_scopes_.emplace(targets, selection);
    return selection;
  }

  // Each consumer's real-target scope excludes deferral; the shared count
  // dimension itself stays static and gives accounting anchors zero weight.
  std::string count_dimension(const std::set<std::string>& items) {
    if (const auto found = count_dimensions_.find(items); found != count_dimensions_.end()) {
      return found->second;
    }
    const auto dimension = fresh("count");
    std::map<std::string, double> values;
    for (const auto& item : items) {
      admit_compiled_entry();
      values[object_name(model_.item_indices.at(item))] = 1;
    }
    solver_->addObjectDimension(dimension, values, 0);
    count_dimensions_.emplace(items, dimension);
    return dimension;
  }

  const ResourceDimension& materialize_resource(const std::string& dimension, bool overlap) {
    const auto key = std::make_pair(dimension, overlap);
    if (const auto found = resource_dimensions_.find(key); found != resource_dimensions_.end()) {
      return found->second;
    }
    auto [values, anchors] = resource_coefficients(dimension, overlap);
    const auto name = fresh("load");
    add_dimension(name, values, 1, anchors);
    Integer bound = 0;
    for (const auto& item : values) {
      Integer maximum = 0;
      for (const auto& value : item) {
        maximum = std::max(maximum, absolute(value.numerator));
      }
      bound += maximum;
    }
    for (const auto& anchor : anchors) {
      bound += anchor;
    }
    return resource_dimensions_.emplace(key, ResourceDimension{name, bound}).first->second;
  }

  const FamilyScope& family_scope(const std::string& family_id) {
    if (const auto found = family_scopes_.find(family_id); found != family_scopes_.end()) {
      return found->second;
    }
    FamilyScope scope{fresh("family"), {}, {}};
    std::map<std::string, std::vector<std::string>> membership{{"deferred", {kSink}}};
    std::size_t index = 0;
    for (const auto& [member, targets] : model_.source.at("scope_families").at(family_id).items()) {
      const auto name = "member_" + std::to_string(index++);
      scope.member_names[member] = name;
      membership[name] = {};
      for (const auto& value : targets) {
        const auto target = value.get<std::string>();
        membership[name].push_back(target_name(model_.target_indices.at(target)));
        scope.target_members[target] = member;
      }
    }
    solver_->addScope(scope.name, membership);
    return family_scopes_.emplace(family_id, std::move(scope)).first->second;
  }

  void add_dimension(const std::string& name, const Coefficients& values,
                     const Integer& scale, const std::vector<Integer>& anchors) {
    std::map<std::string, std::map<std::string, double>> native_values;
    Integer total = 0;
    for (std::size_t item = 0; item < values.size(); ++item) {
      Integer maximum = 0;
      for (std::size_t target = 0; target <= model_.targets.size(); ++target) {
        const auto& rational_value = values[item][target];
        const Integer value = rational_value.numerator * (scale / rational_value.denominator);
        maximum = std::max(maximum, absolute(value));
        const auto container = target == model_.targets.size() ? kSink : target_name(target);
        if (value != 0) {
          admit_compiled_entry();
          native_values[container][object_name(item)] = comparison_double(value);
        }
      }
      total += maximum;
    }
    for (std::size_t target = 0; target < anchors.size(); ++target) {
      total += absolute(anchors[target]);
      if (anchors[target] != 0) {
        admit_compiled_entry();
        native_values[target_name(target)][anchor_name(target)] = comparison_double(anchors[target]);
      }
    }
    comparison_double(total);
    solver_->addDynamicObjectDimension(name, kContainerScope, native_values, 0);
  }

  native::CapacitySpec capacity_spec(const std::string& name, const std::string& scope,
                                    const std::string& dimension, const Integer& limit,
                                    bool minimum = false) {
    native::CapacitySpec spec;
    *spec.name() = name;
    *spec.scope() = scope;
    *spec.dimension() = dimension;
    *spec.definition() = native::CapacitySpecDefinition::AFTER;
    *spec.bound() = minimum ? native::CapacitySpecBound::MIN : native::CapacitySpecBound::MAX;
    *spec.limit()->type() = native::LimitType::ABSOLUTE;
    *spec.limit()->globalLimit() = comparison_double(limit);
    spec.filter()->itemsWhitelist() = std::vector<std::string>{"selected"};
    return spec;
  }

  native::CapacitySpec capacity_spec(const std::string& name, const ScopeSelection& scope,
                                    const std::string& dimension, const Integer& limit,
                                    bool minimum = false) {
    auto spec = capacity_spec(name, scope.name, dimension, limit, minimum);
    spec.filter()->itemsWhitelist() = scope.items;
    return spec;
  }

  void compile_domains() {
    native::AvoidAssignmentsSpec forbidden;
    *forbidden.name() = "domains_and_mandatory_admission";
    *forbidden.scope() = kContainerScope;
    for (std::size_t index = 0; index < model_.items.size(); ++index) {
      native::AvoidAssignment entry;
      *entry.object() = object_name(index);
      const auto& item = model_.items[index];
      const std::set<std::string> eligible(item.eligible.begin(), item.eligible.end());
      for (std::size_t target = 0; target < model_.targets.size(); ++target) {
        if (!eligible.contains(model_.targets[target])) {
          entry.scopeItems()->push_back(target_name(target));
        }
      }
      if (!item.deferrable) {
        entry.scopeItems()->push_back(kSink);
      }
      if (!entry.scopeItems()->empty()) {
        forbidden.assignments()->push_back(std::move(entry));
      }
    }
    if (!forbidden.assignments()->empty()) {
      solver_->addConstraint(forbidden, native::ConstraintPolicy::HARD);
    }
  }

  void forbid(const std::string& name, const std::set<std::string>& items,
              const std::set<std::string>& allowed, bool allow_deferred) {
    native::AvoidAssignmentsSpec spec;
    *spec.name() = name;
    *spec.scope() = kContainerScope;
    for (const auto& id : items) {
      native::AvoidAssignment entry;
      *entry.object() = object_name(model_.item_indices.at(id));
      for (std::size_t target = 0; target < model_.targets.size(); ++target) {
        if (!allowed.contains(model_.targets[target])) {
          entry.scopeItems()->push_back(target_name(target));
        }
      }
      if (!allow_deferred) {
        entry.scopeItems()->push_back(kSink);
      }
      if (!entry.scopeItems()->empty()) {
        spec.assignments()->push_back(std::move(entry));
      }
    }
    if (!spec.assignments()->empty()) {
      solver_->addConstraint(spec, native::ConstraintPolicy::HARD);
    }
  }

  std::pair<Coefficients, std::vector<Integer>> resource_coefficients(
      const std::string& dimension, bool overlap) {
    auto values = coefficients();
    std::vector<Integer> anchors(model_.targets.size());
    for (std::size_t target = 0; target < model_.targets.size(); ++target) {
      anchors[target] = decimal(model_.source.at("targets").at(model_.targets[target])
                                    .at("fixed_load").at(dimension));
    }
    for (const auto& holding : model_.source.at("holdings")) {
      if (holding.at("dimension") == dimension && holding.at("kind").at("kind") == "additional" &&
          (overlap || holding.at("kind").at("retained_at_final").get<bool>())) {
        anchors[model_.target_indices.at(holding.at("target").get<std::string>())] +=
            decimal(holding.at("quantity"));
      }
    }
    for (std::size_t item = 0; item < model_.items.size(); ++item) {
      const auto& source = model_.items[item].observed_target;
      const Integer charge = observed_charge(model_, item, dimension);
      if (overlap && !source.empty()) {
        anchors[model_.target_indices.at(source)] += charge;
      }
      for (std::size_t target = 0; target < model_.targets.size(); ++target) {
        Integer quantity = demand(model_, item, dimension, model_.targets[target]);
        if (overlap && model_.targets[target] == source) {
          quantity = std::max(Integer(0), Integer(quantity - charge));
        }
        values[item][target] = Rational(quantity);
      }
    }
    return {std::move(values), std::move(anchors)};
  }

  Integer historical_load(const std::set<std::string>& selected,
                          const std::string& dimension, bool overlap) {
    Integer load = 0;
    for (const auto& target : selected) {
      load += decimal(model_.source.at("targets").at(target).at("fixed_load").at(dimension));
    }
    for (std::size_t item = 0; item < model_.items.size(); ++item) {
      if (selected.contains(model_.items[item].observed_target)) {
        load += observed_charge(model_, item, dimension);
      }
    }
    for (const auto& holding : model_.source.at("holdings")) {
      if (selected.contains(holding.at("target").get<std::string>()) &&
          holding.at("dimension") == dimension && holding.at("kind").at("kind") == "additional" &&
          (overlap || holding.at("kind").at("retained_at_final").get<bool>())) {
        load += decimal(holding.at("quantity"));
      }
    }
    return load;
  }

  void compile_constraint(const Json& constraint) {
    const auto& rule = constraint.at("rule");
    const auto kind = rule.at("kind").get<std::string>();
    const auto name = fresh("constraint");
    const bool repair = constraint.at("enforcement") == "repair";
    if (kind == "eligibility") {
      forbid(name, string_set(rule.at("items")), string_set(rule.at("targets")), true);
      return;
    }
    if (kind == "fixed_placement") {
      for (const auto& [item, binding] : rule.at("bindings").items()) {
        const bool deferred = binding.at("kind") == "deferred";
        forbid(fresh("fixed"), {item}, deferred ? std::set<std::string>{}
                                                 : std::set<std::string>{binding.at("target").get<std::string>()}, deferred);
      }
      return;
    }
    if (kind == "capacity") {
      const auto selected = string_set(model_.source.at("target_sets").at(rule.at("target_set").get<std::string>()));
      const auto dimension = rule.at("dimension").get<std::string>();
      const bool overlap = rule.at("phase") == "overlap";
      const auto& native_dimension = materialize_resource(dimension, overlap);
      Integer limit = decimal(rule.at("limit"));
      if (repair) {
        limit = std::max(limit, historical_load(selected, dimension, overlap));
      }
      solver_->addConstraint(capacity_spec(name, aggregate_scope(selected), native_dimension.name, limit),
                             native::ConstraintPolicy::HARD);
      return;
    }
    if (kind == "movement_budget") {
      auto values = coefficients();
      Integer scale = 1;
      for (const auto& id : rule.at("items")) {
        const auto item = model_.item_indices.at(id.get<std::string>());
        for (std::size_t target = 0; target <= model_.targets.size(); ++target) {
          const auto destination = target == model_.targets.size() ? "" : model_.targets[target];
          values[item][target] = movement_cost(model_, item, rule.at("costs"), destination);
          scale = common_denominator(scale, values[item][target]);
        }
      }
      const auto limit = rational(rule.at("limit"));
      scale = common_denominator(scale, limit);
      const auto dimension = fresh("movement");
      add_dimension(dimension, values, scale, {});
      // Include the synthetic sink so explicit retirement costs remain charged.
      std::map<std::string, std::string> membership{{kSink, "selected"}};
      for (std::size_t target = 0; target < model_.targets.size(); ++target) {
        membership[target_name(target)] = "selected";
      }
      const auto scope = fresh("movement_scope");
      solver_->addScope(scope, membership);
      solver_->addConstraint(capacity_spec(name, scope, dimension,
                                          limit.numerator * (scale / limit.denominator)),
                             native::ConstraintPolicy::HARD);
      return;
    }
    const auto selected = string_set(model_.source.at("groups").at(rule.at("group").get<std::string>()));
    const auto count = count_dimension(selected);
    const auto scope = aggregate_scope(std::set<std::string>(model_.targets.begin(), model_.targets.end()));
    Integer admitted = 0;
    for (const auto& id : selected) {
      if (!model_.items.at(model_.item_indices.at(id)).observed_target.empty()) {
        ++admitted;
      }
    }
    if (kind == "admission") {
      Integer minimum = decimal(rule.at("minimum"));
      Integer maximum = decimal(rule.at("maximum"));
      if (repair) {
        minimum = std::min(minimum, admitted);
        maximum = std::max(maximum, admitted);
      }
      solver_->addConstraint(capacity_spec(name + "_minimum", scope, count, minimum, true),
                             native::ConstraintPolicy::HARD);
      solver_->addConstraint(capacity_spec(name + "_maximum", scope, count, maximum),
                             native::ConstraintPolicy::HARD);
      return;
    }
    if (kind == "atomic_admission") {
      native::GenericSpec none;
      none.set_capacitySpec(capacity_spec(name + "_none", scope, count, 0));
      native::GenericSpec all;
      all.set_capacitySpec(capacity_spec(name + "_all", scope, count, selected.size(), true));
      native::LogicalOrSpec atomic;
      *atomic.name() = name;
      *atomic.genericSpecs() = {none, all};
      solver_->addConstraint(atomic, native::ConstraintPolicy::HARD);
      return;
    }
    compile_topology(rule, name, selected, repair);
  }

  void compile_topology(const Json& rule, const std::string& name,
                        const std::set<std::string>& selected, bool repair) {
    const auto& family = family_scope(rule.at("family").get<std::string>());
    const auto& scope = family.name;
    const auto& members = family.member_names;
    std::map<std::string, Integer> historical;
    for (const auto& [member, native_member] : members) {
      historical[member] = 0;
    }
    for (const auto& id : selected) {
      const auto& item = model_.items.at(model_.item_indices.at(id));
      if (!item.observed_target.empty()) {
        ++historical[family.target_members.at(item.observed_target)];
      }
    }
    const auto dimension = count_dimension(selected);
    const auto partition = single_partition();
    native::ColocateGroupsSpec spread;
    *spread.name() = name;
    *spread.scope() = scope;
    *spread.partitionName() = partition;
    spread.dimension() = dimension;
    spread.filter()->itemsBlacklist() = std::vector<std::string>{"deferred"};
    *spread.limits()->type() = native::LimitType::ABSOLUTE;
    if (rule.at("kind") == "co_location") {
      *spread.bound() = native::ColocateGroupsSpecBound::MAX;
      *spread.limits()->globalLimit() = 1;
    } else {
      Integer minimum = rule.at("when_admitted").get<bool>() && selected.empty()
                            ? Integer(0) : decimal(rule.at("minimum"));
      if (repair) {
        Integer occupied = 0;
        for (const auto& [member, count] : historical) {
          if (count != 0) {
            ++occupied;
          }
        }
        if (!(rule.at("when_admitted").get<bool>() && occupied == 0)) {
          minimum = std::min(minimum, occupied);
        }
      }
      *spread.bound() = native::ColocateGroupsSpecBound::MIN;
      *spread.limits()->globalLimit() = comparison_double(minimum);
    }
    solver_->addConstraint(spread, native::ConstraintPolicy::HARD);
    if (rule.at("kind") == "spread" && !rule.at("maximum_per_member").is_null()) {
      native::GroupCountSpec maximum;
      *maximum.name() = name + "_per_member";
      *maximum.scope() = scope;
      *maximum.partitionName() = partition;
      *maximum.dimension() = dimension;
      *maximum.bound() = native::GroupCountSpecBound::MAX;
      *maximum.limit()->type() = native::LimitType::ABSOLUTE;
      maximum.filter()->itemsBlacklist() = std::vector<std::string>{"deferred"};
      const Integer declared = decimal(rule.at("maximum_per_member"));
      *maximum.limit()->globalLimit() = comparison_double(declared);
      for (const auto& [member, native_member] : members) {
        (*maximum.limit()->scopeItemLimits())[native_member] =
            comparison_double(repair ? std::max(declared, historical.at(member)) : declared);
      }
      solver_->addConstraint(maximum, native::ConstraintPolicy::HARD);
    }
  }

  void compile_tier(const Json& tier) {
    auto values = coefficients();
    std::vector<DeferredGoal> deferred_goals;
    for (const auto& term : tier.at("terms")) {
      auto factor = rational(term.at("weight")) / rational(term.at("normalizer"));
      if (factor.numerator < 0) {
        throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "objective weight must be nonnegative");
      }
      if (term.at("direction") == "maximize") {
        factor.numerator = -factor.numerator;
      } else if (term.at("direction") != "minimize") {
        throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "unknown objective direction");
      }
      const auto& metric = term.at("metric");
      const auto kind = metric.at("kind").get<std::string>();
      if (kind == "used_targets") {
        if (!metric.at("items").empty() && !model_.targets.empty()) {
          deferred_goals.push_back(used_targets_goal(metric, factor));
        }
        continue;
      }
      if (kind == "maximum_utilization" || kind == "utilization_range") {
        auto goals = utilization_goals(metric, factor, kind == "utilization_range");
        deferred_goals.insert(deferred_goals.end(), goals.begin(), goals.end());
        continue;
      }
      if (kind == "total_absolute_deviation") {
        for (const auto& reference : metric.at("members")) {
          auto goals = deviation_goals(reference, factor);
          deferred_goals.insert(deferred_goals.end(), goals.begin(), goals.end());
        }
        continue;
      }
      if (kind == "repair_debt") {
        for (const auto& component : metric.at("components")) {
          deferred_goals.push_back(repair_goal(component, factor));
        }
        continue;
      }
      std::set<std::string> selected;
      if (kind == "admitted_count" || kind == "movement_cost") {
        selected = string_set(metric.at("items"));
      }
      for (std::size_t item = 0; item < model_.items.size(); ++item) {
        const auto& id = model_.items[item].id;
        for (std::size_t target = 0; target <= model_.targets.size(); ++target) {
          const auto destination = target == model_.targets.size() ? "" : model_.targets[target];
          Rational cost;
          if (kind == "admitted_count" && selected.contains(id) && !destination.empty()) {
            cost = Rational(1);
          } else if (kind == "admitted_priority" && metric.at("priorities").contains(id) &&
                     !destination.empty()) {
            cost = rational(metric.at("priorities").at(id));
          } else if (kind == "assignment_cost" && metric.at("costs").contains(id)) {
            // Ineligible destinations need no cost value: a hard domain forbids them.
            const auto& costs = metric.at("costs").at(id);
            if (destination.empty() || !costs.at("default").is_null() ||
                costs.at("targets").contains(destination)) {
              cost = assignment_cost(costs, destination);
            }
          } else if (kind == "movement_cost" && selected.contains(id)) {
            const auto& costs = metric.at("costs").at("costs").at(id);
            if (destination.empty() || !costs.at("default").is_null() ||
                costs.at("targets").contains(destination)) {
              cost = movement_cost(model_, item, metric.at("costs"), destination);
            }
          }
          values[item][target] = values[item][target] + cost * factor;
        }
      }
    }
    Integer scale = 1;
    for (const auto& item : values) {
      for (const auto& value : item) {
        scale = common_denominator(scale, value);
      }
    }
    for (const auto& goal : deferred_goals) {
      scale = common_denominator(scale, goal.weight);
    }
    // Affinities minimize the negative affinity sum. One scaled integer
    // expression per tier preserves exact rational ordering within the tier.
    native::AssignmentAffinitiesSpec goal;
    *goal.name() = fresh("objective");
    *goal.scope() = kContainerScope;
    Integer bound = 0;
    for (std::size_t item = 0; item < values.size(); ++item) {
      Integer maximum = 0;
      for (std::size_t target = 0; target <= model_.targets.size(); ++target) {
        const auto& value = values[item][target];
        const Integer coefficient = value.numerator * (scale / value.denominator);
        maximum = std::max(maximum, absolute(coefficient));
        if (coefficient != 0) {
          admit_compiled_entry();
          native::AssignmentAffinity affinity;
          *affinity.objectName() = object_name(item);
          *affinity.scopeItemName() = target == model_.targets.size() ? kSink : target_name(target);
          *affinity.affinity() = comparison_double(-coefficient);
          goal.affinities()->push_back(std::move(affinity));
        }
      }
      bound += 2 * maximum;
    }
    for (const auto& goal : deferred_goals) {
      const Integer weight = goal.weight.numerator * (scale / goal.weight.denominator);
      bound += absolute(weight) * goal.bound;
    }
    comparison_double(bound);
    if (bound > kMaximumComparisonMagnitude) {
      // Upstream requires a nonzero relative comparison tolerance. Keeping
      // integral tiers below this bound preserves separation of adjacent values.
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                  "scaled objective tier exceeds the unit-separation magnitude bound");
    }
    if (!goal.affinities()->empty()) {
      solver_->addGoal(goal);
    }
    for (const auto& goal : deferred_goals) {
      const auto weight = comparison_double(goal.weight.numerator * (scale / goal.weight.denominator));
      std::visit([&](const auto& spec) { solver_->addGoal(spec, weight); }, goal.spec);
    }
  }

  std::string single_partition() {
    if (!single_partition_.empty()) {
      return single_partition_;
    }
    const auto partition = fresh("metric_partition");
    std::map<std::string, std::string> groups;
    for (std::size_t item = 0; item < model_.items.size(); ++item) {
      groups[object_name(item)] = "all";
    }
    for (std::size_t target = 0; target < model_.targets.size(); ++target) {
      groups[anchor_name(target)] = "all";
    }
    solver_->addPartition(partition, groups);
    single_partition_ = partition;
    return partition;
  }

  DeferredGoal used_targets_goal(const Json& metric, const Rational& factor) {
    native::AggregatedGroupSpec goal;
    *goal.name() = fresh("used_targets");
    const auto scope = aggregate_scope(std::set<std::string>(model_.targets.begin(), model_.targets.end()));
    *goal.scope() = scope.name;
    *goal.dimension() = count_dimension(string_set(metric.at("items")));
    *goal.partitionName() = single_partition();
    *goal.withinGroupAggregationType() = native::AggregatedGroupSpecAggType::MAX;
    *goal.groupAggregationType() = native::AggregatedGroupSpecAggType::SUM;
    *goal.containerAggregationType() = native::AggregatedGroupSpecAggType::SUM;
    *goal.limit()->type() = native::LimitType::ABSOLUTE;
    *goal.limit()->globalLimit() = 0;
    goal.filter()->itemsWhitelist() = scope.items;
    return {goal, factor, Integer(model_.targets.size())};
  }

  std::vector<DeferredGoal> utilization_goals(const Json& metric, const Rational& factor,
                                             bool range) {
    const auto& members = metric.at("members");
    if (members.empty() || (range && members.size() == 1)) {
      return {};
    }
    const auto dimension = members[0].at("dimension").get<std::string>();
    const bool overlap = members[0].at("phase") == "overlap";
    Integer denominator = 1;
    std::set<std::string> seen;
    std::map<std::string, Integer> multipliers;
    std::map<std::string, std::string> membership{{kSink, "outside"}};
    std::vector<std::string> included;
    for (std::size_t index = 0; index < members.size(); ++index) {
      const auto& member = members[index];
      if (member.at("dimension") != dimension || (member.at("phase") == "overlap") != overlap) {
        throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                    "maximum/range utilization requires one dimension and accounting phase");
      }
      const Integer capacity = decimal(member.at("capacity"));
      if (capacity == 0) {
        throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "utilization denominator must be positive");
      }
      denominator = common_denominator(denominator, Rational(1, capacity));
      const auto native_member = "metric_member_" + std::to_string(index);
      included.push_back(native_member);
      for (const auto& target : model_.source.at("target_sets").at(member.at("target_set").get<std::string>())) {
        const auto id = target.get<std::string>();
        if (!seen.insert(id).second) {
          throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                      "maximum/range utilization target sets must be disjoint for this backend");
        }
        membership[target_name(model_.target_indices.at(id))] = native_member;
        multipliers[id] = capacity;
      }
    }
    for (std::size_t target = 0; target < model_.targets.size(); ++target) {
      if (!seen.contains(model_.targets[target])) {
        membership[target_name(target)] = "outside";
      }
    }
    auto [values, anchors] = resource_coefficients(dimension, overlap);
    Integer bound = 0;
    for (std::size_t target = 0; target < model_.targets.size(); ++target) {
      const auto found = multipliers.find(model_.targets[target]);
      const Integer multiplier = found == multipliers.end() ? Integer(0) : Integer(denominator / found->second);
      anchors[target] *= multiplier;
      bound += anchors[target];
      for (std::size_t item = 0; item < model_.items.size(); ++item) {
        values[item][target] = values[item][target] * Rational(multiplier);
        bound += absolute(values[item][target].numerator);
      }
    }
    comparison_double(bound);
    const auto native_dimension = fresh("utilization");
    add_dimension(native_dimension, values, 1, anchors);
    const auto scope = fresh("utilization_scope");
    std::map<std::string, std::vector<std::string>> scope_members;
    for (const auto& member : included) {
      scope_members[member] = {};
    }
    for (const auto& [container, member] : membership) {
      scope_members[member].push_back(container);
    }
    solver_->addScope(scope, scope_members);
    std::map<std::string, double> capacities;
    for (const auto& member : included) {
      capacities[member] = 1;
    }
    solver_->addScopeDimension(native_dimension, scope, capacities, 0);
    native::MinimizeNthLargestUtilizationSpec maximum;
    *maximum.name() = fresh("maximum_utilization");
    *maximum.scope() = scope;
    *maximum.dimension() = native_dimension;
    *maximum.n() = 0;
    maximum.filter()->itemsWhitelist() = included;
    const auto weight = factor / Rational(denominator);
    std::vector<DeferredGoal> result{{maximum, weight, bound}};
    if (range && included.size() > 1) {
      auto minimum = maximum;
      *minimum.name() = fresh("minimum_utilization");
      *minimum.n() = static_cast<std::int32_t>(included.size() - 1);
      auto negative = weight;
      negative.numerator = -negative.numerator;
      result.push_back({minimum, negative, bound});
    } else if (range) {
      result.clear();
    }
    return result;
  }

  std::vector<DeferredGoal> deviation_goals(const Json& reference, const Rational& factor) {
    const auto& member = reference.at("member");
    const auto selected = string_set(model_.source.at("target_sets").at(member.at("target_set").get<std::string>()));
    const auto dimension = member.at("dimension").get<std::string>();
    const auto point = rational(reference.at("reference"));
    const Integer capacity = decimal(member.at("capacity"));
    if (capacity == 0) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "utilization denominator must be positive");
    }
    auto [values, anchors] = resource_coefficients(dimension, member.at("phase") == "overlap");
    Integer bound = absolute(point.numerator * capacity);
    for (auto& anchor : anchors) {
      anchor *= point.denominator;
      bound += absolute(anchor);
    }
    for (auto& item : values) {
      for (auto& value : item) {
        value = value * Rational(point.denominator);
        bound += absolute(value.numerator);
      }
    }
    comparison_double(bound);
    const auto native_dimension = fresh("deviation_load");
    add_dimension(native_dimension, values, 1, anchors);
    const auto scope = aggregate_scope(selected);
    const Integer threshold = point.numerator * capacity;
    const auto weight = factor / Rational(point.denominator * capacity);
    return {{capacity_spec(fresh("deviation_upper"), scope, native_dimension, threshold), weight, bound},
            {capacity_spec(fresh("deviation_lower"), scope, native_dimension, threshold, true), weight, bound}};
  }

  DeferredGoal repair_goal(const Json& component, const Rational& factor) {
    const auto id = component.at("constraint").get<std::string>();
    const auto selector = component.at("component").get<std::string>();
    const auto found = std::find_if(model_.source.at("constraints").begin(), model_.source.at("constraints").end(),
                                  [&](const Json& constraint) { return constraint.at("id") == id; });
    if (found == model_.source.at("constraints").end() || found->at("enforcement") != "repair") {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "repair objective must select a repairable component");
    }
    const auto& rule = found->at("rule");
    if (rule.at("kind") == "capacity" && selector == "capacity") {
      const auto selected = string_set(model_.source.at("target_sets").at(rule.at("target_set").get<std::string>()));
      const auto& dimension = materialize_resource(rule.at("dimension").get<std::string>(), rule.at("phase") == "overlap");
      Integer bound = decimal(rule.at("limit")) + dimension.bound;
      comparison_double(bound);
      return {capacity_spec(fresh("capacity_debt"), aggregate_scope(selected), dimension.name,
                            decimal(rule.at("limit"))), factor, bound};
    }
    if (rule.at("kind") == "admission" && (selector == "minimum" || selector == "maximum")) {
      const auto selected = string_set(model_.source.at("groups").at(rule.at("group").get<std::string>()));
      const auto dimension = count_dimension(selected);
      const auto scope = aggregate_scope(std::set<std::string>(model_.targets.begin(), model_.targets.end()));
      const auto limit = decimal(rule.at(selector));
      return {capacity_spec(fresh("admission_debt"), scope, dimension, limit, selector == "minimum"),
              factor, Integer(selected.size()) + limit};
    }
    if (rule.at("kind") == "spread") {
      const auto selected = string_set(model_.source.at("groups").at(rule.at("group").get<std::string>()));
      const auto dimension = count_dimension(selected);
      const auto& family = model_.source.at("scope_families").at(rule.at("family").get<std::string>());
      if (selector.starts_with("member:") && !rule.at("maximum_per_member").is_null()) {
        const auto member = selector.substr(7);
        if (!family.contains(member)) {
          throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "unknown spread repair member");
        }
        const auto scope = aggregate_scope(string_set(family.at(member)));
        const auto limit = decimal(rule.at("maximum_per_member"));
        return {capacity_spec(fresh("spread_member_debt"), scope, dimension, limit),
                factor, Integer(selected.size()) + limit};
      }
      if (selector == "minimum") {
        const auto& scope = family_scope(rule.at("family").get<std::string>());
        native::ColocateGroupsSpec goal;
        *goal.name() = fresh("spread_minimum_debt");
        *goal.scope() = scope.name;
        *goal.partitionName() = single_partition();
        goal.dimension() = dimension;
        *goal.bound() = native::ColocateGroupsSpecBound::MIN;
        *goal.limits()->type() = native::LimitType::ABSOLUTE;
        const Integer minimum = rule.at("when_admitted").get<bool>() && selected.empty()
                                    ? Integer(0) : decimal(rule.at("minimum"));
        *goal.limits()->globalLimit() = comparison_double(minimum);
        goal.filter()->itemsBlacklist() = std::vector<std::string>{"deferred"};
        return {goal, factor, minimum};
      }
    }
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "this repair component objective is unsupported by the backend");
  }

  const Model& model_;
  std::unique_ptr<native::ProblemSolver> solver_;
  std::size_t next_identifier_ = 0;
  std::size_t compiled_entries_ = 0;
  std::map<std::set<std::string>, std::string> count_dimensions_;
  std::map<std::pair<std::string, bool>, ResourceDimension> resource_dimensions_;
  std::map<std::string, FamilyScope> family_scopes_;
  std::map<std::set<std::string>, ScopeSelection> aggregate_scopes_;
  std::string single_partition_;
};

}  // namespace

SolveResult solve_model(const Model& model, const wire::SolveOptions& options,
                        const std::string& hint, const std::string& run_id) {
  check_model_support(model);
  if (!hint.empty()) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL,
                "assignment hints are unsupported; observations remain the immutable baseline");
  }
  if (options.threads() == 0 || options.threads() > 128 || options.wall_time_millis() == 0 ||
      options.wall_time_millis() / 1000 > std::numeric_limits<std::int32_t>::max()) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "invalid native search thread or wall-time option");
  }
  if (options.maximum_iterations() != 0) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "native solver has no equivalent iteration budget");
  }
  if (options.has_seed() && options.seed() > std::numeric_limits<std::int32_t>::max()) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "native seed exceeds signed 32-bit range");
  }
  if (options.mode() != wire::SEARCH_MODE_LOCAL_SEARCH && options.mode() != wire::SEARCH_MODE_MIP) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "an explicit supported search mode is required");
  }
  if (options.mode() == wire::SEARCH_MODE_MIP && options.wall_time_millis() < 1000) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "native MIP minimum time budget is one second");
  }
  if (model.items.empty()) {
    return {Json{{"bindings", Json::object()}}, wire::TERMINATION_COMPLETED,
            wire::EVIDENCE_KIND_NONE, "empty assignment; independent verification is required"};
  }
  Compiler compiler(model, run_id, options.threads());
  compiler.compile();
  if (options.mode() == wire::SEARCH_MODE_LOCAL_SEARCH) {
    native::LocalSearchSolverSpec search;
    search.solveTime() = static_cast<std::int32_t>(options.wall_time_millis() / 1000);
    *search.randomSeed() = options.has_seed() ? static_cast<std::int32_t>(options.seed()) : 0;
    native::MoveTypeSpec single;
    single.set_singleMoveTypeSpec(native::SingleMoveTypeSpec{});
    native::MoveTypeSpec swap;
    swap.set_swapMoveTypeSpec(native::SwapMoveTypeSpec{});
    *search.moveTypeList() = {single, swap};
    compiler.solver().addSolver(search);
  } else if (options.mode() == wire::SEARCH_MODE_MIP) {
    native::OptimalSolverSpec search;
    search.solveTime() = static_cast<std::int32_t>(options.wall_time_millis() / 1000);
    *search.solverPackage() = native::OptimalSolverPackage::HIGHS;
    *search.suppressLogs() = true;
    *search.multiObjSolveSettings()->solveType() = native::MultiObjectiveSolveType::HIERARCHICAL;
    (*search.xpressArgs())["threads"] = options.threads();
    if (options.has_seed()) {
      (*search.xpressArgs())["random_seed"] = static_cast<std::int32_t>(options.seed());
    }
    // HiGHS retains a global thread scheduler. Reset it between sequential
    // solves so a warm worker can faithfully apply a different thread budget.
    Highs::resetGlobalScheduler(true);
    compiler.solver().addSolver(search);
  }
  const auto solution = compiler.solver().solve();
  Json bindings = Json::object();
  for (std::size_t index = 0; index < model.items.size(); ++index) {
    const auto found = solution.assignment()->find(object_name(index));
    if (found == solution.assignment()->end()) {
      throw Error(wire::ERROR_CODE_INTERNAL, "native result omits a modeled item");
    }
    if (found->second == kSink) {
      bindings[model.items[index].id] = Json{{"kind", "deferred"}};
      continue;
    }
    bool matched = false;
    for (std::size_t target = 0; target < model.targets.size(); ++target) {
      if (found->second == target_name(target)) {
        bindings[model.items[index].id] = Json{{"kind", "target"}, {"target", model.targets[target]}};
        matched = true;
        break;
      }
    }
    if (!matched) {
      throw Error(wire::ERROR_CODE_INTERNAL, "native result contains an unknown container");
    }
  }
  // Upstream's public result does not expose a sound stopping reason or bound
  // for every stage. Never turn its candidate into an infeasibility/optimality claim.
  return {Json{{"bindings", std::move(bindings)}}, wire::TERMINATION_COMPLETED,
          wire::EVIDENCE_KIND_NONE, "native search returned a candidate; independent verification is required"};
}

}  // namespace dispatch::backend
