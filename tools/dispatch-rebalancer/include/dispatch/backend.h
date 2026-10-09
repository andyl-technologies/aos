#pragma once

#include "dispatch/worker.pb.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <iosfwd>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace dispatch::backend {

namespace wire = ::dispatch::worker::v1;
using Json = nlohmann::json;

// Errors distinguish unsupported semantic input from native execution failure.
class Error : public std::runtime_error {
 public:
  Error(wire::ErrorCode code, std::string message);

  wire::ErrorCode code() const noexcept;

 private:
  wire::ErrorCode code_;
};

inline constexpr std::uint64_t kMaximumExactInteger = (std::uint64_t{1} << 53) - 1;
inline constexpr std::uint64_t kMaximumComparisonMagnitude = (std::uint64_t{1} << 51) - 1;
inline constexpr std::uint32_t kMaximumFrameBytes = 16 * 1024 * 1024;

struct Item {
  std::string id;
  bool deferrable = false;
  std::vector<std::string> eligible;
  std::string observed_target;
};

// The portable source remains the authority for diagnostics and commitments.
struct Model {
  Json source;
  std::vector<Item> items;
  std::vector<std::string> targets;
  std::map<std::string, std::size_t> item_indices;
  std::map<std::string, std::size_t> target_indices;
};

struct SolveResult {
  Json assignment;
  wire::Termination termination = wire::TERMINATION_COMPLETED;
  wire::EvidenceKind evidence = wire::EVIDENCE_KIND_NONE;
  std::string detail;
};

Model parse_model(const std::string& source);
void check_model_support(const Model& model);
SolveResult solve_model(const Model& model, const wire::SolveOptions& options,
                        const std::string& hint, const std::string& run_id);
std::string backend_build_id();
wire::Capabilities capabilities();

// Each worker handles one request at a time; its provider owns hard cancellation.
int run_worker(std::istream& input, std::ostream& output);

}  // namespace dispatch::backend
