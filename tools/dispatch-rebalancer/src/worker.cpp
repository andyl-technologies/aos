#include "dispatch/backend.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <istream>
#include <iostream>
#include <limits>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

#include <google/protobuf/message.h>
#include <fcntl.h>
#include <unistd.h>

namespace dispatch::backend {
namespace {

constexpr std::uint32_t kHelloFrameBytes = 65536;
constexpr std::uint32_t kMaximumDiagnosticBytes = 4096;

class NativeOutputGuard {
 public:
  NativeOutputGuard() {
    std::cout.flush();
    std::fflush(stdout);
    saved_stdout_ = ::fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    if (saved_stdout_ < 0 || ::dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
      if (saved_stdout_ >= 0) {
        ::close(saved_stdout_);
      }
      throw Error(wire::ERROR_CODE_INTERNAL, "cannot isolate native diagnostic output");
    }
  }

  NativeOutputGuard(const NativeOutputGuard&) = delete;
  NativeOutputGuard& operator=(const NativeOutputGuard&) = delete;

  ~NativeOutputGuard() {
    std::cout.flush();
    std::fflush(stdout);
    int restored;
    do {
      restored = ::dup2(saved_stdout_, STDOUT_FILENO);
    } while (restored < 0 && errno == EINTR);
    ::close(saved_stdout_);
    if (restored < 0) {
      // A broken protocol descriptor cannot safely carry another response.
      ::_exit(1);
    }
  }

 private:
  int saved_stdout_ = -1;
};

std::string bounded_detail(const std::string& detail, std::uint32_t maximum_bytes) {
  if (detail.size() <= maximum_bytes) {
    return detail;
  }
  std::size_t end = maximum_bytes;
  while (end > 0 && (static_cast<unsigned char>(detail[end]) & 0xc0) == 0x80) {
    --end;
  }
  return detail.substr(0, end);
}

struct PreparedInput {
  Model model;
  std::string digest;
  std::uint64_t retained_bytes;
};

struct Session {
  bool initialized = false;
  std::uint64_t session_generation = 0;
  std::uint64_t worker_generation = 0;
  std::uint64_t next_handle = 1;
  std::uint64_t last_request_id = 0;
  std::uint64_t retained_bytes = 0;
  wire::WireLimits limits;
  std::map<std::string, PreparedInput> prepared;
};

bool contains_unknown_fields(const google::protobuf::Message& message) {
  const auto* reflection = message.GetReflection();
  if (reflection->GetUnknownFields(message).field_count() != 0) {
    return true;
  }
  std::vector<const google::protobuf::FieldDescriptor*> fields;
  reflection->ListFields(message, &fields);
  for (const auto* field : fields) {
    if (field->cpp_type() != google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE) {
      continue;
    }
    if (field->is_repeated()) {
      for (int index = 0; index < reflection->FieldSize(message, field); ++index) {
        if (contains_unknown_fields(reflection->GetRepeatedMessage(message, field, index))) {
          return true;
        }
      }
    } else if (contains_unknown_fields(reflection->GetMessage(message, field))) {
      return true;
    }
  }
  return false;
}

std::uint64_t wire_varint(std::string_view bytes, std::size_t& position) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 10; ++index) {
    if (position == bytes.size()) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "truncated protobuf varint");
    }
    const auto byte = static_cast<unsigned char>(bytes[position++]);
    if (index == 9 && byte > 1) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "overflowed protobuf varint");
    }
    value |= static_cast<std::uint64_t>(byte & 0x7f) << (index * 7);
    if ((byte & 0x80) == 0) {
      return value;
    }
  }
  throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "unterminated protobuf varint");
}

void preflight_protobuf(std::string_view bytes, const google::protobuf::Descriptor* descriptor,
                        unsigned depth, std::size_t& fields) {
  if (depth > 32) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "protobuf nesting exceeds native bound");
  }
  std::size_t position = 0;
  while (position < bytes.size()) {
    if (++fields > 8192) {
      throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "protobuf field count exceeds native bound");
    }
    const auto tag = wire_varint(bytes, position);
    const auto number = tag >> 3;
    if (number > 536870911) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "invalid protobuf field number");
    }
    const auto* field = descriptor->FindFieldByNumber(static_cast<int>(number));
    if (field == nullptr) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "unknown protobuf field");
    }
    const auto type = tag & 7;
    if (type == 0) {
      if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE ||
          field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_STRING) {
        throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "wrong protobuf scalar wire type");
      }
      wire_varint(bytes, position);
    } else if (type == 2) {
      if (field->cpp_type() != google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE &&
          field->cpp_type() != google::protobuf::FieldDescriptor::CPPTYPE_STRING && !field->is_packed()) {
        throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "wrong protobuf length-delimited wire type");
      }
      const auto length = wire_varint(bytes, position);
      if (length > bytes.size() - position) {
        throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "truncated protobuf field");
      }
      if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE) {
        preflight_protobuf(bytes.substr(position, length), field->message_type(), depth + 1, fields);
      } else if (field->is_packed()) {
        const auto packed = bytes.substr(position, length);
        std::size_t packed_position = 0;
        while (packed_position < packed.size()) {
          if (++fields > 8192) {
            throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "packed protobuf field count exceeds native bound");
          }
          wire_varint(packed, packed_position);
        }
      }
      position += static_cast<std::size_t>(length);
    } else {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "unsupported protobuf wire type");
    }
  }
}

std::optional<wire::WorkerEnvelope> read_frame(std::istream& input,
                                              std::uint32_t maximum_bytes) {
  std::array<unsigned char, 4> header{};
  input.read(reinterpret_cast<char*>(header.data()), header.size());
  if (input.gcount() == 0 && input.eof()) {
    return std::nullopt;
  }
  if (input.gcount() != static_cast<std::streamsize>(header.size())) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "truncated frame header");
  }

  const std::uint32_t bytes = (std::uint32_t{header[0]} << 24) |
                            (std::uint32_t{header[1]} << 16) |
                            (std::uint32_t{header[2]} << 8) | header[3];
  if (bytes == 0 || bytes > maximum_bytes) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "frame length exceeds negotiated bound");
  }

  std::string payload(bytes, '\0');
  input.read(payload.data(), static_cast<std::streamsize>(bytes));
  if (input.gcount() != static_cast<std::streamsize>(bytes)) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "truncated protobuf frame");
  }

  wire::WorkerEnvelope envelope;
  std::size_t fields = 0;
  preflight_protobuf(payload, wire::WorkerEnvelope::descriptor(), 0, fields);
  if (!envelope.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "invalid protobuf frame");
  }
  std::string canonical;
  if (contains_unknown_fields(envelope) || !envelope.SerializeToString(&canonical) ||
      canonical != payload) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "protobuf frame is not canonical known-field encoding");
  }
  return envelope;
}

void write_frame(std::ostream& output, const wire::WorkerEnvelope& envelope,
                 std::uint32_t maximum_bytes) {
  std::string payload;
  if (!envelope.SerializeToString(&payload)) {
    throw Error(wire::ERROR_CODE_INTERNAL, "cannot serialize response");
  }
  if (payload.empty() || payload.size() > maximum_bytes) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "response exceeds negotiated frame bound");
  }

  const auto bytes = static_cast<std::uint32_t>(payload.size());
  const std::array<unsigned char, 4> header{
      static_cast<unsigned char>(bytes >> 24),
      static_cast<unsigned char>(bytes >> 16),
      static_cast<unsigned char>(bytes >> 8),
      static_cast<unsigned char>(bytes)};
  output.write(reinterpret_cast<const char*>(header.data()), header.size());
  output.write(payload.data(), static_cast<std::streamsize>(payload.size()));
  output.flush();
  if (!output) {
    throw Error(wire::ERROR_CODE_INTERNAL, "response stream failed");
  }
}

bool offers_version(const google::protobuf::RepeatedPtrField<wire::Version>& versions) {
  return std::any_of(versions.begin(), versions.end(), [](const auto& version) {
    return version.major() == 1 && version.minor() == 0;
  });
}

std::uint64_t negotiated_limit(std::uint64_t requested, std::uint64_t offered) {
  if (requested == 0 || offered == 0) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "wire limits must be explicit and nonzero");
  }
  return std::min(requested, offered);
}

wire::WireLimits negotiate_limits(const wire::WireLimits& requested) {
  auto limits = capabilities().limits();
#define DISPATCH_LIMIT(field) \
  limits.set_##field(negotiated_limit(requested.field(), limits.field()))
  DISPATCH_LIMIT(max_frame_bytes);
  DISPATCH_LIMIT(max_problem_bytes);
  DISPATCH_LIMIT(max_decoded_bytes);
  DISPATCH_LIMIT(max_items);
  DISPATCH_LIMIT(max_targets);
  DISPATCH_LIMIT(max_dimensions);
  DISPATCH_LIMIT(max_memberships);
  DISPATCH_LIMIT(max_domain_entries);
  DISPATCH_LIMIT(max_overrides);
  DISPATCH_LIMIT(max_constraints);
  DISPATCH_LIMIT(max_objectives);
  DISPATCH_LIMIT(max_nesting);
  DISPATCH_LIMIT(max_string_bytes);
  DISPATCH_LIMIT(max_prepared);
  DISPATCH_LIMIT(max_prepared_bytes);
  DISPATCH_LIMIT(max_diagnostic_bytes);
#undef DISPATCH_LIMIT
  if (limits.max_frame_bytes() < 1024 || limits.max_diagnostic_bytes() < 128) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "negotiated bounds cannot carry control responses");
  }
  return limits;
}

void check_commitment(const std::string& digest, const char* name) {
  if (digest.size() != 32) {
    throw Error(wire::ERROR_CODE_COMMITMENT_MISMATCH,
                std::string(name) + " must contain a 32-byte canonical model commitment");
  }
}

std::uint64_t decoded_size(const Json& value, const wire::WireLimits& limits,
                           unsigned depth = 0) {
  if (depth > limits.max_nesting() ||
      ((value.is_object() || value.is_array()) && depth >= limits.max_nesting())) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model exceeds negotiated nesting bound");
  }
  std::uint64_t size = 64;
  if (value.is_string()) {
    const auto& text = value.get_ref<const std::string&>();
    if (text.size() > limits.max_string_bytes()) {
      throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model string exceeds negotiated bound");
    }
    size += text.size();
  } else if (value.is_object()) {
    for (const auto& [key, child] : value.items()) {
      if (key.size() > limits.max_string_bytes()) {
        throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model identifier exceeds negotiated bound");
      }
      size += key.size() + 64 + decoded_size(child, limits, depth + 1);
      if (size > limits.max_decoded_bytes()) {
        throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model exceeds negotiated decoded-size bound");
      }
    }
  } else if (value.is_array()) {
    for (const auto& child : value) {
      size += decoded_size(child, limits, depth + 1);
      if (size > limits.max_decoded_bytes()) {
        throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "model exceeds negotiated decoded-size bound");
      }
    }
  }
  return size;
}

std::uint64_t array_memberships(const Json& value) {
  std::uint64_t count = 0;
  for (const auto& child : value) {
    count += child.is_array() ? child.size() : array_memberships(child);
  }
  return count;
}

Model load_model(const std::string& source, const Session& session) {
  if (source.empty() || source.size() > session.limits.max_problem_bytes()) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "problem exceeds negotiated byte bound");
  }
  auto model = parse_model(source);
  const auto& problem = model.source;
  decoded_size(problem, session.limits);
  const auto memberships = array_memberships(problem.at("groups")) +
                           array_memberships(problem.at("target_sets")) +
                           array_memberships(problem.at("scope_families"));
  std::uint64_t overrides = 0;
  for (const auto& target : problem.at("targets")) {
    overrides += target.at("capacities").size() + target.at("fixed_load").size();
  }
  for (const auto& item : problem.at("items")) {
    for (const auto& demand : item.at("demands")) {
      overrides += demand.at("overrides").size();
    }
  }
  std::uint64_t terms = problem.at("objectives").size();
  for (const auto& tier : problem.at("objectives")) {
    terms += tier.at("terms").size();
  }
  if (model.items.size() > session.limits.max_items() ||
      model.targets.size() > session.limits.max_targets() ||
      problem.at("dimensions").size() > session.limits.max_dimensions() ||
      memberships > session.limits.max_memberships() ||
      problem.at("holdings").size() > session.limits.max_memberships() ||
      array_memberships(problem.at("domains")) > session.limits.max_domain_entries() ||
      overrides > session.limits.max_overrides() ||
      problem.at("constraints").size() > session.limits.max_constraints() ||
      terms > session.limits.max_objectives()) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "problem exceeds negotiated entity bound");
  }
  check_model_support(model);
  return model;
}

void initialize_session(Session& session, const wire::WorkerEnvelope& request,
                        wire::WorkerEnvelope& response) {
  if (session.initialized || !request.has_hello()) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "Hello must be the first and only handshake");
  }
  const auto& hello = request.hello();
  if (!offers_version(hello.protocol_versions()) || !offers_version(hello.model_versions())) {
    throw Error(wire::ERROR_CODE_UNSUPPORTED_VERSION, "worker requires protocol and model version 1.0");
  }
  if (request.session_generation() == 0 || request.worker_generation() == 0) {
    throw Error(wire::ERROR_CODE_WRONG_GENERATION, "session and worker generations must be nonzero");
  }

  auto offered = capabilities();
  for (const auto& required : hello.required_capabilities()) {
    if (std::find(offered.capabilities().begin(), offered.capabilities().end(), required) ==
        offered.capabilities().end()) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "required capability is unavailable: " + required);
    }
  }

  session.limits = negotiate_limits(hello.limits());
  session.session_generation = request.session_generation();
  session.worker_generation = request.worker_generation();
  session.initialized = true;
  *offered.mutable_limits() = session.limits;
  *response.mutable_capabilities() = std::move(offered);
}

void prepare_input(Session& session, const wire::Prepare& request,
                   wire::WorkerEnvelope& response) {
  check_commitment(request.model_digest(), "model digest");
  if (session.prepared.size() >= session.limits.max_prepared()) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "prepared-input budget exhausted");
  }

  auto model = load_model(request.problem_json(), session);
  const auto handle = std::to_string(session.worker_generation) + ":" +
                      std::to_string(session.next_handle++);
  const auto retained = decoded_size(model.source, session.limits) +
                        256 * (model.items.size() + model.targets.size());
  if (retained > session.limits.max_prepared_bytes() - session.retained_bytes) {
    throw Error(wire::ERROR_CODE_RESOURCE_LIMIT, "prepared-input decoded budget exhausted");
  }
  session.prepared.emplace(handle,
      PreparedInput{std::move(model), request.model_digest(), retained});
  session.retained_bytes += retained;

  auto& prepared = *response.mutable_prepared();
  prepared.set_handle(handle);
  prepared.set_model_digest(request.model_digest());
}

void solve_input(Session& session, const wire::Solve& request,
                 std::uint64_t request_id, wire::WorkerEnvelope& response) {
  check_commitment(request.model_digest(), "model digest");
  check_commitment(request.request_digest(), "request digest");
  const bool inline_model = !request.problem_json().empty();
  const bool prepared_model = !request.prepared_handle().empty();
  if (inline_model == prepared_model) {
    throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "Solve requires exactly one inline model or prepared handle");
  }

  std::optional<Model> owned_model;
  const Model* model;
  if (inline_model) {
    owned_model = load_model(request.problem_json(), session);
    model = &*owned_model;
  } else {
    const auto found = session.prepared.find(request.prepared_handle());
    if (found == session.prepared.end()) {
      throw Error(wire::ERROR_CODE_STALE_HANDLE, "prepared handle is unavailable in this worker generation");
    }
    if (found->second.digest != request.model_digest()) {
      throw Error(wire::ERROR_CODE_COMMITMENT_MISMATCH, "prepared model commitment differs from Solve");
    }
    model = &found->second.model;
  }

  const auto run_id = "dispatch-" + std::to_string(session.session_generation) + "-" +
                      std::to_string(session.worker_generation) + "-" + std::to_string(request_id);
  auto effective = request.options();
  if (request.has_remaining_wall_time_millis()) {
    effective.set_wall_time_millis(std::min(effective.wall_time_millis(),
                                          request.remaining_wall_time_millis()));
  }
  auto& finished = *response.mutable_finished();
  finished.set_model_digest(request.model_digest());
  finished.set_request_digest(request.request_digest());
  finished.set_backend_build_id(backend_build_id());
  *finished.mutable_effective_options() = effective;
  try {
    // Native solver libraries may print directly through C stdio. Keep those
    // diagnostics off the framed protocol even when they throw an exception.
    NativeOutputGuard output_guard;
    auto result = solve_model(*model, effective, request.hint_json(), run_id);
    finished.set_termination(result.termination);
    finished.set_assignment_json(result.assignment.dump());
    finished.mutable_evidence()->set_kind(result.evidence);
    finished.set_detail(result.detail);
  } catch (const Error& error) {
    finished.set_termination(error.code() == wire::ERROR_CODE_INTERNAL
                                 ? wire::TERMINATION_EXECUTION_FAILED : wire::TERMINATION_REJECTED);
    finished.set_error_code(error.code());
    finished.set_detail(bounded_detail(error.what(), session.limits.max_diagnostic_bytes()));
    finished.set_diagnostics_truncated(std::string_view(error.what()).size() > session.limits.max_diagnostic_bytes());
  } catch (const std::exception& error) {
    finished.set_termination(wire::TERMINATION_EXECUTION_FAILED);
    finished.set_error_code(wire::ERROR_CODE_INTERNAL);
    finished.set_detail(bounded_detail(error.what(), session.limits.max_diagnostic_bytes()));
    finished.set_diagnostics_truncated(std::string_view(error.what()).size() > session.limits.max_diagnostic_bytes());
  }
  // Verification fields deliberately remain absent: only the Rust evaluator owns them.
}

wire::WorkerEnvelope respond(Session& session, const wire::WorkerEnvelope& request) {
  wire::WorkerEnvelope response;
  response.mutable_protocol_version()->set_major(1);
  response.mutable_protocol_version()->set_minor(0);
  response.set_session_generation(request.session_generation());
  response.set_worker_generation(request.worker_generation());
  response.set_request_id(request.request_id());

  try {
    if (request.protocol_version().major() != 1 || request.protocol_version().minor() != 0) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_VERSION, "unsupported envelope protocol version");
    }
    if (request.request_id() == 0) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "request id must be nonzero");
    }
    if (session.initialized &&
        (request.session_generation() != session.session_generation ||
         request.worker_generation() != session.worker_generation)) {
      throw Error(wire::ERROR_CODE_WRONG_GENERATION, "request belongs to a different worker generation");
    }
    if (request.request_id() <= session.last_request_id) {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "request ids must strictly increase within a worker generation");
    }
    session.last_request_id = request.request_id();
    if (!session.initialized || request.has_hello()) {
      initialize_session(session, request, response);
      return response;
    }
    if (request.has_prepare()) {
      prepare_input(session, request.prepare(), response);
    } else if (request.has_solve()) {
      solve_input(session, request.solve(), request.request_id(), response);
    } else if (request.has_release()) {
      const auto found = session.prepared.find(request.release().handle());
      if (found == session.prepared.end()) {
        throw Error(wire::ERROR_CODE_STALE_HANDLE, "prepared handle is unavailable");
      }
      session.retained_bytes -= found->second.retained_bytes;
      session.prepared.erase(found);
      response.mutable_released()->set_handle(request.release().handle());
    } else if (request.has_cancel()) {
      throw Error(wire::ERROR_CODE_UNSUPPORTED_MODEL, "graceful cancellation is unavailable; provider must terminate the worker");
    } else {
      throw Error(wire::ERROR_CODE_INVALID_MESSAGE, "message body is not a worker request");
    }
  } catch (const Error& error) {
    response.clear_body();
    response.mutable_error()->set_code(error.code());
    response.mutable_error()->set_detail(bounded_detail(error.what(), session.initialized
        ? session.limits.max_diagnostic_bytes() : kMaximumDiagnosticBytes));
  } catch (const std::exception& error) {
    response.clear_body();
    response.mutable_error()->set_code(wire::ERROR_CODE_INTERNAL);
    response.mutable_error()->set_detail(bounded_detail(error.what(), session.initialized
        ? session.limits.max_diagnostic_bytes() : kMaximumDiagnosticBytes));
  }
  return response;
}

}  // namespace

Error::Error(wire::ErrorCode code, std::string message)
    : std::runtime_error(std::move(message)), code_(code) {}

wire::ErrorCode Error::code() const noexcept {
  return code_;
}

std::string backend_build_id() {
  return std::string(DISPATCH_BACKEND_BUILD_ID) + ":rebalancer:" +
         DISPATCH_REBALANCER_SOURCE_REVISION;
}

int run_worker(std::istream& input, std::ostream& output) {
  Session session;
  while (true) {
    const auto maximum_bytes = session.initialized ? session.limits.max_frame_bytes() : kHelloFrameBytes;
    auto request = read_frame(input, maximum_bytes);
    if (!request) {
      return 0;
    }
    auto response = respond(session, *request);
    write_frame(output, response, session.initialized ? session.limits.max_frame_bytes() : kHelloFrameBytes);
  }
}

}  // namespace dispatch::backend
