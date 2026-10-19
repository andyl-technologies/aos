# Outer host-time timeouts for the packaged five-node Envoy flights.
#
# Campaign policy owns the horizon of every attempt, so this check adds no
# wall-clock ceiling of its own. The timeout is derived from the same policy
# inputs the Rust flight asserts against: each progress-bounded attempt wait
# may take at most its attempt cap, the host time the policy horizon takes at
# the minimum guest rate (never less than the stall window), and a fixed floor
# covers the flight's work outside those waits. The flight's own stall and cap
# checks therefore report a failure before this timeout fires.
{lib}: let
  limits = builtins.fromTOML (
    builtins.readFile ../../crates/crucible-cli/tests/support/campaign_packaged_process/envoy_network/flight_limits.toml
  );

  positive = name: value:
    if builtins.isInt value && value > 0
    then value
    else throw "Envoy flight limit ${name} must be a positive integer";

  horizonPs = positive "policy_virtual_time_ps" limits.policy_virtual_time_ps;
  stallSeconds = positive "stall_window_seconds" limits.stall_window_seconds;
  minimumPsPerSecond = positive "minimum_virtual_ps_per_host_second" limits.minimum_virtual_ps_per_host_second;
  setupFloorSeconds = positive "setup_floor_seconds" limits.setup_floor_seconds;

  # Each wait's attempt cap: ceil(horizon / rate), raised to the stall window.
  attemptCapSeconds =
    lib.max stallSeconds
    ((horizonPs + minimumPsPerSecond - 1) / minimumPsPerSecond);

  flightTimeout = flight: let
    waits = positive "flights.${flight}.attempt_waits" limits.flights.${flight}.attempt_waits;
    seconds = setupFloorSeconds + waits * attemptCapSeconds;
  in
    # The inner cap of any single wait plus the floor must fit first.
    assert seconds >= attemptCapSeconds + setupFloorSeconds; seconds;
in {
  inherit attemptCapSeconds setupFloorSeconds;
  network = flightTimeout "network";
  knownFinding = flightTimeout "known-finding";
}
