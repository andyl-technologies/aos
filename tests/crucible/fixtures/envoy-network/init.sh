#!/bin/sh
# The same immutable disk boots all five roles; the kernel command line picks
# the role. Only the active branch's overlay receives traffic and config writes.
set -eu
# The serial breadcrumb remains visible if init stops before the marker device works.
echo CRUCIBLE-ENVOY-INIT-ENTRY

export PATH=@GUEST_PATH@
export HOME=/tmp

mkdir -p /proc /sys /dev /run /tmp /var/log/nginx /var/lib/nginx
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
crucible-guest event boot.init-mounted

ip link set lo up
ip link set eth0 up

cmdline=" $(cat /proc/cmdline) "
case "$cmdline" in
  *" network.role=router-a "*) role=router-a; address=10.77.0.2 ;;
  *" network.role=router-b "*) role=router-b; address=10.77.0.3 ;;
  *" network.role=router-c "*) role=router-c; address=10.77.0.4 ;;
  *" network.role=traffic-west "*) role=traffic-west; address=10.77.0.1 ;;
  *" network.role=traffic-east "*) role=traffic-east; address=10.77.0.5 ;;
  *) echo "missing network.role" >&2; exit 2 ;;
esac
ip address add "$address/24" dev eth0
crucible-guest event boot.network-configured

control_url=http://10.77.0.2:9090
if [ "$role" = traffic-east ]; then
  # East has a direct link to C, but no direct path to A's control listener.
  control_url=http://10.77.0.4:8080/control
fi

probe() {
  curl --noproxy '*' --connect-timeout 1 --max-time 4 --silent --show-error \
    --fail http://10.77.0.2:8080/probe
}

wait_for_route() {
  attempts=0
  until result=$(probe 2>/dev/null) && [ "$result" = 'east::1:1:1' ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      echo "initial Envoy route failed to converge" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_local_health() {
  attempts=0
  until curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent \
    --show-error --fail "http://$address:8080/healthz" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      echo "$role did not become healthy" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_control_boundary() {
  boundary=$1
  attempts=0
  until status=$(curl --noproxy '*' --connect-timeout 1 --max-time 2 \
    --silent --output /dev/null --write-out '%{http_code}' \
    "$control_url/$boundary" 2>/dev/null) \
    && [ "$status" = 204 ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      echo "$role did not observe $boundary" >&2
      return 1
    fi
    sleep 1
  done
}

acknowledge_control_boundary() {
  phase=$1
  attempts=0
  until curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent \
    --show-error --fail --request POST --data '' \
    "$control_url/ready/$phase/$role" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      echo "$role could not acknowledge $phase readiness" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_peer_acks() {
  phase=$1
  for peer in router-b router-c traffic-east; do
    attempts=0
    until [ -e "/run/ready-$phase-$peer" ]; do
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 90 ]; then
        echo "router-a did not receive $phase readiness from $peer" >&2
        return 1
      fi
      sleep 1
    done
  done
}

start_envoy() {
  strategy=$1
  retry_limit=$2
  fast_reroute=$3
  /etc/crucible/render-envoy.sh "$role" "$strategy" /run/envoy.json \
    "$retry_limit" "$fast_reroute"
  envoy --mode validate --config-path /run/envoy.json >/run/envoy-validate.log 2>&1
  envoy --disable-hot-restart --config-path /run/envoy.json \
    --log-level warning >/run/envoy.log 2>&1 &
  envoy_pid=$!
}

stop_envoy() {
  kill "$envoy_pid"
  wait "$envoy_pid" || :
}

recovery_group() {
  group_verb=$1
  shift
  crucible-guest selectable "$group_verb" "$@" router-a envoy.recovery 1 \
    'discrete@recovery.strategy@1111111111111111111111111111111111111111111111111111111111111111@1111111111111111111111111111111111111111111111111111111111111111=retain_and_probe,2222222222222222222222222222222222222222222222222222222222222222=withdraw_then_relearn,3333333333333333333333333333333333333333333333333333333333333333=restart_adjacency,4444444444444444444444444444444444444444444444444444444444444444=recompute_all,ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff=unsafe_short_circuit' \
    'u64@recovery.hold_down_us@0@5000000@1@20000@us' \
    'u64@recovery.retry_limit@0@12@1@3@count' \
    'bool@recovery.fast_reroute@true'
}

register_recovery_choices() {
  recovery_group register-group 1 recovery.response
}

probe_primary_path() {
  phase=$1
  # A direct request to B traverses A-B and B-C while the selected fault is
  # active, even when the recovery tuple will move A onto the backup route.
  if curl --noproxy '*' --connect-timeout 1 --max-time 1 --silent \
    --output /dev/null --fail http://10.77.0.3:8080/probe; then
    outcome=served
  else
    outcome=disrupted
  fi
  crucible-guest event network.primary.probe "phase=$phase" "outcome=$outcome"
  crucible-guest semantic-marker "fault.$phase.primary-probed" instance-1
}

choose_recovery() {
  instance=$1
  sequence=$2
  phase=$3
  selected=$(recovery_group choose-group "$sequence" recovery.response "$instance")
  strategy_id=
  hold=
  retry=
  fast=
  while IFS='=' read -r member value; do
    case "$member:$value" in
      recovery.strategy:discrete:*) strategy_id=${value#discrete:} ;;
      recovery.hold_down_us:u64:*) hold=${value#u64:} ;;
      recovery.retry_limit:u64:*) retry=${value#u64:} ;;
      recovery.fast_reroute:boolean:*) fast=${value#boolean:} ;;
      *) echo "invalid recovery group member: $member=$value" >&2; exit 2 ;;
    esac
  done <<EOF
$selected
EOF
  case "$strategy_id" in
    1111111111111111111111111111111111111111111111111111111111111111) strategy=retain_and_probe ;;
    2222222222222222222222222222222222222222222222222222222222222) strategy=withdraw_then_relearn ;;
    3333333333333333333333333333333333333333333333333333333333333333) strategy=restart_adjacency ;;
    4444444444444444444444444444444444444444444444444444444444444444) strategy=recompute_all ;;
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) strategy=unsafe_short_circuit ;;
    *) echo "invalid strategy selection: $strategy_id" >&2; exit 2 ;;
  esac
  if [ -z "$hold" ] || [ -z "$retry" ] || [ -z "$fast" ]; then
    echo 'incomplete recovery group selection' >&2
    exit 2
  fi
  probe_primary_path "$phase"
  hold_seconds=$(printf '%d.%06d' "$((hold / 1000000))" "$((hold % 1000000))")
  sleep "$hold_seconds"

  # A selected response alters the live proxy. Retain/probe keeps the current
  # process and route; all other responses restart it with a new bootstrap.
  if [ "$strategy" != retain_and_probe ] || [ "$retry" != 3 ] \
    || [ "$fast" != true ]; then
    stop_envoy
    start_envoy "$strategy" "$retry" "$fast"
  fi
  crucible-guest event recovery.selection "strategy=$strategy" \
    "retry=$retry" "fast=$fast" "hold_us=$hold"
}

run_router() {
  start_envoy retain_and_probe 3 true
  if [ "$role" != router-a ]; then
    crucible-guest setup-complete
    wait_for_local_health
    crucible-guest event boot.local-healthy
    wait_for_control_boundary converged
    acknowledge_control_boundary transport
    crucible-guest event fault.transport.ready
    wait_for_control_boundary followup-ready
    acknowledge_control_boundary followup
    crucible-guest event fault.followup.ready
    wait "$envoy_pid" || :
    crucible-guest unreachable control-plane-crash-or-deadlock \
      'An Envoy router exited during the campaign'
    return
  fi

  register_recovery_choices
  python3 /etc/crucible/traffic.py control >/run/control.log 2>&1 &
  crucible-guest setup-complete
  crucible-guest event boot.route-probing
  wait_for_route
  crucible-guest event boot.route-ready
  while [ ! -e /run/converged ]; do sleep 0.1; done
  wait_for_peer_acks transport
  crucible-guest event fault.transport.ready
  choose_recovery transport/one 1 transport
  touch /run/transport-applied
  crucible-guest semantic-marker fault.transport.signaled instance-1
  while [ ! -e /run/followup-ready ]; do sleep 0.1; done
  wait_for_peer_acks followup
  crucible-guest event fault.followup.ready
  choose_recovery followup/one 2 followup
  crucible-guest sometimes selection-acknowledged-once \
    'Both guest response envelopes were acknowledged' 1
  wait "$envoy_pid" || :
  crucible-guest unreachable control-plane-crash-or-deadlock \
    'Envoy router A exited during the campaign'
}

run_east() {
  nginx -c /etc/nginx/nginx.conf -g 'daemon off; master_process off;' &
  server_pid=$!
  crucible-guest setup-complete
  wait_for_local_health
  crucible-guest event boot.local-healthy
  wait_for_control_boundary converged
  acknowledge_control_boundary transport
  crucible-guest event fault.transport.ready
  wait_for_control_boundary followup-ready
  acknowledge_control_boundary followup
  crucible-guest event fault.followup.ready
  wait "$server_pid"
}

crucible-guest event boot.service-starting
case "$role" in
  router-*) run_router ;;
  traffic-east) run_east ;;
  traffic-west) exec python3 /etc/crucible/traffic.py west ;;
esac
