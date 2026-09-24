#!/bin/sh
# The same immutable disk boots all five roles; the kernel command line picks
# the role. Only the active branch's overlay receives traffic and config writes.
set -eu

export PATH=@GUEST_PATH@
export HOME=/tmp

mkdir -p /proc /sys /dev /run /tmp /var/log/nginx /var/lib/nginx
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run

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

register_recovery_choices() {
  crucible-guest selectable register-discrete 1 recovery.strategy \
    1111111111111111111111111111111111111111111111111111111111111111 \
    1111111111111111111111111111111111111111111111111111111111111111=retain_and_probe \
    2222222222222222222222222222222222222222222222222222222222222222=withdraw_then_relearn \
    3333333333333333333333333333333333333333333333333333333333333333=restart_adjacency \
    4444444444444444444444444444444444444444444444444444444444444444=recompute_all \
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff=unsafe_short_circuit
  crucible-guest selectable register-u64 2 recovery.hold_down_us 0 5000000 1 20000 us
  crucible-guest selectable register-u64 3 recovery.retry_limit 0 12 1 3 count
  crucible-guest selectable register-bool 4 recovery.fast_reroute true
}

choose_recovery() {
  instance=$1
  sequence=$2
  selected=$(crucible-guest selectable choose-discrete "$sequence" \
    recovery.strategy "$instance" \
    1111111111111111111111111111111111111111111111111111111111111111 \
    2222222222222222222222222222222222222222222222222222222222222222 \
    3333333333333333333333333333333333333333333333333333333333333333 \
    4444444444444444444444444444444444444444444444444444444444444444 \
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
  case "$selected" in
    discrete=1111*) strategy=retain_and_probe ;;
    discrete=2222*) strategy=withdraw_then_relearn ;;
    discrete=3333*) strategy=restart_adjacency ;;
    discrete=4444*) strategy=recompute_all ;;
    discrete=ffff*) strategy=unsafe_short_circuit ;;
    *) echo "invalid strategy selection: $selected" >&2; exit 2 ;;
  esac

  hold=$(crucible-guest selectable choose-u64 "$((sequence + 1))" \
    recovery.hold_down_us "$instance" 0 5000000 1)
  retry=$(crucible-guest selectable choose-u64 "$((sequence + 2))" \
    recovery.retry_limit "$instance" 0 12 1)
  fast=$(crucible-guest selectable choose-bool "$((sequence + 3))" \
    recovery.fast_reroute "$instance")
  case "$hold" in
    u64=*) ;;
    *) echo "invalid hold-down selection: $hold" >&2; exit 2 ;;
  esac
  case "$retry" in
    u64=*) ;;
    *) echo "invalid retry selection: $retry" >&2; exit 2 ;;
  esac

  hold=${hold#u64=}
  retry=${retry#u64=}
  case "$fast" in
    boolean=true|boolean=false) ;;
    *) echo "invalid fast-reroute selection: $fast" >&2; exit 2 ;;
  esac
  fast=${fast#boolean=}
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
    wait "$envoy_pid" || :
    crucible-guest unreachable control-plane-crash-or-deadlock \
      'An Envoy router exited during the campaign'
    return
  fi

  register_recovery_choices
  python3 /etc/crucible/traffic.py control >/run/control.log 2>&1 &
  crucible-guest setup-complete
  wait_for_route
  while [ ! -e /run/converged ]; do sleep 0.1; done
  crucible-guest semantic-marker fault.transport.ready instance-1
  choose_recovery transport/one 5
  touch /run/transport-applied
  crucible-guest semantic-marker fault.transport.signaled instance-1
  while [ ! -e /run/followup-ready ]; do sleep 0.1; done
  crucible-guest semantic-marker fault.followup.ready instance-1
  choose_recovery followup/one 9
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
  wait "$server_pid"
}

case "$role" in
  router-*) run_router ;;
  traffic-east) run_east ;;
  traffic-west) exec python3 /etc/crucible/traffic.py west ;;
esac
