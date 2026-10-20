set -eu
invocation=$(cat)
state=$(printf '%s' "$invocation" | jq -r .input.stateDir)
mkdir -p "$state"
printf '%s' "$invocation" > "$state/invocation.json"
invocation="$state/invocation.json"
if jq -e '.input | has("authorized_input")' "$invocation" >/dev/null; then
  receipt=$(jq -r .input.authorized_input "$invocation")
  digest=$(sha256sum "$receipt")
  jq --arg digest "sha256:${digest%% *}" '.input | del(.stateDir) + {
    resource:"fixture-committed-disk",source:"operator",authorized_input_sha256:$digest
  }' "$invocation"
  exit 0
fi
value=$(jq -r .input.value "$invocation")
outputs() {
  jq -n --arg value "$value" '{value:$value,resource:"fixture-host-state"}'
}
case "$1" in
  apply)
    count=0
    if [ -f "$state/count" ]; then count=$(cat "$state/count"); fi
    printf '%s\n' "$((count + 1))" > "$state/count"
    printf '%s' "$value" > "$state/value"
    if jq -e .input.failAfterWrite "$invocation" >/dev/null && [ ! -f "$state/failed-once" ]; then
      touch "$state/failed-once"
      exit 1
    fi
    outputs
    ;;
  observe)
    if [ -f "$state/value" ] && [ "$(cat "$state/value")" = "$value" ]; then
      outputs | jq '{status:"current",outputs:.}'
    else
      jq -n '{status:"retry-safe"}'
    fi
    ;;
  remove) rm -f "$state/value"; jq -n '{}' ;;
  *) exit 1 ;;
esac
