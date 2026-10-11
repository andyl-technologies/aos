set -eu
invocation=$(cat)
state=$(printf '%s' "$invocation" | jq -r .input.stateDir)
mkdir -p "$state"
receipt=$(printf '%s' "$invocation" | jq -r .input.authorized_input)
plan=$(printf '%s' "$invocation" | jq -r .input.committed_plan)
# Real dispatch creates fresh flat store objects, just as the initrd provider
# does. Their source files remain the image's original authorization and plan.
cp "$receipt" "$state/boot-handoff-authorization.json"
cp "$plan" "$state/boot-handoff-plan.json"
receipt=$("$AOS_HANDOFF_NIX_STORE" --store "local?root=$state/source-store" --add-fixed sha256 "$state/boot-handoff-authorization.json")
plan=$("$AOS_HANDOFF_NIX_STORE" --store "local?root=$state/source-store" --add-fixed sha256 "$state/boot-handoff-plan.json")
digest=$(sha256sum "$state/boot-handoff-authorization.json")
jq -n --arg receipt "$receipt" --arg plan "$plan" --arg digest "sha256:${digest%% *}" \
  '{resource:"fixture-committed-disk",source:"operator",authorized_input:$receipt,
    committed_plan:$plan,authorized_input_sha256:$digest}'
