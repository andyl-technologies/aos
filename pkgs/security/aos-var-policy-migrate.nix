##! aos-var-policy-migrate — recovery-authorized TPM enrollment replacement
{
  mkDerivation,
  bash,
  coreutils,
  cryptsetup,
  jq,
  systemd,
  util-linux,
}:
mkDerivation {
  pname = "aos-var-policy-migrate";
  version = "1";
  src = null;

  buildDeps = [];
  runtimeDeps = [
    coreutils
    cryptsetup
    jq
    systemd
    util-linux
  ];
  propagatedDeps = [];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cat > $out/bin/aos-var-policy-migrate <<'SCRIPT'
        #!${bash}/bin/bash
        set -euo pipefail

        usage() {
          echo "usage: aos-var-policy-migrate DEVICE RECOVERY_KEY PCR_PUBLIC_KEY PCR_SIGNATURE EVIDENCE" >&2
          exit 2
        }

        [ "$#" -eq 5 ] || usage
        device=$1
        recovery_key=$2
        public_key=$3
        signature=$4
        evidence=$5

        cs=${cryptsetup}/sbin/cryptsetup
        enroll=${systemd}/bin/systemd-cryptenroll
        jq=${jq}/bin/jq
        plugin_dir=${systemd}/lib/cryptsetup

        [ -b "$device" ] || { echo "not a block device: $device" >&2; exit 1; }
        [ -r "$recovery_key" ] || { echo "recovery key is not readable" >&2; exit 1; }
        [ -r "$public_key" ] || { echo "PCR public key is not readable" >&2; exit 1; }
        [ -r "$signature" ] || { echo "PCR signature is not readable" >&2; exit 1; }
        [ "$signature" = /run/systemd/tpm2-pcr-signature.json ] || {
          echo "PCR signature must use systemd's canonical runtime path" >&2
          exit 1
        }

        mkdir -p /run/lock
        exec 9>/run/lock/aos-var-policy-migrate.lock
        ${util-linux}/bin/flock -n 9 \
          || { echo "another /var policy migration is active" >&2; exit 1; }

        work=$(${coreutils}/bin/mktemp -d /run/aos-var-policy-migrate.XXXXXX)
        trap '${coreutils}/bin/rm -rf "$work"' EXIT
        before=$work/before.json
        after_enroll=$work/after-enroll.json
        after=$work/after.json
        record=$work/record.json

        publish_record() {
          evidence_dir=$(${coreutils}/bin/dirname "$evidence")
          mkdir -p "$evidence_dir"
          evidence_tmp=$(${coreutils}/bin/mktemp "$evidence_dir/.aos-var-policy-migration.XXXXXX")
          ${coreutils}/bin/cp "$record" "$evidence_tmp"
          chmod 0600 "$evidence_tmp"
          ${coreutils}/bin/sync "$evidence_tmp"
          ${coreutils}/bin/mv "$evidence_tmp" "$evidence"
          ${coreutils}/bin/sync -f "$evidence_dir"
        }

        metadata_hash() {
          ${coreutils}/bin/sha256sum "$1" | ${coreutils}/bin/cut -d' ' -f1
        }

        token_contract_filter='
          .value.type == "systemd-tpm2"
          and (.value.keyslots | type == "array" and length == 1)
          and (.value.keyslots[0] | type == "string" and test("^[0-9]+$"))
          and ((.value["tpm2-pcrs"] | sort) == [7, 12])
          and ((.value.tpm2_pubkey_pcrs | sort) == [11])
          and (.value.tpm2_pubkey == $public_key)
          and (.value["tpm2-pcr-bank"] == "sha256")
          and (.value["tpm2-blob"] != null)
          and (.value["tpm2-policy-hash"] != null)
          and ((.value["tpm2-pin"] // false) == false)
          and ((.value.tpm2_pcrlock // false) == false)
          and (.value.tpm2_salt == null)
        '

        exact_target_bindings() {
          "$jq" -r --argjson public_key "$public_key_json" "
            .tokens | to_entries[]
            | select($token_contract_filter)
            | \"\(.key):\(.value.keyslots[0])\"
          " "$1"
        }

        verify_target() {
          metadata=$1
          token_id=$2
          keyslot=$3
          binding=$(exact_target_bindings "$metadata")
          [ "$binding" = "$token_id:$keyslot" ] || {
            echo "target TPM token no longer has the required policy" >&2
            exit 1
          }
          "$cs" open \
            --test-passphrase \
            --token-only \
            --token-id "$token_id" \
            --external-tokens-path "$plugin_dir" \
            "$device"
        }

        verify_recovery() {
          metadata=$1
          token_id=$2
          keyslot=$3
          "$jq" -e --arg token "$token_id" --arg slot "$keyslot" '
            .tokens[$token].type == "systemd-recovery"
            and .tokens[$token].keyslots == [$slot]
          ' "$metadata" >/dev/null
          "$cs" open \
            --test-passphrase \
            --key-slot "$keyslot" \
            --key-file "$recovery_key" \
            "$device"
        }

        "$cs" isLuks "$device"
        "$cs" luksDump --dump-json-metadata "$device" > "$before"
        "$jq" -e '.tokens | type == "object"' "$before" >/dev/null
        luks_uuid=$("$cs" luksUUID "$device")
        public_key_json=$("$jq" -Rs '@base64' "$public_key")
        public_key_hash=$(${coreutils}/bin/sha256sum "$public_key" | ${coreutils}/bin/cut -d' ' -f1)

        recovery_bindings=$("$jq" -r '
          .tokens | to_entries[]
          | select(.value.type == "systemd-recovery")
          | select(.value.keyslots | type == "array" and length == 1)
          | select(.value.keyslots[0] | type == "string" and test("^[0-9]+$"))
          | "\(.key):\(.value.keyslots[0])"
        ' "$before")
        case "$recovery_bindings" in
          ""|*' '*|*$'\n'*)
            echo "migration requires exactly one single-keyslot recovery token" >&2
            exit 1
            ;;
        esac
        recovery_token_id=''${recovery_bindings%%:*}
        recovery_slot=''${recovery_bindings#*:}
        verify_recovery "$before" "$recovery_token_id" "$recovery_slot"

        state=
        prepared_metadata_changed=0
        if [ -e "$evidence" ]; then
          "$jq" -e \
            --arg schema "aos.var-tpm-policy-migration/v1" \
            --arg uuid "$luks_uuid" \
            --arg public_key_sha256 "$public_key_hash" \
            --arg recovery_token_id "$recovery_token_id" \
            --arg recovery_slot "$recovery_slot" '
              .schema == $schema
              and .luks_uuid == $uuid
              and .public_key_sha256 == $public_key_sha256
              and .recovery_token_id == ($recovery_token_id | tonumber)
              and .recovery_keyslot == ($recovery_slot | tonumber)
              and .signed_pcrs == [11]
              and .pinned_pcrs == [7, 12]
              and .recovery_authorized == true
              and (.old_metadata_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
              and (.old_token_ids | type == "array" and . == (unique | sort))
              and (.old_keyslot_ids | type == "array" and . == (unique | sort))
              and if .state == "prepared" then
                (keys | sort) == ([
                  "schema", "state", "luks_uuid", "old_metadata_sha256",
                  "old_token_ids", "old_keyslot_ids", "public_key_sha256",
                  "signed_pcrs", "pinned_pcrs", "recovery_token_id",
                  "recovery_keyslot", "recovery_authorized"
                ] | sort)
              elif .state == "verified" then
                (keys | sort) == ([
                  "schema", "state", "luks_uuid", "old_metadata_sha256",
                  "old_token_ids", "old_keyslot_ids", "public_key_sha256",
                  "signed_pcrs", "pinned_pcrs", "recovery_token_id",
                  "recovery_keyslot", "recovery_authorized",
                  "enrolled_metadata_sha256", "verified_tpm_token_id",
                  "verified_tpm_keyslot", "planned_old_tpm_keyslots"
                ] | sort)
                and (.enrolled_metadata_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
                and (.verified_tpm_token_id | type == "number")
                and (.verified_tpm_keyslot | type == "number")
                and (.planned_old_tpm_keyslots | type == "array" and . == (unique | sort))
              elif .state == "complete" then
                (keys | sort) == ([
                  "schema", "state", "luks_uuid", "old_metadata_sha256",
                  "old_token_ids", "old_keyslot_ids", "public_key_sha256",
                  "signed_pcrs", "pinned_pcrs", "recovery_token_id",
                  "recovery_keyslot", "recovery_authorized",
                  "enrolled_metadata_sha256", "verified_tpm_token_id",
                  "verified_tpm_keyslot", "planned_old_tpm_keyslots",
                  "new_metadata_sha256"
                ] | sort)
                and (.enrolled_metadata_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
                and (.new_metadata_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
                and (.verified_tpm_token_id | type == "number")
                and (.verified_tpm_keyslot | type == "number")
                and (.planned_old_tpm_keyslots | type == "array" and . == (unique | sort))
              else false
              end
            ' "$evidence" >/dev/null
          state=$("$jq" -r .state "$evidence")
          ${coreutils}/bin/cp "$evidence" "$record"
          if [ "$state" = prepared ] \
            && [ "$(metadata_hash "$before")" != "$("$jq" -r .old_metadata_sha256 "$record")" ]; then
            prepared_metadata_changed=1
          fi
        else
          before_hash=$(metadata_hash "$before")
          before_token_ids=$("$jq" -c '[.tokens | keys[] | tonumber] | sort' "$before")
          before_keyslot_ids=$("$jq" -c '[.keyslots | keys[] | tonumber] | sort' "$before")
          "$jq" -n \
            --arg schema "aos.var-tpm-policy-migration/v1" \
            --arg state prepared \
            --arg luks_uuid "$luks_uuid" \
            --arg before_sha256 "$before_hash" \
            --argjson before_token_ids "$before_token_ids" \
            --argjson before_keyslot_ids "$before_keyslot_ids" \
            --arg public_key_sha256 "$public_key_hash" \
            --arg recovery_token_id "$recovery_token_id" \
            --arg recovery_slot "$recovery_slot" \
            '{
              schema: $schema,
              state: $state,
              luks_uuid: $luks_uuid,
              old_metadata_sha256: $before_sha256,
              old_token_ids: $before_token_ids,
              old_keyslot_ids: $before_keyslot_ids,
              public_key_sha256: $public_key_sha256,
              signed_pcrs: [11],
              pinned_pcrs: [7, 12],
              recovery_token_id: ($recovery_token_id | tonumber),
              recovery_keyslot: ($recovery_slot | tonumber),
              recovery_authorized: true
            }' > "$record"
          publish_record
          state=prepared
        fi

        if [ "$state" = complete ]; then
          target_id=$("$jq" -r '.verified_tpm_token_id' "$record")
          target_slot=$("$jq" -r '.verified_tpm_keyslot' "$record")
          [ "$(metadata_hash "$before")" = "$("$jq" -r '.new_metadata_sha256' "$record")" ] || {
            echo "completed migration evidence does not match current LUKS metadata" >&2
            exit 1
          }
          verify_target "$before" "$target_id" "$target_slot"
          verify_recovery "$before" "$recovery_token_id" "$recovery_slot"
          exit 0
        fi

        if [ "$state" = verified ]; then
          target_id=$("$jq" -r '.verified_tpm_token_id' "$record")
          target_slot=$("$jq" -r '.verified_tpm_keyslot' "$record")
          ${coreutils}/bin/cp "$before" "$after_enroll"
        else
          target_bindings=$(exact_target_bindings "$before")
          case "$target_bindings" in
            *' '*|*$'\n'*)
              echo "multiple TPM tokens implement the requested policy" >&2
              exit 1
              ;;
          esac
          if [ -n "$target_bindings" ]; then
            target_id=''${target_bindings%%:*}
            target_slot=''${target_bindings#*:}
            if [ "$prepared_metadata_changed" = 1 ]; then
              "$jq" -e \
                --arg target "$target_id" \
                --arg slot "$target_slot" \
                --slurpfile record "$record" '
                  ([.tokens | keys[] | tonumber] | sort)
                    == ($record[0].old_token_ids + [($target | tonumber)] | unique | sort)
                  and ([.keyslots | keys[] | tonumber] | sort)
                    == ($record[0].old_keyslot_ids + [($slot | tonumber)] | unique | sort)
                ' "$before" >/dev/null || {
                echo "prepared migration metadata changed outside the enrolled target" >&2
                exit 1
              }
            fi
            ${coreutils}/bin/cp "$before" "$after_enroll"
          else
          [ "$prepared_metadata_changed" = 0 ] || {
            echo "prepared migration metadata changed without a recoverable target" >&2
            exit 1
          }
          "$enroll" \
            --unlock-key-file="$recovery_key" \
            --tpm2-device=auto \
            --tpm2-public-key="$public_key" \
            --tpm2-public-key-pcrs=11 \
            --tpm2-pcrs=7+12 \
            --tpm2-signature="$signature" \
            "$device"
          "$cs" luksDump --dump-json-metadata "$device" > "$after_enroll"
            target_bindings=$(exact_target_bindings "$after_enroll")
            case "$target_bindings" in
              ""|*' '*|*$'\n'*)
                echo "enrollment did not create exactly one requested TPM policy" >&2
                exit 1
                ;;
            esac
            target_id=''${target_bindings%%:*}
            target_slot=''${target_bindings#*:}
            "$jq" -e --arg token "$target_id" --arg slot "$target_slot" '
              (.tokens | has($token) | not)
              and (.keyslots | has($slot) | not)
              and ([.tokens[]?.keyslots[]? | select(. == $slot)] | length) == 0
            ' "$before" >/dev/null || {
              echo "enrollment reused an existing token ID or keyslot" >&2
              exit 1
            }
          fi

          verify_target "$after_enroll" "$target_id" "$target_slot"
          [ "$target_slot" != "$recovery_slot" ] || {
            echo "TPM and recovery tokens share a retained keyslot" >&2
            exit 1
          }

          old_slots=$("$jq" -r --arg target "$target_id" '
            .tokens as $tokens
            | [$tokens | to_entries[]
                | select(.value.type == "systemd-tpm2" and .key != $target)] as $old
            | if all($old[];
                (.value.keyslots | type == "array" and length == 1)
                and (.value.keyslots[0] | type == "string" and test("^[0-9]+$")))
              then [$old[].value.keyslots[0]]
              else error("malformed old TPM keyslot binding")
              end as $slots
            | if ($slots | length) != ($slots | unique | length)
              then error("shared TPM keyslot")
              elif all($slots[] as $slot;
                ([$tokens[] | .keyslots[]? | select(. == $slot)] | length) == 1)
              then $slots | sort_by(tonumber) | join(",")
              else error("old TPM keyslot is shared with another token")
              end
          ' "$after_enroll")
          case ",$old_slots," in
            *,"$target_slot",*|*,"$recovery_slot",*)
              echo "planned cleanup overlaps a retained keyslot" >&2
              exit 1
              ;;
          esac
          after_enroll_hash=$(metadata_hash "$after_enroll")
          "$jq" \
            --arg state verified \
            --arg after_enroll_sha256 "$after_enroll_hash" \
            --arg target_id "$target_id" \
            --arg target_slot "$target_slot" \
            --arg old_slots "$old_slots" '
              .state = $state
              | .enrolled_metadata_sha256 = $after_enroll_sha256
              | .verified_tpm_token_id = ($target_id | tonumber)
              | .verified_tpm_keyslot = ($target_slot | tonumber)
              | .planned_old_tpm_keyslots = (if $old_slots == "" then [] else ($old_slots | split(",") | map(tonumber)) end)
            ' "$record" > "$work/verified.json"
          ${coreutils}/bin/mv "$work/verified.json" "$record"
          publish_record
          state=verified
          if [ "''${AOS_VAR_POLICY_MIGRATE_STOP_AFTER_VERIFY:-}" = 1 ]; then
            echo "migration paused after durable target verification" >&2
            exit 75
          fi
        fi

        verify_target "$after_enroll" "$target_id" "$target_slot"
        verify_recovery "$after_enroll" "$recovery_token_id" "$recovery_slot"
        current_slots=$("$jq" -r --arg target "$target_id" '
          .tokens as $tokens
          | [$tokens | to_entries[]
              | select(.value.type == "systemd-tpm2" and .key != $target)] as $old
          | if all($old[];
              (.value.keyslots | type == "array" and length == 1)
              and (.value.keyslots[0] | type == "string" and test("^[0-9]+$")))
            then [$old[].value.keyslots[0]]
            else error("malformed current TPM keyslot binding")
            end as $slots
          | if ($slots | length) != ($slots | unique | length)
            then error("shared current TPM keyslot")
            elif all($slots[] as $slot;
              ([$tokens[] | .keyslots[]? | select(. == $slot)] | length) == 1)
            then $slots | sort_by(tonumber) | join(",")
            else error("current TPM keyslot is shared with another token")
            end
        ' "$after_enroll")
        "$jq" -e --arg current "$current_slots" '
          ($current | if . == "" then [] else split(",") | map(tonumber) end) as $current_slots
          | ($current_slots - .planned_old_tpm_keyslots | length) == 0
        ' "$record" >/dev/null || {
          echo "TPM cleanup set changed after verification" >&2
          exit 1
        }
        if [ -n "$current_slots" ]; then
          "$enroll" \
            --unlock-key-file="$recovery_key" \
            --wipe-slot="$current_slots" \
            "$device"
        fi

        "$cs" luksDump --dump-json-metadata "$device" > "$after"
        "$jq" -e --arg target "$target_id" --arg recovery "$recovery_token_id" '
          ([.tokens | to_entries[] | select(.value.type == "systemd-tpm2")] | length) == 1
          and .tokens[$target].type == "systemd-tpm2"
          and ([.tokens | to_entries[] | select(.value.type == "systemd-recovery")] | length) == 1
          and .tokens[$recovery].type == "systemd-recovery"
        ' "$after" >/dev/null
        verify_target "$after" "$target_id" "$target_slot"
        verify_recovery "$after" "$recovery_token_id" "$recovery_slot"

        after_hash=$(metadata_hash "$after")
        "$jq" \
          --arg state complete \
          --arg after_sha256 "$after_hash" \
          '.state = $state | .new_metadata_sha256 = $after_sha256' \
          "$record" > "$work/complete.json"
        ${coreutils}/bin/mv "$work/complete.json" "$record"
        publish_record
        SCRIPT
        chmod 0755 $out/bin/aos-var-policy-migrate
      '';
    }
  ];

  meta = {
    description = "Migrate /var TPM enrollment to the PCR-7+12 policy";
    license = "Apache-2.0";
  };
}
