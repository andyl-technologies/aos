{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignOperatorFlightContract",
  taskIds ? ["T-CAM-0.5" "T-CAM-4.8" "T-CAM-5.8" "T-CAM-7.7" "T-CAM-8.6" "T-CAM-9.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-operator-flight-contract";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.bash
        pkgs.coreutils
        pkgs.jq
        pkgs.openssl
        pkgs.rust
        pkgs.sed
      ]
      ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "validate-contract-and-recorder";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/campaign-operator-contract-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-harness \
            --test campaign_operator_flight_contract \
            -- --test-threads=1

          recorder=docs/rfcs/0020-crucible-campaigns/fixtures/campaign-manual-flight-recorder.sh
          run_recorder() {
            CAMPAIGN_FLIGHT_OPENSSL=${pkgs.openssl}/bin/openssl \
              CONFIG_SHELL=${pkgs.bash}/bin/bash \
              ${pkgs.bash}/bin/bash "$recorder" "$@"
          }
          evidence="$TMPDIR/operator-evidence"
          manifest="$TMPDIR/flight-manifest.json"
          roles='driver independent-reviewer campaign-model-owner qemu-boundary-owner storage-owner guest-api-owner operations-owner'
          for role in $roles; do
            ${pkgs.openssl}/bin/openssl genpkey -algorithm ED25519 \
              -out "$TMPDIR/$role.private.pem"
            ${pkgs.openssl}/bin/openssl pkey -in "$TMPDIR/$role.private.pem" \
              -pubout -out "$TMPDIR/$role.public.pem"
          done
          key_digest() {
            printf 'sha256:%s' "$(sha256sum "$TMPDIR/$1.public.pem" | cut -d ' ' -f 1)"
          }

          jq -n \
            --arg driver_key "$(key_digest driver)" \
            --arg reviewer_key "$(key_digest independent-reviewer)" \
            --arg campaign_model_key "$(key_digest campaign-model-owner)" \
            --arg qemu_boundary_key "$(key_digest qemu-boundary-owner)" \
            --arg storage_key "$(key_digest storage-owner)" \
            --arg guest_api_key "$(key_digest guest-api-owner)" \
            --arg operations_key "$(key_digest operations-owner)" \
            '{
            schema:"crucible.campaign-manual-flight-manifest.v1",
            gate:"gate:campaign-operator-acceptance",
            acceptance_state:"in-progress",
            flight_id:"fixture-operator-flight",
            runbook:"campaign-manual-flights-v1",
            layer:"operator-acceptance",
            intended_claims:["fixture-schema-validation"],
            planned_duration_hours:4,
            participants:{
              driver:{name:"Fixture Driver", implemented_feature:false},
              "independent-reviewer":{name:"Fixture Reviewer", can_challenge:true},
              observers:[]
            },
            provenance:{
              "build-id":"fixture-build", "source-revision":"fixture-revision",
              "source-tree":"fixture-tree", "qemu-identity":"fixture-qemu",
              "plugin-identity":"fixture-plugin",
              "product-artifact-identities":["fixture-product"],
              "host-profile":"fixture-host", "store-profile":"fixture-store"
            },
            scenario:"fixture-scenario", policy:"fixture-policy", seed:"fixture-seed",
            budget:{attempts:1, concurrency:1},
            starting_store_state:"fixture-generation",
            authorized_fault_actions:[],
            required_artifacts:[
              "runbook", "campaign-snapshots", "exact-reproduction", "thin-reproduction",
              "operational-telemetry", "resource-audit", "automated-gate-results", "final-result"
            ],
            required_result_fields:[
              "observed-result", "operator-task-checklist", "claim-checklist",
              "automated-gate-results", "defects", "documentation-changes", "resource-audit"
            ],
            sign_offs:{
              required_roles:[
                "driver", "independent-reviewer", "campaign-model-owner",
                "qemu-boundary-owner", "storage-owner", "guest-api-owner", "operations-owner"
              ],
              authorized_public_keys:{
                "driver":$driver_key, "independent-reviewer":$reviewer_key,
                "campaign-model-owner":$campaign_model_key,
                "qemu-boundary-owner":$qemu_boundary_key, "storage-owner":$storage_key,
                "guest-api-owner":$guest_api_key, "operations-owner":$operations_key
              },
              unsigned_result:"blocked"
            }
          }' > "$manifest"

          jq -n '{
            schema:"crucible.campaign-manual-flight-manifest.v1",
            gate:"gate:campaign-operator-acceptance", acceptance_state:"in-progress",
            planned_duration_hours:4, provenance:{"build-id":"fixture"},
            sign_offs:{required_roles:["driver"]}
          }' > "$TMPDIR/skeletal-manifest.json"
          if run_recorder init "$TMPDIR/skeletal-evidence" \
            "$TMPDIR/skeletal-manifest.json"; then
            echo 'skeletal evidence manifest unexpectedly passed' >&2
            exit 1
          fi

          jq '.gate = "gate:campaign-dogfood" |
            .layer = "dogfood" | .planned_duration_hours = 24' \
            "$manifest" > "$TMPDIR/dogfood-missing-participants.json"
          if run_recorder init \
            "$TMPDIR/dogfood-missing-participants" \
            "$TMPDIR/dogfood-missing-participants.json"; then
            echo 'dogfood manifest without handoff and release participants unexpectedly passed' >&2
            exit 1
          fi
          jq '.gate = "gate:campaign-dogfood" |
            .layer = "dogfood" | .planned_duration_hours = 24 |
            .participants["handoff-operator"] = {name:"Fixture Handoff Operator"} |
            .participants["release-owner"] = {name:"Fixture Release Owner"}' \
            "$manifest" > "$TMPDIR/dogfood-manifest.json"
          run_recorder init "$TMPDIR/dogfood-evidence" \
            "$TMPDIR/dogfood-manifest.json"

          run_recorder init "$evidence" "$manifest"
          run_recorder record "$evidence" status zero -- \
            ${pkgs.coreutils}/bin/true

          for artifact in runbook campaign-snapshots exact-reproduction thin-reproduction \
            operational-telemetry resource-audit automated-gate-results; do
            printf '{"fixture":"%s","result":"prerequisite-only"}\n' "$artifact" \
              > "$TMPDIR/$artifact.json"
            run_recorder capture "$evidence" "$artifact" \
              "$TMPDIR/$artifact.json"
          done
          jq -n '{
            schema:"crucible.campaign-manual-flight-result.v1",
            "observed-result":"observation",
            "operator-task-checklist":[
              {id:"fixture-task", outcome:"observation", evidence:"schema-only fixture"}
            ],
            "claim-checklist":[
              {id:"fixture-claim", outcome:"observation", evidence:"no acceptance claim"}
            ],
            "automated-gate-results":[
              {gate:"fixture", outcome:"pass", evidence:"contract validator"}
            ],
            defects:[
              {id:"fixture-only", disposition:"resolved", evidence:"not a manual flight"}
            ],
            "documentation-changes":["fixture contract exercised"],
            "resource-audit":{complete:true, "unexplained-resources":[]},
            "sign-off-status":"pending"
          }' > "$TMPDIR/final-result.json"
          run_recorder capture "$evidence" final-result \
            "$TMPDIR/final-result.json"
          run_recorder seal "$evidence"

          first_signature=
          for role in $roles; do
            statement="$TMPDIR/$role.statement.json"
            signature="$TMPDIR/$role.signature"
            signer="Fixture $role"
            run_recorder statement "$evidence" "$role" \
              "$signer" "$TMPDIR/$role.public.pem" "$statement"

            if test "$role" = independent-reviewer; then
              if run_recorder statement "$evidence" "$role" \
                "$signer" "$TMPDIR/driver.public.pem" "$TMPDIR/reused-key.statement"; then
                echo 'public key reuse unexpectedly passed' >&2
                exit 1
              fi
              if run_recorder attest "$evidence" "$role" \
                "$signer" "$TMPDIR/$role.public.pem" "$statement" "$first_signature"; then
                echo 'signature reuse unexpectedly passed' >&2
                exit 1
              fi
            fi

            ${pkgs.openssl}/bin/openssl pkeyutl -sign \
              -inkey "$TMPDIR/$role.private.pem" -rawin -in "$statement" -out "$signature"
            if test "$role" = driver; then
              first_signature=$signature
              jq '.signer = "Tampered Signer"' "$statement" > "$TMPDIR/tampered.statement"
              if run_recorder attest "$evidence" "$role" \
                "$signer" "$TMPDIR/$role.public.pem" "$TMPDIR/tampered.statement" "$signature"; then
                echo 'statement tamper unexpectedly passed' >&2
                exit 1
              fi
            fi
            run_recorder attest "$evidence" "$role" \
              "$signer" "$TMPDIR/$role.public.pem" "$statement" "$signature"
          done
          run_recorder verify "$evidence"

          cp -R "$evidence" "$TMPDIR/tampered-evidence"
          jq '.signer = "Tampered Signer"' \
            "$TMPDIR/tampered-evidence/attestations/driver.statement.json" \
            > "$TMPDIR/tampered-evidence/attestations/driver.statement.tmp"
          mv "$TMPDIR/tampered-evidence/attestations/driver.statement.tmp" \
            "$TMPDIR/tampered-evidence/attestations/driver.statement.json"
          if run_recorder verify "$TMPDIR/tampered-evidence"; then
            echo 'stored statement tamper unexpectedly passed' >&2
            exit 1
          fi
        '';
      }
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p "$out"
          printf '%s\n' '${attrPath}' > "$out/attr-path"
          printf '%s\n' '${lib.concatStringsSep "," taskIds}' > "$out/task-ids"
          printf '%s\n' 'manual-evidence-required' > "$out/acceptance-state"
        '';
      }
    ];

    meta.description = "Validates RFC-0020 operator-flight schemas and evidence recorder";
  }
