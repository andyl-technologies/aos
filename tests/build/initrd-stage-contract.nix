# Real-archive qualification for the normal initrd stage and handoff contract.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixtureAuthorities = {pkgs, ...}: {
    # This real-archive fixture enables the complete canonical-release input
    # set. Give that qualification-only assembly room without weakening the
    # production server's 128 MiB release admission budget.
    aos.image.budgets.maxInitrdMiB = lib.mkForce 144;

    aos.profiles.canonicalRelease = {
      enable = true;
      publicAuthorities = {
        secureBootCertificate = "${pkgs.secure-boot-test-keys}/db.crt";
        moduleSigningCertificate = "${pkgs.secure-boot-test-keys}/modsign.crt";
        pcrPolicyKey = "${pkgs.secure-boot-test-keys}/pcr.pem";
        firmwareEnrollment = "${pkgs.secure-boot-test-keys}";
      };
    };

    # Exercise exact duplicate normalization and one root used in two roles.
    aos.boot.initrd.extraPackages = [
      pkgs.coreutils
      pkgs.coreutils
      pkgs.ability-package-smoke
    ];
    environment.systemPackages = [pkgs.ability-package-smoke];
  };
  system = mkSystem {
    modules = [../../systems/server.nix fixtureAuthorities];
  };
  securityDisabledSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.security.verity.enable = lib.mkForce false;}
    ];
  };
  initrd = system.config.system.build.initrd;
  initrdAbilities = system.config.system.build.initrdStaticAbilityContract;
  hostAbilities = system.config.system.build.staticAbilityContract;
  assembly = system.config.system.build.unsignedImageAssembly;
  baseLib = system.config.aos.config.evalAtBoot.baseLib;
  frozenHostAbilities = baseLib.passthru.frozenArtifacts."host-static-ability-contract";
  moduleAbi = system.config.aos.system.moduleAbi;
  emptyHost = builtins.toFile "static-contract-runtime-host.nix" "{}\n";
  emptyFacts = builtins.toFile "static-contract-runtime-facts.json" "{}\n";
  securityDisabledInitrdServices = securityDisabledSystem.config.boot.initrd.systemd.services;
  securityDisabledHostServices = securityDisabledSystem.config.systemd.services;
in
  assert assembly != null;
  assert securityDisabledInitrdServices ? aos-ability-initrd-controller;
  assert securityDisabledInitrdServices ? aos-ability-initrd-handoff-barrier;
  assert securityDisabledInitrdServices ? mount-var;
  assert securityDisabledInitrdServices ? nix-overlay-setup;
  assert securityDisabledInitrdServices ? aos-seed-profiles;
  assert securityDisabledInitrdServices ? aos-credential-recovery;
  assert securityDisabledInitrdServices.aos-ability-initrd-controller.requiredBy
  == [
    "initrd-fs.target"
    "initrd-switch-root.target"
  ];
  assert securityDisabledInitrdServices.aos-ability-initrd-controller.serviceConfig.RemainAfterExit;
  assert securityDisabledInitrdServices.aos-ability-initrd-handoff-barrier.requires
  == ["aos-ability-initrd-controller.service"];
  assert securityDisabledInitrdServices.aos-ability-initrd-handoff-barrier.after
  == ["aos-ability-initrd-controller.service"];
  assert securityDisabledInitrdServices.aos-ability-initrd-handoff-barrier.requiredBy
  == [
    "initrd-fs.target"
    "initrd-switch-root.target"
  ];
  assert securityDisabledInitrdServices.aos-ability-initrd-handoff-barrier.serviceConfig.RemainAfterExit;
  assert securityDisabledHostServices ? aos-ability-host-receiver;
  assert securityDisabledHostServices ? aos-nix-db;
  assert securityDisabledHostServices ? aos-credential-recovery;
  assert securityDisabledHostServices.aos-ability-host-receiver.requiredBy
  == [
    "aos-eval.service"
    "aos-graph-compile.service"
    "aos-config.target"
  ];
    pkgs.mkDerivation {
      pname = "aos-initrd-stage-contract-check";
      version = "1";
      src = null;
      buildDeps = [assembly baseLib frozenHostAbilities hostAbilities initrdAbilities pkgs.aos.packageRuntime pkgs.aos.testSupport pkgs.coreutils pkgs.cpio pkgs.erofs-utils pkgs.gawk pkgs.grep pkgs.jq pkgs.zstd];
      phases = [
        {
          name = "check";
          script = ''
            set -euo pipefail

            contract=${initrd}/initrd-stage-contract.json
            archive=${initrd}/initrd.img
            initrd_abilities=${initrdAbilities}/contract.json
            host_abilities=${hostAbilities}/contract.json

            # The on-host package set intentionally omits the builder
            # interfaces that create this contract. Its stage-1 path must
            # survive both the frozen artifact map and runtime evaluation.
            base_lib=${baseLib}
            host_static_contract=${frozenHostAbilities}
            ${pkgs.jq}/bin/jq -e '
              (has("buildPackages") | not)
              and ((.stdenv // {}) | has("hostPlatform") | not)
            ' "$base_lib/frozen-pkgs.json" >/dev/null
            test "$(${pkgs.jq}/bin/jq -r '."host-static-ability-contract"' \
              "$base_lib/frozen-artifacts.json")" = "$host_static_contract"
            test "$(readlink \
              "$base_lib/artifact-roots/host-static-ability-contract")" = \
              "$host_static_contract"

            runtime_state="$TMPDIR/static-contract-runtime-root"
            runtime_profile="$TMPDIR/static-contract-runtime-profiles"
            runtime_config="$TMPDIR/static-contract-runtime-config"
            runtime_cache="$TMPDIR/static-contract-runtime-cache"
            runtime_eval="$TMPDIR/static-contract-runtime-eval"
            mkdir -p \
              "$runtime_state/var/lib/apm/config/registries.d" \
              "$runtime_profile/system" \
              "$runtime_config/registries.d" \
              "$runtime_cache" \
              "$runtime_eval"

            runtime_store="local?root=$TMPDIR/static-contract-runtime-store"
            export AOS_ROOT="$runtime_state"
            export AOS_PROFILE_ROOT="$runtime_profile"
            export APM_SYSTEM_CONFIG_DIR="$runtime_config"
            export AOS_NIX_EVAL_CACHE_ROOT="$runtime_cache"
            export AOS_NIX_EVAL_STORE="$runtime_store"
            export NIX_REMOTE="$runtime_store"

            ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __eval \
              --host-nix ${emptyHost} \
              --base-lib "$base_lib" \
              --facts ${emptyFacts} \
              --module-abi ${toString moduleAbi} \
              --out "$runtime_eval/manifest.json" \
              --eval-root "$runtime_eval"
            ${pkgs.jq}/bin/jq -e \
              --arg contract "$host_static_contract" '
              .etc."aos/static-ability-contract.json".kind == "store-symlink"
              and .etc."aos/static-ability-contract.json".target
                == ($contract + "/contract.json")
              and .ownership.etc."aos/static-ability-contract.json" == "@base"
            ' "$runtime_eval/manifest.json" >/dev/null

            validate_contract() {
              candidate=$1
              candidate_archive=$2
              archive_size=$(stat -c %s "$candidate_archive")
              archive_sha256=$(sha256sum "$candidate_archive" | cut -d ' ' -f1)

              ${pkgs.jq}/bin/jq -e \
                --argjson archiveSize "$archive_size" \
                --arg archiveSha256 "sha256:$archive_sha256" \
                '.schema_version == "aos.boot.initrd-stage-contract/v1"
                 and .stage == "initrd"
                 and .artifact.path == "initrd.img"
                 and .artifact.size_bytes == $archiveSize
                 and .artifact.sha256 == $archiveSha256
                 and ([.dependency_roots[]]
                   | length == (unique | length))
                 and .dependency_roots == (.dependency_roots
                   | unique_by([.kind,.store_path,.available_stage])
                   | sort_by([.kind,.store_path,.available_stage]))
                 and ([.dependency_roots[]
                   | select(.store_path == "${pkgs.coreutils}" and .kind == "runtime-package")]
                   | length == 1)
                 and ([.dependency_roots[]
                   | select(.store_path == "${pkgs.coreutils}" and .kind == "extra-package")]
                   | length == 1)
                 and all(.dependency_roots[];
                   .available_stage == "build" or .available_stage == "initrd")
                 and (. as $contract
                   | all(.handoff.required_units[];
                     . as $unit
                     | ($contract.rendered_units | index($unit)) != null
                     and ($contract.masked_units | index($unit)) == null))
                 and .handoff.to_stage == "host"
                 and .handoff.mechanism == "systemd-switch-root"
                 and .handoff.transferable_handles == false
                 and .handoff.receiving_stage_reauthorizes == true
                 and .handoff.receiving_stage_reacquires == true
                 and .handoff.preserved_mounts == (.handoff.preserved_mounts
                   | unique_by([.initrd_path,.host_path])
                   | sort_by([.initrd_path,.host_path]))
                 and .handoff.durable_state_roots == (.handoff.durable_state_roots
                   | unique_by([.initrd_path,.host_path])
                   | sort_by([.initrd_path,.host_path]))' \
                "$candidate" >/dev/null
            }

            validate_unit_graph() {
              graph_root=$1
              graph_contract=$2
              if ! completion=$(${pkgs.jq}/bin/jq -er '.handoff.completion_target' "$graph_contract"); then
                return 1
              fi

              if ! ${pkgs.jq}/bin/jq -r '.handoff.required_units[]' "$graph_contract" > required-units; then
                return 1
              fi
              while IFS= read -r unit; do
                unit_path="$graph_root/etc/systemd/system/$unit"
                requirement_path="$graph_root/etc/systemd/system/$completion.requires/$unit"
                test -L "$requirement_path" || return 1
                requirement_target=$(readlink "$requirement_path")
                resolved_requirement=$(realpath -m -s \
                  "$(dirname "$requirement_path")/$requirement_target")
                resolved_unit=$(realpath -m -s "$unit_path")
                test "$resolved_requirement" = "$resolved_unit" || return 1

                if test -L "$unit_path"; then
                  unit_target=$(readlink "$unit_path")
                  case "$unit_target" in
                    /nix/store/*) unit_content="$graph_root$unit_target" ;;
                    *) return 1 ;;
                  esac
                  test -f "$unit_content" || return 1
                  cmp "$unit_content" "$unit_target" || return 1
                else
                  unit_content="$unit_path"
                fi
                test -f "$unit_content" || return 1
                awk -v target="$completion" '
                      /^[[:space:]]*\[/ {
                        in_unit = ($0 ~ /^[[:space:]]*\[Unit\][[:space:]]*$/)
                        next
                      }
                      in_unit && /^[[:space:]]*Before[[:space:]]*=/ {
                        value = $0
                        sub(/^[^=]*=/, "", value)
                        if (value ~ /^[[:space:]]*$/) {
                          found = 0
                          next
                        }
                        count = split(value, tokens, /[[:space:]]+/)
                        for (token_index = 1; token_index <= count; token_index++) {
                          if (tokens[token_index] == target) found = 1
                        }
                      }
                      END { exit found ? 0 : 1 }
                    ' "$unit_content" || return 1
              done < required-units
            }

            finish_canonical_json() {
              candidate=$1
              candidate_size=$(stat -c %s "$candidate")
              test "$candidate_size" -gt 1
              test "$(tail -c 1 "$candidate" | wc -l)" -eq 1
              truncate -s $((candidate_size - 1)) "$candidate"
            }

            ${pkgs.jq}/bin/jq -cS . "$contract" > canonical.json
            canonical_size=$(stat -c %s canonical.json)
            truncate -s $((canonical_size - 1)) canonical.json
            cmp canonical.json "$contract"
            validate_contract "$contract" "$archive"

            ${pkgs.jq}/bin/jq -e '
              .schema == "aos.boot.static-abilities/v1"
              and .runtime_grants == []
              and (.platforms | length == 1)
              and .platforms[0].execution_stage == "initrd"
              and (.platforms[0].packages | length == 1)
              and .platforms[0].packages[0].name == "ability-package-smoke"
              and (.platforms[0].abilities | length == 1)
              and .platforms[0].abilities[0].availability == "unresolved-at-launch"
              and any(.platforms[0].unresolved_launch_obligations[];
                .kind == "implementation-artifact"
                and .disposition == "external-launch-obligation")
            ' "$initrd_abilities" >/dev/null
            ${pkgs.jq}/bin/jq -e '
              .schema == "aos.boot.static-abilities/v1"
              and .runtime_grants == []
              and (.platforms | length == 1)
              and .platforms[0].execution_stage == "host"
              and (.platforms[0].packages | length == 1)
              and .platforms[0].packages[0].name == "ability-package-smoke"
            ' "$host_abilities" >/dev/null
            test "$(sha256sum "$initrd_abilities" | cut -d ' ' -f1)" != \
              "$(sha256sum "$host_abilities" | cut -d ' ' -f1)"
            cmp "$initrd_abilities" ${initrd}/initrd-static-ability-contract.json
            cmp "$initrd_abilities" ${assembly}/inputs/initrd-static-ability-contract.json
            cmp "$host_abilities" ${assembly}/inputs/host-static-ability-contract.json

            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract "$contract" "$archive"
            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-contract ${assembly} initrd-stage-contract-check

            ${pkgs.zstd}/bin/zstd -dc "$archive" \
              | ${pkgs.cpio}/bin/cpio -it --quiet > archive-files
            ${pkgs.jq}/bin/jq -r '.handoff.required_units[]' "$contract" \
              | while IFS= read -r unit; do
                  grep -Fx "etc/systemd/system/$unit" archive-files >/dev/null
                  grep -Fx "etc/systemd/system/initrd-fs.target.requires/$unit" \
                    archive-files >/dev/null
                done

            mkdir unit-graph
            (
              cd unit-graph
              ${pkgs.zstd}/bin/zstd -dc "$archive" \
                | ${pkgs.cpio}/bin/cpio -idm --quiet
            )
            cmp "$initrd_abilities" \
              unit-graph/usr/lib/aos/initrd/static-ability-contract.json
            activation_selection=unit-graph/etc/aos/initrd-ability-activation.json
            static_contract_hex=$(sha256sum "$initrd_abilities" | cut -d ' ' -f1)
            ${pkgs.jq}/bin/jq -e \
              --arg digest "sha256:$static_contract_hex" '
                keys == [
                  "activation",
                  "disposition",
                  "execution_stage",
                  "schema",
                  "static_ability_contract_sha256"
                ]
                and .schema == "aos.ability.initrd-activation-selection/v1"
                and .execution_stage == "initrd"
                and .disposition == "none"
                and .static_ability_contract_sha256 == $digest
                and .activation == null
              ' "$activation_selection" >/dev/null
            ${pkgs.jq}/bin/jq -cS . "$activation_selection" > canonical-activation.json
            canonical_activation_size=$(stat -c %s canonical-activation.json)
            truncate -s $((canonical_activation_size - 1)) canonical-activation.json
            cmp canonical-activation.json "$activation_selection"

            initrd_controller=unit-graph/etc/systemd/system/aos-ability-initrd-controller.service
            grep -F "Before=initrd-fs.target initrd-switch-root.target" \
              "$initrd_controller" >/dev/null
            grep -F "RemainAfterExit=true" "$initrd_controller" >/dev/null
            switch_root_requirement="unit-graph/etc/systemd/system/initrd-switch-root.target.requires/aos-ability-initrd-controller.service"
            test -L "$switch_root_requirement"
            switch_root_requirement_target=$(readlink "$switch_root_requirement")
            resolved_switch_root_requirement=$(realpath -m -s \
              "$(dirname "$switch_root_requirement")/$switch_root_requirement_target")
            resolved_initrd_controller=$(realpath -m -s "$initrd_controller")
            test "$resolved_switch_root_requirement" = "$resolved_initrd_controller"
            grep -F "__ability-stage-run" "$initrd_controller" >/dev/null
            grep -F -- "--input /etc/aos/initrd-ability-activation.json" \
              "$initrd_controller" >/dev/null
            initrd_barrier=unit-graph/etc/systemd/system/aos-ability-initrd-handoff-barrier.service
            grep -F "Requires=aos-ability-initrd-controller.service" \
              "$initrd_barrier" >/dev/null
            grep -F "After=aos-ability-initrd-controller.service" \
              "$initrd_barrier" >/dev/null
            grep -F "Before=initrd-fs.target initrd-switch-root.target" \
              "$initrd_barrier" >/dev/null
            grep -F "RemainAfterExit=true" "$initrd_barrier" >/dev/null
            grep -F "__ability-stage-validate" "$initrd_barrier" >/dev/null
            grep -F -- "--from-stage initrd" "$initrd_barrier" >/dev/null
            grep -F -- "--root /sysroot" "$initrd_barrier" >/dev/null
            grep -F -- "--image-profile /sysroot/var/lib/profiles/image" \
              "$initrd_barrier" >/dev/null
            barrier_requirement="unit-graph/etc/systemd/system/initrd-switch-root.target.requires/aos-ability-initrd-handoff-barrier.service"
            test -L "$barrier_requirement"
            barrier_requirement_target=$(readlink "$barrier_requirement")
            resolved_barrier_requirement=$(realpath -m -s \
              "$(dirname "$barrier_requirement")/$barrier_requirement_target")
            resolved_initrd_barrier=$(realpath -m -s "$initrd_barrier")
            test "$resolved_barrier_requirement" = "$resolved_initrd_barrier"
            ${pkgs.erofs-utils}/bin/fsck.erofs \
              --extract=root-tree --xattrs --preserve \
              ${assembly}/inputs/root.img >/dev/null
            cmp "$host_abilities" \
              root-tree/usr/lib/aos/host/static-ability-contract.json
            cmp "$initrd_abilities" \
              root-tree/usr/lib/aos/initrd/static-ability-contract.json
            receiver_unit=root-tree/etc/systemd/system/aos-ability-host-receiver.service
            test -e "$receiver_unit"
            for dependent in \
              aos-eval.service \
              aos-graph-compile.service \
              aos-config.target; do
              requirement="root-tree/etc/systemd/system/$dependent.requires/aos-ability-host-receiver.service"
              test -L "$requirement"
              requirement_target=$(readlink "$requirement")
              resolved_requirement=$(realpath -m -s \
                "$(dirname "$requirement")/$requirement_target")
              resolved_receiver=$(realpath -m -s "$receiver_unit")
              test "$resolved_requirement" = "$resolved_receiver"
            done
            ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              image-assembly-attachments \
              ${assembly} initrd-stage-contract-check unit-graph root-tree
            validate_unit_graph unit-graph "$contract"

            first_unit=$(${pkgs.jq}/bin/jq -er '.handoff.required_units[0]' "$contract")
            first_unit_path="unit-graph/etc/systemd/system/$first_unit"
            first_requirement="unit-graph/etc/systemd/system/initrd-fs.target.requires/$first_unit"
            original_unit=$(readlink "$first_unit_path")
            original_requirement=$(readlink "$first_requirement")
            chmod -R u+w unit-graph/etc
            ln -sfn /dev/null "$first_requirement"
            if validate_unit_graph unit-graph "$contract"; then
              echo "initrd unit graph accepted a requirement to the wrong target" >&2
              exit 1
            fi
            ln -sfn /does/not-exist "$first_requirement"
            if validate_unit_graph unit-graph "$contract"; then
              echo "initrd unit graph accepted a dangling requirement" >&2
              exit 1
            fi
            ln -sfn "$original_requirement" "$first_requirement"
            validate_unit_graph unit-graph "$contract"

            rm "$first_unit_path" "$first_requirement"
            ln -s "../$first_unit" "$first_requirement"
            cat > "$first_unit_path" <<'INVALID_SECTION'
            [Service]
            Before=initrd-fs.target
            INVALID_SECTION
            if validate_unit_graph unit-graph "$contract"; then
              echo "initrd unit graph accepted Before= outside [Unit]" >&2
              exit 1
            fi

            cat > "$first_unit_path" <<'RESET_ORDER'
            [Unit]
            Before=initrd-fs.target
            Before=
            RESET_ORDER
            if validate_unit_graph unit-graph "$contract"; then
              echo "initrd unit graph ignored a later Before= reset" >&2
              exit 1
            fi

            cat > "$first_unit_path" <<'WRONG_LITERAL_TOKEN'
            [Unit]
            Before=initrd-fsXtarget
            WRONG_LITERAL_TOKEN
            if validate_unit_graph unit-graph "$contract"; then
              echo "initrd unit graph accepted a nonliteral completion target" >&2
              exit 1
            fi

            rm "$first_unit_path" "$first_requirement"
            ln -s "$original_unit" "$first_unit_path"
            ln -s "$original_requirement" "$first_requirement"
            validate_unit_graph unit-graph "$contract"

            cp "$archive" changed-initrd.img
            chmod u+w changed-initrd.img
            printf x >> changed-initrd.img
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract "$contract" changed-initrd.img \
              > changed-archive.log 2>&1; then
              echo "initrd contract accepted changed archive bytes" >&2
              exit 1
            fi
            grep -F "initrd archive differs from its stage contract" changed-archive.log >/dev/null

            ${pkgs.jq}/bin/jq -cS \
              '.dependency_roots[0].available_stage = "host"' \
              "$contract" > late-stage.json
            finish_canonical_json late-stage.json
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract late-stage.json "$archive" \
              > late-stage.log 2>&1; then
              echo "initrd contract accepted a host-stage dependency" >&2
              exit 1
            fi
            grep -F \
              "initrd dependency root is unavailable during the initrd stage" \
              late-stage.log >/dev/null

            ${pkgs.jq}/bin/jq -cS \
              '.masked_units = ((.masked_units + [.handoff.required_units[0]]) | sort | unique)' \
              "$contract" > required-masked.json
            finish_canonical_json required-masked.json
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract required-masked.json "$archive" \
              > required-masked.log 2>&1; then
              echo "initrd contract accepted a required masked unit" >&2
              exit 1
            fi
            grep -F \
              "initrd handoff unit is masked in the stage-1 manager" \
              required-masked.log >/dev/null

            ${pkgs.jq}/bin/jq -cS \
              '.dependency_roots |= map(select(.kind != "kernel"))' \
              "$contract" > missing-kernel.json
            finish_canonical_json missing-kernel.json
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract missing-kernel.json "$archive" \
              > missing-kernel.log 2>&1; then
              echo "initrd contract accepted a missing mandatory kernel root" >&2
              exit 1
            fi
            grep -F \
              "initrd contract requires exactly one kernel and unit-configuration root" \
              missing-kernel.log >/dev/null

            ${pkgs.jq}/bin/jq -cS \
              '.dependency_roots += [.dependency_roots[0]]' \
              "$contract" > duplicate-root.json
            finish_canonical_json duplicate-root.json
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract duplicate-root.json "$archive" \
              > duplicate-root.log 2>&1; then
              echo "initrd contract accepted a duplicate dependency tuple" >&2
              exit 1
            fi
            grep -F \
              "initrd dependency roots must be sorted and unique" \
              duplicate-root.log >/dev/null

            ${pkgs.jq}/bin/jq -cS \
              '(.dependency_roots[] | select(.kind == "kernel").available_stage) = "initrd"' \
              "$contract" > wrong-kind-stage.json
            finish_canonical_json wrong-kind-stage.json
            if ${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture \
              initrd-contract wrong-kind-stage.json "$archive" \
              > wrong-kind-stage.log 2>&1; then
              echo "initrd contract accepted the wrong stage for a dependency kind" >&2
              exit 1
            fi
            grep -F \
              "initrd dependency kind has the wrong availability stage" \
              wrong-kind-stage.log >/dev/null

            mkdir -p "$out"
            cp "$contract" "$out/initrd-stage-contract.json"
            ${pkgs.jq}/bin/jq -cS -n \
              --arg schema aos.boot.initrd-stage-contract-check/v1 \
              --arg archive "${initrd}/initrd.img" \
              --arg contract "${initrd}/initrd-stage-contract.json" \
              --arg archiveSha256 "sha256:$(sha256sum "$archive" | cut -d ' ' -f1)" \
              --argjson requiredUnits "$(${pkgs.jq}/bin/jq '.handoff.required_units | length' "$contract")" \
              '{schema_version:$schema,archive:$archive,contract:$contract,
                archive_sha256:$archiveSha256,required_units:$requiredUnits,
                changed_archive_rejected:true,host_stage_rejected:true,
                required_mask_rejected:true,missing_kernel_rejected:true,
                duplicate_tuple_rejected:true,wrong_kind_stage_rejected:true,
                wrong_requirement_target_rejected:true,
                dangling_requirement_rejected:true,
                invalid_unit_section_rejected:true,
                ordering_reset_rejected:true,
                nonliteral_target_rejected:true,
                production_finalizer_capture_passed:true}' > "$out/result.json.tmp"
            result_size=$(stat -c %s "$out/result.json.tmp")
            truncate -s $((result_size - 1)) "$out/result.json.tmp"
            mv "$out/result.json.tmp" "$out/result.json"
          '';
        }
      ];
      meta.description = "Exact initrd stage-contract and handoff qualification";
    }
