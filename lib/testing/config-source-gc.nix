# Retained-input GC and cross-ABI re-evaluation acceptance gate.
#
# This check uses an isolated Nix store rather than the builder's global store.
# Its root topology is the production topology established by nix-db.nix:
# Nix's gcroots tree follows the AOS profile tree, whose config generations
# retain outputs in cfg/, evaluator inputs in cfgsrc/, and prior base libraries
# below image-gen-N/baselib/.  The real `apm gc` drives both collection passes.
{
  pkgs,
  lib ? null,
}: let
  fixture = ./fixtures/config-source-gc;
in
  pkgs.mkDerivation {
    pname = "config-source-gc";
    version = "0";
    src = null;
    buildDeps = [
      pkgs.aos
      pkgs.bash
      pkgs.coreutils
      pkgs.diffutils
      pkgs.jq
      pkgs.nix
    ];
    phases = [
      {
        name = "check";
        script = ''
          set -eu

          work="$TMPDIR/config-source-gc"
          aos_root="$work/aos-root"
          store_uri="local?root=$aos_root"
          store_dir="$aos_root/nix/store"
          state_dir="$aos_root/nix/var/nix"
          log_dir="$aos_root/nix/var/log/nix"
          profile_root="$state_dir/gcroots/aos-profiles"
          system_profile="$profile_root/system"
          config_root="$work/apm-config"
          home="$work/home"
          cache="$work/cache"
          nix_conf="$work/nix-conf"
          mkdir -p \
            "$store_dir" \
            "$state_dir/db" \
            "$profile_root" \
            "$log_dir" \
            "$system_profile/gen-1/cfg" \
            "$system_profile/gen-1/cfgsrc" \
            "$profile_root/images/image-gen-1/baselib" \
            "$profile_root/images/image-gen-2/baselib" \
            "$config_root/registries.d" \
            "$home" \
            "$cache" \
            "$nix_conf"

          fail() {
            echo "FAIL: $1" >&2
            exit 1
          }

          cat > "$nix_conf/nix.conf" <<'NIXCONF'
          experimental-features = nix-command
          sandbox = false
          substituters =
          NIXCONF

          nix_store() {
            env \
              NIX_CONF_DIR="$nix_conf" \
              ${pkgs.nix}/bin/nix-store --store "$store_uri" "$@"
          }

          add_tree() {
            logical=$(nix_store --add-fixed --recursive sha256 "$1")
            printf '%s%s\n' "$aos_root" "$logical"
          }

          add_file() {
            logical=$(nix_store --add-fixed sha256 "$1")
            printf '%s%s\n' "$aos_root" "$logical"
          }

          locked_input() {
            physical="$1"
            logical="''${physical#"$aos_root"}"
            test "$logical" != "$physical" \
              || fail "evaluator input is outside the isolated store: $physical"
            nar_hash=$(nix_store --query --hash "$logical")
            sri_hash=$(env NIX_CONF_DIR="$nix_conf" \
              ${pkgs.nix}/bin/nix hash convert \
                --hash-algo sha256 --to sri "$nar_hash")
            printf '(builtins.fetchTree { type = "path"; path = "%s"; narHash = "%s"; }).outPath' \
              "$physical" "$sri_hash"
          }

          root_path() {
            target="$1"
            directory="$2"
            logical="''${target#"$aos_root"}"
            test "$logical" != "$target" \
              || fail "root target is outside the isolated store: $target"
            basename="''${logical##*/}"
            hash="''${basename%%-*}"
            ${pkgs.coreutils}/bin/ln -s "$logical" "$directory/$hash"
          }

          assert_valid() {
            logical="''${1#"$aos_root"}"
            nix_store --query --hash "$logical" >/dev/null 2>&1 \
              || fail "expected retained store path is invalid: $1"
            test -e "$1" \
              || fail "expected retained store path is absent: $1"
          }

          assert_collected() {
            logical="''${1#"$aos_root"}"
            if nix_store --query --hash "$logical" >/dev/null 2>&1; then
              fail "unrooted store path survived collection: $1"
            fi
            test ! -e "$1" \
              || fail "unrooted store path remains on disk: $1"
          }

          write_entry() {
            destination="$1"
            base_lib="$2"
            requested_abi="$3"
            # Production parses the normalized JSON outside the evaluator and
            # renders host-facts.nix. Embed the same authenticated bytes here
            # as a Nix string before fromJSON.
            facts_json=$(${pkgs.jq}/bin/jq -Rs . "$facts_store")
            base_expr=$(locked_input "$base_lib")
            host_expr=$(locked_input "$host_store")
            config_module_expr=$(locked_input "$config_module_store")
            cat > "$destination" <<ENTRY
          let
            baseLib = import $base_expr;
            host = import $host_expr;
            configModule = import $config_module_expr;
            facts = builtins.fromJSON $facts_json;
            evaluated = baseLib.evalRetained {
              inherit host configModule facts;
              requestedAbi = $requested_abi;
            };
          in
            { manifest = evaluated; }
          ENTRY
          }

          eval_entry() {
            entry="$1"
            destination="$2"
            env HOME="$home" XDG_CACHE_HOME="$cache" NIX_CONF_DIR="$nix_conf" \
            ${pkgs.nix}/bin/nix-instantiate \
              --store "$store_uri" \
              --extra-experimental-features "nix-command flakes" \
              --eval \
              --strict \
              --json \
              --pure-eval \
              --option restrict-eval true \
              --option allow-import-from-derivation false \
              --option allowed-uris "path:$store_dir/" \
              - \
              < "$entry" \
              > "$destination" || return $?
          }

          nix_store --init

          # Negative topology control: a symlink below gcroots whose target is
          # an external directory does not make child symlinks GC roots. This
          # is the broken bridge shape that the runtime bind mount replaces.
          external_profile="$work/external-profile"
          external_bridge="$state_dir/gcroots/external-profile"
          ${pkgs.coreutils}/bin/mkdir -p "$external_profile/cfgsrc"
          external_store=$(add_file ${fixture}/facts.json)
          root_path "$external_store" "$external_profile/cfgsrc"
          ${pkgs.coreutils}/bin/ln -s "$external_profile" "$external_bridge"
          nix_store --gc > "$work/external-symlink-gc.log"
          assert_collected "$external_store"
          ${pkgs.coreutils}/bin/rm -f "$external_bridge"

          # Add the exact five identities a committed configuration needs:
          # old and new base libraries, the content-pinned host module, the
          # normalized facts, and the authenticated package config output.
          base_v1_store=$(add_tree ${fixture}/base-lib-v1)
          base_v2_store=$(add_tree ${fixture}/base-lib-v2)
          config_module_store=$(add_tree ${fixture}/config-output)
          host_store=$(add_file ${fixture}/host.nix)
          facts_store=$(add_file ${fixture}/facts.json)

          # Produce and retain the ABI-1 config output. It deliberately lives
          # under cfg/, not cfgsrc/, so the negative control can prove output
          # retention is insufficient for a future re-evaluation.
          write_entry "$work/abi-1-entry.nix" "$base_v1_store" 1
          eval_entry "$work/abi-1-entry.nix" "$work/abi-1-eval.json"
          ${pkgs.jq}/bin/jq -e '
            .manifest.moduleAbi == 1
            and .manifest.baseLibGeneration == "v1"
            and .manifest.hostName == "cfgsrc-gc-host"
            and .manifest.configValue == "retained-config-output"
            and .manifest.instanceFact == "retained-instance-fact"
          ' "$work/abi-1-eval.json" >/dev/null
          config_output_store=$(add_file "$work/abi-1-eval.json")

          # Match the running system's bind-mounted GC-root view. Nix does not
          # follow a symlink to an external directory here: the profile tree
          # itself must appear as a directory below gcroots.
          root_path "$config_output_store" "$system_profile/gen-1/cfg"
          root_path "$host_store" "$system_profile/gen-1/cfgsrc"
          root_path "$facts_store" "$system_profile/gen-1/cfgsrc"
          root_path "$config_module_store" "$system_profile/gen-1/cfgsrc"
          root_path "$base_v1_store" "$system_profile/gen-1/cfgsrc"
          root_path "$base_v2_store" "$system_profile/gen-1/cfgsrc"
          base_v1_logical="''${base_v1_store#"$aos_root"}"
          base_v2_logical="''${base_v2_store#"$aos_root"}"
          ${pkgs.coreutils}/bin/ln -s "$base_v1_logical" \
            "$profile_root/images/image-gen-1/baselib/1"
          ${pkgs.coreutils}/bin/ln -s "$base_v2_logical" \
            "$profile_root/images/image-gen-2/baselib/2"

          env \
            HOME="$home" \
            XDG_CACHE_HOME="$cache" \
            AOS_PROFILE_ROOT="$profile_root" \
            AOS_SWITCH_LOCK_PATH="$work/switch.lock" \
            APM_SYSTEM_CONFIG_DIR="$config_root" \
            NIX_REMOTE="$store_uri" \
            NIX_CONF_DIR="$nix_conf" \
            ${pkgs.aos.apm}/bin/apm gc > "$work/positive-gc.log"

          for retained in \
            "$config_output_store" \
            "$host_store" \
            "$facts_store" \
            "$config_module_store" \
            "$base_v1_store" \
            "$base_v2_store"; do
            assert_valid "$retained"
          done

          # Re-evaluate the ABI-1 generation under ABI 2. The changed base-lib
          # result proves this is evaluation, not replay of the cfg/ output.
          write_entry "$work/abi-2-entry.nix" "$base_v2_store" 2
          eval_entry "$work/abi-2-entry.nix" "$work/abi-2-eval.json"
          ${pkgs.jq}/bin/jq -e '
            .manifest.moduleAbi == 2
            and .manifest.baseLibGeneration == "v2"
            and .manifest.crossAbiReevaluated == true
            and .manifest.hostName == "cfgsrc-gc-host"
            and .manifest.configValue == "retained-config-output"
            and .manifest.instanceFact == "retained-instance-fact"
          ' "$work/abi-2-eval.json" >/dev/null
          ${pkgs.diffutils}/bin/cmp \
            "$config_output_store" "$work/abi-1-eval.json"
          if ${pkgs.diffutils}/bin/cmp -s \
            "$config_output_store" "$work/abi-2-eval.json"; then
            fail "cross-ABI evaluation replayed the retained ABI-1 output"
          fi

          # Negative control: preserve cfg/ but remove only the two input-root
          # classes. GC must collect every re-evaluation input while retaining
          # the old config output, and the same ABI-2 evaluator call must fail.
          ${pkgs.coreutils}/bin/rm -r "$system_profile/gen-1/cfgsrc"
          ${pkgs.coreutils}/bin/rm -r "$profile_root/images/image-gen-1/baselib"
          ${pkgs.coreutils}/bin/rm -r "$profile_root/images/image-gen-2/baselib"
          env \
            HOME="$home" \
            XDG_CACHE_HOME="$cache" \
            AOS_PROFILE_ROOT="$profile_root" \
            AOS_SWITCH_LOCK_PATH="$work/switch.lock" \
            APM_SYSTEM_CONFIG_DIR="$config_root" \
            NIX_REMOTE="$store_uri" \
            NIX_CONF_DIR="$nix_conf" \
            ${pkgs.aos.apm}/bin/apm gc > "$work/negative-gc.log"

          assert_valid "$config_output_store"
          for collected in \
            "$host_store" \
            "$facts_store" \
            "$config_module_store" \
            "$base_v1_store" \
            "$base_v2_store"; do
            assert_collected "$collected"
          done
          # A conditional command is immune to both errexit and the stdenv's
          # ERR trap, so the expected evaluator rejection remains observable.
          if eval_entry "$work/abi-2-entry.nix" "$work/unrooted-eval.json" \
            > "$work/unrooted-eval.stdout" 2> "$work/unrooted-eval.stderr"; then
            unrooted_status=0
          else
            unrooted_status=$?
          fi
          if [ "$unrooted_status" -eq 0 ]; then
            fail "cross-ABI re-evaluation succeeded after its inputs were collected"
          fi
          test ! -s "$work/unrooted-eval.json" \
            || fail "failed cross-ABI re-evaluation published output"

          mkdir -p "$out"
          {
            echo "configuration-source GC acceptance: PASS"
            echo "  apm gc retained cfg/, cfgsrc/, and prior base-lib roots"
            echo "  ABI-1 inputs re-evaluated under ABI 2 without replay"
            echo "  removing only cfgsrc/baselib roots made inputs collectable"
            echo "  retained cfg/ output alone could not satisfy re-evaluation"
            echo "  external-directory symlink bridges did not root children"
          } > "$out/result"
        '';
      }
    ];
  }
