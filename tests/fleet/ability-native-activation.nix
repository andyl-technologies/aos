##! Native structured-ability activation, rollback, and reboot acceptance.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
in {
  name = "ability-native-activation";
  timeout = 3600;
  bootTimeout = 600;

  machines.runtime = {
    system = fixture.runtimeSystem;
    extraClosures = fixture.extraClosures;
    varSizeMiB = 8192;
    memoryMiB = 4096;
  };

  testScript =
    fixture.testPrelude
    + # python
    ''
      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def switch_host(host, label):
          runtime.succeed(
              f"{APM} switch "
              f"--from {shlex.quote(host)} "
              f"--eval-root /run/ability-eval-{label}",
              timeout=600,
          )
          generation = current_generation()
          runtime.succeed(
              f"test \"$(readlink /var/lib/profiles/system/current)\" "
              f"= gen-{generation}"
          )
          return generation


      def retained_transactions(generation):
          root = f"/var/lib/profiles/system/gen-{generation}/ability-transactions"
          bundles = runtime.succeed(
              f"{FIND} {root} -mindepth 2 -maxdepth 2 "
              "-name plan-bundle.json -type f -print"
          ).splitlines()
          journals = runtime.succeed(
              f"{FIND} {root} -mindepth 2 -maxdepth 2 "
              "-name execution.journal -type f -size +0c -print"
          ).splitlines()
          terminals = runtime.succeed(
              f"{FIND} {root} -mindepth 2 -maxdepth 2 "
              "-name terminal.json -type f -print"
          ).splitlines()
          bundle_by_transaction = {
              path.rsplit("/", 2)[-2]: path for path in bundles
          }
          journal_by_transaction = {
              path.rsplit("/", 2)[-2]: path for path in journals
          }
          terminal_by_transaction = {
              path.rsplit("/", 2)[-2]: path for path in terminals
          }
          assert len(bundle_by_transaction) == len(bundles), bundles
          assert len(journal_by_transaction) == len(journals), journals
          assert len(terminal_by_transaction) == len(terminals), terminals
          assert bundle_by_transaction.keys() == journal_by_transaction.keys(), (
              bundles,
              journals,
          )
          assert bundle_by_transaction.keys() == terminal_by_transaction.keys(), (
              bundles,
              terminals,
          )
          for transaction, bundle in bundle_by_transaction.items():
              runtime.succeed(
                  f"{JQ} -e '.schema == \"aos.ability.plan-bundle/v1\"' "
                  f"{shlex.quote(bundle)}"
              )
              runtime.succeed(
                  f"{JQ} -e --arg transaction {shlex.quote(transaction)} "
                  "'.schema == \"aos.ability.transaction-terminal/v1\" "
                  "and .transaction == $transaction' "
                  f"{shlex.quote(terminal_by_transaction[transaction])}"
              )
          return frozenset(bundle_by_transaction)


      def assert_redacted_diagnostic(generation, transaction):
          transaction_root = (
              f"/var/lib/profiles/system/gen-{generation}/ability-transactions/"
              f"{transaction}"
          )
          journal = f"{transaction_root}/execution.journal"
          bundle = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(transaction_root + '/plan-bundle.json')}"
          ))
          journal_digest_before = runtime.succeed(
              f"{COREUTILS}/sha256sum {shlex.quote(journal)}"
          ).split()[0]

          diagnostic = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"{shlex.quote(f'/var/lib/profiles/system/gen-{generation}')} "
              f"{shlex.quote(transaction)}"
          ))

          journal_digest_after = runtime.succeed(
              f"{COREUTILS}/sha256sum {shlex.quote(journal)}"
          ).split()[0]
          assert journal_digest_after == journal_digest_before, (
              journal_digest_before,
              journal_digest_after,
          )
          assert diagnostic["schema"] == "aos.ability.diagnostic-bundle/v1", diagnostic
          assert diagnostic["audience"] == "redacted", diagnostic
          assert diagnostic["inputs"]["disclosure"] == "redacted", diagnostic
          assert diagnostic["plan"] == bundle["plan"], (diagnostic, bundle)
          assert diagnostic["timeline"]["plan"] == bundle["plan"], diagnostic
          return diagnostic


      def native_transaction_documents(generation, transaction):
          transaction_root = (
              f"/var/lib/profiles/system/gen-{generation}/ability-transactions/"
              f"{transaction}"
          )
          bundle = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(transaction_root + '/plan-bundle.json')}"
          ))
          diagnostic = json.loads(runtime.succeed(
              f"{AOS} --json ability diagnostic "
              f"{shlex.quote(f'/var/lib/profiles/system/gen-{generation}')} "
              f"{shlex.quote(transaction)}"
          ))
          return bundle, diagnostic


      def assert_completed_native_updates(generation, transaction, instances):
          bundle, diagnostic = native_transaction_documents(generation, transaction)
          operations = bundle["transition"]["effect_document"]["operations"]
          completed_ordinals = {
              event["node_ordinal"]
              for event in diagnostic["timeline"]["events"]
              if event["kind"] == "effect-completed"
          }
          for instance in instances:
              required = {
                  (f"{instance}-configuration", "publish"),
                  (f"{instance}-service", "reload"),
              }
              matching_ordinals = {
                  ordinal
                  for ordinal, operation in enumerate(operations)
                  if (
                      operation["target"]["resource"]["key"],
                      operation["method"],
                  ) in required
              }
              assert len(matching_ordinals) == len(required), (
                  instance,
                  operations,
              )
              assert matching_ordinals <= completed_ordinals, (
                  instance,
                  matching_ordinals,
                  completed_ordinals,
              )


      def assert_post_publication_reload_failure(generation, transaction, instance):
          bundle, diagnostic = native_transaction_documents(generation, transaction)
          operations = bundle["transition"]["effect_document"]["operations"]
          expected_operations = {
              "publish": (f"{instance}-configuration", "publish"),
              "reload": (f"{instance}-service", "reload"),
          }
          ordinals = {}
          for name, expected in expected_operations.items():
              matching = [
                  ordinal
                  for ordinal, operation in enumerate(operations)
                  if (
                      operation["target"]["resource"]["key"],
                      operation["method"],
                  ) == expected
              ]
              assert len(matching) == 1, (name, expected, operations)
              ordinals[name] = matching[0]

          completed_ordinals = {
              event["node_ordinal"]
              for event in diagnostic["timeline"]["events"]
              if event["kind"] == "effect-completed"
          }
          settled_ordinals = {
              event["node_ordinal"]
              for event in diagnostic["timeline"]["events"]
              if event["kind"] == "settled-failure"
          }
          assert ordinals["publish"] in completed_ordinals, (
              ordinals,
              diagnostic,
          )
          assert ordinals["reload"] in settled_ordinals, (
              ordinals,
              diagnostic,
          )
          assert ordinals["reload"] not in completed_ordinals, (
              ordinals,
              diagnostic,
          )

          terminal_path = (
              f"/var/lib/profiles/system/gen-{generation}/ability-transactions/"
              f"{transaction}/terminal.json"
          )
          terminal = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(terminal_path)}"
          ))
          assert terminal["terminal"] == "settled-failure", terminal


      def assert_completed_native_disable(generation, transaction, instance):
          bundle, diagnostic = native_transaction_documents(generation, transaction)
          operations = bundle["transition"]["effect_document"]["operations"]
          required = {
              (
                  "shared-configuration",
                  f"{instance}-configuration",
                  "release",
              ),
              ("shared-service", f"{instance}-service", "stop"),
              (instance, "virtual-hosts", "release"),
          }
          matching_ordinals = {
              ordinal
              for ordinal, operation in enumerate(operations)
              if (
                  operation["target"]["resource"]["provider"]["key"],
                  operation["target"]["resource"]["key"],
                  operation["method"],
              ) in required
          }
          assert len(matching_ordinals) == len(required), operations
          completed_ordinals = {
              event["node_ordinal"]
              for event in diagnostic["timeline"]["events"]
              if event["kind"] == "effect-completed"
          }
          assert matching_ordinals <= completed_ordinals, (
              matching_ordinals,
              completed_ordinals,
          )


      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=300
      )

      # The runtime image contains nginx but does not predeclare the reference
      # unit or configuration. The first ordinary switch must create both.
      runtime.fail("systemctl status nginx-nginx-main.service --no-pager")
      runtime.fail("systemctl status nginx-nginx-secondary.service --no-pager")
      runtime.fail("test -e /var/lib/aos/ability-reference/nginx-main.conf")
      runtime.fail("test -e /var/lib/aos/ability-reference/nginx-secondary.conf")
      assert_route_absent("alpha.example", 18081)
      assert_route_absent("gamma.example", 18082)
      runtime.succeed(
          f"{COREUTILS}/install -m 0600 /dev/null "
          "/run/ability-nginx-reload.calls"
      )

      publish_reference_packages()

      activation_v1 = generate_activation_fixture(
          "/run/ability-activation-v1",
          "alpha-v1",
          "gamma-v1",
          "/run/ability-authority-v1",
      )
      authority_v1 = provision_operator_authority(
          activation_v1, "/run/ability-authority-v1"
      )
      runtime.succeed(f"test -f {shlex.quote(authority_v1)}")
      write_activation_host("/run/ability-host-v1.nix", activation_v1)

      generation_v1 = switch_host("/run/ability-host-v1.nix", "v1")
      assert_reference_packages_installed()
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-main.service", timeout=120
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=120
      )
      runtime.succeed(
          f"test \"$({COREUTILS}/stat -c %a "
          "/var/lib/aos/ability-reference/nginx-main.conf)\" = 600"
      )
      runtime.succeed(
          f"test \"$({COREUTILS}/stat -c %a "
          "/var/lib/aos/ability-reference/nginx-secondary.conf)\" = 600"
      )
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("beta.example", 18081, "app-b", "beta-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      assert_consumer_observation(activation_v1)
      selected_v1, selected_v1_content = assert_managed_configuration_selected(
          activation_v1, "nginx-secondary"
      )
      assert "gamma-v1" in selected_v1_content, selected_v1_content
      transactions_v1 = retained_transactions(generation_v1)
      assert len(transactions_v1) == 1, transactions_v1
      assert_redacted_diagnostic(generation_v1, next(iter(transactions_v1)))

      # Identical desired input retains the generation, records a separately
      # verified empty transition, and invokes no provider effect adapter.
      reload_calls_v1 = runtime.succeed(
          f"{COREUTILS}/cat /run/ability-nginx-reload.calls"
      )
      configuration_digests_v1 = runtime.succeed(
          f"{COREUTILS}/sha256sum "
          "/var/lib/aos/ability-reference/nginx-main.conf "
          "/var/lib/aos/ability-reference/nginx-secondary.conf"
      )
      repeated_generation_v1 = switch_host(
          "/run/ability-host-v1.nix", "v1-no-op"
      )
      assert repeated_generation_v1 == generation_v1, (
          generation_v1,
          repeated_generation_v1,
      )
      transactions_v1_after_no_op = retained_transactions(generation_v1)
      assert transactions_v1 < transactions_v1_after_no_op, (
          transactions_v1,
          transactions_v1_after_no_op,
      )
      no_op_transactions = transactions_v1_after_no_op - transactions_v1
      assert len(no_op_transactions) == 1, no_op_transactions
      no_op_transaction = next(iter(no_op_transactions))
      no_op_root = (
          f"/var/lib/profiles/system/gen-{generation_v1}/ability-transactions/"
          f"{no_op_transaction}"
      )
      no_op_bundle_bytes = runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(no_op_root + '/plan-bundle.json')}"
      ).encode()
      no_op_bundle = json.loads(no_op_bundle_bytes)
      no_op_marker = json.loads(runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(no_op_root + '/native-no-op-verification.json')}"
      ))
      no_op_bundle_digest = "sha256:" + hashlib.sha256(
          b"aos.ability.plan-bundle/v1\0" + no_op_bundle_bytes
      ).hexdigest()
      assert no_op_bundle["transition"]["effect_document"]["operations"] == [], (
          no_op_bundle
      )
      assert no_op_marker == {
          "schema": "aos.ability.native-no-op-verification/v1",
          "transaction": no_op_transaction,
          "plan": no_op_bundle["plan"],
          "plan_bundle": no_op_bundle_digest,
      }, (no_op_marker, no_op_bundle_digest)
      no_op_activation_record = json.loads(runtime.succeed(
          f"{COREUTILS}/cat "
          f"/var/lib/profiles/system/gen-{generation_v1}/activation.json"
      ))
      assert no_op_activation_record["status"] == "complete", (
          no_op_activation_record
      )
      assert (
          no_op_activation_record["native_ability_transaction"]
          == no_op_transaction
      ), (no_op_activation_record, no_op_transaction)
      assert runtime.succeed(
          f"{COREUTILS}/cat /run/ability-nginx-reload.calls"
      ) == reload_calls_v1
      assert runtime.succeed(
          f"{COREUTILS}/sha256sum "
          "/var/lib/aos/ability-reference/nginx-main.conf "
          "/var/lib/aos/ability-reference/nginx-secondary.conf"
      ) == configuration_digests_v1
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("beta.example", 18081, "app-b", "beta-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      transactions_v1 = transactions_v1_after_no_op

      manifest_v1 = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{generation_v1}/manifest.json"
      ))
      assert manifest_v1["schema"] == "aos.config-manifest/v3", manifest_v1
      activation_input_v1 = manifest_v1["inputs"]["ability_activation"]
      assert activation_input_v1["required_features"] == [
          "abilities-v1",
          "ability-effects-v1",
          "native-platform-policy-v1",
          "native-resource-map-v2",
      ], activation_input_v1
      assert [package["name"] for package in activation_input_v1["packages"]] == [
          entry["name"] for entry in sorted(
              REFERENCE_PACKAGES, key=lambda entry: entry["name"]
          )
      ], activation_input_v1

      # The second generation publishes a valid native configuration candidate,
      # then a deterministic systemd reload failure leaves the live consumer on
      # the old revision while preserving the new generation and transaction.
      activation_v2 = generate_activation_fixture(
          "/run/ability-activation-v2",
          "alpha-v1",
          "gamma-v2",
          "/run/ability-authority-v2",
      )
      authority_v2 = provision_operator_authority(
          activation_v2, "/run/ability-authority-v2"
      )
      runtime.succeed(f"test -f {shlex.quote(authority_v2)}")
      write_activation_host("/run/ability-host-v2.nix", activation_v2)
      runtime.succeed(f"{COREUTILS}/touch /run/ability-force-native-reload-failure")

      status, stdout, stderr = runtime.execute(
          f"{APM} switch --from /run/ability-host-v2.nix "
          "--eval-root /run/ability-eval-v2",
          timeout=600,
      )
      assert status == 6, (status, stdout, stderr)
      generation_v2 = current_generation()
      assert generation_v2 != generation_v1, (generation_v1, generation_v2)
      failed_record_path = (
          f"/var/lib/profiles/system/gen-{generation_v2}/activation.json"
      )
      failed_record = json.loads(runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(failed_record_path)}"
      ))
      assert failed_record["status"] == "native-pending", failed_record
      assert failed_record["activation_exit"] == 6, failed_record
      assert failed_record["native_ability_prior_generation"] == generation_v1, (
          failed_record,
          generation_v1,
      )
      failed_transaction = failed_record["native_ability_transaction"]
      assert isinstance(failed_transaction, str) and failed_transaction, failed_record
      failed_transaction_root = (
          f"/var/lib/profiles/system/gen-{generation_v2}/ability-transactions/"
          f"{failed_transaction}"
      )
      runtime.succeed(
          f"test -f {shlex.quote(failed_transaction_root + '/plan-bundle.json')}"
      )
      runtime.succeed(
          f"test -s {shlex.quote(failed_transaction_root + '/execution.journal')}"
      )
      assert_post_publication_reload_failure(
          generation_v2, failed_transaction, "nginx-secondary"
      )
      selected_v2, selected_v2_content = assert_managed_configuration_selected(
          activation_v2, "nginx-secondary"
      )
      assert selected_v2["revision"] != selected_v1["revision"], (
          selected_v1,
          selected_v2,
      )
      assert "gamma-v2" in selected_v2_content, selected_v2_content
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      assert_consumer_observation(activation_v1)

      # Rollback first publishes the already settled v2 failure, then commits a
      # fresh v1 transaction that republishes and reloads the affected instance.
      runtime.succeed(
          f"{COREUTILS}/rm -f /run/ability-force-native-reload-failure"
      )
      runtime.succeed(
          f"{APM} rollback --system "
          f"--generation {generation_v1}",
          timeout=600,
      )
      assert current_generation() == generation_v1
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-main.service", timeout=120
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=120
      )
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("beta.example", 18081, "app-b", "beta-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      assert_consumer_observation(activation_v1)
      resumed_record = json.loads(runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(failed_record_path)}"
      ))
      assert resumed_record["status"] == "native-failed", resumed_record
      assert resumed_record["activation_exit"] == 6, resumed_record
      assert resumed_record["native_ability_transaction"] == failed_transaction, (
          resumed_record,
          failed_transaction,
      )
      transactions_v2 = retained_transactions(generation_v2)
      assert transactions_v2 == {failed_transaction}, transactions_v2
      assert transactions_v1.isdisjoint(transactions_v2), (
          transactions_v1,
          transactions_v2,
      )
      transactions_v1_after_rollback = retained_transactions(generation_v1)
      assert transactions_v1 < transactions_v1_after_rollback, (
          transactions_v1,
          transactions_v1_after_rollback,
      )
      assert len(transactions_v1_after_rollback - transactions_v1) == 1, (
          transactions_v1,
          transactions_v1_after_rollback,
      )
      assert transactions_v1_after_rollback.isdisjoint(transactions_v2), (
          transactions_v1_after_rollback,
          transactions_v2,
      )
      rollback_record = json.loads(runtime.succeed(
          f"{COREUTILS}/cat "
          f"/var/lib/profiles/system/gen-{generation_v1}/activation.json"
      ))
      rollback_transaction = rollback_record["native_ability_transaction"]
      assert isinstance(rollback_transaction, str) and rollback_transaction, (
          rollback_record
      )
      assert rollback_transaction != failed_transaction, (
          rollback_transaction,
          failed_transaction,
      )
      assert rollback_transaction in (
          transactions_v1_after_rollback - transactions_v1
      ), (rollback_transaction, transactions_v1_after_rollback)
      assert_completed_native_updates(
          generation_v1, rollback_transaction, ("nginx-secondary",)
      )
      restored_v1, restored_v1_content = assert_managed_configuration_selected(
          activation_v1, "nginx-secondary"
      )
      assert restored_v1["revision"] == selected_v1["revision"], (
          restored_v1,
          selected_v1,
      )
      assert "gamma-v1" in restored_v1_content, restored_v1_content

      # Removing boot metadata forces recovery from the selected generation's
      # durable host input, plan bundle, resource inventory, and journal.
      runtime.reboot_without_metadata()
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-main.service", timeout=300
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=300
      )
      assert current_generation() == generation_v1
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("beta.example", 18081, "app-b", "beta-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v1")
      assert_consumer_observation(activation_v1)
      assert retained_transactions(generation_v1) == transactions_v1_after_rollback

      # The retained unit references a store-backed reload helper. Prove it is
      # still executable after reboot by committing and observing a real update.
      activation_v3 = generate_activation_fixture(
          "/run/ability-activation-v3",
          "alpha-v1",
          "gamma-v3",
          "/run/ability-authority-v3",
      )
      authority_v3 = provision_operator_authority(
          activation_v3, "/run/ability-authority-v3"
      )
      runtime.succeed(f"test -f {shlex.quote(authority_v3)}")
      write_activation_host("/run/ability-host-v3.nix", activation_v3)

      generation_v3 = switch_host("/run/ability-host-v3.nix", "v3")
      assert generation_v3 not in {generation_v1, generation_v2}, (
          generation_v1,
          generation_v2,
          generation_v3,
      )
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet nginx-nginx-secondary.service", timeout=120
      )
      assert_route("alpha.example", 18081, "app-a", "alpha-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v3")
      assert_consumer_observation(activation_v3)
      transactions_v3 = retained_transactions(generation_v3)
      assert len(transactions_v3) == 1, transactions_v3
      assert_completed_native_updates(
          generation_v3, next(iter(transactions_v3)), ("nginx-secondary",)
      )

      # Removing one consumer contribution recomputes the shared aggregate and
      # reloads its owner once while preserving the other contribution.
      activation_v4 = generate_activation_fixture(
          "/run/ability-activation-v4",
          "unused-v4",
          "gamma-v3",
          "/run/ability-authority-v4",
          lifecycle="remove-primary-contributor",
      )
      provision_operator_authority(activation_v4, "/run/ability-authority-v4")
      write_activation_host("/run/ability-host-v4.nix", activation_v4)
      generation_v4 = switch_host("/run/ability-host-v4.nix", "v4-remove-app-a")
      assert generation_v4 not in {generation_v1, generation_v2, generation_v3}
      selected_v4, selected_v4_content = assert_managed_configuration_selected(
          activation_v4, "nginx-main"
      )
      assert "alpha.example" not in selected_v4_content, selected_v4_content
      assert_route("beta.example", 18081, "app-b", "beta-v1")
      assert_route("gamma.example", 18082, "app-c", "gamma-v3")
      transactions_v4 = retained_transactions(generation_v4)
      assert len(transactions_v4) == 1, transactions_v4
      assert_completed_native_updates(
          generation_v4, next(iter(transactions_v4)), ("nginx-main",)
      )

      # Removing the final contribution does not disable an operator-enabled
      # provider. Its service stays active with the empty aggregate selected.
      activation_v5 = generate_activation_fixture(
          "/run/ability-activation-v5",
          "unused-v5",
          "gamma-v3",
          "/run/ability-authority-v5",
          lifecycle="remove-main-contributors",
      )
      provision_operator_authority(activation_v5, "/run/ability-authority-v5")
      write_activation_host("/run/ability-host-v5.nix", activation_v5)
      generation_v5 = switch_host("/run/ability-host-v5.nix", "v5-empty-main")
      assert generation_v5 not in {
          generation_v1,
          generation_v2,
          generation_v3,
          generation_v4,
      }
      runtime.succeed("systemctl is-active --quiet nginx-nginx-main.service")
      selected_v5, selected_v5_content = assert_managed_configuration_selected(
          activation_v5, "nginx-main"
      )
      assert "alpha.example" not in selected_v5_content, selected_v5_content
      assert "beta.example" not in selected_v5_content, selected_v5_content
      assert_route_absent("alpha.example", 18081)
      assert_route("gamma.example", 18082, "app-c", "gamma-v3")
      transactions_v5 = retained_transactions(generation_v5)
      assert len(transactions_v5) == 1, transactions_v5
      assert_completed_native_updates(
          generation_v5, next(iter(transactions_v5)), ("nginx-main",)
      )

      # Explicit disable stops the workload before releasing its eligible
      # configuration and controller resources. The other instance remains up.
      activation_v6 = generate_activation_fixture(
          "/run/ability-activation-v6",
          "unused-v6",
          "gamma-v3",
          "/run/ability-authority-v6",
          lifecycle="disable-main",
      )
      provision_operator_authority(activation_v6, "/run/ability-authority-v6")
      write_activation_host("/run/ability-host-v6.nix", activation_v6)
      generation_v6 = switch_host("/run/ability-host-v6.nix", "v6-disable-main")
      assert generation_v6 not in {
          generation_v1,
          generation_v2,
          generation_v3,
          generation_v4,
          generation_v5,
      }
      runtime.fail("systemctl is-active --quiet nginx-nginx-main.service")
      runtime.fail("test -e /var/lib/aos/ability-reference/nginx-main.conf")
      runtime.succeed("test -d /var/lib/aos/ability-reference/nginx-main")
      assert_route_absent("alpha.example", 18081)
      assert_route("gamma.example", 18082, "app-c", "gamma-v3")
      transactions_v6 = retained_transactions(generation_v6)
      assert len(transactions_v6) == 1, transactions_v6
      assert_completed_native_disable(
          generation_v6, next(iter(transactions_v6)), "nginx-main"
      )
    '';
  }
  // lib.optionalAttrs qualificationImage {
    qualification = {
      candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
      extraClosures = fixture.extraClosures;
      setupBody = fixture.qualificationSetupBody;
    };
  }
