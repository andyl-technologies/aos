# tests/fleet/rfc-0011-gc-roots.nix — durable config-generation retention.
#
# Creates four production configuration generations, selects an older current
# generation outside the retention window, prunes under the public APM
# porcelain, and runs real Nix GC. Retained cfg/cfgsrc roots must keep both the
# rendered output and all cross-ABI re-evaluation inputs alive; roots belonging
# only to pruned generations must be released.
{
  pkgs,
  systems,
  ...
}: {
  name = "rfc-0011-gc-roots";
  timeout = 1500;

  machines.target = {
    system = systems.server-test;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-test-agent" ];
        environment.etc."rfc0011-gc-generation".text = "one\n";
      }
    '';
  };

  testScript =
    # python
    ''
      import base64
      import json

      APM = "${pkgs.aos}/bin/apm"
      JQ = "${pkgs.jq}/bin/jq"


      def current_generation():
          return int(target.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def switch(value):
          host = f'''{{
            aos.provisioning.storage.partitions.var.sizeMin = "2G";
            aos.apm.desiredPackages = [ "aos-test-agent" ];
            environment.etc."rfc0011-gc-generation".text = "{value}\\n";
          }}
          '''
          encoded = base64.b64encode(host.encode()).decode()
          target.succeed(
              f"printf '%s' {encoded} | base64 -d > /run/rfc0011-gc-{value}.nix"
          )
          target.succeed(f'''
              {APM} switch \
                --from /run/rfc0011-gc-{value}.nix \
                --eval-root /run/rfc0011-gc-eval-{value}
          ''', timeout=300)
          generation = current_generation()
          target.succeed(
              f'test "$(cat /etc/rfc0011-gc-generation)" = {value}'
          )
          return generation


      def state():
          return json.loads(target.succeed(
              "cat /var/lib/profiles/system/state.json"
          ))


      def record(number):
          matches = [
              generation for generation in state()["generations"]
              if generation["number"] == number
          ]
          assert len(matches) == 1, (number, matches)
          return matches[0]


      def assert_retained_inputs(number):
          generation = record(number)
          generation_dir = f"/var/lib/profiles/system/gen-{number}"
          target.succeed(f"test -d {generation_dir}/cfg")
          target.succeed(f"test -d {generation_dir}/cfgsrc")
          target.succeed(f'''
              set -eu
              for root in {generation_dir}/cfg/* {generation_dir}/cfgsrc/*; do
                test -L "$root"
                target_path=$(readlink -f "$root")
                test -e "$target_path"
              done
          ''')
          inputs = [
              generation["host_nix_ref"],
              generation["facts_ref"],
              generation["base_lib_ref"],
              generation["evaluator_ref"],
              *generation["config_module_paths"],
          ]
          for input_path in inputs:
              target.succeed(f"test -e {input_path}")
              target.succeed(f'''
                  ${pkgs.findutils}/bin/find {generation_dir}/cfgsrc \
                    -type l -lname {input_path} | ${pkgs.grep}/bin/grep -q .
              ''')


      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      first = current_generation()
      second = switch("two")
      third = switch("three")
      fourth = switch("four")
      assert len({first, second, third, fourth}) == 4

      # Put generation two outside `--keep 1` while making it current. The
      # retention contract keeps both it and the numerically latest gen four.
      target.succeed(
          f"{APM} rollback --system --generation {second}", timeout=300
      )
      assert current_generation() == second
      target.succeed('test "$(cat /etc/rfc0011-gc-generation)" = two')
      pruned_host = record(third)["host_nix_ref"]

      clean = json.loads(target.succeed(
          f"{APM} --json clean --system --generations --keep 1"
      ))
      config = clean["configuration"]
      assert config["current_generation"] == second, clean
      assert config["generations_before"] == [first, second, third, fourth], clean
      assert config["generations_after"] == [second, fourth], clean
      assert config["removed_generations"] == [first, third], clean
      target.fail("test -e /var/lib/profiles/system/.prune-intent.json")
      target.succeed(f"test ! -e /var/lib/profiles/system/gen-{first}")
      target.succeed(f"test ! -e /var/lib/profiles/system/gen-{third}")
      target.succeed(f"test -d /var/lib/profiles/system/gen-{second}")
      target.succeed(f"test -d /var/lib/profiles/system/gen-{fourth}")

      target.succeed(f"{APM} gc", timeout=300)
      assert_retained_inputs(second)
      assert_retained_inputs(fourth)
      target.succeed(f"test ! -e {pruned_host}")

      image_state = json.loads(target.succeed(
          "cat /var/lib/profiles/image/state.json"
      ))
      running_image = next(
          image for image in image_state["generations"]
          if image["number"] == image_state["running"]
      )
      baselib_root = (
          "/var/lib/profiles/image/"
          f"image-gen-{running_image['number']}/baselib/"
          f"{running_image['module_abi']}"
      )
      target.succeed(f"test -L {baselib_root}")
      target.succeed(f"test -e $(readlink -f {baselib_root})")

      # A retained config generation remains a complete rollback artifact
      # after GC: direct activation materializes its exact /etc lower.
      target.succeed(
          f"{APM} rollback --system --generation {fourth}", timeout=300
      )
      assert current_generation() == fourth
      target.succeed('test "$(cat /etc/rfc0011-gc-generation)" = four')
      target.succeed("systemctl is-active --quiet multi-user.target")
      target.succeed("systemctl is-active --quiet aos-test-agent.service")
    '';
}
