##! Runtime qualification checks derived from resolved systemd realizations.
{lib}: let
  unitIdentitiesFor = resource: let
    realization = resource.realization;
    lifecycle = resource.value.lifecycle;
    primaryRemainsActive =
      realization.enabled
      && (
        lifecycle.execution_model
        != "oneshot"
        || lifecycle.remain_after_exit
      );
    installedAuxiliaryIdentities = builtins.filter (
      identity: identity != realization.systemd_unit
    ) (builtins.map (link: link.child) realization.links);
  in
    lib.unique (
      lib.optional primaryRemainsActive realization.systemd_unit
      ++ installedAuxiliaryIdentities
    );

  serviceCheck = resource: {
    name = "service-${lib.abilities.identityKeyFor "aos.systemd.service-qualification-check/v1" {
      inherit (resource) resource revision;
    }}";
    description = "The selected systemd provider observes the resolved ${resource.value.service} service resource as active";
    script = ''
      import json
      import shlex

      identities = json.loads(${builtins.toJSON (builtins.toJSON (unitIdentitiesFor resource))})

      for identity in identities:
          if identity["kind"] == "unit":
              unit = identity["unit_name"]
          elif identity["kind"] == "template-instance":
              unit = vm.succeed(
                  "systemd-escape --template="
                  + shlex.quote(identity["template_unit_name"])
                  + " "
                  + shlex.quote(identity["instance"])
              ).strip()
          else:
              raise AssertionError(f"unsupported selected systemd unit identity: {identity!r}")

          vm.wait_until_succeeds(
              "systemctl is-active --quiet " + shlex.quote(unit), timeout=90
          )
    '';
  };
in {
  inherit serviceCheck unitIdentitiesFor;
}
