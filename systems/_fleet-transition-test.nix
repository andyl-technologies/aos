# Test-only image policy for exercising evaluator-compatible image transitions.
#
# This is a source-backed system module so the image's embedded evaluator keeps
# the fleet control unit in its structural graph after first-boot activation.
# The leading underscore excludes it from production system auto-discovery.
{pkgs, ...}: {
  aos.packages.aos-test-agent.bundle = true;

  systemd.services.aos-test-agent = {
    description = "AOS VM Test Guest Agent";
    # Keep the control channel available while first-boot evaluation blocks
    # the normal boot target. The evaluator's wants edge schedules this unit,
    # and the ordering edge makes it ready before evaluation begins.
    wantedBy = [
      "aos-eval.service"
      "multi-user.target"
    ];
    before = ["aos-eval.service"];
    restartIfChanged = false;
    stopIfChanged = false;
    stopOnRemoval = false;
    unitConfig.RefuseManualStop = true;
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent";
      Restart = "on-failure";
      RestartSec = 1;
      Environment = "PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
    };
  };
}
