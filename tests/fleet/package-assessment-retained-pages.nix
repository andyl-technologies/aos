# Real CLI pagination through an isolated transport and persistent Native SQL.
{
  mkSystem,
  pkgs,
  ...
}: let
  fixture = import ./_assessment-retained-pages-native.nix {inherit pkgs;};
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [pkgs.aos fixture];}
  ];
in {
  name = "package-assessment-retained-pages";
  timeout = 900;
  bootTimeout = 300;
  machines.hub = {
    inherit system;
    memoryMiB = 4096;
    varSizeMiB = 2048;
  };
  testScript = ''
    hub.wait_for_unit("multi-user.target", timeout=240)
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.testSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained scan pages survive scan mutation and database reopen" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.subscriptionTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained subscription pages survive review replacement and database reopen" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.alertTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained alert revisions survive acknowledgement and database reopen" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.scheduleTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained schedule reviews survive replacement and database reopen" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.deliveryTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained delivery attempts survive review replacement and database reopen" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.serviceTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI service review survives reviewing credential revocation and database reopen" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.serviceRevocationTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.notificationServiceTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.scheduleQueueTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.continuousTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.deadlineTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.advisoryTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 "
        "${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.advisoryCliTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained advisory revisions survive new evidence and database reopen" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.statusTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.statusBoundsTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--exact ${fixture.passthru.statusUnassessedTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "1 passed; 0 failed" in output, output
    output = hub.succeed(
        "AOS_ASSESSMENT_CLI=${pkgs.aos}/bin/aos TOKIO_WORKER_THREADS=2 ${fixture}/bin/aos-assessment-retained-pages-fixture "
        "--ignored --exact ${fixture.passthru.statusCliTestSelector} --nocapture --test-threads=1",
        timeout=240,
    )
    assert "PASS: actual CLI retained status heads survive cancellation and database reopen" in output, output
  '';
}
