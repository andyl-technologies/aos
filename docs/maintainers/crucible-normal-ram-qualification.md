# Normal service RAM qualification

`checks.crucible.ram.normalService` runs the installed Crucible suite under
real systemd in the existing disposable kernel VM. The process policy pins the
suite's selected controller ELF, while the service launches its ordinary suite
wrapper. The client uses the actual Unix campaign endpoint and authenticated
mutual-TLS host endpoint. It tests service-family delegation, scoped full-kernel
userfaultfd access, stale target rejection, policy mutation, and exact request
retry. Native startup or admission refusal fails this operational component.

Operational success is insufficient for complete RAM qualification.
`checks.crucible.ram.normalServiceFullMeasurements` is a required independent
gate consuming the same VM result, not launching another VM. It retains the
selected artifact build graph, observed Main executable, target, observation
sequence, and policy/reservation revisions. It requires the actual authenticated
status to declare complete measurements available and all five physical
classifications to contain nonnegative numeric values. Unknown classifications
remain null; neither partial residency at an earlier cut nor paging activity can
satisfy this gate. The current producer declares complete measurements
unavailable, so this prerequisite remains unsatisfied until the genuine producer
and its physical correctness controls qualify.

Neither gate replaces the existing independent RAM-byte/root and guest-state
oracles, cold fault continuation controls, native artifact eligibility, original
resource funding, or cleanup qualification. All remain required before accepting
complete normal runtime paging. Test certificates, semantic campaign inputs,
observation identities, and success markers create no resource or native
execution authority. These checks change no host deployment or kernel setting.
