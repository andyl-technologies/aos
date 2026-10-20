##! Pins identity-provider shells for runtime execution and bootstrap account seeds.
{
  bash,
  util-linux,
}: {
  login = "${bash}/bin/bash";
  nologin = "${util-linux}/sbin/nologin";
}
