##! Private relative-import helper for the config-output smoke fixture.
{lib}: {
  enabledByDefault = false;
  assertionMessage = "${lib.concatStringsSep "." ["configModuleSmoke" "enable"]} remains evaluable";
}
