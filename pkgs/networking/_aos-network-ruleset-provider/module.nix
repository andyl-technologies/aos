##! Selects the retained nftables handler for the native host ruleset operation.
{package, ...}: {
  aos.abilities.networkPolicy.operations.ruleset.handler.program = package;
}
