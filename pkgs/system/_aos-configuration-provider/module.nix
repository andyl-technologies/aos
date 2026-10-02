##! Selects portable durable configuration reconciliation without host policy.
{package, ...}: {
  aos.abilities.configuration.operations.file.handler.program = package;
}
