##! Exercises a named handler output without selecting unrelated package payloads.
{
  lib,
  package,
  ...
}: {
  aos.abilities.echo.operations.run.handler.program = lib.getOutput "tools" package;
}
