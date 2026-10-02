##! Handler implementation selecting its own realized package artifact.
{package, ...}: {
  aos.abilities.echo.operations.run.handler.program = package;
}
