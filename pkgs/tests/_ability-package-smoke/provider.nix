##! Pure provider functions for the native package ability smoke fixture.
{...}: {
  config.aos.abilities.implementations.default = {
    compose = context: context;
    transition = context: context;
  };
}
