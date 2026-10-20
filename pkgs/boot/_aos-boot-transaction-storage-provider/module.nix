##! Checked native view of already mounted boot transaction storage.
{
  lib,
  package,
  ...
}: {
  aos.abilities.bootTransactionStorage.operations.view = {
    input.options.path = lib.mkOption {
      type = lib.types.str;
      description = "Absolute journal directory mounted before the package runtime starts.";
    };
    result.options.path = lib.mkOption {
      type = lib.types.str;
      description = "Verified boot transaction journal directory.";
    };
    handler.program = package;
  };
}
