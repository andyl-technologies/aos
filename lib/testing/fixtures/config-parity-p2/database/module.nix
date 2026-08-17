{lib, ...}: {
  options.database.port = lib.mkOption {
    type = lib.types.int;
  };
  config.database.port = 5432;
}
