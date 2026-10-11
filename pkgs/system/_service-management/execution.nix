##! Explicit instrumentation settings retained in the admitted configuration.
{lib, ...}: {
  options.aos.execution.observer = lib.mkOption {
    extensible = true;
    type = lib.types.nullOr (lib.types.submodule {
      options = {
        socketPath = lib.mkOption {
          type = lib.types.deferred lib.types.str;
          description = "Protected native activation boundary observer socket.";
        };
        timeoutMillis = lib.mkOption {
          type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 90000);
          default = 90000;
          description = "Finite transport budget for each native boundary acknowledgement.";
        };
      };
    });
    default = null;
    description = "Optional fail-closed native activation instrumentation endpoint.";
  };
}
