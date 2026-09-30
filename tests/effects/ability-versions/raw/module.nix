##! Proves that contract exports never inspect operation implementation values.
{...}: {
  aos.abilities.raw = {
    version = "0.3.0";
    operations.unavailable = {
      input = throw "Contract projection forced operation input.";
      result = throw "Contract projection forced operation result.";
      handler = throw "Contract projection forced a handler.";
      effects = throw "Contract projection forced effects.";
    };
  };
}
