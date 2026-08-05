{
  moduleAbi = 2;

  evalRetained = {
    requestedAbi,
    host,
    configModule,
    facts,
  }:
    if requestedAbi != 2
    then throw "base-lib v2 cannot evaluate a different module ABI"
    else if requestedAbi < configModule.moduleAbiCompat.min
      || requestedAbi > configModule.moduleAbiCompat.max
    then throw "retained config output is incompatible with base-lib v2"
    else {
      moduleAbi = requestedAbi;
      baseLibGeneration = "v2";
      crossAbiReevaluated = true;
      hostName = host.hostName;
      configValue = configModule.value;
      instanceFact = facts.instance;
    };
}
