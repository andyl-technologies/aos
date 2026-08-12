{
  moduleAbi = 1;

  evalRetained = {
    requestedAbi,
    host,
    configModule,
    facts,
  }:
    if requestedAbi != 1
    then throw "base-lib v1 cannot evaluate a different module ABI"
    else {
      moduleAbi = requestedAbi;
      baseLibGeneration = "v1";
      hostName = host.hostName;
      configValue = configModule.value;
      instanceFact = facts.instance;
    };
}
