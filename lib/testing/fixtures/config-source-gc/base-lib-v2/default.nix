{
  moduleAbi = 2;

  evalRetained = {
    requestedAbi,
    host,
    packageModule,
    facts,
  }:
    if requestedAbi != 2
    then throw "base-lib v2 cannot evaluate a different module ABI"
    else if
      requestedAbi
      < packageModule.moduleAbiCompat.min
      || requestedAbi > packageModule.moduleAbiCompat.max
    then throw "retained package module is incompatible with base-lib v2"
    else {
      moduleAbi = requestedAbi;
      baseLibGeneration = "v2";
      crossAbiReevaluated = true;
      hostName = host.hostName;
      configValue = packageModule.value;
      instanceFact = facts.instance;
    };
}
