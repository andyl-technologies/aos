{outputs, ...}: {
  environment.systemPackages = [outputs.self];
}
