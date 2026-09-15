{outputs, ...}: {
  config.test.provider = "${outputs.self}:${outputs.dependencies.helper}";
}
