{
  outputs,
  packageVersion,
  ...
}: {
  config.test.provider = "${packageVersion}:${outputs.self}:${outputs.dependencies.helper}";
}
