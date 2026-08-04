## RFC-0011 migration fixture: the module-evaluated representation of the
## legacy `web` expose.config corpus pinned by golden_config_artifact.rs.
{
  config.packageExpose.config.artifacts = [
    {
      name = "env";
      path = "/etc/aos/packages/web/env";
      format = "env";
      required = ["TOKEN"];
      optional = ["URL"];
      units = ["web.service"];
      reload = "reload";
    }
    {
      name = "json";
      path = "/etc/aos/packages/web/json";
      format = "json";
      required = ["a"];
      optional = ["b"];
      units = ["web.service"];
      reload = "reload";
    }
    {
      name = "toml";
      path = "/etc/aos/packages/web/toml";
      format = "toml";
      required = ["k"];
      units = ["web.service"];
      reload = "reload";
    }
  ];

  config.parityDesired = {
    env = {
      TOKEN = "abc 123";
      URL = "https://x";
    };
    json = {
      a = 1;
      b = "two";
    };
    toml.k = "v";
  };
}
