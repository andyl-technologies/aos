using Workerd = import "/workerd/workerd.capnp";
const runtimeCheck :Workerd.Config = (
  services = [
    (name = "main", worker = (
      modules = [(name = "worker.js", esModule = embed "runtime-check.js")],
      compatibilityDate = "2026-08-01",
      compatibilityFlags = ["nodejs_compat"]
    )),
    (name = "internet", network = (allow = []))
  ]
);
