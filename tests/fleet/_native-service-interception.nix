##! Selects retained response barriers before constructing the original scenario graph.
{...}: {
  aos.nativeHandlerInterception = {
    native-handler-interception-systemd.operations = [
      { ability = "identity"; name = "group"; }
      { ability = "identity"; name = "principal"; }
      { ability = "identity"; name = "membership"; }
    ];
    native-handler-interception-systemd-service.operations = [
      { ability = "serviceManagement"; name = "realize"; }
    ];
  };
}
