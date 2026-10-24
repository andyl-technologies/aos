##! Preserves the image-selected unit owner in native host-stage evaluation.
{...}: {
  # The parent enclosure already owns these immutable definitions. Replaying
  # package services must reconcile their lifecycle without replacing units or
  # reloading PID 1; the handler still authenticates each selected unit's bytes.
  aos.servicesRetainImageDefinitions = true;
}
