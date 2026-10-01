##! Retains portable system policy independently of image build machinery.
{
  imports = [./kernel.nix ./networking.nix ./hardening.nix ./journald.nix ./configuration-lower.nix ./role-edge.nix ./role-server.nix ./security-level.nix ./observer-bootstrap.nix ./session-environment.nix ./pki.nix ./users.nix ./homes.nix ./package-environment.nix];
}
