assert builtins.length builtins.nixPath == 5;
import <a.nix> + import <b.nix> + import <c.nix> + import <dir5/c.nix>
