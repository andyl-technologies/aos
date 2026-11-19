import Std.Tactic.BVDecide

namespace Fixture

/-- Rotates a byte left by two bits. -/
def rotate (x : BitVec 8) : BitVec 8 :=
  x.rotateLeft 2

/-- Rotation distributes over exclusive or. `bv_decide` discharges the goal
with the bundled CaDiCaL SAT solver and checks its LRAT certificate. -/
theorem rotate_xor (x y : BitVec 8) : rotate (x ^^^ y) = rotate x ^^^ rotate y := by
  unfold rotate
  bv_decide

end Fixture
