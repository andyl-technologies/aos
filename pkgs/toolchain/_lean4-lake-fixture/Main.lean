import Fixture

def main : IO Unit := do
  let input : BitVec 8 := 0x2a
  IO.println s!"fixture: {input.toNat} rotates to {(Fixture.rotate input).toNat}"
