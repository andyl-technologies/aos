"""Solve a small bit-vector problem through the installed z3 Python package."""

import sys

import z3

x = z3.BitVec("x", 16)
y = z3.BitVec("y", 16)

solver = z3.Solver()
solver.add(x * 7 == 91, y == x << 2, z3.ULT(x, 100))

if solver.check() != z3.sat:
    sys.exit("z3 bindings: expected sat")

model = solver.model()
values = (model[x].as_long(), model[y].as_long())
if values != (13, 52):
    sys.exit(f"z3 bindings: unexpected model {values}")

solver.add(x != 13)
if solver.check() != z3.unsat:
    sys.exit("z3 bindings: expected unsat after excluding the model")

print(f"z3 bindings passed: x={values[0]} y={values[1]} version={z3.get_version_string()}")
