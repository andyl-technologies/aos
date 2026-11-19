------------------------------ MODULE Counter ------------------------------
(***************************************************************************)
(* A counter that can be incremented or reset to zero.                     *)
(***************************************************************************)
EXTENDS Naturals

VARIABLE count

Init == count = 0

Increment == count' = count + 1

Reset ==
    /\ count > 0
    /\ count' = 0

Next == Increment \/ Reset

Spec == Init /\ [][Next]_count
=============================================================================
