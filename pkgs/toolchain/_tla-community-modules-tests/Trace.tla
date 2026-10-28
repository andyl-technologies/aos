------------------------------- MODULE Trace -------------------------------
(***************************************************************************)
(* Trace validation for Counter.  Each line of the newline-delimited JSON *)
(* log records one event and the counter value observed after it.  The    *)
(* log path comes from the TRACE_FILE environment variable.  The trace is *)
(* a behavior of Counter exactly when TLC can match every logged event    *)
(* with a step of the specification, which TraceConsumed asserts.         *)
(***************************************************************************)
EXTENDS Counter, Json, IOUtils, Sequences, Naturals, TLC

TraceLog == ndJsonDeserialize(IOEnv.TRACE_FILE)

ASSUME Len(TraceLog) > 0
ASSUME \A i \in DOMAIN TraceLog :
        /\ TraceLog[i].event \in {"Increment", "Reset"}
        /\ TraceLog[i].count \in Nat

\* Round-trip the parsed log through TLC's binary value format.
ASSUME IOSerialize(TraceLog, "trace.vos", FALSE)
ASSUME IODeserialize("trace.vos", FALSE) = TraceLog

\* Index of the next log line to match.
VARIABLE line

traceVars == <<count, line>>

LogLine == TraceLog[line]

IsEvent(name) ==
    /\ line <= Len(TraceLog)
    /\ LogLine.event = name
    /\ line' = line + 1

TraceInit ==
    /\ Init
    /\ line = 1

TraceNext ==
    \/ /\ IsEvent("Increment")
       /\ Increment
       /\ count' = LogLine.count
    \/ /\ IsEvent("Reset")
       /\ Reset
       /\ count' = LogLine.count

TraceSpec == TraceInit /\ [][TraceNext]_traceVars /\ WF_traceVars(TraceNext)

\* A mismatched event disables TraceNext before the end of the log, after
\* which the behavior stutters forever and this property is violated.
TraceConsumed == <>(line > Len(TraceLog))
=============================================================================
