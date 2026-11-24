# ADR-0002: Scoring is a pure, versioned function; AI never scores
**Decision.** Scores come only from `scoring/cmmc.py` over human-recorded objective results, using a rules
file transcribed from 32 CFR 170.24/170.21 with its own version and review status.
**Why.** Reproducibility (same inputs → same hash → same score), auditability (trace lines), and the
legal reality that only an assessor determines MET/NOT MET. Unresolved items are treated as NOT MET in
readiness mode and block OFFICIAL mode. Missing requirements never default to MET.
