# Security Policy

HATLS is a research prototype, not production software. Do not use it to protect real secrets yet.

## Reporting

Found a way to defeat the mandate that the attack playground does not already show? That is a
result, not just a bug. Open an issue describing the attack, or email the maintainer. Please include
a reproducing script.

## Scope

The protocol's honest limit is stated in `docs/THREAT-MODEL.md`: a physical insider on the enrolled
chip is narrowed and its window measured, not eliminated. Attacks that assume that capability are
in-scope to *measure*, not to "fix".
