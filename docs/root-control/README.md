# root-control documentation

root-control is the privileged host-side controller boundary for Zog. Its contracts must be read alongside box-control's trusted local API; callers must not bypass its validated operations.

## Privileged host boundary

Responsibility, allowed operations, validation and failure behavior are governed by the implementation and repository README. This chapter will be consolidated from existing contract and code evidence rather than asserting undocumented permissions.

## Journal barrier and durability

The [journal barrier contract](JOURNAL-BARRIER.md) describes optional build-job journal synchronization, its systemd requirements, and its limits: synchronization is not proof of log retention.

## Traceability

[Traceability and editorial status](TRACEABILITY.md) records retained source documents and boundaries.
