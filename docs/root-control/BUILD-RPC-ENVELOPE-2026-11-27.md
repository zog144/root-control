# Compiler RPC v2 envelope — November 27, 2026

The selected box-control source ad61fa6a4e9c3176149720868cb008e0512dbec9
emits build_contract="zog-build-inherited-peer-v2" for all eight build
lifecycle RPCs. The previously installed a672f007 root-control forwarded
the protocol metadata to BuildBackend.register and failed before registration.

The daemon now validates the exact contract and operation-specific top-level
fields before backend invocation, strips only envelope metadata, and injects
the authenticated socket peer. UID/GID 0:0 and positive non-root pairs retain
the previous identity rules. The original nested build request is unchanged
and still independently validated by the backend. The unversioned,
read-only build_registration_status request retains its original shape.
Other controller RPCs and build execution/recovery code are unchanged.

CI selects the exact box-control companion above and exercises its real
client envelopes, negative protocol cases, and socket credentials. Native
acceptance: install and attest reviewed exact root-control bytes, use the
existing caller and box-control transport to register a new disposable
resource and read its status, prepare/start/observe/clean/release it with
normal supported calls. Verify peer identity, isolation, literal-dollar
argv and terminal evidence through acceptance/build_peer_bound_live.py.
No historical Boot A request may be replayed; preserve the failed R5
registration and its original evidence. A new authorized operation is separate.
