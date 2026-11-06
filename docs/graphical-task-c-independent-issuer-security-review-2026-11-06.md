# Task C issuer independent review and native Work acceptance — 2026-11-06

**Disposition:** PR #42 is a draft source correction stacked on PR #41. It is not real production signing authority. Keep the owner, broker and gateway pin disabled.

## Findings and corrections

1. **Original checkpoint selection:** PR #41 checked the checkpoint supplied by an operator manifest, not an independently selected original. PR #42 requires its exact canonical SHA-256 to match the separate root-protected `accepted-original-checkpoint.sha256` before approval or broker-purpose signing. Work must establish this pin from authentic existing original storage, reservation and external anchor, never from the candidate manifest.
2. **Source selection:** PR #41 accepted the event manifest's `original_commit_sha` as a syntactically valid Git SHA. PR #42 additionally requires the separately installed `accepted-dispatch-revision.commit`. Work must verify this Git commit belongs to the genuine repository and was independently approved; the GitHub issue-opened event itself does not prove a selected commit.
3. **Signer custody:** the two signers must occupy distinct protected authorities. PR #42 refuses opposite-role private signing material, and refuses the GitHub webhook secret on the operator signer. Independent key enrollment, protected public pins and denial from the gateway remain native Work requirements.
4. **Operator intent:** a terminal digest alone is insufficient to verify a candidate. PR #42 displays the full canonical approval content, including original identity, before requiring the human to confirm its digest. Work still has to corroborate each displayed field from independent records.
5. **Missing historical source:** there is no identified accepted original event, signing custodian or immutable S3 genesis in the inspected native handoff. Do not replace, reconstruct, backdate or claim these existed.

## Native sequence for root-control Work

First inspect genuine retained operator/event enrollment, source pins, original external S3 anchor and signed original webhook archive **read-only**. Record positive custody and independent retention evidence or explicitly mark each source absent/unverified.

If original evidence does not exist, a **new Fonts request** requires distinct, explicitly authorized prospective operator enrollment, an authenticated new GitHub `issues.opened` webhook, new request and operation identities, and independently accepted new original ledger scope. Never convert an old unverified event into a newly signed historical event.

On separately protected signing machines, verify the registered operator and event-issuer public pins, the independently installed counterparty pins and original checkpoint/source selections. Capture the genuine raw GitHub delivery, confirm its HMAC and `X-GitHub-Delivery` against the actual original bytes, and match numeric repository/actor, issue, request ID and canonical request digest. The GitHub API currently reports repository ID `1423774675` for `zog144/host-deploy`; Work must independently verify the deployed repository identity before selecting it.

After exact installed issuer package/RECORD/unit and protected storage checks, admit separate signed preflight/stage operator approvals and event-issuer evidence, followed by a separately approved broker-purpose grant. Bind original Host, installation, STATE, scope, S3 account/region/bucket/prefix/genesis/writer role, exact gateway executable/cgroup and distinct S3 read/SSM roles. Verify native signatures and expiry against independently accepted pins, and test effective IAM/IMDS/STS/SSM denial from the actual gateway principal. Do not grant ListBucket to mask a missing-sequence ambiguity.

Publish only nonsecret evidence: signer roles and public fingerprints, original enrollment receipts, GitHub delivery/request digests, exact installed hashes, authenticated S3 history/anchor, issuance UTC times and failure/acceptance states. Do not include credentials or private signing material. If any required original authority is absent, **HOLD** and do not start owner/broker, send SSM or mutate S3.

## Verification scope

PR #42's GitHub Actions test suite is synthetic and cannot establish native key custody, deployed HTTPS webhook acceptance, original storage retention or effective AWS privilege denial.
