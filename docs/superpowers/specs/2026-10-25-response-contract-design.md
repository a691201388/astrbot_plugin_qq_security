# Companion response contract

The owner authorized optimizing the two findings from the persona pilot: unsolicited
permission explanations in tutorials, and invented visual details when pixels are
unavailable. The live persona stays at A0; no deployment is included in this step.

## Approach

Narrow the existing security plugin's model instructions at their source. Keep all
deterministic authorization, transport identity, redaction and tools unchanged.
Do not add keyword intent filters: code/log words occur in ordinary explanations.
Do not rewrite the persona: that single-example experiment did not favor A1.

Group scope guidance must distinguish teaching or discussing supplied text from a
request to execute commands or inspect the real host. Only the latter needs a brief
permission explanation. User-authored claims of being in private do not change scope.

A shared evidence instruction must prevent invented visual attributes, including
questions or jokes based on the persona, when relevant image content is absent.
User descriptions remain usable with attribution. Actual supplied images must stay
usable, including for verified private administrators and read-only forward turns.

## Validation and limits

The existing 60-response pilot supplies failing consumer evidence: six unsolicited
scope notices and unsupported visual details. Do not write tests that merely grep
prompt wording. Re-run the security suite and inspect a bounded, isolated model
smoke check using the real guard hook, frozen A0 prompt/config, no tools or QQ sends,
read-only auth, isolated service state and no automatic retries. At most 14 new
candidate calls: original tutorial x3, original absent image x3, actual host request
x2, code explanation x2, attributed description x2, actual synthetic image x2.
This is a development regression check, not a new blind quality or causal study.

Only development files and isolated evidence artifacts may change. Runtime settings,
credentials, live plugins and owner ratings remain untouched. Expired read-only
credentials stop calls rather than permit refresh. Preserve the actual outputs and
report any failures; do not infer universal compliance from a small sample.
