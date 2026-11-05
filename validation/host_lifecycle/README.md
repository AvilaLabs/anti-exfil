# Host lifecycle model

`model.py` is a small state model of the host's failure, warning and retry rules. `check.py` explores it, and `adapter.py` and `host_adapter.py` drive the reference host through the same events to compare the two. The model checks the reference host against the rules as we read them. It doesn't show that the text allows only one reading.

## Readings of the text

The model's switches, `U1` to `U11`, each hold one reading. Quotes are from `spec/bip-anti-exfil.md`. Its text settles all but `U5`.

| Switch | Question | Reading | Text |
|---|---|---|---|
| U1 | How long does an acknowledgement last? | One new attempt. The model voids an unused one on restart, the safe direction | "An acknowledgement covers exactly one new attempt and is used up in the same durable write". Whether an unused one survives a restart stays open, and does no harm |
| U2 | When has the host "warned"? | When the user acknowledges | "since the user last acknowledged a warning" |
| U3 | Does a warning stay owed after a reset? | No | "A reset clears any pending warning" |
| U4 | An unrequested message with no attempt open | Discarded, no charge | "Outside any attempt the host discards it" |
| U5 | An unrequested message while another response is outstanding | The host can't tell it from the response, so it treats it as the response | **Not stated.** It does no harm: a malformed response is a failure event anyway |
| U6 | Records that can't be read | Treated as a recorded failure, added once | "count of at least one" |
| U7 | A decline the user confirms was unrelated | The attempt ends, and the count doesn't change | "A decline that is not counted, under the rule below, also ends this way" (Abandoned) |
| U8 | What is a retry? | A repeat send after a failure event, with a budget per step | "Three retries for each of steps 2 and 4 is a reasonable default" |
| U9 | Are the count and the attempt's state separate writes? | No | "in one atomic write" |
| U10 | A restart after the attempt is recorded and before `hc` is sent | Charged, although the device saw nothing | "At startup, an attempt still recorded as open counts as failed" |
| U11 | Is repeating step 2 after the reveal required? | Optional, with its own budget | "It MAY repeat step 2 with the same `(m, hc)`" |
