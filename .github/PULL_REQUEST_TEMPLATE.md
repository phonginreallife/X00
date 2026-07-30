## What this changes

<!-- And why. The why is the part reviewers cannot reconstruct from the diff. -->

## Effect on the guarantee

<!--
KernelSeal's security property is an ordering one: the agent marks a PID
protected before it releases any secret, and execve preserves the PID, so no
protected process ever runs with readable secrets.

State whether this change touches that ordering, who can request secrets, what
the agent trusts a caller to assert, or where plaintext exists. "No effect" is a
fine answer when it is true.
-->

## Testing

- [ ] `make verify` passes
- [ ] `make test-delivery` passes
- [ ] `make test-integration` passes, or is not applicable
- [ ] BPF programs changed, and `make abi-check` still passes

<!--
The enforcement tests skip rather than fail without root and a kernel booted with
bpf in its lsm= list, so a green make verify does not mean enforcement was
tested. If you could not run them, say so here rather than leaving it implicit.
-->

## Documentation

- [ ] SECURITY.md updated, or the threat model is unaffected
- [ ] README.md updated, or configuration and deployment are unaffected
- [ ] Any new limitation is written down in the known limitations list
