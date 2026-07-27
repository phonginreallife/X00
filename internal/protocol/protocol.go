// Package protocol defines the wire format between the kernelseal-exec shim and
// the KernelSeal agent.
//
// The shim connects, states which binary it is about to exec, and receives the
// environment variables to apply. The agent marks the caller's PID as protected
// before replying, so the secrets never exist in an unprotected process.
package protocol

// DefaultSocketPath is where the agent listens and the shim connects. It lives
// on a volume shared between the KernelSeal container and the application
// container.
const DefaultSocketPath = "/run/kernelseal/kernelseal.sock"

// MaxMessageSize bounds how much either side will read from a peer, so a
// malformed or hostile message cannot exhaust memory.
const MaxMessageSize = 1 << 20 // 1 MiB

// Request is sent by the shim.
type Request struct {
	// Binary is the path the shim is about to exec. It selects which secret
	// bindings apply.
	//
	// This is a claim, not an identity: the shim has not exec'd yet, so
	// /proc/<pid>/exe still points at the shim and the agent cannot verify it.
	// Authorization therefore rests on being able to reach the socket at all,
	// which is scoped to the pod. See SECURITY.md.
	Binary string `json:"binary"`
}

// Response is returned by the agent.
type Response struct {
	// OK reports whether the request was served. A request that matched no
	// secret bindings is still OK, with an empty Env.
	OK bool `json:"ok"`

	// Env holds the variables the shim should set before exec.
	Env map[string]string `json:"env,omitempty"`

	// Protected reports whether the agent installed kernel-level protection for
	// the caller. False means secrets were withheld or BPF-LSM is unavailable.
	Protected bool `json:"protected"`

	// Error describes why OK is false.
	Error string `json:"error,omitempty"`
}
