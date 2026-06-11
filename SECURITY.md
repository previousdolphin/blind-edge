# Security

B.E.Chat is an **open-source protocol demo**. The cryptography is real and the
design is honest, but **this code has not been professionally audited**. Do not
rely on it for life-safety communication.

## Threat model — what we defend against

| Threat | Defense |
|---|---|
| Relay operator reading messages | E2EE: ephemeral ECDH P-256 → HKDF → AES-256-GCM; relay holds ciphertext only |
| Relay operator identifying users | No accounts; addresses are SHA-256 hashes of public keys |
| Message tampering / forgery in transit | ECDSA P-256 signature over `ephPub ‖ iv ‖ ciphertext`, verified before decryption |
| Replay of captured envelopes | Strictly monotonic counter sealed inside the ciphertext |
| Message-length traffic analysis | All payloads padded to 256-byte blocks |
| Theft of the identity file / localStorage | Private keys + recovery entropy wrapped in AES-256-GCM under PBKDF2-SHA256 (600k iterations) of the App Password |
| Compromise of sender's long-term key (past sent messages) | Per-message ephemeral keys are discarded after use (sender-side forward secrecy) |
| Relay flooding | Per-IP rate limits (30 sends/min, 180 syncs/min); 24h envelope TTL |

## Out of scope — what we do NOT defend against

- **MITM during key exchange.** Keys are trusted on first use. A compromised
  exchange channel can substitute keys undetectably. Mitigation: exchange QR
  codes in person; compare identicons out-of-band. Safety numbers are future work.
- **Compromised endpoint.** Anyone with full access to the unlocked browser
  profile can read message history (stored readable by design — the App
  Password protects keys, not history) and use the identity.
- **Recipient-side forward secrecy / post-compromise security.** A leaked
  long-term private key decrypts past messages *sent to* that key that an
  attacker recorded. Double-Ratchet-style PFS requires recipient-published
  prekeys — out of scope for this version.
- **Relay metadata.** Timing, padded sizes, and IP addresses are visible to
  the relay operator. Run your own relay; use a VPN/Tor if IP matters.
- **Denial of service by the relay.** A malicious relay can drop or delay
  messages (it can never read or forge them).

## Reporting a vulnerability

Open a GitHub issue with the label `security`, or email the repository owner
(see the GitHub profile). There is no bounty program. Please allow a
reasonable disclosure window for a fix before publishing details.

## Known design trade-offs

These are documented choices, not oversights — see "Honest limitations" in the
app and README: TOFU key trust, sender-side-only PFS, plaintext-at-rest local
history, single-relay metadata exposure.
