# ECDSA-partially-known-nonce-attack
ECDSA (Elliptic Curve Digital Signature Algorithm) relies on the fact that the secret nonce is chosen randomly and employed only once, besides not being known to the attacker. However, it's possible to reconstruct its entire value starting from a contiguous set of its bits. 
This project involves the proof-of-concept of the attack described in Section 5.2 of https://cic.iacr.org/p/1/1/28/pdf , employing Python and Sagemath.
