# Crypto
Implementing the blind RSA scheme in Java

The scheme was introduced by David Chaum. The scheme works as follows: the message to be signed is firstly blinded, this way the signing party does not learn the content of the message. The signature can be publicly verified against the original, unblinded message in the manner of a regular digital signature. Blind signatures are typically employed in privacy-related protocols where the signing party and message author are distinct entities. Examples include cryptographic election systems and digital cash schemes.

In our implementation:

Alice, the signing party, produces an RSA keypair and can use it to issue digital signatures

Bob, the author of the message, wants to get a signature over a message without revealing the actual message to Alice
