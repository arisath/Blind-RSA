# Blind RSA
Implementing the blind RSA scheme in Java

[![Generic badge](https://img.shields.io/badge/<CRYPTO>-<RSA>-<COLOR>.svg)](https://shields.io/)


The scheme was introduced by David Chaum and works as follows: the message to be signed is firstly blinded, this way the signing party does not learn its contents. The resulting signature can be publicly verified against the original, unblinded message in the manner of a regular digital signature. Blind signatures are typically employed in privacy-related protocols where the signing party and message author are distinct entities. Examples include cryptographic election systems and digital cash schemes.

In our implementation:

Alice, the signing party, produces an RSA keypair and can use it to issue digital signatures

Bob wants to get a signature over a message without revealing its actual content to Alice
