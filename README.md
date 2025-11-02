# Blind RSA
Implementing the blind RSA scheme in Java

[![Generic badge](https://img.shields.io/badge/CRYPTO-RSA-<COLOR>.svg)](https://shields.io/)
![fork this repo](https://img.shields.io/github/forks/arisath/Blind-RSA?style=flat)


## Table of Contents
- [Introduction](#introduction)
- [Blind RSA Overview](#blind-rsa-overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Visualizer](#visualizer)
- [Protocol Flow](#protocol-flow)
- [Security & Caveats](#security--caveats)
- [Contributing](#contributing)
- [License](#license)

---

## Blind RSA Overview

The scheme was introduced by David Chaum and works as follows: the message to be signed is firstly blinded, this way the signing party does not learn its contents. The resulting signature can be publicly verified against the original, unblinded message in the manner of a regular digital signature. Blind signatures are typically employed in privacy-related protocols where the signing party and message author are distinct entities. Examples include cryptographic election systems and digital cash schemes.

Read more: https://en.wikipedia.org/wiki/Blind_signature

In our implementation:

Alice, the signing party, produces an RSA keypair and can use it to issue digital signatures

Bob wants to get a signature over a message without revealing its actual content to Alice


### What is Blind RSA?
In the standard RSA signature scheme, a signer with private key \(d\) signs a message \(m\) by computing  
\[
s = m^d \bmod n.
\]
The verifier checks \( s^e \bmod n = m \).

With Blind RSA, the requester (Bob) blinds his message before sending it to the signer (Alice). That way Alice signs the blinded message, and Bob then unblinds the result to obtain a valid signature — while Alice never sees the original message.

### Why use Blind RSA?
- **Privacy**: The signer does not learn the actual message.
- **Unlinkability**: The resulting signature cannot be linked by the signer back to the blinded request.
- **Applications**: Digital cash, anonymity systems, voting, blind credential issuance.


### Protocol at a glance

1. Alice (signer) generates RSA key pair (n, e, d).
2. Bob (requester) chooses message m.
3. Bob picks random r coprime to n, computes blinded message m' = m * r^e mod n.
4. Bob sends m' to Alice.
5. Alice signs: s' = (m')^d mod n.
6. Alice returns s'.
7. Bob computes unblinded signature: s = s' * r^-1 mod n.
8. Bob verifies: s^e mod n = m.

---
## Features
- Java implementation using `java.security.KeyPairGenerator` and manual big‑integer math.
- Logging of each step (key generation, blinding, signing, unblinding, verification).
- JSON export of protocol steps for visualisation.
- Front‑end visualiser (sequence diagram) with animations and annotations.
- Distinction between local actions and messages sent between parties.

---

## Introduction

This repository contains a simple yet clear implementation of Blind RSA — a variant of the standard RSA signature scheme — that allows a requester to obtain a signature on a message **without revealing that message** to the signer.  
It also includes a visualisation (sequence diagram) to help understand the entire process.

---

## Getting Started

1. Clone the repository:
2. Build with Maven:
3. Run the main class:
4. This will generate `output.json`.
5. Open the visualiser HTML file in a browser

