# LWE-Auth (Authenticated Learning With Errors)

A C-implementation of a post-quantum cryptosystem based on the *Learning With Errors (LWE) * problem. This project integrates lattice mathematics with HMAC-SHA256 authentication and direct kernel entropy extraction, focusing on security against lateral channel and ciphertext forging attacks.

## Security Architecture

* **Quantum Resistance (LWE):** The core of encryption is based on noise injection into multidimensional lattices, making breaking by quantum algorithms such as Shor's unfeasible.
* **Side-Channel Resistance:** The code was written eliminating secret-dependent branches and explicit arithmetic module operators, preventing *Timing Attacks*.
* **IND-CCA2 defense:** Ciphertext has an integrity layer signed via HMAC-SHA256, using derived keys. Changes in transit result in the rejection of decryption in constant time.
* **Kernel Entropy:** Replacement of insecure PRNGs by extraction of random entropy from the OS ('getrandom'), mitigating initial state prediction.

## Requirements and Compilation

Requires the GCC compiler and the OpenSSL library ('libssl-dev' / 'openssl').

```bash
make 