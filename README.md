cca2python
==========

Cramer-Shoup encryption in Python

**Do not use this code in anything security-sensitive.  This code is PROOF OF CONCEPT only!!**

This is a demonstration of a cryptosystem with security against adaptive chosen ciphertext attacks, with a code base that is small enough to be audited quickly.  For key exchange, the Cramer-Shoup public key encryption system (hash-free variant) is used.  Symmetric encryption is done using the composition of the Naor-Reingold PRF and the DDH-based PRG of Farashahi et al.  These are all instantiated in the group of quadratic residues modulo a safe prime, which simplifies keying and parameter generation (this also simplifies the seed for the PRG).

I will add more documentation when I have a chance.  Comments, suggestions, and bug fixes are welcome.
