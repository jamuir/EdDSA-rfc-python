# EdDSA-rfc-python

This repository provides a python implementation of EdDSA taken directly
from [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032),
"Edwards-Curve Digital Signature Algorithm (EdDSA)" by S. Josefsson &
I. Liusvaara.

RFC 8032 gives python code in **Section 6**, **Appendix A** and
**Appendix B**; test vectors are given in **Section 7**.

The code from Section 6 is for the Ed25519 variant only.  You can
exercise that code like this:

```bash
$ python3 Section-6.py
```

The code from Appendix A covers all five variants: Ed25519,
Ed25519ctx, Ed25519ph, Ed448, Ed448ph.

The code from Appendix B reads a file of Ed25519 test vectors and
exercises them against the library code in Appendix A:

```bash
$ python3 Appendix-B.py < sign.input
```

The 21 test vectors given in RFC 8032 are pulled out into the file
`Section-7.input`.  To parse those test vectors and exercise them
against the library code, the script `test-eddsa2.py` was created.  It
can be used like so:

```bash
$ python3 test-eddsa2.py < Section-7.input
```
