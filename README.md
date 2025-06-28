# x509-2-pgp
Creates a bridge between ITU-T X.690/X.509 and OpenPGP/GNU Privacy Guard

Provides a command-line tool (for **Linux and Windows**) that converts e.g. OpenSSL public keys or full key pairs to binary PGP packet structures, which can be imported into your PGP keyring.
Comes with a full PKCS#11 integration, i.e. there is no need to set up possibly complicated software stacks to use your smartcard, token or even Hardware Security Module (HSM).

This software currently works with **signature keys / key pairs only**. No encryption whatsoever. Supports RSA, ECDSA, and EdDSA (Edwards Curves).

## Introduction
This tool closes the gap between ASN.1 and the OpenPGP standard with respect to signature keys. Plus: It enables you to create detached, binary PGP signatures using a PKCS#11 module.

## Platforms
1. Linux (64bit, any architecture); GNU autoconf/automake
2. Windows (64bit, x86-64); solution and project provided in win32 subfolder (also a pre-built OpenSSL for Windows)
3. Mac OS (prepared but not yet tested - I do not have an Apple box...)

## Available functionalities
This command-line tool was mainly written to support PGP code signing scenarios (with built-in PKCS#11 support). One example scenario is the GRUB2 bootloader, which also comes with a GNU Privacy Guard implementation to verify code signatures.
The command-line tool is split into applets:
1. Generate key pairs for RSA, ECDSA, and EdDSA (ED25519/ED448) either in software (OpenSSL) or in a PKCS#11 module.
2. Create binary PGP import package structures (files) for your keys or key pairs, respectively. Also, X.509v3 certificates may be used as public keys (possibly providing PGP user name and/or PGP E-mail address).
3. Create raw binary, detached, PGP signatures using private keys stored in a PKCS#11 module (you do NOT have to set up any PGP PKCS#11 stuff for this!).
4. Create raw binary, detached, non-PGP signatures (with PKCS#11 support).
5. Verify raw binary, detached, non-PGP signatures (always in software using OpenSSL).
6. Patch X.509v3 certificates with their associated private keys residing in a PKCS#11 module (i.e. first issue an X.509v3 certificate using a dummy, temporary software key pair, then exchange the public key in this X.509v3 certificate template by the public key of a key pair stored in a PKCS#11 module - you do NOT have to setup OpenSSL ENGINEs or crypto providers for this!).

## Supported and unsupported features
1. Only signature keys - algorithms: RSA PKCS#1 v1.5 (GnuPG, PGP signatures), RSA PKCS#1 PSS (OpenSSL, raw signatures), ECDSA, EdDSA
2. Full PKCS#11 built-in support for smartcards, tokens, HSMs
3. OpenPGP RFC 9580 - version four (4) and five (5) PGP packets; unsupported: version six (6) packets
4. AES-CFB (256bit) private key encryption (these keys are called 'secret keys' in the PGP specs.)
5. all SHA2 message digests (SHA-224,-256,-384,-512) but **no** SHA3 message digests (new in RFC 9580)
6. Elliptic Curves: NIST 256bit/384bit/521bit (prime256v1, secp384r1, and secp521r1), Brainpool 256bit/384bit/512bit (brainpoolP256R1,..,brainpoolP512R1)
7. Edwards Curves: ED25519 (v4 PGP packet format) and ED448 (v5 PGP packet format)

## Build instructions
Please **DO READ** the accompanying **README** file first. For the impatient, on Linux, execute:

    ./autgen.sh && ./configure && make && sudo make install

A man page is available, too. Add '--enable-debug' to build a non-optimized version with full debug information. You may also use
a non-standard OpenSSL installation (see './configure --help').

On Windows, use the solution in the subfolder win32. A pre-built OpenSSL for Windows (version 3.5.0) is included as well.

## Testsuite
To execute the test suite (see README), you have to configure '--enable-tests' on Linux (the Windows version comes with all tests enabled already).

You need a GNU Privacy Guard installation to run the tests (on either Windows or Linux). All tests are carried out in a separate, temporary GNUPG keyring. It does not harm your existing keyrings.
If you want to execute the test suite with all PKCS#11 tests enabled, then please note that the test suite deletes, re-creates, and again deletes required test key pairs. The PKCS#11 test key labels
all start with the prefix 'p11_'. 

**DO NOT USE THE PKCS#11-ENABLED TEST SUITE ON A PRODUCTION PKCS#11 MODULE!!!**
