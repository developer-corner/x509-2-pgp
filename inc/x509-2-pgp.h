/**
 * @file   x509-to-pgp.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  declares structures and functions for importing X.509v3 / public /
 *         private keys to PGP (OpenPGP, GnuPG, other)
 *
 * [MIT license]
 *
 * Copyright (c) 2025 Ingo A. Kubbilun
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _INC_X509_2_PGP_H_
#define _INC_X509_2_PGP_H_

#ifdef _cplusplus
extern "C" {
#endif

#if defined(_LINUX) || defined(_MACOS)

#ifndef __USE_GNU
#define __USE_GNU
#endif // __USE_GNU

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <byteswap.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>

#define likely(expr)    (__builtin_expect(!!(expr), 1))
#define unlikely(expr)  (__builtin_expect(!!(expr), 0))

#define FMT64_PREFIX    "l"
#define PATHSEP_CHAR    '/'

#elif defined(_WINDOWS)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <direct.h>
#include <sysinfoapi.h>
#define likely(expr)    (expr)
#define unlikely(expr)  (expr)

#define strcasecmp      _stricmp
#define FMT64_PREFIX    "I64"
#define PATHSEP_CHAR    '\\'

#define bswap_16(_x)    _byteswap_ushort(_x)
#define bswap_32(_x)    (((_x)>>24) | (((_x)>>8) & 0x0000FF00) | (((_x)<<8) & 0x00FF0000) | ((_x)<<24))
#define bswap_64(_x)    _byteswap_uint64(_x)

#undef unlink
#undef read
#undef write
#undef close
#undef mkdir
#undef rmdir
#undef putenv
#define unlink          _unlink
#define strcasecmp      _stricmp
#define read            _read
#define write           _write
#define close           _close
#define mkdir(_a,_b)    _mkdir(_a)
#define rmdir           _rmdir
#define putenv          _putenv
#define __sync_fetch_and_and(_a,_b)     InterlockedAnd(_a,_b)
#define __sync_fetch_and_or(_a,_b)      InterlockedOr(_a,_b)

static inline int unsetenv(const char* var)
{
  char buffer[256];
  snprintf(buffer, sizeof(buffer), "%s=", var); // variable just with '=' removes an environment variable
  return _putenv(buffer);
}

#else

#error "Please define either _LINUX, _WINDOWS or _MACOS"

#endif

#define VERSION_MAJOR       0
#define VERSION_MINOR       1

#if !defined(DATA_ORDER_IS_BIG_ENDIAN) && !defined(DATA_ORDER_IS_LITTLE_ENDIAN)
# error "DATA_ORDER must be defined!"
#endif

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/pkcs7.h>
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/core_names.h>

#define MD_TYPE_SHA1                    0x00000000
#define MD_TYPE_RIPEMD160               0x00000001
#define MD_TYPE_SHA2_224                0x00000002
#define MD_TYPE_SHA2_256                0x00000003
#define MD_TYPE_SHA2_384                0x00000004
#define MD_TYPE_SHA2_512                0x00000005  ///< ED25519 implicitly uses SHA2-512
#define MD_TYPE_SHA3_224                0x00000006
#define MD_TYPE_SHA3_256                0x00000007
#define MD_TYPE_SHA3_384                0x00000008
#define MD_TYPE_SHA3_512                0x00000009
#define MD_TYPE_SHAKE_256               0x0000000A  ///< this is solely for ED448

#define SIG_TYPE_RSA_PKCS1_V15          0x00000000  ///< 2048/3072/4096, PKCS#1 v1.5
#define SIG_TYPE_RSA_PSS_SHA256         0x00000001  ///< 2048/3072/4096, PSS with SHA-256 also used for KDF1, salt length: 32 bytes, trailer BC
#define SIG_TYPE_RSA_PSS_SHA384         0x00000002  ///< 2048/3072/4096, PSS with SHA-384 also used for KDF1, salt length: 48 bytes, trailer BC
#define SIG_TYPE_RSA_PSS_SHA512         0x00000003  ///< 2048/3072/4096, PSS with SHA-512 also used for KDF1, salt length: 64 bytes, trailer BC
#define SIG_TYPE_ECDSA_SECP256R1        0x00000004  ///< ECDSA, secp256r1 aka prime256v1
#define SIG_TYPE_ECDSA_SECP384R1        0x00000005  ///< ECDSA, secp384r1
#define SIG_TYPE_ECDSA_SECP521R1        0x00000006  ///< ECDSA, secp521r1
#define SIG_TYPE_ECDSA_SECT571R1        0x00000007  ///< ECDSA, sect571r1 (NOT USED BY PGP)
#define SIG_TYPE_ECDSA_BRAINPOOLP256R1  0x00000008  ///< ECDSA, brainpoolP256r1
#define SIG_TYPE_ECDSA_BRAINPOOLP384R1  0x00000009  ///< ECDSA, brainpoolP384r1
#define SIG_TYPE_ECDSA_BRAINPOOLP512R1  0x0000000A  ///< ECDSA, brainpoolP512r1
#define SIG_TYPE_EDDSA_25519            0x0000000B  ///< EdDSA, ED25519
#define SIG_TYPE_EDDSA_448              0x0000000C  ///< EdDSA, ED448
#define SIG_TYPE_EDDSA_25519PH          0x0000000D  ///< EdDSA, ED25519, pre-hashed
#define SIG_TYPE_EDDSA_448PH            0x0000000E  ///< EdDSA, ED448, pre-hashed

#define IS_ECDSA(_t) (((_t)>=SIG_TYPE_ECDSA_SECP256R1) && ((_t)<=SIG_TYPE_ECDSA_BRAINPOOLP512R1))

#define X509_SIG_ALGO_PKCS1_V15_SHA256  0x00000000  ///< sha256WithRsaEncryption
#define X509_SIG_ALGO_PKCS1_V15_SHA384  0x00000001  ///< sha384WithRsaEncryption
#define X509_SIG_ALGO_PKCS1_V15_SHA512  0x00000002  ///< sha512WithRsaEncryption
#define X509_SIG_ALGO_RSAPSS_SHA256     0x00000003  ///< rsa-PSS with SHA256 as hash function, MGF1 hash function, salt length = md size = 32, trailerField BC
#define X509_SIG_ALGO_RSAPSS_SHA384     0x00000004  ///< rsa-PSS with SHA384 as hash function, MGF1 hash function, salt length = md size = 48, trailerField BC
#define X509_SIG_ALGO_RSAPSS_SHA512     0x00000005  ///< rsa-PSS with SHA512 as hash function, MGF1 hash function, salt length = md size = 64, trailerField BC
#define X509_SIG_ALGO_ECDSA_SHA256      0x00000006  ///< ecdsaWithSha256
#define X509_SIG_ALGO_ECDSA_SHA384      0x00000007  ///< ecdsaWithSha384
#define X509_SIG_ALGO_ECDSA_SHA512      0x00000008  ///< ecdsaWithSha512
#define X509_SIG_ALGO_EDDSA_ED25519     0x00000009  ///< EdDSA, ED25519, SHA-512 implicitly
#define X509_SIG_ALGO_EDDSA_ED448       0x0000000A  ///< EdDSA, ED448, SHAKE-256 implicitly

#define X509_PK_ALGO_RSA                0x00000000
#define X509_PK_ALGO_EC                 0x00000001
#define X509_PK_ALGO_ED                 0x00000002

#define KEY_TYPE_RSA2048                0x00000000
#define KEY_TYPE_RSA3072                0x00000001
#define KEY_TYPE_RSA4096                0x00000002
#define KEY_TYPE_ECNIST256              0x00000003
#define KEY_TYPE_ECNIST384              0x00000004
#define KEY_TYPE_ECNIST521              0x00000005
#define KEY_TYPE_ECBPOOL256             0x00000006
#define KEY_TYPE_ECBPOOL384             0x00000007
#define KEY_TYPE_ECBPOOL512             0x00000008
#define KEY_TYPE_ED25519                0x00000009
#define KEY_TYPE_ED448                  0x0000000A

#define NUM_NAMED_EC_CURVES             8

#define CURVE_NIST_256                  0
#define CURVE_NIST_384                  1
#define CURVE_NIST_521                  2
#define CURVE_BRAINPOOL_256             3
#define CURVE_BRAINPOOL_384             4
#define CURVE_BRAINPOOL_512             5
#define CURVE_ED25519                   6
#define CURVE_ED448                     7

// old ED448 means: create v5 packets, not v4!!!
extern bool       edwards_legacy;             ///< true if ED25519/448 legacy PGP algorithm scheme, false if new ED25519/448 PGP algorithm scheme
extern bool       do_verify;                  ///< verify digital signature in software after having computed it (either in software or via PKCS#11)
extern bool       use_rsa_pss;                ///< use RSA-PSS instead of RSA PKCS#1 v1.5
extern bool       use_ed_ph;                  ///< use Edwards Curve algorithm in 'ph' = pre-hashed form
extern bool       pgp_new_packet_format;      ///< use PGP new packet format instead of old format (default)
extern bool       force;                      ///< do not ask use before deleting PKCS#11 keys in hardware module
extern bool       be_quiet;                   ///< be quiet, no extra output
extern time_t     key_creation_ts;            ///< 0 or key creation timestamp (seconds since 1970-01-01 00:00:00)
extern char       pkcs11_library[256];        ///< fully-qualified file name of .dll (Windows) or .so (Linux) of PKCS#11 library
extern char       pkcs11_pin[256];            ///< PKCS#11 PIN, please note that if this is empty, then SECRET is also checked in terms of a PKCS#11 PIN
extern uint32_t   pkcs11_slot;                ///< PKCS#11 slot, defaults to zero (0)
extern char       secret[256];                ///< secret read from SECRET environment variable; for PKCS#11, you may alternatively use PKCS11_PIN
extern char       pgp_secret[256];            ///< PGP secret read from PGP_SECRET environment variable
extern bool       secret_set;                 ///< true if SECRET set (also if this string is empty meaning: 'no password')
extern char       serial[256];                ///< serial number override
extern bool       convert_pubkey_only;        ///< convert public key only, not private key, i.e. create PGP PUBLIC KEY PACKET, not SECRET KEY PACKET
extern char       user_name[256];             ///< user name (override if not specified by X.509v3 input)
extern char       email_addr[256];            ///< E-mail address (override if not specified by X.509v3 input)
extern char       pkcs11_label[256];          ///< pkcs11_label of private key to use for signature operations
extern bool       expiry_days_set;            ///< true if expiry days explicitly specified
extern uint32_t   expiry_days;                ///< expiry days, 0 means "does not expire"
extern uint32_t   md_type;                    ///< digest specified (our own implementation)
extern uint32_t   pgp_digest_algo;            ///< 'official' PGP DIGEST_ALGO_xxx constant
extern uint64_t   rsa_pubexp;                 ///< RSA public exponent e, default to 65.537
extern uint32_t   gpg_enc_algo;               ///< none, CFB128 or GCM (the latter two AES-256); AES-GCM currently not testable because no GnuPG impl. available (2025/06/01)
extern char       pkcs11_label_cert[256];     ///< PKCS#11 label of key pair for certification
extern char       input_filename[256];        ///< input filename (only for patchx509)
extern char       output_filename[256];       ///< output filename
extern char       private_key_file[256];      ///< private key file (PEM)
extern char       public_key_file[256];       ///< public key file or X.509v3 file (PEM)
extern char       private_key_cert_file[256]; ///< private key file (PEM) for certification - if omitted, then self-signature
extern char       public_key_cert_file[256];  ///< public key file or X.509v3 file (PEM) for certification - if not X.509v3, then email_addr_cert required
extern char       email_addr_cert[256];       ///< E-mail address used for certification
extern bool       dryrun;                     ///< do NOT emit pgpimport file, just display what would be done

extern char ctrlReset[16];
extern char ctrlRed[16];
extern char ctrlGreen[16];
extern char ctrlYellow[16];
extern char ctrlBlue[16];
extern char ctrlMagenta[16];
extern char ctrlCyan[16];

#ifdef _cplusplus
}
#endif

#endif // _INC_X509_2_PGP_H_
