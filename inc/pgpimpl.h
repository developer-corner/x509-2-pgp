/**
 * @file   pgpimpl.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  declaration of all PGP (OpenPGP/GnuPG) specific stuff
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

#ifndef _INC_PGPIMPL_H_
#define _INC_PGPIMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <x509-2-pgp.h>

#define PKT_NONE                   0
#define PKT_PUBKEY_ENC             1 /* Public key encrypted packet. */
#define PKT_SIGNATURE              2 /* Secret key encrypted packet. */
#define PKT_SYMKEY_ENC             3 /* Session key packet. */
#define PKT_ONEPASS_SIG            4 /* One pass sig packet. */
#define PKT_SECRET_KEY             5 /* Secret key. */
#define PKT_PUBLIC_KEY             6 /* Public key. */
#define PKT_SECRET_SUBKEY          7 /* Secret subkey. */
#define PKT_COMPRESSED             8 /* Compressed data packet. */
#define PKT_ENCRYPTED              9 /* Conventional encrypted data. */
#define PKT_MARKER                10 /* Marker packet. */
#define PKT_PLAINTEXT             11 /* Literal data packet. */
#define PKT_RING_TRUST            12 /* Keyring trust packet. */
#define PKT_USER_ID               13 /* User id packet. */
#define PKT_PUBLIC_SUBKEY         14 /* Public subkey. */
#define PKT_OLD_COMMENT           16 /* Comment packet from an OpenPGP draft. */
#define PKT_ATTRIBUTE             17 /* PGP's attribute packet. */
#define PKT_ENCRYPTED_MDC         18 /* Integrity protected encrypted data. */
#define PKT_MDC                   19 /* Manipulation detection code packet. */
#define PKT_ENCRYPTED_AEAD        20 /* AEAD encrypted data packet. */
#define PKT_COMMENT               61 /* new comment packet (GnuPG specific). */
#define PKT_GPG_CONTROL           63 /* internal control packet (GnuPG specific). */

#define SIGSUBPKT_TEST_CRITICAL   -3
#define SIGSUBPKT_LIST_UNHASHED   -2
#define SIGSUBPKT_LIST_HASHED     -1
#define SIGSUBPKT_NONE             0
#define SIGSUBPKT_SIG_CREATED      2 /* Signature creation time. */
#define SIGSUBPKT_SIG_EXPIRE       3 /* Signature expiration time. */
#define SIGSUBPKT_EXPORTABLE       4 /* Exportable. */
#define SIGSUBPKT_TRUST            5 /* Trust signature. */
#define SIGSUBPKT_REGEXP           6 /* Regular expression. */
#define SIGSUBPKT_REVOCABLE        7 /* Revocable. */
#define SIGSUBPKT_KEY_EXPIRE       9 /* Key expiration time. */
#define SIGSUBPKT_ARR             10 /* Additional recipient request. */
#define SIGSUBPKT_PREF_SYM        11 /* Preferred symmetric algorithms. */
#define SIGSUBPKT_REV_KEY         12 /* Revocation key. */
#define SIGSUBPKT_ISSUER          16 /* Issuer key ID. */
#define SIGSUBPKT_NOTATION        20 /* Notation data. */
#define SIGSUBPKT_PREF_HASH       21 /* Preferred hash algorithms. */
#define SIGSUBPKT_PREF_COMPR      22 /* Preferred compression algorithms. */
#define SIGSUBPKT_KS_FLAGS        23 /* Key server preferences. */
#define SIGSUBPKT_PREF_KS         24 /* Preferred keyserver. */
#define SIGSUBPKT_PRIMARY_UID     25 /* Primary user id. */
#define SIGSUBPKT_POLICY          26 /* Policy URL. */
#define SIGSUBPKT_KEY_FLAGS       27 /* Key flags. */
#define SIGSUBPKT_SIGNERS_UID     28 /* Signer's user id. */
#define SIGSUBPKT_REVOC_REASON    29 /* Reason for revocation. */
#define SIGSUBPKT_FEATURES        30 /* Feature flags. */
#define SIGSUBPKT_SIGNATURE       32 /* Embedded signature. */
#define SIGSUBPKT_ISSUER_FPR      33 /* Issuer fingerprint. */
#define SIGSUBPKT_PREF_AEAD       34 /* Preferred AEAD algorithms. */
#define SIGSUBPKT_ATTST_SIGS      37 /* Attested Certifications.  */
#define SIGSUBPKT_KEY_BLOCK       38 /* Entire key used.          */
#define SIGSUBPKT_META_HASH       40 /* Literal Data Meta Hash.   */
#define SIGSUBPKT_TRUST_ALIAS     41 /* Trust Alias.              */
#define SIGSUBPKT_FLAG_CRITICAL  128

#define CIPHER_ALGO_NONE           0
#define CIPHER_ALGO_IDEA           1
#define CIPHER_ALGO_3DES           2
#define CIPHER_ALGO_CAST5          3
#define CIPHER_ALGO_BLOWFISH       4
#define CIPHER_ALGO_AES            7
#define CIPHER_ALGO_AES192         8
#define CIPHER_ALGO_AES256         9
#define CIPHER_ALGO_TWOFISH       10
#define CIPHER_ALGO_CAMELLIA128   11
#define CIPHER_ALGO_CAMELLIA192   12
#define CIPHER_ALGO_CAMELLIA256   13
#define CIPHER_ALGO_PRIVATE10    110

#define AEAD_ALGO_NONE             0
#define AEAD_ALGO_EAX              1
#define AEAD_ALGO_OCB              2
#define AEAD_ALGO_GCM              3

#define PUBKEY_ALGO_RSA            1
#define PUBKEY_ALGO_RSA_E          2 /* RSA encrypt only (legacy). */
#define PUBKEY_ALGO_RSA_S          3 /* RSA sign only (legacy).    */
#define PUBKEY_ALGO_KYBER          8 /* Kyber (FIPS-203 final)     */
#define PUBKEY_ALGO_ELGAMAL_E     16 /* Elgamal encrypt only.      */
#define PUBKEY_ALGO_DSA           17
#define PUBKEY_ALGO_ECDH          18 /* RFC-6637                                   */
#define PUBKEY_ALGO_ECDSA         19 /* RFC-6637                                   */
#define PUBKEY_ALGO_ELGAMAL       20 /* Elgamal encrypt+sign (legacy).             */
#define PUBKEY_ALGO_EDDSA_LEGACY  22 /* EdDSA, only ED25519, legacy                */  /* curve OID and two MPIs as signature */
#define PUBKEY_ALGO_EDDSA_25519   27 /* EdDSA with ED25519, new                    */  /* no curve OID, just 64 octets as signature */
#define PUBKEY_ALGO_EDDSA_448     28 /* EdDSA with ED448, new (there is no legacy) */  /* no curve OID, just 114 octets as signature */
#define PUBKEY_ALGO_DIL3_25519    35 /* Dilithium3 + Ed25519 (aka ML-DSA-65)       */
#define PUBKEY_ALGO_DIL5_448      36 /* Dilithium5 + Ed448   (aka ML-DSA-87)       */
#define PUBKEY_ALGO_SPHINX_SHA2   41 /* SPHINX+-simple-SHA2  (aka SLH-DSA-SHA2)    */
#define PUBKEY_ALGO_PRIVATE10    110

#define DIGEST_ALGO_MD5            1
#define DIGEST_ALGO_SHA1           2
#define DIGEST_ALGO_RMD160         3
#define DIGEST_ALGO_SHA256         8
#define DIGEST_ALGO_SHA384         9
#define DIGEST_ALGO_SHA512        10
#define DIGEST_ALGO_SHA224        11
#define DIGEST_ALGO_SHA3_256      12
#define DIGEST_ALGO_SHA3_512      14
#define DIGEST_ALGO_PRIVATE10    110

#define COMPRESS_ALGO_NONE         0
#define COMPRESS_ALGO_ZIP          1
#define COMPRESS_ALGO_ZLIB         2
#define COMPRESS_ALGO_BZIP2        3
#define COMPRESS_ALGO_PRIVATE10  110

#define SECRET_KEY_ENCR_NONE       0
#define SECRET_KEY_ENCR_AES_CFB128 1
#define SECRET_KEY_ENCR_AES_GCM    2

typedef uint32_t                          gpg_size_t;

typedef struct _gpg_binary                gpg_binary, *gpg_binary_ptr;
typedef struct _gpg_evp_key               gpg_evp_key, *gpg_evp_key_ptr;

#define MIN_KID_SIZE                      20          ///< e.g. SHA-1
#define MAX_KID_SIZE                      64          ///< e.g. SHA-512, this is the maximum subjectKeyIdentifier value we can process

#define MPI_SIZE(_p)                      ((((((uint32_t)(_p[0]))<<8)|((uint32_t)(_p[1])))+7)>>3)

#define GPGBIN_FLAG_NEW_PACKET_FORMAT     0x00000001

struct _gpg_binary
{
  uint32_t                    flags;

  uint8_t                    *p_workarea;             ///< do not free this!
  uint32_t                    l_workarea;
  uint32_t                    workarea_idx;

  uint32_t                    l_user;                 ///< != 0 if user name derived from X.509v3 subject DN (commonName)
  uint8_t                    *p_user;                 ///< always zero-terminated, zero-terminator not counted in l_user

  uint32_t                    l_email;                ///< != 0 if email address derived from X.509v3 SubjectAlternativeNames X.509v3 extension
  uint8_t                    *p_email;                ///< always zero-terminated, zero-terminator not counted in l_email

  uint32_t                    l_subkid;
  uint8_t                     subkid[MAX_KID_SIZE];

  uint32_t                    creation_ts;

  uint32_t                    key_expiration_ts;      ///< this is the notAfter from an X.509v3 certificate

  uint32_t                    pack_user_id_idx;       ///< zero-based index to user id packet (if pack_user_id_len != 0)
  uint32_t                    pack_user_id_len;
  uint32_t                    pack_user_id_data_idx;  ///< index of data area of this packet
  uint32_t                    pack_user_id_data_len;  ///< size of the data area of this packet

  uint32_t                    pack_key_idx;           ///< zero-based index to public/private key packet (if pack_key_len != 0)
  uint32_t                    pack_key_len;

  uint32_t                    pack_key_num_mpis;      ///< number of big integers in key packet
  uint32_t                    pack_key_mpi_idx[8];    ///< maximum number of big integers is eight; these are the indexes to the two-octet bit size

  uint16_t                    eddsa_csum;             ///< necessary because for ED25519 (new) and ED448, a SECRET KEY PACKET computes the fingerprint over everything

  // for SECRET KEY PACKET encryption:

  uint32_t                    aes_gcm_ad_index;       ///< index in buffer of associated data
  uint32_t                    aes_gcm_ad_size;        ///< size of associated data in bytes
  uint32_t                    aes_gcm_pt_index;       ///< index of plaintext = index of ciphertext
  uint32_t                    aes_gcm_pt_size;        ///< size of plaintext = size of ciphertext (recall: AES-GCM works like a stream cipher!)
  EVP_CIPHER                 *p_cipher;
  EVP_CIPHER_CTX             *p_cipher_ctx;           ///< pointer to EVP_CIPHER_CTX structure for AES-GCM/256bit, 96bit IV, 128bit tag

  uint8_t                     key_usage;              ///< key usage bits for PGP, converted from X.509 keyUsage extensions or defaults to 0x02 (SIGN)
};

#define GPGBIN_ERROR_OK                   0x00000000
#define GPGBIN_ERROR_PARAMETERS           0x00000001      ///< function parameter error
#define GPGBIN_ERROR_BUFFEROVERFLOW       0x00000002      ///< work area exhausted
#define GPGBIN_ERROR_INSUFFICIENT_MEMORY  0x00000003      ///< malloc() failed
#define GPGBIN_ERROR_TIME_OUTOFBOUNDS     0x00000004      ///< GPG only supports 32bit timestamps
#define GPGBIN_ERROR_UNSUPP_KEYTYPE       0x00000005      ///< this implementation supports RSA, EC, and Edwards Curves ED25519/ED448 only
#define GPGBIN_ERROR_INTERNAL             0x00000006      ///< internal error, e.g. OpenSSL error
#define GPGBIN_ERROR_PUBKEY               0x00000007      ///< erroneous public key specified (not all required components available)
#define GPGBIN_ERROR_PRIVKEY              0x00000008      ///< erroneous private key specified (not all required components available)
#define GPGBIN_ERROR_UNSUPP_EC_ED_CURVE   0x00000009      ///< the Elliptic/Edwards Curve indicated by the priv/pub-key is not supported
#define GPGBIN_ERROR_FP_MISSING           0x0000000A      ///< finger print missing and cannot be computed in this scenario
#define GPGBIN_ERROR_FP_SIZE              0x0000000B      ///< finger print size bad; has to be in the interval [20..64]
#define GPGBIN_ERROR_SIGN_USER_ID_MISS    0x0000000C      ///< the user email address are missing
#define GPGBIN_ERROR_SIG_CREATION_FAILED  0x0000000D      ///< unable to create digital signature; either PKCS#11 error or provided EVP_PKEY does not contain private key
#define GPGBIN_ERROR_SIG_VERIFY_FAILED    0x0000000E      ///< the loop-back signature verification in software (OpenSSL) failed

/**
 * @brief instantiate a new GPGBIN structure
 *
 * @param [in]        new_packet_format       true to use new packet format, false to use old packet format
 * @param [in]        workarea_size           size of the internal work buffer in bytes. If zero (0) is
 *                                            specified, then 64KB (65.536 bytes) is used.
 *
 * @return NULL on error (insufficient memory available or parameter error) or a newly allocated gpg_binary
 *         structure on the heap, which has to be freed by the caller using GPGBIN_free.
 */
gpg_binary_ptr GPGBIN_new ( bool new_packet_format, uint32_t workarea_size );

/**
 * @brief frees a GPGBIN structure and all data associated with it
 *
 * @param [in]        p_gpg                   pointer to gpg_binary structure on the heap
 */
void GPGBIN_free ( gpg_binary_ptr p_gpg );

/**
 * @brief adds a signature public key (RSA, ECDSA or EdDSA) to the gpg_binary structure
 *
 * @param [in]        p_gpg                   pointer to gpg_binary structure on the heap
 * @param [in]        p_key                   OpenSSL EVP_PKEY pointer; can be public key or key pair
 * @param [in]        creation_time           key (pair) creation time expressed in seconds beginning
 *                                            1970/01/01 00:00:00 - please note that GPG only supports
 *                                            32bit second counters, see GPGBIN_ERROR_TIME_OUTOFBOUNDS
 * @param [in]        expiration_time         key (pair) expiration time; if 0, then does not expire
 * @param [in]        secret_key              p_key has to be a key pair and if secret_key is true, then
 *                                            create a SECRET KEY PACKET, not a PUBLIC KEY PACKET.
 *                                            CAUTION: This function NEVER ENCRYPTS secret keys!!!
 *
 * @return GPGBIN_ERROR_xxx error code
 */
uint32_t GPGBIN_addpacket_sign_key ( gpg_binary_ptr p_gpg, const EVP_PKEY *p_key, time_t creation_time, time_t expiration_time, bool secret_key );

/**
 * @brief adds a signature public key (RSA, ECDSA or EdDSA) from an X.509v3 certificate
 *        to the gpg_binary structure; also, additional information items are extracted from the
 *        certificate.
 *
 *        The public key hash is either taken from the SubjectKeyIdentifier X.509v3 extension or computed
 *        via SHA-1 (Internet standard). It is stored in the gpg_binary structure for possible later use.
 *        The commonName X.501 attribute is extracted from the subject DN as the user name - for possible
 *        later use.
 *        The SubjectAlternativesNames X.509v3 extension is scanned for an email address, which is also
 *        stored for possible later use.
 *        The commonName together with the email address may be used later on to create a GPG user ID
 *        automatically. The public key hash can be used to create a GPG fingerprint / key ID.
 *
 * @param [in]        p_gpg                   pointer to gpg_binary structure on the heap
 * @param [in]        p_x509                  X.509v3 certificate used as the source for the public key,
 *                                            possible user name (commonName attribute of subject DN),
 *                                            email address (SubjectAlternativeNames extension).
 * @param [in]        creation_time           key (pair) creation time expressed in seconds beginning
 *                                            1970/01/01 00:00:00 - please note that GPG only supports
 *                                            32bit second counters, see GPGBIN_ERROR_TIME_OUTOFBOUNDS
 *                                            If this is zero (0), then the notBefore timestamp of the
 *                                            X.509v3 certificate is used as the creation time.
 * @param [in]        expiration_time         key (pair) expiration time; if 0, then does not expire, if
 *                                            1, then get notAfter from X.509v3
 *
 * @return GPGBIN_ERROR_xxx error code
 */
uint32_t GPGBIN_addpacket_x509_sign_public_key ( gpg_binary_ptr p_gpg, const X509 *p_x509, time_t creation_time, time_t expiration_time );

/**
 * @brief adds the user ID GPG packet; if an X.509v3 certificate was the source of a previous signature public key
 *        packet addition, then the user name and/or the email address can be NULL and are automatically taken from
 *        the X.509v3 certificate, i.e. commonName X.501 attribute of subject DN and RFC822 name = email address from
 *        SubjectAlternativeNames X.509v3 extension (if any)
 *
 * @param [in]        p_gpg                   pointer to gpg_binary structure on the heap
 * @param [in]        p_user                  NULL or pointer to user name
 * @param [in]        l_user                  0 or size of user name in characters = bytes
 * @param [in]        p_email                 NULL or pointer to email address
 * @param [in]        l_email                 0 or size of email address in characters = bytes
 *
 * @return GPGBIN_ERROR_xxx error code
 */
uint32_t GPGBIN_addpacket_user_id ( gpg_binary_ptr p_gpg, const char *p_user, uint32_t l_user, const char *p_email, uint32_t l_email );

/**
 * @brief the GnuPG/OpenPGP signature packet is the most complex 'thing'. This function either
 *        emits a type 0x00 (raw binary) signature packet or a type 0x13 'Positive certification of a User ID and Public Key'
 *        packet.
 *
 *        If (NULL == p_tbs || 0 == l_tbs), then this function assumes that a private/public key has to be signed. Otherwise,
 *        the TBS = To-Be-Signed data is used to create a 0x00 (raw binary) signature.
 *
 *        The OpenSSL EVP_PKEY has always be specified and is either a public key or a full key pair. If pkcs11_key_label is
 *        NULL, then it HAS TO BE A FULL KEY PAIR (usable for digital signatures, which is a private key op). If pkcs11_key_label
 *        is != NULL, then it is assumed that the private key is a PKCS#11 private key (smartcard, HSM, whatever).
 *
 *        If p_fingerprint == NULL or l_fingerprint == 0, then the function fails if a raw binary signature 0x00 has to be computed.
 *        Otherwise, the function either takes the X.509v3 extracted SubjectPublicKeyIdentifier (or computed via SHA-1 over the
 *        SubjectPublicKeyInfo ASN.1 BIT STRING). If no subkid is available in p_gpg, then a GPG-like fingerprint is computed here
 *        (using SHA-1).
 *
 * @param [in]        p_gpg                   pointer to gpg_binary structure on the heap
 * @param [in]        p_tbs                   NULL or pointer to To-Be-Signed part
 * @param [in]        l_tbs                   0 or size of To-Be-Signed part in bytes (if 0, then a key packet and a user id have to be there already)
 * @param [in]        digest_algo             one of DIGEST_ALGO_xxx constants, only SHA2-224|256|384|512 supported
 * @param [in]        p_evp_key               either public key or full key pair
 * @param [in]        p_pkcs11_label          may be NULL - PKCS#11 label of signature key if != NULL
 * @param [in]        p_fingerprint           NULL or pointer to finger print (see text above)
 * @param [in]        l_fingerprint           0 or size of finger print in bytes. If this is != 0 but less than 20 bytes, the function fails.
 * @param [in]        expiration_time         0 (does not expire) or time_t of expiration time (is only evaluated for signature type 0x13 packets);
 *                                            if 0 != p_gpg->key_expiration_ts, then this ALWAYS overrides this parameter!
 * @param [in]        p_email                 signer's email address, may be NULL if already part of gpg_binary structure; only required for sig-type 0x00
 * @param [in]        l_email                 size of signer's email address in chars=bytes, may be 0 (if gpg_binary has this already stored internally)
 *
 * @return GPGBIN_ERROR_xxx error code
 */
uint32_t GPGBIN_addpacket_signature ( gpg_binary_ptr  p_gpg,
                                      uint8_t        *p_tbs, // no const because this pointer is used internally if NULL!
                                      uint32_t        l_tbs,
                                      uint32_t        digest_algo,
                                      const EVP_PKEY *p_evp_key,
                                      const char     *p_pkcs11_label,
                                      const uint8_t  *p_fingerprint,
                                      uint32_t        l_fingerprint,
                                      time_t          expiration_time,
                                      const char     *p_email,
                                      uint32_t        l_email,
                                      bool            do_verify );

/**
 * @brief formats an error message for a GPGBIN error code
 *
 * @param [in]      gpgbin_error          one of the above defined error codes
 * @param [out]     buffer                pointer to buffer (IN); filled with message (OUT)
 * @param [in/out]  p_l_buffer            pointer to buffer size (IN); filled with number
 *                                        of copied message bytes (OUT) NOT COUNTING the
 *                                        always stored zero-terminator
 */
void GPGBIN_format_error_message ( uint32_t gpgbin_error, char *buffer, size_t *p_l_buffer );

#define MAX_KEY_PUB_COMPONENTS  2
#define MAX_KEY_PRV_COMPONENTS  4

/**
 * @brief this is kind of an 'augmented' OpenSSL EVP_PKEY with extracted MPIs and key creation timestamp (32bit only for GPG)
 */
struct _gpg_evp_key
{
  const EVP_PKEY             *p_ossl_evp_pkey;        ///< the original OpenSSL pointer
  uint8_t                    *p_md_buffer;            ///< the to-be-hashed part required to compute the fingerprint and/or key ID
  uint32_t                    creation_ts;            ///< key creation timestamp limited to 32bit (seconds since 1970-01-01 00:00:00, the epoch)
  uint32_t                    l_md_buffer;            ///< number of bytes in p_md_buffer
  uint32_t                    pubkey_algo;            ///< GPG public key algorithm
  uint32_t                    curve_idx;              ///< only meaningful for ECDSA/EdDSA: the zero-based curve index
  uint32_t                    comp_len;               ///< only meaningful for ECDSA/EdDSA: length of a component
  uint8_t                     curve_oid[32];          ///< one byte ASN.1 length followed by ASN.1 encoded OBJECT IDENTIFIER (namedCurve)

  uint32_t                    num_pub_components;     ///< for ECDSA/EdDSA: this is one (un-)compressed point always counted as one, for RSA: this is two (n,e)
  uint32_t                    num_prv_components;     ///< for ECDSA/EdDSA: this is one (the scalar); for RSA: this is four: (d,p,q,u)

  uint8_t                    *pub_components[MAX_KEY_PUB_COMPONENTS];
  uint8_t                    *prv_components[MAX_KEY_PRV_COMPONENTS];

  uint8_t                     fipr[SHA256_DIGEST_LENGTH];
  uint8_t                     keyid[8];

  bool                        is_keypair;             ///< true if this is a full key pair, false if it is just a public key
  bool                        use_v5;                 ///< true to use version 5 instead of version 4
  uint16_t                    csum;                   ///< 16bit checksum computed only over private key parts
};

/**
 * @brief converts an OpenSSL EVP_PKEY* to our augmented GPG one
 *
 * @param [in]  p_ossl_evp_pkey       pointer to OpenSSL EVP_PKEY*
 * @param [in]  creation_ts           seconds since the epoch; limited to 32bit
 *
 * @return NULL on error or the pointer to the gpg_evp_key structure allocated on the heap;
 *         the caller has to call GPGBIN_gpg_evp_key_free in order to free it
 */
gpg_evp_key_ptr GPGBIN_ossl_evp_pkey_to_gpg_evp_key ( const EVP_PKEY *p_ossl_evp_pkey, uint32_t creation_ts );

/**
 * @brief frees an augmented (GPG) EVP_PKEY*. All private key parts are purged using
 *        memset_secure (before actually freeing them)
 *
 * @param [in]  p_gekp              pointer to gpg_evp_key structure on the heap
 */
void GPGBIN_gpg_evp_key_free ( gpg_evp_key_ptr p_gekp );






#ifdef __cplusplus
}
#endif
#endif
