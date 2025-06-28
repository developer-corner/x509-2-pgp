/**
 * @file   osslimpl.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  declaration of all OpenSSL 3 specific stuff
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

#ifndef _INC_OSSLIMPL_H_
#define _INC_OSSLIMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <x509-2-pgp.h>

/**
 * @brief initializes everything that is needed to call OpenSSL API functions
 *
 * Has to be called once, an internal atomic counter ensures that the initialization
 * is performed only once.
 *
 * @return true on success, false on error.
 */
bool ossl_init ( void );

/**
 * @brief de-initializes OpenSSL (an internal atomic counter ensures that this is
 *        performed only once even if called multiple times)
 */
void ossl_fini ( void );

/**
 * @brief convenience function for calculating message digests (in a single step)
 *
 * @param [in]      md_type     one of the MD_TYPE_xxx constants (see x509-2-pgp.h)
 * @param [in]      data        to-be-hashed data
 * @param [in]      data_size   number of octets (bytes) to be hashed
 * @param [out]     md          pointer to array receiving the message digest; you may
 *                              just dimension this array for 64 bytes because this is
 *                              currently the maximum amount of returned data (e.g. for SHA-512);
 *                              if you call this function with md = NULL, then just the
 *                              message digest size in bytes is returned but nothing is computed
 *
 * @return number of bytes stored in md
 */
uint32_t ossl_hash ( uint32_t md_type, const uint8_t *data, uint32_t data_size, uint8_t *md );

/**
 * @brief generates an asymmetric key pair (ossl_init has to be called first); this function
 *        supports RSA2048/3072/4096, optional with user-supplied public exponent e, Elliptic
 *        Curves prime256v1, secp384r1, secp521r1, brainpoolP256R1, brainpoolP384R1,
 *        brainpoolP512R1, Edwards Curves ED25519 and ED448.
 *
 * @param [in]      key_type    one of the KEY_TYPE_xxx constants (see x509-2-pgp.h)
 * @param [in]      rsa_pubexp  only recognized for RSA key pairs; limited to 64bit, which is
 *                              sufficient; has to be prime (not checked here!); usually,
 *                              equals to 65.537 but can e.g. also be 0xC0000001 (only few
 *                              bits SHALL be one, though).
 *
 * @return NULL on error or an EVP_PKEY* containing the full key pair; call OpenSSL's
 *         EVP_PKEY_free() to free it.
 */
EVP_PKEY *ossl_generate_openssl_keypair ( uint32_t key_type, uint64_t rsa_pubexp );

/**
 * @brief stores an OpenSSL key pair as a PEM file on disk.
 *
 * If the global variable 'secret' does not specify a pass phrase, then it is
 * queried on the console. If 'secret' was set empty, then the key pair is stored
 * PLAIN.
 *
 * If you press just <ENTER> when asked for the password, then the key pair is also
 * stored PLAIN.
 *
 * @param [in]      filename    pointer to zero-terminated file name
 * @param [in]      pkey        pointer to OpenSSL EVP_PKEY
 *
 * @return true on success, false on error. Most likely, parameter error (NULL pointer)
 *         or disk I/O error.
 */
bool ossl_store_keypair ( const char *filename, EVP_PKEY *pkey );

/**
 * @brief reads an OpenSSL key pair or public key from a PEM file on disk.
 *
 * If the global variable 'secret' does not specify a pass phrase, and the file to
 * be read contains an encrypted key pair, then the password is queried on the console.
 *
 * @param [in]      filename          pointer to zero-terminated file name
 * @param [out]     is_keypair        on success, returns true here if it is a full key pair
 *                                    or false if it is just a public key
 * @param [out]     p_key_creation_ts OPTIONAL, may be NULL; if not NULL and the key is
 *                                    a private key PEM file, then the string 'KEY-CREATION-TIMESTAMP: '
 *                                    is searched in the PEM file; if found, then the
 *                                    timestamp is parsed in a time_t; if any error occurs,
 *                                    then zero (0) is returned here but the function DOES
 *                                    NOT fail
 *
 * @return NULL on error (parameter error or disk I/O error); pointer to EVP_PKEY
 *         on success. The caller has to call OpenSSL's EVP_PKEY_free() to free it.
 */
EVP_PKEY* ossl_load_openssl_key ( const char *filename, bool *is_keypair, time_t *p_key_creation_ts );


#define MIN_KID_SIZE                20
#define MAX_KID_SIZE                64

typedef struct _x509parsed          x509parsed, *x509parsed_ptr;

/**
 * @brief this structure results from a call to ossl_parse_x509, i.e. a full
 *        X.509v3 certificate is parsed and various data items are automatically
 *        extracted, e.g. the distinguished names (subject/issuer) in a human readable
 *        format (RFC 4514).
 *
 * The commonName X.501 attribute is extracted from the subject DN because this may be
 * used for PGP as the user name. Also, the emailaddress X.501 attribute is scanned for
 * an E-mail address.
 *
 * Moreover, the subjectAlternativeNames X.509v3 extensions is checked for an RFC822 name,
 * which is the canonical way of specifying an E-mail address nowadays.
 *
 * The SubjectKeyIdentifier X.509v3 extension, if available, is scanned as well. The above
 * defined macros MIN_KID_SIZE and MAX_KID_SIZE are defined as 20 or 64, respectively.
 *
 * Although, SHA-1 is deprecated today, it is still used to compute the KIDs of an X.509v3.
 * The standard KID size is 20 bytes because of this.
 *
 * Please note that initially, we wanted to use the SubjectKeyIdentifier if an ASN.1 key pair
 * is transferred into the PGP domain but this DOES NOT work: PGP relies on their own specific
 * way of computing "key fingerprints".
 *
 * The keyUsage X.509v3 extension may also be used to derive key usage bits in the PGP domain,
 * although there is no 1:1 relationship...
 */
struct _x509parsed
{
  X509                             *p_cert;

  uint32_t                          x509_sig_algo;

  BIGNUM                           *p_serialno;
  char                              serialno_dec[256];
  char                              serialno_hex[256];

  uint64_t                          notBefore;
  uint64_t                          notAfter;

  uint32_t                          l_subkid;
  uint8_t                           subkid[SHA512_DIGEST_LENGTH];

  uint32_t                          l_commonName;
  uint8_t                           commonName[256];

  uint32_t                          l_emailaddr;
  uint8_t                           emailaddr[256];

  uint32_t                          l_subjectDN;
  uint8_t                           subjectDN[1024];

  uint32_t                          l_issuerDN;
  uint8_t                           issuerDN[1024];

  EVP_PKEY                         *p_pubkey;
  uint64_t                          pk_rsa_pubexp;
  uint32_t                          pk_algo;
  uint32_t                          pk_key_bits;
  uint32_t                          pk_ec_curve;
  uint32_t                          pk_ec_complen;

  uint32_t                          sig_bit_size;     ///< for RSA and 1st component EC/ED
  uint32_t                          sig_bit_size2;    ///< 2nd component EC/ED

  uint8_t                           key_usage;        ///< PGP-CONVERTED keyUsage extension to PGP key flags
};

/**
 * @brief parses an X.509v3 (this is the only function supported PEM and DER) extracting
 *        various pieces of information from it
 *
 * @param [in]      p_input       pointer of either ITU-T X.690 DER-encoded or PEM-encoded (BASE64)
 *                                X.509v3 certificate in memory
 * @param [in]      l_input       number of input bytes (hint: PEM does not have to be a zero-terminated string)
 * @param [in]      is_pem        tell the function if this is PEM (true) or DER (false)
 *
 * @return NULL on error or pointer to allocated x509parsed structure on the heap. The caller
 *         has to call ossl_free_x509 (see below) to free it and all contained data.
 */
x509parsed_ptr ossl_parse_x509 ( const uint8_t *p_input, uint32_t l_input, bool is_pem );

/**
 * @brief frees a parsed X.509v3 structure on the heap
 *
 * @param [in]      p_cert        pointer to structure returned and allocated by ossl_parse_x509
 */
void ossl_free_x509 ( x509parsed_ptr p_cert );

/**
 * @brief convenience function that returns an OpenSSL EVP_MD* for an md_type (our own message
 *        digest constants)
 *
 * @param [in]      md_type       one of the MD_TYPE_xxx constans (see x509-2-pgp.h)
 *
 * @return NULL on error (parameter error) or const EVP_MD*, which can be used in other
 *         OpenSSL API calls (DO NOT FREE THIS, IT IS OWNED BY OPENSSL).
 */
const EVP_MD* ossl_get_evp_md_by_type ( uint32_t md_type );

/**
 * @brief creates a digital signature using the to-be-signed (=to-be-hashed) as one single
 *        piece of data, i.e. there is no init-update-final schema implemented here
 *
 * @param [in]      pkey          pointer to EVP_PKEY containing a key pair (or privat key),
 *                                a public key is insufficient and returns an error
 * @param [in]      sig_type      SIG_TYPE_xxx constant (see x509-2-pgp.h); if this constant
 *                                is incompatible with pkey, false is returned by this function
 * @param [in]      md_type       MD_TYPE_xxx constant specifying the message digest
 * @param [in]      tbs           the to-be-signed = to-be-hashed data
 * @param [in]      tbs_size      number of bytes to be hashed
 * @param [out]     sig           returns a MALLOCed area containing the digital signature on success
 * @param [out]     sig_size      returns the number of bytes of the binary signature
 * @param [in]      ecdsaAsn1     if true, then SEQUENCE { INTEGER R, INTEGER S } is returned as a
 *                                DER encoding (both integers are automatically canonicalized).
 *                                if false, then just R||S (size is twice the size of the curve)
 *                                is returned for ECDSA signatures; this Boolean is ignored for all
 *                                other public key algorithms.
 *                                EdDSA signatures ARE ALWAYS returned as R||S.
 * @param [in]      edPh          only for EdDSA: use pre-hashed EdDSA and not pure EdDSA (see RFC 8032)
 *
 * @return true on success, false on error (parameter error or internal OpenSSL error).
 */
bool ossl_create_digital_signature ( EVP_PKEY      *pkey,
                                     uint32_t       sig_type,
                                     uint32_t       md_type,
                                     const uint8_t *tbs,
                                     uint32_t       tbs_size,
                                     uint8_t      **sig,
                                     uint32_t      *sig_size,
                                     bool           ecdsaAsn1,
                                     bool           edPh );

/**
 * @brief verifies a digital signature using OpenSSL in software; also all hardware signatures
 *        (PKCS#11) are always verified in software, no PKCS#11 verification is done whatsoever
 *
 * @param [in]      pkey          OpenSSL EVP_PKEY* containing at least a public key (may also be
 *                                a full key pair); please note that this could also be extracted
 *                                from an X.509v3 certificate, the so called SubjectPublicKeyInfo
 * @param [in]      sig_type      SIG_TYPE_xxx constant (see x509-2-pgp.h); if this constant
 *                                is incompatible with pkey, false is returned by this function
 * @param [in]      md_type       MD_TYPE_xxx constant specifying the message digest
 * @param [in]      tbs           the to-be-signed = to-be-hashed data
 * @param [in]      tbs_size      number of bytes to be hashed
 * @param [in]      sig           pointer to raw binary signature; please note that this function
 *                                AUTOMATICALLY detects ECDSA ASN.1 signatures converting them
 *                                internally and temporarily into R||S !!!
 * @param [in]      sig_size      size of the signature in bytes
 * @param [in]      edPh          only for EdDSA: expect pre-hashed EdDSA and not pure EdDSA (see RFC 8032)
 *
 * @return true on success (signature valid), false on error (parameter error or internal OpenSSL error).
 */
bool ossl_verify_digital_signature ( EVP_PKEY      *pkey,
                                     uint32_t       sig_type,
                                     uint32_t       md_type,
                                     const uint8_t *tbs,
                                     uint32_t       tbs_size,
                                     const uint8_t *sig,
                                     uint32_t       sig_size,
                                     bool           edPh );

/// just to render human readable outputs: signature algorithm names
extern const char x509_sig_algo_names[X509_SIG_ALGO_EDDSA_ED448 + 1][64];

/// just to render human readable outputs: Elliptic Curve / Edwards Curve names (the X.509v3-known 'namedCurve' option, i.e. one OBJECT IDENTIFIER - internally)
extern const char elliptic_curve_names[NUM_NAMED_EC_CURVES][32];

/// just to render human readable outputs: public key algorithms
extern const char public_key_algorithm[3][32];

/**
 * @brief using an OpenSSL EVP_PKEY* as input, extracts all kinds of information
 *        pieces from this key or key pair, respectively.
 *
 * @param [in]      p_evp_pkey    pointer to OpenSSL EVP_PKEY*, public or key pair
 * @param [out]     p_pk_algo     returns one of the X509_PK_ALGO_xxx constants, just
 *                                disregard the prefix 'X509_' in these constants, it
 *                                is just either RSA or EC or ED (Edwards Curves)
 * @param [out]     p_key_bits    number of key bits; please DO NOTE that e.g. for RSA,
 *                                this may be 2.047 for a 256 byte key if the most significant
 *                                bit is not set (which might happen)
 * @param [out]     p_ec_curve    only for EC/ED: one of the constants CURVE_xxx (see x509-2-pgp.h)
 * @param [out]     p_ec_complen  the length of one EC/ED components; as an exception, this is
 *                                57 not 56 = 448/8 for ED448!!!
 * @param [out]     p_rsa_pubexp  only for RSA: returns the public exponent e (BUT LIMITED TO
 *                                64 BITS, WHICH SHALL BE SUFFICIENT, THOUGH)
 *
 * @return true on success, false on error (parameter error or unsupported algorithm).
 */
bool ossl_pubkey_algo_from_evp ( const EVP_PKEY *p_evp_key,
                                 uint32_t       *p_pk_algo,
                                 uint32_t       *p_key_bits,
                                 uint32_t       *p_ec_curve,
                                 uint32_t       *p_ec_complen,
                                 uint64_t       *p_rsa_pubexp );

#ifdef __cplusplus
}
#endif
#endif

