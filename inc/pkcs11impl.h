/**
 * @file   pkcs11impl.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  declaration of all PKCS#11 specific stuff
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

#ifndef _INC_PKCS11IMPL_H_
#define _INC_PKCS11IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <x509-2-pgp.h>

#ifdef _WINDOWS
#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#else
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif

#ifndef NULL_PTR
# define NULL_PTR 0
#endif

#include <pkcs11.h>

/**
 * @brief dynamically load a PKCS#11 library (on Linux: .so via dlopen, on
 *        Windows: .dll via LoadLibraryA) and initializes it also providing
 *        mutex primitives and getting the PKCS#11 function pointers
 *
 * This function drives a kind of a SINGLETON, i.e. you MUST NOT call this function
 * several times or from several threads.
 *
 * @param [in]        pkcs11_lib_name   pointer to the zero-terminated, fully-qualified
 *                                      PKCS#11 library name
 * @param [in]        pkcs11_slot       use this slot number (normally: 0)
 *
 * @return true on success, false on error; PLEASE DO CALL pkcs11_fini to
 *         avoid memory leaks.
 */
bool pkcs11_init ( const char *pkcs11_lib_name, uint32_t pkcs11_slot );

/**
 * @brief de-initializes a PKCS#11 library freeing all resources associated with it
 *
 * See pkcs11_init: because this is kind of a singleton, all handles (e.g. library handle)
 * are stored internally and are hidden.
 */
void pkcs11_fini ( void );

/**
 * @brief perform a PKCS#11 login for the PKCS#11 user (the PKCS#11 SO is not used here)
 *
 * This function also reads the environment variables 'SECRET' and 'PKCS11_PIN' (in this
 * order) to check if the environment specifies the PKCS#11 user password already.
 *
 * If there is no password specified by the call, the function first checks for a
 * CKF_PROTECTED_AUTHENTICATION_PATH, i.e. there might be e.g. a smartcard reader with
 * a pinpad and a display. In this case, no password is queried on the console. This has
 * to be done by the connected smartcard reader then.
 *
 * Please also note that certain Hardware Security Modules (HSMs) implement their own
 * custom authentication mechanisms on top of the PKCS#11 user PIN, i.e. e.g.
 * additional (also dual control = two person rule) mechanisms may be enforced by the
 * HSM, possibly involving a smartcard reader with smartcard login(s).
 *
 * @param [in]        passwd      pointer to password; may be NULL
 * @param [in]        passwd_len  size of password in bytes = characters; may be 0
 *
 * @return true if login successful and a PKCS#11 session was established, false on error
 */
bool pkcs11_login ( const uint8_t *passwd, uint32_t passwd_len );

#define P11_CURVE_SECP112R1                 0       // already broken
#define P11_CURVE_SECP112R2                 1       // already broken
#define P11_CURVE_SECP128R1                 2
#define P11_CURVE_SECP128R2                 3
#define P11_CURVE_SECP160K1                 4       // like RSA 1.024 , symmetric: 80
#define P11_CURVE_SECP160R1                 5       // like RSA 1.024 , symmetric: 80
#define P11_CURVE_SECP160R2                 6       // like RSA 1.024 , symmetric: 80
#define P11_CURVE_SECP192K1                 7
#define P11_CURVE_SECP224K1                 8       // like RSA 2.048 , symmetric: 112
#define P11_CURVE_SECP224R1                 9       // like RSA 2.048 , symmetric: 112
#define P11_CURVE_SECP256K1                 10      // like RSA 3.072 , symmetric: 128 -> NSA: with SHA-256 for level SECRET
#define P11_CURVE_SECP384R1                 11      // like RSA 7.680 , symmetric: 192 -> NSA: with SHA-384 for level TOP SECRET
#define P11_CURVE_X9_62_PRIME384V1          P11_CURVE_SECP384R1
#define P11_CURVE_SECP521R1                 12      // like RSA 15.360, symmetric: 256
#define P11_CURVE_SECT113R1                 13
#define P11_CURVE_SECT113R2                 14
#define P11_CURVE_SECT131R1                 15
#define P11_CURVE_SECT131R2                 16
#define P11_CURVE_SECT163K1                 17
#define P11_CURVE_SECT163R1                 18
#define P11_CURVE_SECT163R2                 19
#define P11_CURVE_SECT193R1                 20
#define P11_CURVE_SECT193R2                 21
#define P11_CURVE_SECT233K1                 22
#define P11_CURVE_SECT233R1                 23
#define P11_CURVE_SECT239K1                 24
#define P11_CURVE_SECT283K1                 25
#define P11_CURVE_SECT283R1                 26
#define P11_CURVE_SECT409K1                 27
#define P11_CURVE_SECT409R1                 28
#define P11_CURVE_SECT571K1                 29
#define P11_CURVE_SECT571R1                 30
#define P11_CURVE_X9_62_PRIME192V1          31
#define P11_CURVE_SECP192R1                 P11_CURVE_X9_62_PRIME192V1
#define P11_CURVE_X9_62_PRIME192V2          32
#define P11_CURVE_X9_62_PRIME192V3          33
#define P11_CURVE_X9_62_PRIME239V1          34
#define P11_CURVE_X9_62_PRIME239V2          35
#define P11_CURVE_X9_62_PRIME239V3          36
#define P11_CURVE_X9_62_PRIME256V1          37      // like RSA 3.072 , symmetric: 128 -> NSA: with SHA-256 for level SECRET
#define P11_CURVE_SECP256R1                 P11_CURVE_X9_62_PRIME256V1
#define P11_CURVE_BRAINPOOLP160R1           38      // like RSA 1.024 , symmetric: 80
#define P11_CURVE_BRAINPOOLP160T1           39      // like RSA 1.024 , symmetric: 80
#define P11_CURVE_BRAINPOOLP192R1           40
#define P11_CURVE_BRAINPOOLP192T1           41
#define P11_CURVE_BRAINPOOLP224R1           42      // like RSA 2.048 , symmetric: 112
#define P11_CURVE_BRAINPOOLP224T1           43      // like RSA 2.048 , symmetric: 112
#define P11_CURVE_BRAINPOOLP256R1           44      // like RSA 3.072 , symmetric: 128 -> NSA: with SHA-256 for level SECRET
#define P11_CURVE_BRAINPOOLP256T1           45      // like RSA 3.072 , symmetric: 128 -> NSA: with SHA-256 for level SECRET
#define P11_CURVE_BRAINPOOLP320R1           46
#define P11_CURVE_BRAINPOOLP320T1           47
#define P11_CURVE_BRAINPOOLP384R1           48      // like RSA 7.680 , symmetric: 192 -> NSA: with SHA-384 for level TOP SECRET
#define P11_CURVE_BRAINPOOLP384T1           49      // like RSA 7.680 , symmetric: 192 -> NSA: with SHA-384 for level TOP SECRET
#define P11_CURVE_BRAINPOOLP512R1           50      // like RSA 15.360, symmetric: 256
#define P11_CURVE_BRAINPOOLP512T1           51      // like RSA 15.360, symmetric: 256

/**
 * @brief generates an asymmetric RSA key pair in the PKCS#11 module (which may last
 *        quite long, e.g. for RSA >= 4.096 bits depending on hardware); two PKCS#11
 *        objects are created, one private and one public - the private key is marked
 *        as non-exportable and sensitive (it will never leave the PKCS#11 module)
 *
 * @param [in]        keybits           number of bits, e.g. 2048, 3072, 4096, 6144, ...
 * @param [in]        public_exponent   the public exponent e limited to 64 bits
 * @param [in]        key_id            pointer to key ID as array of opaque bytes;
 *                                      optional, may be NULL; please note that this
 *                                      PGP implementation uses key IDs of eight bytes
 *                                      storing the 64bit number of seconds since 1970
 *                                      as the key creation timestamp
 * @param [in]        key_id_length     number of key ID bytes, zero allowed
 * @param [in]        key_label         the key label, MUST NOT be NULL
 * @param [in]        key_label_length  number of bytes = characters in the key label
 *
 * @return NULL on error or the pointer to a MALLOCed OpenSSL EVP_PKEY* containing the
 *         extracted RSA public key, i.e. the pair (n,e). You may store this public key
 *         on disk for later usage, e.g. if a digital signature has to be verified.
 *         The caller has to call OpenSSL EVP_PKEY_free() to free it.
 */
EVP_PKEY *pkcs11_generate_rsa_keypair ( uint32_t        keybits,
                                        uint64_t        public_exponent,
                                        const uint8_t  *key_id,
                                        uint32_t        key_id_length,
                                        const uint8_t  *key_label,
                                        uint32_t        key_label_length );

/**
 * @brief generates an asymmetric EC key pair in the PKCS#11 module ; two PKCS#11
 *        objects are created, one private and one public - the private key is marked
 *        as non-exportable and sensitive (it will never leave the PKCS#11 module)
 *
 * This function is somewhat 'fault-tolerant' because there are broken PKCS#11 implementations
 * out there: A 'good' (correct) PKCS#11 implementation has to return (for the public
 * key) an ASN.1 OCTET STRING (tag 0x04), followed by the ASN.1 length, followed by the
 * byte array 0x04||X||Y (UNCOMPRESSED POINT (x,y)).
 *
 * Some (broken) PKCS#11 implementations just return 0x04||X||Y and, as you can see
 * this first 0x04 telling us 'uncompressed point' matches the ASN.1 tag 0x04 of an
 * OCTET STRING...
 *
 * Anyway, the function tries to guess what is returned (from the size of the returned
 * public key and an ASN.1 decode try for a properly formatted ASN.1 OCTET STRING)...
 *
 * @param [in]        curve             this is a zero-based index 0..51 or one of the
 *                                      constants P11_CURVE_xxx - this function is able
 *                                      to generate EC key pairs for all kinds of currently
 *                                      namedCurves
 * @param [in]        key_id            pointer to key ID as array of opaque bytes;
 *                                      optional, may be NULL; please note that this
 *                                      PGP implementation uses key IDs of eight bytes
 *                                      storing the 64bit number of seconds since 1970
 *                                      as the key creation timestamp
 * @param [in]        key_id_length     number of key ID bytes, zero allowed
 * @param [in]        key_label         the key label, MUST NOT be NULL
 * @param [in]        key_label_length  number of bytes = characters in the key label
 *
 * @return NULL on error or the pointer to a MALLOCed OpenSSL EVP_PKEY* containing the
 *         extracted EC public key, i.e. the point (X,Y). You may store this public key
 *         on disk for later usage, e.g. if a digital signature has to be verified.
 *         The caller has to call OpenSSL EVP_PKEY_free() to free it.
 *         Please note that only UNCOMPRESSED POINT public keys, i.e. 04||X||Y are
 *         processed by this function, neither COMPRESSED nor HYBRID formats.
 */
EVP_PKEY *pkcs11_generate_ec_keypair ( uint32_t         curve,
                                       const uint8_t   *key_id,
                                       uint32_t         key_id_length,
                                       const uint8_t   *key_label,
                                       uint32_t         key_label_length );

/**
 * @brief generates an asymmetric Edwards Curve key pair in the PKCS#11 module ; two PKCS#11
 *        objects are created, one private and one public - the private key is marked
 *        as non-exportable and sensitive (it will never leave the PKCS#11 module)
 *
 * Please note that not all PKCS#11 implementations support this!
 *
 * @param [in]        ed448             because there are currently only two curves,
 *                                      ED25519 and ED448, this Boolean controls which
 *                                      type of curve gets generated
 * @param [in]        key_id            pointer to key ID as array of opaque bytes;
 *                                      optional, may be NULL; please note that this
 *                                      PGP implementation uses key IDs of eight bytes
 *                                      storing the 64bit number of seconds since 1970
 *                                      as the key creation timestamp
 * @param [in]        key_id_length     number of key ID bytes, zero allowed
 * @param [in]        key_label         the key label, MUST NOT be NULL
 * @param [in]        key_label_length  number of bytes = characters in the key label
 *
 * @return NULL on error or the pointer to a MALLOCed OpenSSL EVP_PKEY* containing the
 *         extracted ED public key, i.e. the COMPRESSED point. You may store this public key
 *         on disk for later usage, e.g. if a digital signature has to be verified.
 *         The caller has to call OpenSSL EVP_PKEY_free() to free it.
 *         For ED25519, 32 bytes are returned, for ED448, 57 bytes (not 448/8 = 56 !!!)
 *         are returned. Always compressed.
 */
EVP_PKEY *pkcs11_generate_edwards_keypair ( bool            ed448,
                                            const uint8_t  *key_id,
                                            uint32_t        key_id_length,
                                            const uint8_t  *key_label,
                                            uint32_t        key_label_length );

/**
 * @brief deletes a key pair in the PKCS#11 module removing both PKCS#11 objects,
 *        the public and the private one.
 *
 * Please note that this function fails if none or more than one occurrence of
 * this key (either by label or by label+key_id) is found in the PKCS#11 module.
 *
 * @param [in]      key_id            pointer to key ID or NULL
 * @param [in]      key_id_length     size of key ID in bytes or 0
 * @param [in]      key_label         pointer to key label (must not be NULL)
 * @param [in]      key_label_length  size of the key label in bytes
 * @param [in]      ask_confirmation  true to ask the user on the console before the
 *                                    key gets removed, false to do this silently
 *                                    (possibly DANGEROUS)
 *
 * @return true if key (singular key) was found and removed, false in all
 *         other cases (error, confirmation answered with 'No', etc.)
 */
bool pkcs11_delete_key ( const uint8_t* key_id, uint32_t key_id_length, const uint8_t* key_label, uint32_t key_label_length, bool ask_confirmation );

/**
 * @brief retrieves the PKCS#11 key id, which is for this implementation the
 *        64bit time_t of the key creation point in time; the lower 32bits
 *        are used as the creation_ts, e.g. when creating a digital signature
 *        using a private key that is stored in the PKCS#11 module
 *
 * @param [in]      key_label         pointer to key label
 * @param [in]      key_label_length  size of the key label in bytes
 * @param [in/out]  key_id            pointer to buffer (IN), filled with key ID (OUT)
 * @param [in/out]  p_key_id_length   size of the key_id buffer (IN), updated with
 *                                    the key ID size on OUT
 *
 * @return true (success), false on error
 */
bool pkcs11_get_key_id_by_key_label(const uint8_t* key_label, uint32_t key_label_length, uint8_t* key_id, uint32_t *p_key_id_length);

/**
 * @brief creates a digital signature using the to-be-signed (=to-be-hashed) as one single
 *        piece of data, i.e. there is no init-update-final schema implemented here, carried
 *        out in the PKCS#11 (hardware) module
 *
 * @param [in]      p11label      key label selecting the signature key (private key)
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
bool pkcs11_create_signature ( const char    *p11label,
                               uint32_t       sig_type,
                               uint32_t       md_type,
                               const uint8_t *tbs,
                               uint32_t       tbs_size,
                               uint8_t      **sig,
                               uint32_t      *p_sig_size,
                               bool           ecdsaAsn1,
                               bool           edPh );

/**
 * @brief this function fetches the public key from the PKCS#11 module for a given
 *        key (either only by label or by label+key_id) converting it to an OpenSSL EVP_PKEY*
 *
 * @param [in]      key_id            NULL or pointer to key ID
 * @param [in]      key_id_length     0 or size of key ID
 * @param [in]      key_label         pointer to key label
 * @param [in]      key_label_length  size of key label in bytes
 *
 * @return NULL on error or pointer to MALLOCed EVP_PKEY* containing the
 *         public key; the caller has to call OpenSSL's EVP_PKEY_free() to
 *         free it.
 */
EVP_PKEY *pkcs11_get_ossl_public_evp_key_from_pubkey ( const uint8_t  *key_id,
                                                       uint32_t        key_id_length,
                                                       const uint8_t  *key_label,
                                                       uint32_t        key_label_length );

#ifdef _WINDOWS
#pragma pack(pop, cryptoki)
#endif

#ifdef __cplusplus
}
#endif
#endif
