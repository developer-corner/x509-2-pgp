/**
 * @file   utils.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  declaration of utility functions
 *
 * [MIT license]
 *
 * Copyright (c) 2021-2025 Ingo A. Kubbilun
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

#ifndef _INC_UTILS_H_
#define _INC_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <x509-2-pgp.h>

#define SYSTIME_BASE_1970         12220502400ULL  ///< this is the difference in seconds between 1970-01-01 and 1582-10-01
#define SYSTIME_BASE_2000         13167187200ULL  ///< this is the difference in seconds between 2000-01-01 and 1582-10-01

#define IS_HDIGIT(_c)             ((((_c)>='0') && ((_c)<='9')) || (((_c)>='A') && ((_c)<='F')) || (((_c)>='a') && ((_c)<='f')))
#define IS_DDIGIT(_c)             (((_c)>='0') && ((_c)<='9'))

#define NUMBER_OF_TAGS            (RELATIVE_OID_IRI_TAG_CODE+1)

/// no tag is zero
#define NO_TAG_CODE               0x00
/// ASN.1 type <I>BOOLEAN</I> tag is 0x01
#define BOOLEAN_TAG_CODE          0x01
/// ASN.1 type <I>INTEGER</I> tag is 0x02
#define INTEGER_TAG_CODE          0x02
/// ASN.1 type <I>BIT STRING</I> tag is 0x03
#define BITSTRING_TAG_CODE        0x03
/// ASN.1 type <I>OCTET STRING</I> tag is 0x04
#define OCTETSTRING_TAG_CODE      0x04
/// ASN.1 type <I>NULL</I> tag is 0x05
#define NULLTYPE_TAG_CODE         0x05
/// ASN.1 type <I>OBJECT IDENTIFIER</I> (OID) tag is 0x06
#define OID_TAG_CODE              0x06
/// ASN.1 type <I>OBJECT DESCRIPTOR</I> (OD) tag is 0x07 (<b>unused</b>)
#define OD_TAG_CODE               0x07
/// ASN.1 type <I>EXTERNAL</I> tag is 0x08 (<b>unused</b>)
#define EXTERNAL_TAG_CODE         0x08
/// ASN.1 type <I>REAL</I> tag is 0x09 (<b>unused</b>)
#define REAL_TAG_CODE             0x09
/// ASN.1 type <I>ENUMERATED</I> (ENUM) tag is 0x0A
#define ENUM_TAG_CODE             0x0A
/// ASN.1 type <I>EMBEDDED</I> tag is 0x0B
#define EMBEDDED_TAG_CODE         0x0B
/// ASN.1 type <I>UTF8String</I> tag is 0x0C
#define UTF8STRING_TAG_CODE       0x0C
/// ASN.1 type <I>RELATIVE-OID</I> (ROID) tag is 0x0D
#define RELATIVE_OID_TAG_CODE     0x0D
/// ASN.1 type <I>TIME</I> tag is 0x0E
#define TIME_TAG_CODE             0x0E
/// ASN.1 type <I>RFU_0F</I> tag is 0x0F
#define RFU_0F_TAG_CODE           0x0F
/// ASN.1 type <I>SEQUENCE</I> tag is 0x10
#define SEQ_TAG_CODE              0x10
/// ASN.1 type <I>SET</I> tag is 0x11
#define SET_TAG_CODE              0x11
/// ASN.1 type <I>NumericString</I> tag is 0x12
#define NUMERICSTRING_TAG_CODE    0x12
/// ASN.1 type <I>PrintableString</I> tag is 0x13
#define PRINTABLESTRING_TAG_CODE  0x13
/// ASN.1 type <I>TeletexString</I> tag is 0x14
#define TELETEXSTRING_TAG_CODE    0x14
/// ASN.1 type <I>VideotexString</I> tag is 0x15
#define VIDEOTEXSTRING_TAG_CODE   0x15
/// ASN.1 type <I>IA5String</I> tag is 0x16
#define IA5STRING_TAG_CODE        0x16
/// ASN.1 type <I>UTCTime</I> tag is 0x17
#define UTCTIME_TAG_CODE          0x17
/// ASN.1 type <I>GeneralizedTime</I> tag is 0x18
#define GENERALIZEDTIME_TAG_CODE  0x18
/// ASN.1 type <I>GraphicString</I> tag is 0x19
#define GRAPHICSTRING_TAG_CODE    0x19
/// ASN.1 type <I>VisibleString</I> tag is 0x1A
#define VISIBLESTRING_TAG_CODE    0x1A
/// ASN.1 type <I>GeneralString</I> tag is 0x1B
#define GENERALSTRING_TAG_CODE    0x1B
/// ASN.1 type <I>UniversalString</I> tag is 0x1C
#define UNIVERSALSTRING_TAG_CODE  0x1C
/// ASN.1 type <I>CHARACTER STRING</I> tag is 0x1D
#define CHARACTERSTRING_TAG_CODE  0x1D
/// ASN.1 type <I>BMPString</I> tag is 0x1E
#define BMPSTRING_TAG_CODE        0x1E
/// ASN.1 type <I>DATE</I> tag is 0x1F
#define DATE_TAG_CODE             0x1F
/// ASN.1 type <I>TIME-OF-DAY</I> tag is 0x20
#define TIME_OF_DAY_TAG_CODE      0x20
/// ASN.1 type <I>DATE-TIME</I> tag is 0x21
#define DATE_TIME_TAG_CODE        0x21
/// ASN.1 type <I>DURATION</I> tag is 0x22
#define DURATION_TAG_CODE         0x22
/// ASN.1 type <I>OID-IRI</I> tag is 0x23
#define OID_IRI_TAG_CODE          0x23
/// ASN.1 type <I>RELATIVE-OID-IRI</I> tag is 0x24
#define RELATIVE_OID_IRI_TAG_CODE 0x24

/// Tag mask (least significant five bits)
#define TAG_MASK                  0x1F

/** @brief Tag class 'UNIVERSAL' */
#define TAG_CLASS_UNIVERSAL       0x00
/// Tag class 'APPLICATION'
#define TAG_CLASS_APPLICATION     0x40
/// Tag class 'CONTEXT SPECIFIC'
#define TAG_CLASS_CONTEXTSPEC     0x80
/// Tag class 'PRIVATE'
#define TAG_CLASS_PRIVATE         0xC0
/// Tag class mask (most significant two bits)
#define TAG_CLASS_MASK            TAG_CLASS_PRIVATE

/// Tag for primitive types
#define TAG_PRIMITIVE             0x00
/// Tag for constructed types
#define TAG_CONSTRUCTED           0x20
/// Tag constructed mask
#define TAG_CONS_MASK             TAG_CONSTRUCTED

#define TAG_GET_CLASS_CONS(_t)    (((_t)>>24)&(TAG_CLASS_PRIVATE|TAG_CONSTRUCTED))
#define TAG_GET_CLASS(_t)         (((_t)>>24)&TAG_CLASS_PRIVATE)
#define TAG_GET_LENGTH(_t)        (((_t)>>24)&3)
#define TAG_IS_CONSTRUCTED(_t)    (TAG_CONSTRUCTED==(((_t)>>24) & TAG_CONSTRUCTED))
#define TAG_GET_RAW(_t)           ((_t)&0x00FFFFFF)
#define TAG_ADJUST_LEFT(_t)       (TAG_GET_RAW(_t) << ((4-TAG_GET_LENGTH(_t))<<3))

#define MAKE_TAG1(_is_constructed,_tag)     ((_is_constructed) ? ((TAG_CONSTRUCTED << 24) | TAG_CONSTRUCTED         | 0x01000000 | (_tag)) : (0x01000000 | (_tag)))
#define MAKE_TAG2(_is_constructed,_tag)     ((_is_constructed) ? ((TAG_CONSTRUCTED << 24) | (TAG_CONSTRUCTED << 8)  | 0x02000000 | (_tag)) : (0x02000000 | (_tag)))
#define MAKE_TAG3(_is_constructed,_tag)     ((_is_constructed) ? ((TAG_CONSTRUCTED << 24) | (TAG_CONSTRUCTED << 16) | 0x03000000 | (_tag)) : (0x03000000 | (_tag)))

#define MAKE_TAG1_CONTEXTSPEC(_is_constructed,_tag)     ((((_is_constructed) ? ((TAG_CONSTRUCTED << 24) | TAG_CONSTRUCTED | 0x01000000 | (_tag)) : (0x01000000 | (_tag)))) | (TAG_CLASS_CONTEXTSPEC << 24))
#define MAKE_TAG2_APPLICATION(_is_constructed,_tag)     ((((_is_constructed) ? ((TAG_CONSTRUCTED << 24) | (TAG_CONSTRUCTED << 8) | 0x02000000 | (_tag)) : (0x02000000 | (_tag)))) | (TAG_CLASS_APPLICATION << 24))

/**
 * @brief returns the number of key bits given a signature type
 *
 * @param [in]  sig_type      one of the SIG_TYPE_xxx constants (see x509-2-pgp.h)
 * @param [in]  rsa_key_bits  only for RSA: number of key bits have to be specified
 *                            because, as opposite to EC/ED, the number of key bits
 *                            cannot be derived from the curve.
 *
 * @return number of key bits
 */
uint32_t sigtype2keybits ( uint32_t sig_type, uint32_t rsa_key_bits );

#define ASN1_INDEFINITE_LENGTH        ((uint64_t)0xFFFFFFFFFFFFFFFF)        ///< we use (uint64_t)-1 to encode 0x80, the BER infinite length

/**
 * @brief encode an ASN.1 length according to ITU-T X.690
 *
 * @param [in]      der     pointer to BER/DER encoding
 * @param [in]      derlen  the to-be-encoded length
 * @param [in]      len     maximum size of buffer pointed to be der
 * @param [in/out]  idx     current zero-based index in der; updated on out
 */
bool asn1_encodelen(uint8_t* der, uint64_t derlen, uint64_t len, uint64_t* idx);

/**
 * @brief returns the number of bytes required to encode an ASN.1 length
 *
 * @param [in]      derlen  the DER length (can also be -1 for indefinite BER length
 *                          resulting in a one byte 0x80 encoding)
 *
 * @return the number of bytes required to encode the length; this is limited to
 *         64bit lengths, which is more than sufficient today.
 */
uint32_t asn1_getlengthencodinglength(uint64_t derlen);

/**
 * @brief tries to decode an ASN.1 length
 *
 * @param [in]      der     pointer to DER/BER encoding
 * @param [in]      len     size of the DER encoding in bytes
 * @param [in/out]  derlen  pointer to uint64_t (IN); filled with decoded length
 *                          on OUT (only in the success case)
 * @param [in/out]  idx     pointer to zero-based index (IN); updated on OUT
 *
 * @return true on success, false if an ASN.1 length could not be decoded or a
 *         parameter error occurred or the decoded length would exceed the maximum
 *         DER encoding length
 */
bool asn1_decodelen(const uint8_t* der, uint64_t len, uint64_t* derlen, uint64_t* idx);

/**
 * @brief helper function for reading binary files from disk
 *
 * @param [in]      filename    pointer to zero-terminated file name
 * @param [out]     size        returns the number of bytes read (limited to 4GB = 32bit)
 *
 * @return MALLOCed pointer containing the file on success (call free() to free it) or
 *         NULL on error (parameter error, disk I/O error, etc.)
 */
uint8_t *read_file ( const char *filename, uint32_t *size );

/**
 * @brief helper function for writing binary data to disk
 *
 * @param [in]      filename    pointer to zero-terminated file name
 * @param [in]      data        the binary data to be written
 * @param [in]      size        number of bytes, limited to 4GB = 32bit
 *
 * @return true on success, false on error.
 */
bool write_file ( const char *filename, const uint8_t *data, uint32_t size );

/**
 * @brief returns if this is a leap year (divisible by four, not divisible by 100,
 *        divisible by 400 - this is the reason why Y2K was a leap year btw.)
 *
 * @param [in]      year        year to be checked
 *
 * @return true if leap year, false if not.
 */
bool is_leap_year ( uint32_t year );

/**
 * @brief converts YYYY-MM-DD into an internal days representation used to perform
 *        Gregorian Calendar calculations
 *
 * @param [in]      year        year, please note that GC starts at 1582-10-01
 * @param [in]      month       the month 1..12
 * @param [in]      mday        the day 1..31
 *
 * @return internal days value
 */
int32_t time_date2day(int32_t year, int32_t month, int32_t mday);

/**
 * @brief converts YYYY-MM-DD HH:MM:SS without any external source code dependency
 *        into the number of seconds since 1970-01-01 00:00:00 (although this function
 *        may also convert dates beginning 1581-10-01, which is disabled in the code)
 *
 * @param [out]     systime     returns the 64bit number of seconds since 1970
 * @param [in]      year        year, 1970..9999
 * @param [in]      month       1..12
 * @param [in]      mday        1..31
 * @param [in]      hour        0..23
 * @param [in]      minute      0..59
 * @param [in]      second      0..59
 *
 * @return true on success, false if you specified an invalid date combination
 */
bool time_date2systime(uint64_t* systime,
                       uint32_t year, uint32_t month, uint32_t mday,
                       uint32_t hour, uint32_t minute, uint32_t second);

bool time_systime2date(uint64_t systime,
                       uint32_t* year, uint32_t* month, uint32_t* mday,
                       uint32_t* hour, uint32_t* minute, uint32_t* second);

/**
 * @brief convenience function that emits hex dumps (mainly for debugging purposes)
 *
 * This emits 16 bytes dumps per line together with their ASCII codes (only in the
 * range 32..126, a dot otherwise).
 *
 * @param [in]      f           pointer to output stream
 * @param [in]      data        pointer to data to be dumped
 * @param [in]      size        number of bytes to be dumped
 * @param [in]      hex_upper   use 'A'..'F' instead of 'a'..'f'
 * @param [in]      indent      0, 2, 4, ... number of spaces to be inserted (indent)
 */
void hexdump ( FILE *f, const uint8_t *data, uint32_t size, bool hex_upper, uint32_t indent );

/**
 * @brief converts an ASN.1 ECDSA signature, i.e. SEQUENCE { INTEGER R, INTEGER S } into
 *        a raw binary ECDSA signature
 *
 * The raw_size parameter (see below) is important: It has to be divisible by two and specifies
 * the full length of the raw binary signature, which is R||S. It is twice the curve bit size
 * converted to bytes.
 *
 * The component length of R and S is just (raw_size / 2).
 *
 * Because an ASN.1 encoded ECDSA signature (without any context such as the namedCurve info)
 * contains canonicalized ASN.1 integers, we do not know the component length without getting
 * this information from the caller.
 *
 * Both, R and S, may come with one leading zero byte (if the most significant bit is set) or
 * may be even shorted if one or more leading zeros had been removed (yes, this might happen,
 * too).
 *
 * @param [in]      sig         pointer to ASN.1 DER encoded signature
 * @param [in]      sig_size    full size of the DER encoding including tag, length, etc.
 * @param [in/out]  raw         pointer to buffer (IN) receiving R||S (OUT)
 * @param [in]      raw_size    size of the raw signature in bytes, yes, the caller HAS TO
 *                              specify this, e.g. 64 for 256bit curves, 128 for 512bit curves,
 *                              132 for 521bit curves, etc. (reason, see above).
 *
 * @return true on success, false on error (ASN.1 decoding error, parameter error, etc.)
 */
bool asn1ECDSAASN1RSSequence2RawSignature(const uint8_t* sig, uint32_t sig_size, uint8_t *raw, uint32_t raw_size);

/**
 * @brief converts a raw ECDSA signature, which is R||S into an ASN.1 DER-encoded
 *        ECDSA signature SEQUENCE { INTEGER R, INTEGER S } and automatically
 *        canonicalizes R and S
 *
 * @param [in]      raw       pointer to raw signature R||S
 * @param [in]      raw_size  pointer of raw signature, i.e. the component length of R, S is
 *                            (raw_size / 2), i.e. raw_size has to be divisible by two
 * @param [out]     sig_size  receives the size of the ASN.1 DER encoding on OUT
 *
 * @return NULL on error or the MALLOCed buffer containing the ASN.1 DER-encoded ECDSA signature;
 *         the user has to call free() to free it.
 */
uint8_t* asn1ECDSARawSignature2ASN1RSSequence(const uint8_t* raw, uint32_t raw_size, uint32_t* sig_size);

#define NUM_UNIV_ASN1_TAG_NAMES         37

extern const char g_szAsn1UniversalTagNames[NUM_UNIV_ASN1_TAG_NAMES][32];

// ALL FUNCTIONS PREFIXED BY "a1t_" HAVE BEEN BORROWED FROM ANOTHER OF MY ASN.1 PROJECTS.
// THIS STUFF IS ABOUT ASN.1 TREES AND IS USED HERE TO PATCH X.509v3 CERTIFICATES.

/**********************************************************************************************//**
 * @fn  bool a1t_decodetag(const uint8_t* der, uint32_t len, uint32_t* tag, uint32_t* idx);
 *
 * @brief Decodes an ASN.1 tag according to ITU-T X.690 (BER/DER encoding). Only up to three
 *        tag bytes are supported because the resulting tag is stored in a 32bit unsigned integer
 *        with the most significant byte storing metadata about the tag.
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param           der pointer to the DER (or BER) encoding
 * @param           len length of the DER/BER encoding in bytes
 * @param [in,out]  tag receives the decoded ASN.1 tag as an uint32_t on success
 * @param [in,out]  idx zero-based index into der; is updated on exit
 *
 * @returns true on success, false on error.
 **************************************************************************************************/

bool a1t_decodetag(const uint8_t* der, uint32_t len, uint32_t* tag, uint32_t* idx);

/**********************************************************************************************//**
 * @fn  uint32_t a1t_decodetag_value(uint32_t tag);
 *
 * @brief Takes a decodes tag (as an uint32_t) and returns the raw value of the tag, i.e. the tag
 *        'number'. This is a series of 7-bit values, which are shuffled together.
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param tag The decoded ASN.1 tag as a compact uint32_t.
 *
 * @returns The raw tag number of the ASN.1 tag (this is often printed in square brackets).
 *          (uint32_t)-1 is returned on error.
 **************************************************************************************************/

uint32_t a1t_decodetag_value(uint32_t tag);

/**********************************************************************************************//**
 * @fn  bool a1t_printtag(uint32_t tag, char* tagstr, size_t tagstr_size);
 *
 * @brief Performs a human-readable printout of an ASN.1 tag (either using its universal name or as an integer)
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param           tag         the compact (decoded) uint32_t ASN.1 tag
 * @param [in,out]  tagstr      pointer to target buffer (will always be zero-terminated)
 * @param           tagstr_size size of the target buffer in bytes. Up to (bytes-1) plus the zero-terminator are dumped here.
 *
 * @returns true on success, false on error
 **************************************************************************************************/

bool a1t_printtag(uint32_t tag, char* tagstr, uint32_t tagstr_size);

/**********************************************************************************************//**
 * @fn  uint32_t a1t_gettagencodinglength(const uint8_t* der, uint32_t len, uint32_t idx);
 *
 * @brief Retrieves the number of bytes required to decode the next ASN.1 tag in the buffer
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param der DER/BER encoding.
 * @param len length of DER/BER encoding in bytes.
 * @param idx zero-based index in the buffer; this index is NOT updates as with many other ASN.1
 *            routines implemented here. You can just add the return value to the index to get it
 *            updated!
 *
 * @returns the number of bytes required to decode the next ASN.1 tag in the buffer. Please
 *          remember that the functions implemented here only supports up to three tag bytes.
 **************************************************************************************************/

uint32_t a1t_gettagencodinglength(const uint8_t* der, uint32_t len, uint32_t idx);

/**********************************************************************************************//**
 * @fn  bool a1t_encodetag(uint8_t* der, uint32_t tag, uint32_t len, uint32_t* idx);
 *
 * @brief Encodes an ASN.1 tag, i.e. takes the compact uint32_t representation and dumps one, two or three bytes
 *        into the target buffer
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param [in,out]  der pointer to target DER/BER encoding buffer
 * @param           tag the ASN.1 tag (compact, decoded, uint32_t)
 * @param           len length of the buffer pointed to by der
 * @param [in,out]  idx zero-based index in the target buffer, gets updated on out
 *
 * @returns true on success, false on error
 **************************************************************************************************/

bool a1t_encodetag(uint8_t* der, uint32_t tag, uint32_t len, uint32_t* idx);

/**********************************************************************************************//**
 * @fn  bool a1t_decodelen(const uint8_t* der, uint32_t len, uint32_t* derlen, uint32_t* idx);
 *
 * @brief Decodes an ASN.1 length; (uint32_t)-1 is used to indicate INFINITE length, which is a BER-
 *        specific feature
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param           der     pointer to the BER/DER encoding.
 * @param           len     length of the buffer pointed to by der in bytes.
 * @param [in,out]  derlen  receives the decoded BER/DER length on exit (-1 is reserved for
 *                          INFINITE = 0x80)
 * @param [in,out]  idx     zero-based index; gets updated on exit.
 *
 * @returns true on success, false on error (please note that it is also checked that the indicated
 *          length (of the data) fits into the buffer, not only the length encoding itself).
 **************************************************************************************************/

bool a1t_decodelen(const uint8_t* der, uint32_t len, uint32_t* derlen, uint32_t* idx);

/**********************************************************************************************//**
 * @fn  bool a1t_encodelen(uint8_t* der, uint32_t derlen, uint32_t len, uint32_t* idx);
 *
 * @brief Encodes an ASN.1 length (32bit max); 0xFFFFFFFF is reserved for the INFINITE length, which gets encoded as 0x80.
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param [in,out]  der     pointer to target BER/DER buffer
 * @param           derlen  length to be encoded
 * @param           len     length of the target buffer der
 * @param [in,out]  idx     zero-based index into der buffer; gets updated on out
 *
 * @returns true on success, false on error.
 **************************************************************************************************/

bool a1t_encodelen(uint8_t* der, uint32_t derlen, uint32_t len, uint32_t* idx);

/**********************************************************************************************//**
 * @fn  uint32_t a1t_getlengthencodinglength(uint32_t derlen);
 *
 * @brief Calculates the number of bytes required to encode the given DER/BER length; please note
 *        that 0xFFFFFFFF is reserved for the INFINITE length and returns 1 (because this is
 *        encoded as 0x80)
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param derlen  BER/DER length to be encoded.
 *
 * @returns number of bytes required to store this length in ITU-T X.690 format. This is one byte
 *          for INFINITE length or length &lt;= 127, respectively. All other lengths require one
 *          additional prefix byte.
 **************************************************************************************************/

uint32_t a1t_getlengthencodinglength(uint32_t derlen);

/**********************************************************************************************//**
 * @fn  uint32_t a1t_decode_object_identifier(const uint8_t* oid, uint32_t oidlen, char* oidstr, uint32_t oidstr_size, bool is_roid);
 *
 * @brief Decodes an ASN.1 OBJECT IDENTIFIER into a human-readable string (dotted notation). CAUTION: One arc MUST NOT EXCEED 32bit or the decoding yields wrong results.
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param           oid         the encoded OID (only the value, no tag, no length)
 * @param           oidlen      length of the OID encoding in bytes
 * @param [in,out]  oidstr      pointer to target buffer receiving the decoded OID (will be always zero-terminated).
 * @param           oidstr_size size of the target buffer in bytes
 * @param           is_roid     true if it is a relative OID, false if not.
 *
 * @returns 0 on error or the number of characters dumped into the target buffer EXCLUDING the trailing zero.
 **************************************************************************************************/

uint32_t a1t_decode_object_identifier(const uint8_t* oid, uint32_t oidlen, char* oidstr, uint32_t oidstr_size, bool is_roid);

/**********************************************************************************************//**
 * @fn  uint32_t a1t_encode_object_identifier(const char* oidstr, uint8_t* buffer, uint32_t buffer_size, bool is_roid);
 *
 * @brief Encodes an ASN.1 OBJECT IDENTIFIER (given as a string in dotted notation).
 *
 * @author  Ikubbilun
 * @date  08.01.2022
 *
 * @param           oidstr      pointer to the ZERO-TERMINATED input string (dotted OID)
 * @param [in,out]  buffer      pointer to the target buffer receiving the resulting TLV, which is
 *                              0x06,&lt;len&gt;,&lt;data&gt; (only OIDs of length up to 127 bytes
 *                              are supported here - it is likely uncommon that this gets exceeded).
 * @param           buffer_size size of the target buffer in bytes.
 * @param           is_roid     true if it is a relative OID, false if it is an absolute OID.
 *
 * @returns 0 on error or the number of bytes dumped to the target buffer on success. This is a
 *          full TLV (with tag 0x06).
 **************************************************************************************************/

uint32_t a1t_encode_object_identifier(const char* oidstr, uint8_t* buffer, uint32_t buffer_size, bool is_roid);

typedef struct _deritem           deritem;

#ifndef _DEF_DERITEM_PTR
#define _DEF_DERITEM_PTR
typedef struct _deritem          *deritem_ptr;
#endif

struct _deritem                                 ///< the size of this structure is always allocated in a way that its size is divisible by eight (8)
{
  deritem_ptr                     prev;         ///< previous item or NULL
  deritem_ptr                     next;         ///< next item or NULL
  deritem_ptr                     parent;       ///< parent item or NULL
  deritem_ptr                     child;        ///< child item or NULL
  uint32_t                        prefixlen;    ///< this is tag length plus length length, the 'overhead'; full length of item is prefixlen + len
  uint32_t                        tag;          ///< ASN.1 tag
  uint32_t                        len;          ///< ASN.1 length
  uint8_t                         value[4];     ///< ASN.1 value, this is a variable size array; if NULL != child, then this is empty!!!
                                                ///< child is NOT empty if tag indicates CONSTRUCTED or if BIT STRING/OCTET STRING and encapsulated item
};

typedef struct _mempool           mempool, *mempool_ptr;

struct _mempool
{
  void                           *p_memory;     ///< pointer to allocated memory block
  uint32_t                        used;         ///< used memory in bytes
  uint32_t                        avail;        ///< available memory in bytes
};

/**
 * @brief allocates a memory pool to be used by ASN.1 routines
 *
 * @param[in/out] p_mp        pointer to memory pool structure
 * @param[in]     size        size of memory pool in bytes
 *
 * @return true (OK) or false on error. On success, the caller has to
 *         free the memory p_mp->p_memory using gsmck_free().
 */
bool a1t_mempool_alloc ( mempool_ptr p_mp, uint32_t size );

/**
 * @brief allocates memory from the memory pool
 *
 * @param[in] p_mp      pointer to memory pool
 * @param[in] size      size in bytes
 *
 * @return NULL on error or the pointer to the allocated memory IN THE
 *         MEMORY POOL.
 */
void *a1t_malloc ( mempool_ptr p_mp, uint32_t size );

/**
 * @brief decodes a full ASN.1 structure
 *
 * @param[in] p_mp          pointer to memory pool
 * @param[in] p_der         DER-encoding to be decoded
 * @param[in] l_der         length of DER-encoding in bytes
 * @param[in] decode_encap  true to also try to decode BIT STRING/OCTET STRING encoded data
 *
 * @return NULL on error or the pointer to the root element of the full DER structure
 */
deritem_ptr a1t_decode_structure ( mempool_ptr p_mp, const uint8_t *p_der, uint32_t l_der, bool decode_encap );

/**
 * @brief encodes a full (or partial) ASN.1 structure to a DER-encoding
 *
 * @param[in]     dip         pointer to root or child item
 * @param[in/out] p_l_der     pointer to uint32_t (IN); filled with size of DER-encoding in bytes (OUT)
 *
 * @return NULL on error or the allocated memory region containing the full DER-encoding
 *         of the input parameter dip
 */
uint8_t *a1t_encode_structure ( deritem_ptr dip, uint32_t *p_l_der );

/**
 * @brief encodes a full (or partial) ASN.1 structure to a DER-encoding
 *
 * @param[in] dip     pointer to root or child item
 * @param[in] p_der   pointer to target DER buffer
 * @param[in] l_der   size of buffer pointed to by p_der (has to be dip->len + dip->prefixlen)
 *
 * @return false on error, true if OK.
 */
bool a1t_encode_structure_to_buffer ( deritem_ptr dip, uint8_t *p_der, uint32_t l_der );

/**
 * @brief frees a full ASN.1 structure in memory (if and only if dip is the root)
 *
 * @param[in] p_mp          pointer to memory pool
 * @param[in] dip           pointer to root DER item pointer (dip)
 */
void a1t_free_structure ( mempool_ptr p_mp, deritem_ptr dip );

/**
 * @brief walks down a DER-decoded structure according to what we call 'DER path' (comparable to XML path)
 *
 * A DER path may contain two different characters plus an optional prefix. A plus sign '+' means
 * 'go to the next item'. A star sign '*' means 'go down to the child'. Both characters MAY be
 * preceded by a decimal number, e.g. "10+" means '10 times +'.
 *
 * @param[in] dip           pointer to root or child node of DER item structure in memory
 * @param[in] p_derpath     pointer to 'DER path'
 *
 * @return NULL (not found) or the pointer in the DER structure
 */
deritem_ptr a1t_seek_item ( deritem_ptr dip, const char *p_derpath );

/**
 * @brief walks down a DER-decoded structure and tries to locate the first occurrence of an ASN.1 tag
 *
 * @param[in] dip           pointer to root or child node of DER item structure in memory
 * @param[in] tag           ASN.1 tag as an uint32_t value (encoded, see e.g. a1t_encodetag)
 *
 * @return NULL (not found) or the pointer in the DER structure
 */
deritem_ptr a1t_search_tag ( deritem_ptr dip, uint32_t tag );

/**
 * @brief walks down a DER-decoded structure and tries to locate the first occurrence of a T-L-V
 *
 * @param[in] dip           pointer to root or child node of DER item structure in memory
 * @param[in] tag           ASN.1 tag as an uint32_t value (encoded, see e.g. a1t_encodetag)
 * @param[in] len           length of DER encoding (value, see below)
 * @param[in] value         pointer to value (byte array)
 *
 * @return NULL (not found) or the pointer in the DER structure
 */
deritem_ptr a1t_search_tlv ( deritem_ptr dip, uint32_t tag, uint32_t len, const uint8_t *value );

/**
 * @brief pastes (inserts) a deritem into another deritem structure REPLACING the
 *        target deritem
 *
 * This function can be used to modify some kind of 'template DER' in memory by replacing
 * an existing target node by another source node. The function first checks if the ASN.1 tags
 * of both items match (if not, function aborts).
 *
 * If there is a match, then the dip_source structure replaces the dip_target structure
 * maintaining all pointers (prev, next, and parent). The child pointer (if any) is taken from
 * dip_source (obviously).
 *
 * @param[in] p_mp              pointer to memory pool
 * @param[in] dip_target        the target node where the source node will be inserted
 * @param[in] dip_source        the source node to be inserted
 * @param[in] duplicate_source  set to true to instruct this function to make copies of the
 *                              source tree (if false, then it is taken 'as is')
 *
 * @return true (successful), false on error. Please note the the target DER structure
 *         'takes over' the source DER structure, i.e. the caller MUST NOT free the dip_source
 *         after this operation reports success (if duplicate_source is false).
 */
bool a1t_paste_item ( mempool_ptr p_mp, deritem_ptr dip_target, deritem_ptr dip_source, bool duplicate_source );

/**
 * @brief appends another item at the end of the current dip_target, which has to be
 *        an ASN.1 SEQUENCE OF ANY.
 *
 * @param[in] p_mp              pointer to memory pool
 * @param[in] dip_target        the target node where the source node will be inserted
 * @param[in] dip_source        the source node to be appended
 * @param[in] duplicate_source  set to true to instruct this function to make copies of the
 *                              source tree (if false, then it is taken 'as is')
 *
 * @return true (successful), false on error. Please note the the target DER structure
 *         'takes over' the source DER structure, i.e. the caller MUST NOT free the dip_source
 *         after this operation reports success (if duplicate_source is false).
 */
bool a1t_append_sequence_item ( mempool_ptr p_mp, deritem_ptr dip_target, deritem_ptr dip_source, bool duplicate_source );

/**
 * @brief create a very simple ASN.1 item
 *
 * @param[in] p_mp              pointer to memory pool
 * @param[in] tag               the ASN.1 tag
 * @param[in] len               the ASN.1 length in bytes of the item (may be 0)
 * @param[in] value             NULL (if and only if len is 0) or pointer to value
 *
 * @return NULL on error or the pointer to the new DER item
 */
deritem_ptr a1t_create_simple_item ( mempool_ptr p_mp, uint32_t tag, uint32_t len, const uint8_t *value );

/**
 * @brief recomputes an ASN.1 sequence length and prefix length (sequence modified in memory)
 *
 * @param[in] dip               deritem pointer (has to be ASN.1 sequence)
 *
 * @return true if OK, false otherwise
 */
bool a1t_recompute_sequence_length ( deritem_ptr dip );

/**
 * @brief creates an in-memory copy of an existing DER item structure
 *
 * @param[in] p_mp  pointer to memory pool
 * @param[in] dip   pointer to DER item structure to be duplicated
 *
 * @return NULL on error or != NULL, the pointer to the newly created copy
 */
deritem_ptr a1t_copy_structure ( mempool_ptr p_mp, deritem_ptr dip );

/**
 * @brief dumps a full ASN.1 tree (as a deritem structure)
 *
 * @param[in] dip       pointer to deritem structure (a full tree)
 */
void a1t_dump_tree ( deritem_ptr dip );

/**
 * @brief checks the integrity of all pointers in a deritem structure
 *
 * @param[in] dip       pointer to deritem structure (a full tree); must be != NULL
 *
 * @return true if everything OK, false if deritem structure corrupt
 */
bool a1t_check_structure ( deritem_ptr dip );

/**
 * @brief renders a given DER structure and computes the message digest over the DER encoding
 *        (i.e. the To-Be-Signed)
 *
 * @param[in]     dip         pointer to DER structure (tree)
 * @param[in]     md_type     hash algorithm
 * @param[in/out] hash        pointer to message digest buffer (IN); filled with MD (OUT)
 *
 * @return true (OK), false on error
 */
bool a1t_compute_hash_over_structure ( deritem_ptr dip, uint32_t md_type, uint8_t *hash );

typedef struct _explore_x509        explore_x509, *explore_x509_ptr;

struct _explore_x509
{
  deritem_ptr             tbs_cert;
  deritem_ptr             serialno;
  deritem_ptr             sig_algo1;
  deritem_ptr             issuer_name;
  deritem_ptr             validity;
  deritem_ptr             subject_name;
  deritem_ptr             spki;
  deritem_ptr             extensions;   ///< this is the SEQUENCE below the EXPLICIT tag, may be NULL
  deritem_ptr             sig_algo2;
  deritem_ptr             sigval_bs;
};

bool a1t_explore_x509 ( deritem_ptr dip, explore_x509_ptr p_explore );

bool a1t_modify_x509_validity ( mempool_ptr p_mp, deritem_ptr p_validity, uint32_t expiration_days );

uint32_t get_executable_path(char* buffer, uint32_t buffer_size, bool cut_exe);

void init_colored_console ( bool no_colors );

void fini_colored_console ( void );

int putenv_fmt(char *buffer, size_t buffer_len, const char* fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
