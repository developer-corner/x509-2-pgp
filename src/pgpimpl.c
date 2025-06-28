/**
 * @file   pgpimpl.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implementation of all PGP (OpenPGP/GnuPG) specific stuff
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

#include <pgpimpl.h>
#include <osslimpl.h>
#include <pkcs11impl.h>

// at least with v5 signature packets and ED448, a bug in GnuPG 2.4.7 was observed:
// the calculated signature became a pair (R,S) with the first byte of R 0x00, i.e.
// the MPI conversion function completely removed the first byte.
// GnuPG 2.4.7 reported that it cannot verify the signature in this case...
// If you define the following macro, then, if for Edwards ED25519 or ED448, if
// the first byte or bytes are zero, they are NOT removed from R, S and the MPI
// length is adjusted, resulting in non-canonicalized values being stored as MPIs
// According to their bug tracker, this is a known bug (currently handled with low
// priority)
#define _USE_GPG_BUGFIX_EDWARDS

#define RSA_GPG_ALGO      PUBKEY_ALGO_RSA_S
//#define RSA_GPG_ALGO      PUBKEY_ALGO_RSA
//#define USE_ED_PH         true
#define USE_ED_PH         false

/**
 * X.509 keyUsage extension and mapping to OpenPGP:
 * ------------------------------------------------
 *
 *  KeyUsage ::= BIT STRING {
 *          digitalSignature        (0),  0x02 = This key may be used to sign data.
 *          nonRepudiation          (1),
 *          keyEncipherment         (2),  0x04 = This key may be used to encrypt communications
 *          dataEncipherment        (3),  0x04 = This key may be used to encrypt communications
 *          keyAgreement            (4),
 *          keyCertSign             (5),  0x01 = This key may be used to make User ID certifications (Signature Type IDs 0x10-0x13) or Direct Key signatures (Signature Type ID 0x1F) over other keys.
 *          cRLSign                 (6),
 *          encipherOnly            (7),
 *          decipherOnly            (8) }
 */

const uint8_t unused_most_significant_bits[256] =
{
  /*00*/ 0x08,0x07,0x06,0x06,0x05,0x05,0x05,0x05,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
  /*10*/ 0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  /*20*/ 0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  /*30*/ 0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  /*40*/ 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  /*50*/ 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  /*60*/ 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  /*70*/ 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  /*80*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*90*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*A0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*B0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*C0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*D0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*E0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  /*F0*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

typedef struct _named_ec_curves   nec_curves;

struct _named_ec_curves
{
  char          shortname[24];
  char          longname[64];
  unsigned char curve_oid[16];
  char          oid_string[24];
};

// also contains the two Edwards Curves ED25519 and ED448!
static const nec_curves named_ec_curves[NUM_NAMED_EC_CURVES] =
{
  { "prime256v1"     , "X9.62/SECG curve over a 256 bit prime field"        , { 8, 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.2.840.10045.3.1.7" },   /* 32 bytes comp.len. */
  { "secp384r1"      , "NIST/SECG curve over a 384 bit prime field"         , { 5, 0x2B,0x81,0x04,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.132.0.34" },          /* 48 bytes comp.len. */
  { "secp521r1"      , "NIST/SECG curve over a 521 bit prime field"         , { 5, 0x2B,0x81,0x04,0x00,0x23,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.132.0.35" },          /* 66 bytes comp.len. */
  { "brainpoolP256r1", "RFC 5639 curve over a 256 bit prime field"          , { 9, 0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.36.3.3.2.8.1.1.7" },  /* 32 bytes comp.len. */
  { "brainpoolP384r1", "RFC 5639 curve over a 384 bit prime field"          , { 9, 0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.36.3.3.2.8.1.1.11" }, /* 48 bytes comp.len. */
  { "brainpoolP512r1", "RFC 5639 curve over a 512 bit prime field"          , { 9, 0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0D,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.36.3.3.2.8.1.1.13" }, /* 64 bytes comp.len. */
  { "ed25519",         "Edwards curve 25519 expressed as elliptic curve oid", { 9, 0x2B,0x06,0x01,0x04,0x01,0xDA,0x47,0x0F,0x01,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.6.1.4.1.11591.15.1"}, /* 32 bytes comp.len */
  { "ed448",           "Edwards curve 448 expressed as elliptic curve oid"  , { 9, 0x2B,0x06,0x01,0x04,0x01,0xDA,0x47,0x0F,0x02,0x00,0x00,0x00,0x00,0x00,0x00 }, "1.3.6.1.4.1.11591.15.2"}  /* 56 bytes comp.len */
};
const uint8_t ed448_legacy_oid[4] =                                           { 3,0x2B,0x65,0x71 };

#if 0
static void _gpg_hexdump ( FILE *f, const uint8_t *data, gpg_size_t size, bool hex_upper, uint32_t indent )
{
  char                szHexLine[88], szIndent[64];
  uint8_t             x;
  int                 i,j;
  static const char   hexupper_table[16] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46 };
  static const char   hexlower_table[16] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66 };
  const char         *hex_table = hex_upper ? hexupper_table : hexlower_table;
  gpg_size_t          ofs = 0;

  if ( 0 == size )
    return;

  if (0 == indent)
    szIndent[0] = 0;
  else
  {
    memset(szIndent,0x20, indent);
    szIndent[indent] = 0x00;
  }

  while (size>0)
  {
    memset(szHexLine,0x20,sizeof(szHexLine));
    szHexLine[77] = 0x00;
    if (size>8)
      szHexLine[34] = '-';

    szHexLine[0] = hex_table[(ofs >> 28) & 0xF];
    szHexLine[1] = hex_table[(ofs >> 24) & 0xF];
    szHexLine[2] = hex_table[(ofs >> 20) & 0xF];
    szHexLine[3] = hex_table[(ofs >> 16) & 0xF];
    szHexLine[4] = hex_table[(ofs >> 12) & 0xF];
    szHexLine[5] = hex_table[(ofs >> 8)  & 0xF];
    szHexLine[6] = hex_table[(ofs >> 4)  & 0xF];
    szHexLine[7] = hex_table[ofs         & 0xF];

    i=0;j=0;
    while (size>0)
    {
      x = *(data++);
      size--;
      ofs++;

      szHexLine[i*3+10+j] = hex_table[x >>  4];
      szHexLine[i*3+11+j] = hex_table[x & 0xF];

      if ((x<32) || (x>=127)) x = '.';

      szHexLine[i+61] = (char)x;

      i++;
      if (i==8)
        j = 2;
      if (i==16)
        break;
    }

    fprintf(f,"%s%s\n",szIndent, szHexLine);
  }
}
#endif

void GPGBIN_format_error_message ( uint32_t gpgbin_error, char *buffer, size_t *p_l_buffer )
{
  size_t s;

  switch(gpgbin_error)
  {
    case GPGBIN_ERROR_OK:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000000: no error (OK)");
      break;
    case GPGBIN_ERROR_PARAMETERS:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000001: function parameter error");
      break;
    case GPGBIN_ERROR_BUFFEROVERFLOW:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000002: work area exhausted (please specify a bigger buffer)");
      break;
    case GPGBIN_ERROR_INSUFFICIENT_MEMORY:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000003: insufficient memory; malloc/realloc() failed");
      break;
    case GPGBIN_ERROR_TIME_OUTOFBOUNDS:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000004: PGP supports 32bit timestamps only; until: 2106-02-07 06:28:15");
      break;
    case GPGBIN_ERROR_UNSUPP_KEYTYPE:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000005: this implementation supports RSA, ECC, and Edwards Curves ED25519/ED448 only");
      break;
    case GPGBIN_ERROR_INTERNAL:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000006: internal error, also OpenSSL API error(s)");
      break;
    case GPGBIN_ERROR_PUBKEY:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000007: erroneous public key specified (not all required components available)");
      break;
    case GPGBIN_ERROR_PRIVKEY:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000008: erroneous private key / key pair specified (not all required components available)");
      break;
    case GPGBIN_ERROR_UNSUPP_EC_ED_CURVE:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x00000009: the Elliptic Curve indicated by the priv/pub-key is not supported; only prime256v1, secp384r1, secp521r1, brainpoolP256R1 (plus bpool: 384/512)");
      break;
    case GPGBIN_ERROR_FP_MISSING:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x0000000A: key finger print missing and cannot be computed in the current setup");
      break;
    case GPGBIN_ERROR_FP_SIZE:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x0000000B: key finger print size bad; has to be in the interval [20..64]; currently only 20 and 32 supported by PGP, though");
      break;
    case GPGBIN_ERROR_SIGN_USER_ID_MISS:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x0000000C: signing not possible because signer's E-mail address missing");
      break;
    case GPGBIN_ERROR_SIG_CREATION_FAILED:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x0000000D: unable to create digital signature; either no key or just public key provided or PKCS#11 module error (some PKCS#11 implementation DO NOT support all algorithms)");
      break;
    case GPGBIN_ERROR_SIG_VERIFY_FAILED:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x0000000E: verification of digital signature (always in software using OpenSSL) failed");
      break;
    default:
      s = (size_t)snprintf(buffer, *p_l_buffer, "0x%08X: unknown error code", gpgbin_error);
      break;
  }

  *p_l_buffer = s;
}

#ifndef _WINDOWS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static bool _GPGBIN_addsubpacket_tag_len ( gpg_binary_ptr p_gpg, uint8_t tag, bool critical, uint32_t len )
{
  len++; // the subpacket tag itself also counts...

  tag |= critical ? 0x80 : 0x00;

  if (len < 0xC0)
  {
    if (unlikely((p_gpg->workarea_idx + 2 + len) > p_gpg->l_workarea))
      return false;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
  }
  else
  if (len < 0x20C0)
  {
    if (unlikely((p_gpg->workarea_idx + 3 + len) > p_gpg->l_workarea))
      return false;
    len -= 0xC0;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = ((uint8_t)(len >> 8))+0xC0;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
  }
  else
  {
    if (unlikely((p_gpg->workarea_idx + 6 + len) > p_gpg->l_workarea))
      return false;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = 0xFF;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 24);
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 16);
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 8);
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
  }

  return true;
}
#ifndef _WINDOWS
#pragma GCC diagnostic pop
#endif

// no length check here, just adding the data
// returns updated index
static uint32_t _GPGBIN_addsubpacket_tag_len_buffer ( uint8_t *p_buffer, uint32_t idx, uint8_t tag, bool critical, uint32_t len )
{
  len++; // the subpacket tag itself also counts...

  tag |= critical ? 0x80 : 0x00;

  if (len < 0xC0)
  {
    p_buffer[idx++] = (uint8_t)len;
    p_buffer[idx++] = tag;
  }
  else
  if (len < 0x20C0)
  {
    len -= 0xC0;
    p_buffer[idx++] = ((uint8_t)(len >> 8))+0xC0;
    p_buffer[idx++] = (uint8_t)len;
    p_buffer[idx++] = tag;
  }
  else
  {
    p_buffer[idx++] = 0xFF;
    p_buffer[idx++] = (uint8_t)(len >> 24);
    p_buffer[idx++] = (uint8_t)(len >> 16);
    p_buffer[idx++] = (uint8_t)(len >> 8);
    p_buffer[idx++] = (uint8_t)len;
    p_buffer[idx++] = tag;
  }

  return idx;
}

static bool _GPGBIN_addpacket_tag_len ( gpg_binary_ptr p_gpg, uint8_t tag, uint32_t len )
{
  if (GPGBIN_FLAG_NEW_PACKET_FORMAT & p_gpg->flags)
  {
    tag = (tag & 0x3F) | 0xC0;

    if (len < 0xC0)
    {
      if (unlikely((p_gpg->workarea_idx + 2 + len) > p_gpg->l_workarea))
        return false;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
    else
    if (len < 0x20C0)
    {
      if (unlikely((p_gpg->workarea_idx + 3 + len) > p_gpg->l_workarea))
        return false;
      len -= 0xC0;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = ((uint8_t)(len >> 8))+0xC0;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
    else
    {
      if (unlikely((p_gpg->workarea_idx + 6 + len) > p_gpg->l_workarea))
        return false;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = 0xFF;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 24);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 16);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 8);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
  }
  else // OLD packet format
  {
    tag = ((tag & 0x0F) << 2) | 0x80;
    if (len < 0x100)
    {
      if (unlikely((p_gpg->workarea_idx + 2 + len) > p_gpg->l_workarea))
        return false;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
    else
    if (len < 0x10000)
    {
      if (unlikely((p_gpg->workarea_idx + 3 + len) > p_gpg->l_workarea))
        return false;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag | 0x01;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 8);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
    else
    {
      if (unlikely((p_gpg->workarea_idx + 5 + len) > p_gpg->l_workarea))
        return false;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = tag | 0x02;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 24);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 16);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(len >> 8);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)len;
    }
  }
  return true;
}

#ifndef _WINDOWS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static int _gpg_get_curve_from_oid ( const uint8_t *p_oid, uint32_t l_oid, char *human_readable, size_t max_human_readable )
{
  uint32_t        i;

  if (NULL != human_readable)
    memset(human_readable, 0x00, max_human_readable);

  for (i=0;i<NUM_NAMED_EC_CURVES;i++)
  {
    if ((l_oid == named_ec_curves[i].curve_oid[0]) && (!memcmp(p_oid, &named_ec_curves[i].curve_oid[1], l_oid)))
    {
      if (NULL != human_readable)
        snprintf(human_readable, max_human_readable, "%s (%s)", named_ec_curves[i].shortname, named_ec_curves[i].oid_string);

      return (int)i;
    }
  }

  return -1;
}
#ifndef _WINDOWS
#pragma GCC diagnostic pop
#endif

gpg_binary_ptr GPGBIN_new ( bool new_packet_format, uint32_t workarea_size )
{
  gpg_binary_ptr          p_gpg;

  workarea_size = 0 == workarea_size ? 65536 : workarea_size;

  p_gpg = (gpg_binary_ptr)malloc( ((sizeof(gpg_binary) + 15) & ~15) + workarea_size );

  if (unlikely(NULL == p_gpg))
    return NULL;

  memset(p_gpg, 0x00, ((sizeof(gpg_binary) + 15) & ~15) + workarea_size);

  p_gpg->flags |= new_packet_format ? GPGBIN_FLAG_NEW_PACKET_FORMAT : 0;
  p_gpg->l_workarea = workarea_size;

  p_gpg->p_workarea = ((uint8_t*)p_gpg) + ((sizeof(gpg_binary) + 15) & ~15);

  p_gpg->key_usage = 0x02; // at least: May be used to sign data

  return p_gpg;
}

void GPGBIN_free ( gpg_binary_ptr p_gpg )
{
  if (NULL != p_gpg)
  {
    if (NULL != p_gpg->p_cipher_ctx)
      EVP_CIPHER_CTX_free(p_gpg->p_cipher_ctx);

    if (NULL != p_gpg->p_cipher)
      EVP_CIPHER_free(p_gpg->p_cipher);

    if (NULL != p_gpg->p_user)
      free(p_gpg->p_user);

    if (NULL != p_gpg->p_email)
      free(p_gpg->p_email);

    free(p_gpg);
  }
}

static uint8_t *_GPGBIN_format_ossl_bignum_as_mpi ( const BIGNUM *p_bn, uint32_t *p_mpilen, uint16_t *p_checksum )
{
  uint8_t          *p_mpi, *p_bn_bytes;
  uint32_t          num_bytes, num_bits, idx, run, i;

  if (NULL != p_mpilen)
    *p_mpilen = 0;

  // handle zero (0) case first:

  if (NULL == p_bn || BN_is_zero(p_bn))
  {
HandleZero:
    p_mpi = (uint8_t*)malloc(2);
    if (unlikely(NULL == p_mpi))
      return NULL;
    p_mpi[0] = p_mpi[1] = 0x00;
    if (NULL != p_mpilen)
      *p_mpilen = 2;
    // checksum update, if desired, not necessary
    return p_mpi;
  }

  num_bytes = (uint32_t)BN_num_bytes(p_bn);
  if (unlikely(0 == num_bytes))
    goto HandleZero;

  p_bn_bytes = (uint8_t*)malloc(num_bytes);

  if (unlikely(NULL == p_bn_bytes))
    return NULL;

  BN_bn2bin(p_bn, p_bn_bytes);

  num_bits = num_bytes << 3;

  run = num_bytes;
  idx = 0;

  while (0 != run)
  {
    num_bits -= unused_most_significant_bits[p_bn_bytes[idx]];

    if (0x00 != p_bn_bytes[idx])
      break;

    idx++;
    run--;
  }

  if (unlikely(0 == run))
  {
    free(p_bn_bytes);
    goto HandleZero;
  }

  num_bytes = (num_bits + 7) >> 3;

  p_mpi = (uint8_t*)malloc(2 + num_bytes);
  if (unlikely(NULL == p_mpi))
  {
    free(p_bn_bytes);
    return NULL;
  }

  if (NULL != p_mpilen)
  *p_mpilen = 2 + num_bytes;

  p_mpi[0] = (uint8_t)(num_bits >> 8);
  p_mpi[1] = (uint8_t)num_bits;

  memcpy(p_mpi + 2, p_bn_bytes + idx, num_bytes);

  free(p_bn_bytes);

  if (NULL != p_checksum)
  {
    for (i = 0; i < (2 + num_bytes); i++)
      (*p_checksum) += p_mpi[i];
  }

  return p_mpi;
}

static uint16_t _GPGBIN_compute_checksum ( const uint8_t *p_data, uint32_t l_data )
{
  uint32_t          i;
  uint16_t          csum = 0x0000;

  for (i = 0; i < l_data; i++)
    csum += p_data[i];

  return csum;
}

#ifdef _USE_GPG_BUGFIX_EDWARDS

#define _GPGBIN_format_byte_number_as_mpi_no_edwards(_1,_2,_3,_4,_5)  _GPGBIN_format_byte_number_as_mpi(_1,_2,_3,_4,_5,false)
#define _GPGBIN_format_byte_number_as_mpi_edwards(_1,_2,_3,_4,_5)     _GPGBIN_format_byte_number_as_mpi(_1,_2,_3,_4,_5,true)

// prefix_byte == -1 if not existing; if existing, then prefix byte (low 8 bits of prefix_byte MUST NOT BE ZERO(0))
static uint8_t *_GPGBIN_format_byte_number_as_mpi ( const uint8_t *p_number, uint32_t l_number, uint32_t *p_mpilen, int prefix_byte, uint16_t *p_checksum, bool is_edwards )
{
  uint8_t          *p_mpi;
  uint32_t          l_mpi, num_bits, i;

  if (NULL != p_mpilen)
    *p_mpilen = 0;

  // handle zero(0) case first

  if (NULL == p_number || 0 == l_number)
  {
HandleZero:
    p_mpi = (uint8_t*)malloc(2);
    if (unlikely(NULL == p_mpi))
      return NULL;
    p_mpi[0] = p_mpi[1] = 0x00;
    if (NULL != p_mpilen)
      *p_mpilen = 2;
    // checksum update, if desired, not necessary
    return p_mpi;
  }

  if (0 == prefix_byte) // not allowed
    return NULL;

  // canonicalize if and only if no prefix_byte specified

  if (-1 == prefix_byte)
  {
    if (!is_edwards)
    {
      while (0 != l_number && 0x00 == *p_number)
      {
        p_number++;
        l_number--;
      }
      if (unlikely(0 == l_number))
        goto HandleZero;
    }
  }

  l_mpi = (-1 != prefix_byte) ? (1 + l_number) : l_number;

  p_mpi = (uint8_t*)malloc(2 + l_mpi);
  if (unlikely(NULL == p_mpi))
    return NULL;

  if (-1 != prefix_byte)
  {
    p_mpi[2] = (uint8_t)prefix_byte;
    memcpy(p_mpi + 3, p_number, l_number);
  }
  else
    memcpy(p_mpi + 2, p_number, l_number);

  if (!is_edwards)
    num_bits = (l_mpi << 3) - unused_most_significant_bits[ p_mpi[2] ];
  else
  {
    num_bits = (l_mpi << 3);

    if (0x00 == p_mpi[2]) // this DOES NOT work with GnuPG 2.4.7, so fake the bit number here...
      num_bits -= 7; // this is a fake, normally, the first byte would 'vanish'...
    else
      num_bits -= unused_most_significant_bits[ p_mpi[2] ];
  }

  if (NULL != p_mpilen)
    *p_mpilen = 2 + l_mpi;

  p_mpi[0] = (uint8_t)(num_bits >> 8);
  p_mpi[1] = (uint8_t)num_bits;

  if (NULL != p_checksum)
  {
    for (i = 0; i < (2 + l_mpi); i++)
      (*p_checksum) += p_mpi[i];
  }

  return p_mpi;
}

#else

#define _GPGBIN_format_byte_number_as_mpi_no_edwards(_1,_2,_3,_4,_5)  _GPGBIN_format_byte_number_as_mpi(_1,_2,_3,_4,_5)
#define _GPGBIN_format_byte_number_as_mpi_edwards(_1,_2,_3,_4,_5)     _GPGBIN_format_byte_number_as_mpi(_1,_2,_3,_4,_5)

// prefix_byte == -1 if not existing; if existing, then prefix byte (low 8 bits of prefix_byte MUST NOT BE ZERO(0))
static uint8_t *_GPGBIN_format_byte_number_as_mpi ( const uint8_t *p_number, uint32_t l_number, uint32_t *p_mpilen, int prefix_byte, uint16_t *p_checksum )
{
  uint8_t          *p_mpi;
  uint32_t          l_mpi, num_bits, i;

  *p_mpilen = 0;

  // handle zero(0) case first

  if (NULL == p_number || 0 == l_number)
  {
HandleZero:
    p_mpi = (uint8_t*)malloc(2);
    if (unlikely(NULL == p_mpi))
      return NULL;
    p_mpi[0] = p_mpi[1] = 0x00;
    *p_mpilen = 2;
    // checksum update, if desired, not necessary
    return p_mpi;
  }

  if (0 == prefix_byte) // not allowed
    return NULL;

  // canonicalize if and only if no prefix_byte specified

  if (-1 == prefix_byte)
  {
    while (0 != l_number && 0x00 == *p_number)
    {
      p_number++;
      l_number--;
    }
    if (unlikely(0 == l_number))
      goto HandleZero;
  }

  l_mpi = (-1 != prefix_byte) ? (1 + l_number) : l_number;

  p_mpi = (uint8_t*)malloc(2 + l_mpi);
  if (unlikely(NULL == p_mpi))
    return NULL;

  if (-1 != prefix_byte)
  {
    p_mpi[2] = (uint8_t)prefix_byte;
    memcpy(p_mpi + 3, p_number, l_number);
  }
  else
    memcpy(p_mpi + 2, p_number, l_number);

  num_bits = (l_mpi << 3) - unused_most_significant_bits[ p_mpi[2] ];

  *p_mpilen = 2 + l_mpi;

  p_mpi[0] = (uint8_t)(num_bits >> 8);
  p_mpi[1] = (uint8_t)num_bits;

  if (NULL != p_checksum)
  {
    for (i = 0; i < *p_mpilen; i++)
      (*p_checksum) += p_mpi[i];
  }

  return p_mpi;
}

#endif

#if 0
/**
 * @brief creates the To-Be-Signed part of a fingerprint hash (please note that
 *        PGP also uses the trailing eight bytes as the key ID); only the public
 *        parts of the key are used for hashing (only the private parts are used
 *        for the 16bit checksum, see below)
 *
 *        The fingerprint is computed over an overhead (6 or 10 bytes, v4/v5) and
 *        all MPIs comprising the public key. For each MPI, all bytes including
 *        the two prefix (bit size) bytes are used for hashing.
 *
 *        This implementation extracts the required MPIs directly from an OpenSSL EVP_PKEY*
 *
 *        v4 is standard, v5 is only used for EdDSA (legacy) and ED448
 *
 * @param [in]        p_key         pointer to a private/key pair or public EVP_PKEY*
 * @param [out]       p_l_tbs       returns the size of the To-Be-Signed = To-Be-Hashed
 * @param [out]       p_md          pointer to 32 bytes buffer returning the hash (only 20
 *                                  bytes used if SHA-1); may be NULL if only the to-be-hashed
 *                                  fingerprint packet has to be created, not the MD itself
 * @param [out]       p_l_md        size of hash (20 for v4 or 32 for v5); may be NULL if not needed
 * @param [in]        pubkey_algo   numeric identifier of PGP public key algorithm; legacy EdDSA
 *                                  25519/448 use 0x16 (448 is a v5 packet!), new EdDSA 25519 is
 *                                  0x1B, new EdDSA 448 is 0x1C - the new variants do NOT use
 *                                  MPIs for pub/priv key storage but plain octet strings
 * @param [in]        p_curve_oid   pointer to one length byte followed by ASN.1 encoded curve OID -
 *                                  if any/if applicable or NULL if not Elliptic Curve / Edwards Curve (legacy only)
 * @param [in]        comp_len      for ECDSA/EdDSA: component length in bytes, i.e. 32 for 256bit
 *                                  curves, 48 for 384bit curves, 64 for 512bit, 66 for 521bit,
 *                                  32 for ED25519, 57 for ED448 (not 56, which is 448/8!!!)
 * @param [in]        creation_ts   key pair creation timestamp
 *
 * @return MALLOCed area with *p_l_tbs octets; NULL on error
 */
static uint8_t *_GPGBIN_public_key_fingerprint_ossl ( const EVP_PKEY  *p_key,
                                                      uint32_t        *p_l_tbs,
                                                      uint8_t         *p_md,
                                                      uint32_t        *p_l_md,
                                                      uint8_t          pubkey_algo,
                                                      const uint8_t   *p_curve_oid,
                                                      uint32_t         comp_len,
                                                      uint32_t         creation_ts )
{
  uint32_t            n, m, idx = 0, l_v5 = 0;
  uint8_t            *p_md_buffer;
  bool                use_v5 = false;
  const RSA          *p_rsa_key = NULL;
  const EC_KEY       *p_ec_key = NULL;
  const EC_GROUP     *p_ec_group;
  const EC_POINT     *p_ec_point;
  uint8_t             ec_pubkey[256], ed_pubkey[256];
  const BIGNUM       *p_n, *p_e;
  uint8_t            *p_n_mpi = NULL, *p_e_mpi = NULL, *p_Q_mpi = NULL;
  uint32_t            l_n_mpi = 0, l_e_mpi = 0, l_Q_mpi = 0, l_ec_point;
  size_t              l_ed_pubkey;

  if (unlikely(NULL == p_key || NULL == p_l_tbs))
    return NULL;

  *p_l_tbs = 0;
  if (NULL != p_l_md)
    *p_l_md = 0;

  // retrieve the required public key MPIs first (from the OpenSSL EVP_PKEY*, which can either be a full key pair or just a public key)

  switch(EVP_PKEY_id(p_key))
  {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2: // this is an RSA (public) key
      p_rsa_key = EVP_PKEY_get0_RSA(p_key);

      if (unlikely(NULL == p_rsa_key))
        return NULL;

      p_n = RSA_get0_n(p_rsa_key);
      p_e = RSA_get0_e(p_rsa_key);

      if (unlikely(NULL == p_n || NULL == p_e))
        return NULL;

      p_n_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_n, &l_n_mpi, NULL/*public components NOT included in checksum*/);
      if (unlikely(NULL == p_n_mpi))
        return NULL;

      p_e_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_e, &l_e_mpi, NULL/*public components NOT included in checksum*/);
      if (unlikely(NULL == p_e_mpi))
      {
        free(p_n_mpi);
        return NULL;
      }

      break;

    case EVP_PKEY_EC: // Elliptic Curve
      p_ec_key = EVP_PKEY_get0_EC_KEY(p_key);
      if (unlikely(NULL == p_ec_key))
        return NULL;

      p_ec_group = EC_KEY_get0_group(p_ec_key);
      if (unlikely(NULL == p_ec_group))
        return NULL;

      p_ec_point = EC_KEY_get0_public_key(p_ec_key);

      memset(ec_pubkey, 0x00, sizeof(ec_pubkey));
      l_ec_point = (uint32_t)EC_POINT_point2oct(p_ec_group, p_ec_point, POINT_CONVERSION_UNCOMPRESSED, ec_pubkey, sizeof(ec_pubkey), NULL);
      if (unlikely(0 == l_ec_point))
        return NULL;

      p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_no_edwards(ec_pubkey, l_ec_point, &l_Q_mpi, -1 /* no prefix byte, 0x04 already included */, NULL/*public components NOT included in checksum*/);

      if (unlikely(NULL == p_Q_mpi))
        return NULL;

      break;

    case EVP_PKEY_ED25519:
      goto EdwardsContinue;
    case EVP_PKEY_ED448:
      if (PUBKEY_ALGO_EDDSA_LEGACY == pubkey_algo)
      {
        p_curve_oid = ed448_legacy_oid;
        use_v5 = true;
      }
EdwardsContinue:
      l_ed_pubkey = sizeof(ed_pubkey);
      memset(ed_pubkey, 0x00, sizeof(ed_pubkey));
      if (unlikely(1 != EVP_PKEY_get_raw_public_key(p_key, &ed_pubkey[1], &l_ed_pubkey)))
        return NULL;

      if (PUBKEY_ALGO_EDDSA_LEGACY == pubkey_algo)
      {
        if (!use_v5)
        {
          ed_pubkey[0] = 0x40; // this is GPG-specific...
          l_ed_pubkey++;
          p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(ed_pubkey, (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
        else
        {
          p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
      }
      else
      {
        p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
      }

      if (unlikely(NULL == p_Q_mpi))
        return NULL;

      break;

    default:
      return NULL;
  }

  // overhead:
  // ---------
  //
  // v4: 0x99,nn,nn,{0x04,TS,TS,TS,TS,pk_algo} 6 bytes
  // v5: 0x9A,nn,nn,nn,nn,{0x05,TS,TS,TS,TS,pk_algo,mm,mm,mm,mm} 10 bytes

  n = use_v5 ? 10 : 6;
  m = use_v5 ?  5 : 3; // hash tag 0x99/0x9A plus nn,nn (v4) or nn,nn,nn,nn (v5)

  // reminder: new ED25519/ED448 DO NOT work currently but are implemented in terms of fingerprint:

  if (PUBKEY_ALGO_EDDSA_25519 == pubkey_algo || PUBKEY_ALGO_EDDSA_448 == pubkey_algo)
  {
    n += comp_len;
    l_v5 += comp_len;
  }
  else
  {
    n += l_n_mpi + l_e_mpi + l_Q_mpi; // either (n,e) for RSA or Q populated, i.e. != 0
    l_v5 += l_n_mpi + l_e_mpi + l_Q_mpi;
  }

  // if curve OID specified, then add it including the OID length byte (+1)

  if (NULL != p_curve_oid)
  {
    n += p_curve_oid[0] + 1;
    l_v5 += p_curve_oid[0] + 1;
  }

  // allocate the MD buffer, i.e. the To-Be-Signed / To-Be-Hashed buffer

  if (NULL != p_l_tbs)
    *p_l_tbs = n + m;
  p_md_buffer = (uint8_t*)malloc(n + m);
  if (unlikely(NULL == p_md_buffer))
  {
ErrorExit:
    if (NULL != p_n_mpi)
      free(p_n_mpi);
    if (NULL != p_e_mpi)
      free(p_e_mpi);
    if (NULL != p_Q_mpi)
      free(p_Q_mpi);
    return NULL; // error
  }

  idx = 0;

  // prefix byte 0x99 (v4) or 0x9A (v5)
  // total length n (16 bit for v4, 32 bit for v5)

  if (use_v5)
  {
    p_md_buffer[idx++] = 0x9A;
    p_md_buffer[idx++] = (uint8_t)(n >> 24);
    p_md_buffer[idx++] = (uint8_t)(n >> 16);
  }
  else
    p_md_buffer[idx++] = 0x99;

  p_md_buffer[idx++] = (uint8_t)(n >> 8);
  p_md_buffer[idx++] = (uint8_t)n;

  // public key version
  p_md_buffer[idx++] = use_v5 ? 0x05 : 0x04;

  // key creation timestamp (32bit)

  p_md_buffer[idx++] = (uint8_t)(creation_ts >> 24);
  p_md_buffer[idx++] = (uint8_t)(creation_ts >> 16);
  p_md_buffer[idx++] = (uint8_t)(creation_ts >> 8);
  p_md_buffer[idx++] = (uint8_t) creation_ts;

  // public key algorithm

  p_md_buffer[idx++] = (uint8_t)pubkey_algo;

  // only for v5:

  if (use_v5)
  {
    p_md_buffer[idx++] = (uint8_t)(l_v5 >> 24);
    p_md_buffer[idx++] = (uint8_t)(l_v5 >> 16);
    p_md_buffer[idx++] = (uint8_t)(l_v5>> 8);
    p_md_buffer[idx++] = (uint8_t) l_v5;
  }

  // add curve OID if applicable:

  if (NULL != p_curve_oid)
  {
    memcpy(p_md_buffer + idx, p_curve_oid, p_curve_oid[0] + 1);
    idx += p_curve_oid[0] + 1;
  }

  if (PUBKEY_ALGO_EDDSA_25519 == pubkey_algo || PUBKEY_ALGO_EDDSA_448 == pubkey_algo)
  {
    memcpy(p_md_buffer + idx, p_Q_mpi + 2/*skip MPI prefix bytes because just octet string*/, comp_len);
    idx += comp_len;
  }
  else
  {
    if (NULL != p_Q_mpi) // this is Elliptic Curve
    {
      memcpy(p_md_buffer + idx, p_Q_mpi, l_Q_mpi);
      idx += l_Q_mpi;
    }
    else // RSA n and e
    {
      memcpy(p_md_buffer + idx, p_n_mpi, l_n_mpi);
      idx += l_n_mpi;
      memcpy(p_md_buffer + idx, p_e_mpi, l_e_mpi);
      idx += l_e_mpi;
    }
  }

  // sanity check

  if (idx != (n + m))
  {
    free(p_md_buffer);
    goto ErrorExit;
  }

  if (!use_v5)
  {
    if (NULL != p_md)
      SHA1(p_md_buffer, idx, p_md);
    if (NULL != p_l_md)
      *p_l_md = SHA_DIGEST_LENGTH;
  }
  else
  {
    if (NULL != p_md)
      SHA256(p_md_buffer, idx, p_md);
    if (NULL != p_l_md)
      *p_l_md = SHA256_DIGEST_LENGTH;
  }

  if (NULL != p_n_mpi)
    free(p_n_mpi);
  if (NULL != p_e_mpi)
    free(p_e_mpi);
  if (NULL != p_Q_mpi)
    free(p_Q_mpi);

  return p_md_buffer;
}

/**
 * @brief creates the To-Be-Signed part of a fingerprint hash (please note that
 *        PGP also uses the trailing eight bytes as the key ID); only the public
 *        parts of the key are used for hashing (only the private parts are used
 *        for the 16bit checksum, see below)
 *
 *        The fingerprint is computed over an overhead (6 or 10 bytes, v4/v5) and
 *        all MPIs comprising the public key. For each MPI, all bytes including
 *        the two prefix (bit size) bytes are used for hashing.
 *
 *        This implementation stores the indexes to the public key MPIs in the
 *        gpg_binary C structure.
 *
 *        v4 is standard, v5 is only used for EdDSA (legacy) and ED448
 *
 * @param [in]        p_gpg         pointer to the binary GPG structure
 * @param [out]       p_l_tbs       returns the size of the To-Be-Signed = To-Be-Hashed
 * @param [out]       p_md          pointer to 32 bytes buffer returning the hash (only 20
 *                                  bytes used if SHA-1); may be NULL if only the to-be-hashed
 *                                  fingerprint packet has to be created, not the MD itself
 * @param [out]       p_l_md        size of hash (20 for v4 or 32 for v5); may be NULL if not needed
 * @param [in]        pubkey_algo   numeric identifier of PGP public key algorithm; legacy EdDSA
 *                                  25519/448 use 0x16 (448 is a v5 packet!), new EdDSA 25519 is
 *                                  0x1B, new EdDSA 448 is 0x1C - the new variants do NOT use
 *                                  MPIs for pub/priv key storage but plain octet strings
 * @param [in]        p_curve_oid   pointer to one length byte followed by ASN.1 encoded curve OID -
 *                                  if any/if applicable
 * @param [in]        comp_len      for ECDSA/EdDSA: component length in bytes, i.e. 32 for 256bit
 *                                  curves, 48 for 384bit curves, 64 for 512bit, 66 for 521bit,
 *                                  32 for ED25519, 57 for ED448 (not 56, which is 448/8!!!)
 *
 * @return MALLOCed area with *p_l_tbs octets
 */
static uint8_t *_GPGBIN_public_key_fingerprint ( gpg_binary_ptr   p_gpg,
                                                 uint32_t        *p_l_tbs,
                                                 uint8_t         *p_md,
                                                 uint32_t        *p_l_md,
                                                 uint8_t          pubkey_algo,
                                                 const uint8_t   *p_curve_oid,
                                                 uint32_t         comp_len )
{
  uint32_t            i, n, m, idx = 0, len, l_v5 = 0;
  uint8_t            *p_md_buffer;
  bool                use_v5 = (PUBKEY_ALGO_EDDSA_LEGACY == pubkey_algo && 57 == comp_len); // only for legacy ED448

  // overhead:
  // ---------
  //
  // v4: 0x99,nn,nn,{0x04,TS,TS,TS,TS,pk_algo} 6 bytes
  // v5: 0x9A,nn,nn,nn,nn,{0x05,TS,TS,TS,TS,pk_algo,mm,mm,mm,mm} 10 bytes

  n = use_v5 ? 10 : 6;
  m = use_v5 ?  5 : 3; // hash tag 0x99/0x9A plus nn,nn (v4) or nn,nn,nn,nn (v5)

  // reminder: new ED25519/ED448 DO NOT work currently but are implemented in terms of fingerprint:

  if (PUBKEY_ALGO_EDDSA_25519 == pubkey_algo || PUBKEY_ALGO_EDDSA_448 == pubkey_algo)
  {
    n += comp_len;
    l_v5 += comp_len;
  }
  else
  {
    // n incorporates all public key MPIs including the two prefix length bytes (the bit size)
    for (i=0;i<p_gpg->pack_key_num_mpis;i++)
    {
      n += ( ( ((((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i]]) << 8) | ((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i] + 1])) + 7 ) >> 3 ) + 2;
      l_v5 += ( ( ((((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i]]) << 8) | ((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i] + 1])) + 7 ) >> 3 ) + 2;
    }
  }

  // if curve OID specified, then add it including the OID length byte (+1)

  if (NULL != p_curve_oid)
  {
    n += p_curve_oid[0] + 1;
    l_v5 += p_curve_oid[0] + 1;
  }

  // allocate the MD buffer, i.e. the To-Be-Signed / To-Be-Hashed buffer

  if (NULL != p_l_tbs)
    *p_l_tbs = n + m;
  p_md_buffer = (uint8_t*)malloc(n + m);
  if (unlikely(NULL == p_md_buffer))
    return NULL; // error

  idx = 0;

  // prefix byte 0x99 (v4) or 0x9A (v5)
  // total length n (16 bit for v4, 32 bit for v5)

  if (use_v5)
  {
    p_md_buffer[idx++] = 0x9A;
    p_md_buffer[idx++] = (uint8_t)(n >> 24);
    p_md_buffer[idx++] = (uint8_t)(n >> 16);
  }
  else
    p_md_buffer[idx++] = 0x99;

  p_md_buffer[idx++] = (uint8_t)(n >> 8);
  p_md_buffer[idx++] = (uint8_t)n;

  // public key version
  p_md_buffer[idx++] = use_v5 ? 0x05 : 0x04;

  // key creation timestamp (32bit)

  p_md_buffer[idx++] = (uint8_t)(p_gpg->creation_ts >> 24);
  p_md_buffer[idx++] = (uint8_t)(p_gpg->creation_ts >> 16);
  p_md_buffer[idx++] = (uint8_t)(p_gpg->creation_ts >> 8);
  p_md_buffer[idx++] = (uint8_t) p_gpg->creation_ts;

  // public key algorithm

  p_md_buffer[idx++] = (uint8_t)pubkey_algo;

  // only for v5:

  if (use_v5)
  {
    //n -= 10;
    p_md_buffer[idx++] = (uint8_t)(l_v5 >> 24);
    p_md_buffer[idx++] = (uint8_t)(l_v5 >> 16);
    p_md_buffer[idx++] = (uint8_t)(l_v5>> 8);
    p_md_buffer[idx++] = (uint8_t) l_v5;
    //n += 10;
  }

  // add curve OID if applicable:

  if (NULL != p_curve_oid)
  {
    memcpy(p_md_buffer + idx, p_curve_oid, p_curve_oid[0] + 1);
    idx += p_curve_oid[0] + 1;
  }

  if (PUBKEY_ALGO_EDDSA_25519 == pubkey_algo || PUBKEY_ALGO_EDDSA_448 == pubkey_algo)
  {
    memcpy(p_md_buffer + idx, p_gpg->p_workarea + p_gpg->pack_key_mpi_idx[0] + 2/*skip MPI prefix bytes because just octet string*/, comp_len);
    idx += comp_len;
  }
  else
  {
    for (i=0;i<p_gpg->pack_key_num_mpis;i++)
    {
      len = (( ((((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i]]) << 8) | ((uint32_t)p_gpg->p_workarea[p_gpg->pack_key_mpi_idx[i] + 1])) + 7 ) >> 3) + 2;
      memcpy(p_md_buffer + idx, p_gpg->p_workarea + p_gpg->pack_key_mpi_idx[i],len);
      idx += len;
    }
  }

  // sanity check

  if (idx != (n + m))
  {
    free(p_md_buffer);
    return NULL;
  }

  if (!use_v5)
  {
    if (NULL != p_md)
      SHA1(p_md_buffer, idx, p_md);
    if (NULL != p_l_md)
      *p_l_md = SHA_DIGEST_LENGTH;
  }
  else
  {
    if (NULL != p_md)
      SHA256(p_md_buffer, idx, p_md);
    if (NULL != p_l_md)
      *p_l_md = SHA256_DIGEST_LENGTH;
  }

  return p_md_buffer;
}

#endif

static uint32_t _GPGBIN_compute_secret_key_encrypted_packet_overhead ( uint32_t encr_mode, bool is_v5, uint32_t *p_auth_length )
{
  uint32_t        l_overhead;

  switch(encr_mode)
  {
    case SECRET_KEY_ENCR_AES_CFB128:
      l_overhead = 1/* 254                                        */ +
                   1/* 0x09 = AES-256                             */ +
                   1/* 0x03 = ITERSALTED S2K                      */ +
                   1/* 0x08 = SHA-256 MESSAGE DIGEST              */ +
                   8/* the salt                                   */ +
                   1/* the count byte 0xDF                        */ +
                  16/* the IV length, 128 bits                    */;
      *p_auth_length = SHA_DIGEST_LENGTH /* 20 bytes for SHA-1(SECRET) */;
      break;

    case SECRET_KEY_ENCR_AES_GCM:
      l_overhead = 1/* 253                           */ +
                   1/* 0x09 = AES-256                */ +
                   1/* 0x03 = GCM                    */ +
                   1/* 0x03 = ITERSALTED S2K         */ +
                   1/* 0x08 = SHA-256 MESSAGE DIGEST */ +
                   8/* the salt                      */ +
                   1/* the count byte 0xDF           */ +
                  12/* the IV length, 96 bits        */;

      *p_auth_length = 16 /*the AES GCM tag, 128 bits */;
      break;

    default: // no encryption
      l_overhead = 1 /* the 0x00 byte */;
      *p_auth_length = 2; /* the 16bit checksum */
      break;
  }

  return is_v5 ? (l_overhead + 1) : l_overhead; // in v5, a secondary byte (currently NOT evaluated by GnuPG 2.4.7 source)
                                                // comes right behind the encryption type byte. It seems to contain the number
                                                // of bytes for the S2K stuff, which equals "l_overhead - 2", i.e. the enc type
                                                // and the additional v5 byte are NOT counted
}

// GCC / Visual C won't optimize this away... (never use memset because of intrinsic!)
static void _memset_secure ( volatile uint8_t *p, uint8_t b, size_t s )
{
  for (size_t i=0;i<s;i++) p[i] = b;
}

static void mpi_clear_free ( uint8_t *p, size_t l )
{
  _memset_secure((volatile uint8_t*)p, 0x00, l);
  free(p);
}

#define KEYSIZE SHA256_DIGEST_LENGTH

//#define _USE_AES128_CFB_PGP

#ifdef _USE_AES128_CFB_PGP
#undef KEYSIZE
#define KEYSIZE 16
#endif

static bool _GPGBIN_encryption_prologue ( gpg_binary_ptr p_gpg, uint32_t enc_algo, bool is_v5,
                                          const uint8_t *p_secret, uint32_t l_secret, uint32_t l_enc_overhead )
{
  static const uint8_t      zeros[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
  volatile uint8_t          md[SHA256_DIGEST_LENGTH], key[KEYSIZE], hmac_md[KEYSIZE], hmac_md2[KEYSIZE];
  uint8_t                   info[5];
  uint32_t                  salt_index, count_index, iv_index, iterations, to_go, l_hmac_md, l_hmac_md2, used = 0, pass, i, count;
  SHA256_CTX                ctx;
  OSSL_PARAM                params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
  size_t                    gcm_ivlen = 12; // 96 bit
  int                       outlen = 0;

  if (unlikely(NULL == p_gpg || 0 == p_gpg->aes_gcm_ad_index || 0 == p_gpg->aes_gcm_ad_size))
    return false;

  if (SECRET_KEY_ENCR_NONE == enc_algo)
  {
    if (!is_v5)
    {
      if (unlikely(1 != l_enc_overhead)) // sanity check
        return false;
    }
    else
    {
      if (unlikely(2 != l_enc_overhead)) // sanity check
        return false;
    }

    p_gpg->p_workarea[p_gpg->workarea_idx++] = 0x00;
    if (is_v5)
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_enc_overhead-2); // assert: shall be zero here
    return true;
  }

  // handle this 'heavyweight PGP' stuff now... (we implement the one and only encryption scheme here from the one BILLION possibilities)
  // AES, Galois Counter Mode, 96bit IV, 128bit GCM tag
  // HASH always SHA2-256
  // S2K iteration count 0xDF (encoded) meaning high-nibble 0xD = 13, low-nibble 0xF = 15; result: (16 + low_nibble) << (6 + high-nibble) =
  // 31 << 19 = 16.252.928 bytes
  //
  // According to RFC 9580: AEAD(HKDF(S2K(passphrase), info), secrets, packetprefix) - a nightmare:
  //
  // S2K: count-times hashing of SALT || <INPUT-SECRET or previous message digest>
  // HKDF: see RFC 5869 involving HMAC(SHA-256)
  // What is 'info'? Packet Type ID, packet version, cipher algo, AEAD mode => 4 bytes 0xC5,4/5, CIPHER_ALGO_AES256, AEAD_ALGO_GCM
  // What is 'packetprefix'? 0xC5, 4/5, four octets creation time, one octet PK algorithm, algo-specific public key stuff
  // => 'packetprefix' is the Associated Data

  if (SECRET_KEY_ENCR_AES_GCM == enc_algo)
  {
    p_gpg->p_workarea[p_gpg->workarea_idx++] = 253;                 // AEAD = Authenticated Encryption with Associated Data
    if (is_v5)
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_enc_overhead-2);
    p_gpg->p_workarea[p_gpg->workarea_idx++] = CIPHER_ALGO_AES256;  // AES-256bit (0x09)
    p_gpg->p_workarea[p_gpg->workarea_idx++] = AEAD_ALGO_GCM;       // AEAD mode = GCM = Galois Counter Mode (0x03)
  }
  else // AES-CFB128
  {
    p_gpg->p_workarea[p_gpg->workarea_idx++] = 254;                 // AES-CFB128
    if (is_v5)
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_enc_overhead-2);
#ifdef _USE_AES128_CFB_PGP
    p_gpg->p_workarea[p_gpg->workarea_idx++] = CIPHER_ALGO_AES;     // AES-128bit (0x07)
#else
    p_gpg->p_workarea[p_gpg->workarea_idx++] = CIPHER_ALGO_AES256;  // AES-256bit (0x09)
#endif
  }
  // S2K iterated, salted hash starts here:
  p_gpg->p_workarea[p_gpg->workarea_idx++] = 0x03;                  // ITERATED AND SALTED S2K
  p_gpg->p_workarea[p_gpg->workarea_idx++] = DIGEST_ALGO_SHA256;    // SHA-256 hash (SHA2-256) (0x08)

  salt_index = p_gpg->workarea_idx;
  RAND_pseudo_bytes(p_gpg->p_workarea + p_gpg->workarea_idx, 8);  // eight bytes salt
  p_gpg->workarea_idx += 8;

  count_index = p_gpg->workarea_idx;
  p_gpg->p_workarea[p_gpg->workarea_idx++] = 0xDF;                // 16.252.928 bytes

  if (SECRET_KEY_ENCR_AES_GCM == enc_algo)
  {
    // nonce aka Initialization Vector IV = 96bit = 12 bytes:
    iv_index = p_gpg->workarea_idx;
    RAND_pseudo_bytes(p_gpg->p_workarea + p_gpg->workarea_idx, 12); // twelve bytes IV
    p_gpg->workarea_idx += 12;
    // encrypted payload followed by 128bit (16 bytes GCM tag)
  }
  else // AES-CFB128
  {
    iv_index = p_gpg->workarea_idx;
    RAND_pseudo_bytes(p_gpg->p_workarea + p_gpg->workarea_idx, 16); // sixteen bytes IV
    p_gpg->workarea_idx += 16;
    // SHA-1 over secret components follows ciphertext
  }

  // prepare the secret = password now; start with the iterated hashing of it...

  iterations = (16 + ((uint32_t)(p_gpg->p_workarea[count_index] & 15))) << (6 + (p_gpg->p_workarea[count_index] >> 4));
  SHA256_Init(&ctx);
  for (pass = 0; used < KEYSIZE; pass++)
  {
    if (0 != pass)
    {
      SHA256_Init(&ctx);
      i = 0;
      while (i < pass)
      {
        to_go = pass - i;
        if (to_go > sizeof(zeros))
          to_go = sizeof(zeros);
        SHA256_Update(&ctx, zeros, to_go);
        i += to_go;
      }
    }

    count = iterations;
    if (count < (l_secret + 8))
      count = l_secret + 8;

    while (count > (l_secret + 8))
    {
      SHA256_Update(&ctx, p_gpg->p_workarea + salt_index, 8);
      SHA256_Update(&ctx, p_secret, l_secret);
      count -= l_secret + 8;
    }

    if (count < 8)
      SHA256_Update(&ctx, p_gpg->p_workarea + salt_index, count);
    else
    {
      SHA256_Update(&ctx, p_gpg->p_workarea + salt_index, 8);
      count -= 8;
      SHA256_Update(&ctx, p_secret, count);
    }

    i = SHA256_DIGEST_LENGTH;
    if (i > (KEYSIZE - used))
      i = KEYSIZE - used;

    SHA256_Final((uint8_t*)md, &ctx);

    memcpy((uint8_t*)(key+used), (uint8_t *)md, i);
    used += i;
  }

  _memset_secure((volatile uint8_t*)md, 0x00, sizeof(md));
  _memset_secure((volatile uint8_t*)&ctx, 0x00, sizeof(ctx));

  // 'key' now contains the iterated, hashed password

  if (SECRET_KEY_ENCR_AES_CFB128 == enc_algo) // AES, 256bit, CFB128 mode
  {
    p_gpg->p_cipher_ctx = EVP_CIPHER_CTX_new();
    if (unlikely(NULL == p_gpg->p_cipher_ctx))
    {
ErrorExit1:
      _memset_secure((volatile uint8_t*)key, 0x00, sizeof(key));
      if (NULL != p_gpg->p_cipher_ctx)
        EVP_CIPHER_CTX_free(p_gpg->p_cipher_ctx), p_gpg->p_cipher_ctx = NULL;
      if (NULL != p_gpg->p_cipher)
        EVP_CIPHER_free(p_gpg->p_cipher), p_gpg->p_cipher = NULL;
      return false;
    }

#ifdef _USE_AES128_CFB_PGP
    if (!EVP_EncryptInit_ex(p_gpg->p_cipher_ctx, EVP_aes_128_cfb128(), NULL, (const uint8_t*)key, p_gpg->p_workarea + iv_index))
#else
    if (!EVP_EncryptInit_ex(p_gpg->p_cipher_ctx, EVP_aes_256_cfb128(), NULL, (const uint8_t*)key, p_gpg->p_workarea + iv_index))
#endif
      goto ErrorExit1;

    _memset_secure((volatile uint8_t*)key, 0x00, sizeof(key));
  }
  else // AES Galois Counter Mode
  {
    // RFC 5869: Extract step: Because we do not use salt here, salt is defined as 32 zeros (matching the SHA-256 digest size)

    // 'md' is the zero-salt
    l_hmac_md = sizeof(hmac_md);
    // PRK = HMAC-Hash(salt, IKM)
    HMAC(EVP_sha256(),/*key*/(const uint8_t*)key, /*key size*/KEYSIZE,
         /*data = zero salt*/(const uint8_t*)md, /*data size*/SHA256_DIGEST_LENGTH,(uint8_t*)hmac_md,&l_hmac_md);
    _memset_secure((volatile uint8_t*)key, 0x00, sizeof(key));
    // PRK is in hmac_md, 32 bytes = SHA256_DIGEST_LENGTH
    // info = 0xC5,4/5, CIPHER_ALGO_AES256, AEAD_ALGO_GCM (4 bytes)
    // L = length of output keying material = 32 bytes (for AES-256)
    //
    // N = ceil(L/HashLen) = 1
    // T = T(1) | T(2) | T(3) | ... | T(N) = T(N=1)
    //
    // where:
    // T(0) = empty string (zero length)
    // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01) <- 0x01, 0x02, 0x03, ... are one byte each!
    // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)

    // => HMAC-Hash(PRK, T(0) = empty | info | 0x01)

    info[0] = 0xC5;
    info[1] = is_v5 ? 0x05 : 0x04;
    info[2] = CIPHER_ALGO_AES256;
    info[3] = AEAD_ALGO_GCM;
    info[4] = 0x01;

    l_hmac_md2 = sizeof(hmac_md2);
    HMAC(EVP_sha256(),/*key*/(const uint8_t*)hmac_md, /*key size*/KEYSIZE,
         /*data*/info, /*data size*/5, (uint8_t*)hmac_md2, &l_hmac_md2);

    _memset_secure((volatile uint8_t*)md, 0x00, sizeof(md));
    _memset_secure((volatile uint8_t*)hmac_md, 0x00, sizeof(hmac_md));

    // finally, hmac_md2 contains the AES-256bit key for AES-GCM (hopefully...)

    p_gpg->p_cipher_ctx = EVP_CIPHER_CTX_new();
    if (unlikely(NULL == p_gpg->p_cipher_ctx))
    {
  ErrorExit:
      _memset_secure((volatile uint8_t*)hmac_md2, 0x00, sizeof(hmac_md2));
      if (NULL != p_gpg->p_cipher_ctx)
        EVP_CIPHER_CTX_free(p_gpg->p_cipher_ctx), p_gpg->p_cipher_ctx = NULL;
      if (NULL != p_gpg->p_cipher)
        EVP_CIPHER_free(p_gpg->p_cipher), p_gpg->p_cipher = NULL;
      return false;
    }

    p_gpg->p_cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (unlikely(NULL == p_gpg->p_cipher))
      goto ErrorExit;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &gcm_ivlen);

    if (!EVP_EncryptInit_ex2(p_gpg->p_cipher_ctx, p_gpg->p_cipher, (const uint8_t*)hmac_md2, p_gpg->p_workarea + iv_index, params))
      goto ErrorExit;

    _memset_secure((volatile uint8_t*)hmac_md2, 0x00, sizeof(hmac_md2));

    // Add associated data (AD)

    if (!EVP_EncryptUpdate(p_gpg->p_cipher_ctx, NULL, &outlen, p_gpg->p_workarea + p_gpg->aes_gcm_ad_index, p_gpg->aes_gcm_ad_size))
      goto ErrorExit;
  }

  return true;
}

static bool _GPGBIN_encryption_epilogue ( gpg_binary_ptr p_gpg, uint32_t enc_algo, uint16_t csum )
{
  int                       outlen = 0, tmplen = 0;
  uint8_t                   outbuf[32]; // dummy, not used (2x16 as array dimension because there is no algo with a block size > 128bit out there)
  OSSL_PARAM                params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

  if (SECRET_KEY_ENCR_NONE == enc_algo)
  {
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(csum >> 8);
    p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)csum;
    return true;
  }

  if (unlikely(NULL == p_gpg->p_cipher_ctx || 0 == p_gpg->aes_gcm_pt_index || 0 == p_gpg->aes_gcm_pt_size))
    return false;

  // 1.) If this is AES-CFB128, then first compute the SHA-1 over the secret key components BEFORE encrypting it

  if (SECRET_KEY_ENCR_AES_CFB128 == enc_algo)
  {
    SHA1(p_gpg->p_workarea + p_gpg->aes_gcm_pt_index, p_gpg->aes_gcm_pt_size, p_gpg->p_workarea + p_gpg->workarea_idx);
    p_gpg->workarea_idx += SHA_DIGEST_LENGTH;
    p_gpg->aes_gcm_pt_size += SHA_DIGEST_LENGTH;
  }

  // 2.) Encrypt the plaintext (in-place)

  if (!EVP_EncryptUpdate(p_gpg->p_cipher_ctx,
                         p_gpg->p_workarea + p_gpg->aes_gcm_pt_index, &outlen,
                         p_gpg->p_workarea + p_gpg->aes_gcm_pt_index, p_gpg->aes_gcm_pt_size))
  {
ErrorExit:
    EVP_CIPHER_CTX_free(p_gpg->p_cipher_ctx);
    p_gpg->p_cipher_ctx = NULL;
    if (NULL != p_gpg->p_cipher)
      EVP_CIPHER_free(p_gpg->p_cipher), p_gpg->p_cipher = NULL;
    return false;
  }

  // sanity check (no padding whatsoever, all algos here (GCM, CFB128) work like stream ciphers

  if (unlikely(outlen != ((int)p_gpg->aes_gcm_pt_size)))
    goto ErrorExit;

  /* Finalize: NOTE: get no output for GCM */
  if (!EVP_EncryptFinal_ex(p_gpg->p_cipher_ctx, outbuf, &tmplen))
    goto ErrorExit;

  if (unlikely(0 != tmplen)) // sanity check #2
    goto ErrorExit;

  // 3.) Get the AES GCM tag and store it

  if (SECRET_KEY_ENCR_AES_GCM == enc_algo)
  {
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, p_gpg->p_workarea + p_gpg->workarea_idx, 16);

    if (!EVP_CIPHER_CTX_get_params(p_gpg->p_cipher_ctx, params))
      goto ErrorExit;

    p_gpg->workarea_idx += 16;
  }

  EVP_CIPHER_CTX_free(p_gpg->p_cipher_ctx);
  p_gpg->p_cipher_ctx = NULL;
  if (NULL != p_gpg->p_cipher)
    EVP_CIPHER_free(p_gpg->p_cipher), p_gpg->p_cipher = NULL;

  return true;
}

gpg_evp_key_ptr GPGBIN_ossl_evp_pkey_to_gpg_evp_key ( const EVP_PKEY *p_ossl_evp_pkey, uint32_t creation_ts )
{
  gpg_evp_key_ptr         p_gekp;
  const RSA              *p_rsa_key;
  const EC_KEY           *p_ec_key;
  const EC_GROUP         *p_ec_group;
  const EC_POINT         *p_ec_point;
  int                     ec_curve_nid, cmp;
  uint8_t                 ed_pubkey[256], ed_privkey[64], ec_pubkey[256];
  size_t                  l_ed_pubkey, l_ed_privkey = sizeof(ed_privkey);
  uint32_t                l_ec_point, n, m, l_v5 = 0, idx = 0, i;
  const BIGNUM           *p_n = NULL, *p_e = NULL, *p_d = NULL, *p_p = NULL, *p_q = NULL, *p_ec_priv_key = NULL, *p_xchg;
  BIGNUM                 *p_u = NULL;

  if (unlikely(NULL == p_ossl_evp_pkey))
    return NULL;

  p_gekp = (gpg_evp_key_ptr)malloc(sizeof(gpg_evp_key));
  if (unlikely(NULL == p_gekp))
    return NULL;

  memset(p_gekp, 0x00, sizeof(gpg_evp_key));
  memset(ed_pubkey, 0x00, sizeof(ed_pubkey));
  memset(ed_privkey, 0x00, sizeof(ed_privkey));
  memset(ec_pubkey, 0x00, sizeof(ec_pubkey));

  p_gekp->p_ossl_evp_pkey = p_ossl_evp_pkey;
  p_gekp->creation_ts = creation_ts;

  // depending on key type, get components

  switch(EVP_PKEY_id(p_ossl_evp_pkey))
  {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2: // this is an RSA (public) key
      p_rsa_key = EVP_PKEY_get0_RSA(p_ossl_evp_pkey);

      if (unlikely(NULL == p_rsa_key))
      {
ErrorExit:
        p_gekp->p_ossl_evp_pkey = NULL; // do not purge the caller's EVP_PKEY* if we fail...
        GPGBIN_gpg_evp_key_free(p_gekp);
        if (NULL != p_u)
          BN_clear_free(p_u);
        _memset_secure(ed_privkey, 0x00, sizeof(ed_privkey));
        return NULL;
      }

      p_n = RSA_get0_n(p_rsa_key);
      p_e = RSA_get0_e(p_rsa_key);

      if (unlikely(NULL == p_n || NULL == p_e))
        goto ErrorExit;

      p_d = RSA_get0_d(p_rsa_key);
      p_p = RSA_get0_p(p_rsa_key);
      p_q = RSA_get0_q(p_rsa_key);

      if (NULL != p_d && NULL != p_p && NULL != p_q)
      {
        p_gekp->is_keypair = true;

        cmp = BN_cmp(p_p, p_q); // PGP requires p < q

        if (unlikely(0 == cmp))
          goto ErrorExit;

        if (cmp > 0) // exchange p and q
        {
          p_xchg = p_p;
          p_p = p_q;
          p_q = p_xchg;
        }

        // compute u, which is ipmq (not OpenSSL's iqmp!); u is required by GPG

        p_u = BN_new();
        if (unlikely(NULL == p_u))
          goto ErrorExit;

        if (unlikely(NULL == BN_mod_inverse(p_u, p_p, p_q, NULL)))
          goto ErrorExit;
      }

      p_gekp->num_pub_components = 2;
      p_gekp->pub_components[0] = _GPGBIN_format_ossl_bignum_as_mpi(p_n, NULL, NULL/*no csum for public component*/);
      p_gekp->pub_components[1] = _GPGBIN_format_ossl_bignum_as_mpi(p_e, NULL, NULL/*no csum for public component*/);

      if (unlikely(NULL == p_gekp->pub_components[0] || NULL == p_gekp->pub_components[1]))
        goto ErrorExit;

      if (p_gekp->is_keypair)
      {
        p_gekp->num_prv_components = 4;
        p_gekp->prv_components[0] = _GPGBIN_format_ossl_bignum_as_mpi(p_d, NULL, &p_gekp->csum);
        p_gekp->prv_components[1] = _GPGBIN_format_ossl_bignum_as_mpi(p_p, NULL, &p_gekp->csum);
        p_gekp->prv_components[2] = _GPGBIN_format_ossl_bignum_as_mpi(p_q, NULL, &p_gekp->csum);
        p_gekp->prv_components[3] = _GPGBIN_format_ossl_bignum_as_mpi(p_u, NULL, &p_gekp->csum);

        if (unlikely(NULL == p_gekp->pub_components[0] || NULL == p_gekp->pub_components[1] ||
                     NULL == p_gekp->pub_components[2] || NULL == p_gekp->pub_components[3]))
          goto ErrorExit;
      }

      p_gekp->pubkey_algo = RSA_GPG_ALGO;

      break;

    case EVP_PKEY_EC: // Elliptic Curve
      p_ec_key = EVP_PKEY_get0_EC_KEY(p_ossl_evp_pkey);
      if (unlikely(NULL == p_ec_key))
        goto ErrorExit;

      p_ec_group = EC_KEY_get0_group(p_ec_key);
      if (unlikely(NULL == p_ec_group))
        goto ErrorExit;

      ec_curve_nid = EC_GROUP_get_curve_name(p_ec_group);

      switch(ec_curve_nid)
      {
        case NID_X9_62_prime256v1:
          p_gekp->curve_idx = CURVE_NIST_256;
          p_gekp->comp_len = 32;
          break;
        case NID_secp384r1:
          p_gekp->curve_idx = CURVE_NIST_384;
          p_gekp->comp_len = 48;
          break;
        case NID_secp521r1:
          p_gekp->curve_idx = CURVE_NIST_521;
          p_gekp->comp_len = 66;
          break;
        case NID_brainpoolP256r1:
          p_gekp->curve_idx = CURVE_BRAINPOOL_256;
          p_gekp->comp_len = 32;
          break;
        case NID_brainpoolP384r1:
          p_gekp->curve_idx = CURVE_BRAINPOOL_384;
          p_gekp->comp_len = 48;
          break;
        case NID_brainpoolP512r1:
          p_gekp->curve_idx = CURVE_BRAINPOOL_512;
          p_gekp->comp_len = 64;
          break;
        default:
          goto ErrorExit;
      }

      memcpy(p_gekp->curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid[0] + 1);

      p_ec_point = EC_KEY_get0_public_key(p_ec_key);

      memset(ec_pubkey, 0x00, sizeof(ec_pubkey));
      l_ec_point = (uint32_t)EC_POINT_point2oct(p_ec_group, p_ec_point, POINT_CONVERSION_UNCOMPRESSED, ec_pubkey, sizeof(ec_pubkey), NULL);
      if (unlikely(0 == l_ec_point))
        goto ErrorExit;

      p_gekp->num_pub_components = 1;
      p_gekp->pub_components[0] = _GPGBIN_format_byte_number_as_mpi_no_edwards(ec_pubkey, l_ec_point, NULL,
                                                                               -1 /* no prefix byte, 0x04 already included */,
                                                                               NULL/*public components NOT included in checksum*/);
      if (unlikely(NULL == p_gekp->pub_components[0]))
        goto ErrorExit;

      p_ec_priv_key = EC_KEY_get0_private_key(p_ec_key);
      if (NULL != p_ec_priv_key)
      {
        p_gekp->is_keypair = true;
        p_gekp->num_prv_components = 1;
        p_gekp->prv_components[0] = _GPGBIN_format_ossl_bignum_as_mpi(p_ec_priv_key, NULL, &p_gekp->csum);

        if (unlikely(NULL == p_gekp->prv_components[0]))
          goto ErrorExit;
      }

      p_gekp->pubkey_algo = PUBKEY_ALGO_ECDSA;

      break;

    case EVP_PKEY_ED25519:
      p_gekp->curve_idx = CURVE_ED25519;
      p_gekp->pubkey_algo = edwards_legacy ? PUBKEY_ALGO_EDDSA_LEGACY : PUBKEY_ALGO_EDDSA_25519;
      memcpy(p_gekp->curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid[0] + 1);
      p_gekp->comp_len = 32;
      goto EdwardsContinue;
    case EVP_PKEY_ED448:
      p_gekp->curve_idx = CURVE_ED448;
      p_gekp->pubkey_algo = edwards_legacy ? PUBKEY_ALGO_EDDSA_LEGACY : PUBKEY_ALGO_EDDSA_448;
      p_gekp->comp_len = 57;
      if (edwards_legacy)
      {
        memcpy(p_gekp->curve_oid, ed448_legacy_oid, ed448_legacy_oid[0] + 1);
        p_gekp->use_v5 = true;
      }
      else
        memcpy(p_gekp->curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid, named_ec_curves[p_gekp->curve_idx].curve_oid[0] + 1);

EdwardsContinue:
      l_ed_pubkey = sizeof(ed_pubkey);
      if (unlikely(1 != EVP_PKEY_get_raw_public_key(p_ossl_evp_pkey, &ed_pubkey[1], &l_ed_pubkey)))
        goto ErrorExit;

      p_gekp->num_pub_components = 1;

      if (PUBKEY_ALGO_EDDSA_LEGACY == p_gekp->pubkey_algo)
      {
        if (!p_gekp->use_v5)
        {
          ed_pubkey[0] = 0x40; // this is GPG-specific...
          l_ed_pubkey++;
          p_gekp->pub_components[0] = _GPGBIN_format_byte_number_as_mpi_edwards(ed_pubkey, (uint32_t)l_ed_pubkey, NULL, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
        else
        {
          p_gekp->pub_components[0] = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, NULL, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
      }
      else
      {
        p_gekp->pub_components[0] = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, NULL, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
      }

      if (unlikely(NULL == p_gekp->pub_components[0]))
        goto ErrorExit;

      if (1 == EVP_PKEY_get_raw_private_key(p_ossl_evp_pkey, ed_privkey, &l_ed_privkey))
      {
        p_gekp->is_keypair = true;

        p_gekp->num_prv_components = 1;

        if (PUBKEY_ALGO_EDDSA_25519 == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_448 == p_gekp->pubkey_algo)
        {
          p_gekp->prv_components[0] = _GPGBIN_format_byte_number_as_mpi_edwards(ed_privkey, (uint32_t)l_ed_privkey, NULL, -1 /* no prefix byte */, NULL);
          p_gekp->csum = _GPGBIN_compute_checksum(ed_privkey, (uint32_t)l_ed_privkey); // we have to manually compute this in this case
        }
        else
          p_gekp->prv_components[0] = _GPGBIN_format_byte_number_as_mpi_edwards(ed_privkey, (uint32_t)l_ed_privkey, NULL, -1 /* no prefix byte */, &p_gekp->csum);

        _memset_secure((volatile uint8_t*)ed_privkey, 0x00, sizeof(ed_privkey));

        if (unlikely(NULL == p_gekp->prv_components[0]))
          goto ErrorExit;
      }

      break;

    default:
      goto ErrorExit;
  }

  // compute PGP fingerprint: this is SHA-1 for v4 (trailing eight bytes are key ID) or SHA-256 for v5 (first eight bytes are key ID)

  // overhead:
  // ---------
  //
  // v4: 0x99,nn,nn,{0x04,TS,TS,TS,TS,pk_algo} 6 bytes
  // v5: 0x9A,nn,nn,nn,nn,{0x05,TS,TS,TS,TS,pk_algo,mm,mm,mm,mm} 10 bytes

  n = p_gekp->use_v5 ? 10 : 6;
  m = p_gekp->use_v5 ?  5 : 3; // hash tag 0x99/0x9A plus nn,nn (v4) or nn,nn,nn,nn (v5)

  // reminder: new ED25519/ED448 DO NOT work currently but are implemented in terms of fingerprint:

  if (PUBKEY_ALGO_EDDSA_25519 == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_448 == p_gekp->pubkey_algo)
  {
    n += p_gekp->comp_len;
    l_v5 += p_gekp->comp_len;
  }
  else
  {
    for (i=0;i<p_gekp->num_pub_components;i++)
      l_v5 += MPI_SIZE(p_gekp->pub_components[i]) + 2;
    n += l_v5;
  }

  // if curve OID specified, then add it including the OID length byte (+1)

  if (0x00 != p_gekp->curve_oid[0])
  {
    n += p_gekp->curve_oid[0] + 1;
    l_v5 += p_gekp->curve_oid[0] + 1;
  }

  // allocate the MD buffer, i.e. the To-Be-Signed / To-Be-Hashed buffer

  p_gekp->p_md_buffer = (uint8_t*)malloc(n + m);
  if (unlikely(NULL == p_gekp->p_md_buffer))
    goto ErrorExit;

  // prefix byte 0x99 (v4) or 0x9A (v5)
  // total length n (16 bit for v4, 32 bit for v5)

  if (p_gekp->use_v5)
  {
    p_gekp->p_md_buffer[idx++] = 0x9A;
    p_gekp->p_md_buffer[idx++] = (uint8_t)(n >> 24);
    p_gekp->p_md_buffer[idx++] = (uint8_t)(n >> 16);
  }
  else
    p_gekp->p_md_buffer[idx++] = 0x99;

  p_gekp->p_md_buffer[idx++] = (uint8_t)(n >> 8);
  p_gekp->p_md_buffer[idx++] = (uint8_t)n;

  // public key version
  p_gekp->p_md_buffer[idx++] = p_gekp->use_v5 ? 0x05 : 0x04;

  // key creation timestamp (32bit)

  p_gekp->p_md_buffer[idx++] = (uint8_t)(p_gekp->creation_ts >> 24);
  p_gekp->p_md_buffer[idx++] = (uint8_t)(p_gekp->creation_ts >> 16);
  p_gekp->p_md_buffer[idx++] = (uint8_t)(p_gekp->creation_ts >> 8);
  p_gekp->p_md_buffer[idx++] = (uint8_t) p_gekp->creation_ts;

  // public key algorithm

  p_gekp->p_md_buffer[idx++] = (uint8_t)p_gekp->pubkey_algo;

  // only for v5:

  if (p_gekp->use_v5)
  {
    p_gekp->p_md_buffer[idx++] = (uint8_t)(l_v5 >> 24);
    p_gekp->p_md_buffer[idx++] = (uint8_t)(l_v5 >> 16);
    p_gekp->p_md_buffer[idx++] = (uint8_t)(l_v5>> 8);
    p_gekp->p_md_buffer[idx++] = (uint8_t) l_v5;
  }

  // add curve OID if applicable:

  if (0x00 != p_gekp->curve_oid[0])
  {
    memcpy(p_gekp->p_md_buffer + idx, p_gekp->curve_oid, p_gekp->curve_oid[0] + 1);
    idx += p_gekp->curve_oid[0] + 1;
  }

  if (PUBKEY_ALGO_EDDSA_25519 == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_448 == p_gekp->pubkey_algo)
  {
    memcpy(p_gekp->p_md_buffer + idx, p_gekp->pub_components[0] + 2/*skip MPI prefix bytes because just octet string*/, p_gekp->comp_len);
    idx += p_gekp->comp_len;
  }
  else
  {
    for (i=0;i<p_gekp->num_pub_components;i++)
    {
      memcpy(p_gekp->p_md_buffer + idx, p_gekp->pub_components[i], MPI_SIZE(p_gekp->pub_components[i]) + 2);
      idx += MPI_SIZE(p_gekp->pub_components[i]) + 2;
    }
  }

  // sanity check

  if (unlikely(idx != (n + m)))
    goto ErrorExit;

  if (!p_gekp->use_v5)
  {
    SHA1(p_gekp->p_md_buffer, idx, p_gekp->fipr);
    memcpy(p_gekp->keyid, &p_gekp->fipr[SHA_DIGEST_LENGTH - 8], 8);
  }
  else
  {
    SHA256(p_gekp->p_md_buffer, idx, p_gekp->fipr);
    memcpy(p_gekp->keyid, p_gekp->fipr, 8);
  }

  p_gekp->l_md_buffer = idx;

  if (NULL != p_u)
    BN_clear_free(p_u);

  _memset_secure(ed_privkey, 0x00, sizeof(ed_privkey));

  return p_gekp;
}

void GPGBIN_gpg_evp_key_free ( gpg_evp_key_ptr p_gekp )
{
  uint32_t              i;

  if (NULL != p_gekp)
  {
    for (i=0;i<p_gekp->num_pub_components;i++)
    {
      if (NULL != p_gekp->pub_components[i])
        free(p_gekp->pub_components[i]);
    }

    for (i=0;i<p_gekp->num_prv_components;i++)
    {
      if (NULL != p_gekp->prv_components[i])
      {
        _memset_secure(p_gekp->prv_components[i], 0x00, MPI_SIZE(p_gekp->prv_components[i]) + 2);
        free(p_gekp->prv_components[i]);
      }
    }

    if (NULL != p_gekp->p_md_buffer)
      free(p_gekp->p_md_buffer);

    _memset_secure((volatile void*)p_gekp, 0x00, sizeof(gpg_evp_key));
    free(p_gekp);
  }
}

uint32_t GPGBIN_addpacket_sign_key ( gpg_binary_ptr p_gpg, const EVP_PKEY *p_key, time_t creation_time, time_t expiration_time, bool secret_key )
{
  const RSA              *p_rsa_key;
  const EC_KEY           *p_ec_key;
  const EC_GROUP         *p_ec_group;
  const EC_POINT         *p_ec_point;
  int                     ec_curve_nid, cmp;
  uint8_t                 algo, ed_pubkey[256], ed_privkey[64], ec_pubkey[256], *p_n_mpi, *p_e_mpi, *p_Q_mpi,
                          *p_d_mpi = NULL, *p_p_mpi = NULL, *p_q_mpi = NULL, *p_u_mpi = NULL,
                          *p_priv_mpi = NULL;
  size_t                  l_ed_pubkey, l_ed_privkey = sizeof(ed_privkey);
  const BIGNUM           *p_n, *p_e, *p_d = NULL, *p_p = NULL, *p_q = NULL, *p_ec_priv_key = NULL;
  BIGNUM                 *p_u = NULL;
  uint32_t                v5_len, curve_idx, l_packet, l_n_mpi, l_e_mpi, l_ec_point, l_enc_overhead = 0, l_enc_auth = 0;
  uint32_t                l_Q_mpi, l_d_mpi = 0, l_p_mpi = 0, l_q_mpi = 0, l_u_mpi = 0, l_priv_mpi = 0,
                          saved_workarea_idx, saved_workarea_idx2;
  uint16_t                csum = 0x0000;
  const uint8_t          *p_curve_oid = NULL;
  bool                    use_v5 = false;
  char                    password[256];
  uint32_t                passwd_len = 0;

  if (unlikely(NULL == p_gpg || NULL == p_key))
    return GPGBIN_ERROR_PARAMETERS;

  if (((uint64_t)creation_time) > 0xFFFFFFFF)
    return GPGBIN_ERROR_TIME_OUTOFBOUNDS;

  if (0 != expiration_time)
  {
    if (((uint64_t)expiration_time) > 0xFFFFFFFF)
      return GPGBIN_ERROR_TIME_OUTOFBOUNDS;

    p_gpg->key_expiration_ts = (uint32_t)expiration_time;
  }

  memset(password, 0, sizeof(password));

  if (SECRET_KEY_ENCR_NONE != gpg_enc_algo)
  {
    if (0 != pgp_secret[0])
      strncpy((char*)password, pgp_secret, sizeof(password) - 1);
    else
    {
      fprintf(stdout,"Please enter password twice for PGP private key encryption (leave empty for plain storage).\n");
      EVP_read_pw_string((char*)password, sizeof(password), "PGP encryption password:", 1);
    }
    passwd_len = (uint32_t)strlen((const char*)password);
    if (0 == passwd_len)
      gpg_enc_algo = SECRET_KEY_ENCR_NONE;
  }

  /**
   * public key packet: tag 6 or secret key packet: 5
   *
   * 1 byte 0x04/0x05 = version 4/5
   * 4 bytes = creation timestamp
   * 1 byte algorithm: PUBKEY_ALGO_RSA_S or PUBKEY_ALGO_ECDSA or PUBKEY_ALGO_EDDSA
   * <one or more MPIs>
   * 2 bytes checksum (only secret key packet)
   *
   */

  switch(EVP_PKEY_id(p_key))
  {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2: // this is an RSA (public) key
      p_rsa_key = EVP_PKEY_get0_RSA(p_key);

      if (unlikely(NULL == p_rsa_key))
        return GPGBIN_ERROR_INTERNAL;

      p_n = RSA_get0_n(p_rsa_key);
      p_e = RSA_get0_e(p_rsa_key);

      if (unlikely(NULL == p_n || NULL == p_e))
        return GPGBIN_ERROR_PUBKEY;

      if (secret_key)
      {
        p_d = RSA_get0_d(p_rsa_key);
        p_p = RSA_get0_p(p_rsa_key);
        p_q = RSA_get0_q(p_rsa_key);

        cmp = BN_cmp(p_p, p_q); // PGP requires p < q

        if (unlikely(0 == cmp))
          return GPGBIN_ERROR_PRIVKEY;
        if (cmp > 0) // exchange p and q
        {
          const BIGNUM *tmp = p_p;
          p_p = p_q;
          p_q = tmp;
        }

        // compute u, which is ipmq (not OpenSSL's iqmp!); u is required by GPG

        p_u = BN_new();
        if (unlikely(NULL == p_u))
          return GPGBIN_ERROR_INSUFFICIENT_MEMORY;

        if (unlikely(NULL == BN_mod_inverse(p_u, p_p, p_q, NULL)))
        {
          BN_clear_free(p_u);
          return GPGBIN_ERROR_INTERNAL;
        }

        if (unlikely(NULL == p_d || NULL == p_p || NULL == p_q || NULL == p_u))
        {
          if (NULL != p_u)
            BN_clear_free(p_u);
          return GPGBIN_ERROR_PRIVKEY;
        }
      }

      p_n_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_n, &l_n_mpi, NULL/*public components NOT included in checksum*/);
      if (unlikely(NULL == p_n_mpi))
      {
        BN_clear_free(p_u);
        return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
      }

      p_e_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_e, &l_e_mpi, NULL/*public components NOT included in checksum*/);
      if (unlikely(NULL == p_e_mpi))
      {
        BN_clear_free(p_u);
        free(p_n_mpi);
        return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
      }

      if (secret_key) // SECRET KEY PACKET
      {
        p_d_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_d, &l_d_mpi, &csum);
        p_p_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_p, &l_p_mpi, &csum);
        p_q_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_q, &l_q_mpi, &csum);
        p_u_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_u, &l_u_mpi, &csum);

        BN_clear_free(p_u), p_u = NULL;

        if (unlikely(NULL == p_d_mpi || NULL == p_p_mpi || NULL == p_q_mpi || NULL == p_u_mpi))
        {
          if (NULL != p_d_mpi)
            mpi_clear_free(p_d_mpi, l_d_mpi);
          if (NULL != p_p_mpi)
            mpi_clear_free(p_p_mpi, l_p_mpi);
          if (NULL != p_q_mpi)
            mpi_clear_free(p_q_mpi, l_q_mpi);
          if (NULL != p_u_mpi)
            mpi_clear_free(p_u_mpi, l_u_mpi);
          free(p_e_mpi);
          free(p_n_mpi);
          return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
        }

        // create packet with tag and length now:

        l_enc_overhead = _GPGBIN_compute_secret_key_encrypted_packet_overhead(gpg_enc_algo, false/*v4*/, &l_enc_auth);
        l_packet = 6 + l_n_mpi + l_e_mpi + l_enc_overhead +
                   l_d_mpi + l_p_mpi + l_q_mpi + l_u_mpi + l_enc_auth;

        if (!_GPGBIN_addpacket_tag_len(p_gpg, (uint8_t)PKT_SECRET_KEY, l_packet))
        {
          mpi_clear_free(p_d_mpi, l_d_mpi);
          mpi_clear_free(p_p_mpi, l_p_mpi);
          mpi_clear_free(p_q_mpi, l_q_mpi);
          mpi_clear_free(p_u_mpi, l_u_mpi);
          free(p_e_mpi);
          free(p_n_mpi);
          return GPGBIN_ERROR_BUFFEROVERFLOW;
        }
        p_gpg->pack_key_idx = p_gpg->workarea_idx;
      }
      else // PUBLIC KEY PACKET
      {
        l_packet = 6 /* overhead */ + l_n_mpi + l_e_mpi;

        if (!_GPGBIN_addpacket_tag_len(p_gpg, (uint8_t)PKT_PUBLIC_KEY, l_packet))
        {
          free(p_e_mpi);
          free(p_n_mpi);
          return GPGBIN_ERROR_BUFFEROVERFLOW;
        }
        p_gpg->pack_key_idx = p_gpg->workarea_idx;
      }

      p_gpg->aes_gcm_ad_index = p_gpg->workarea_idx; // associated data (if secret key encrypted), starts here

      p_gpg->p_workarea[p_gpg->workarea_idx++] = 0x04; // version 4
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 24);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 16);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 8);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)creation_time;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)RSA_GPG_ALGO;

      p_gpg->pack_key_mpi_idx[p_gpg->pack_key_num_mpis++] = p_gpg->workarea_idx;
      memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_n_mpi, l_n_mpi);
      p_gpg->workarea_idx += l_n_mpi;

      p_gpg->pack_key_mpi_idx[p_gpg->pack_key_num_mpis++] = p_gpg->workarea_idx;
      memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_e_mpi, l_e_mpi);
      p_gpg->workarea_idx += l_e_mpi;

      p_gpg->aes_gcm_ad_size = p_gpg->workarea_idx - p_gpg->aes_gcm_ad_index; // this is the size of the associated data

      if (secret_key)
      {
        saved_workarea_idx = p_gpg->workarea_idx;

        p_gpg->workarea_idx += l_enc_overhead;

        p_gpg->aes_gcm_pt_index = p_gpg->workarea_idx;
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_d_mpi, l_d_mpi);
        p_gpg->workarea_idx += l_d_mpi;
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_p_mpi, l_p_mpi);
        p_gpg->workarea_idx += l_p_mpi;
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_q_mpi, l_q_mpi);
        p_gpg->workarea_idx += l_q_mpi;
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_u_mpi, l_u_mpi);
        p_gpg->workarea_idx += l_u_mpi;
        p_gpg->aes_gcm_pt_size = p_gpg->workarea_idx - p_gpg->aes_gcm_pt_index;

        saved_workarea_idx2 = p_gpg->workarea_idx;

        p_gpg->workarea_idx = saved_workarea_idx;

        //p_gpg->p_workarea[p_gpg->workarea_idx++] = 0x00; // indicator byte: this is unencrypted (plain)
        if (!_GPGBIN_encryption_prologue(p_gpg, gpg_enc_algo, false, (const uint8_t*)password, passwd_len, l_enc_overhead))
        {
          mpi_clear_free(p_d_mpi, l_d_mpi);
          mpi_clear_free(p_p_mpi, l_p_mpi);
          mpi_clear_free(p_q_mpi, l_q_mpi);
          mpi_clear_free(p_u_mpi, l_u_mpi);
          free(p_e_mpi);
          free(p_n_mpi);
          return GPGBIN_ERROR_INTERNAL;
        }

        p_gpg->workarea_idx = saved_workarea_idx2;

        if (!_GPGBIN_encryption_epilogue(p_gpg, gpg_enc_algo, csum))
        {
          mpi_clear_free(p_d_mpi, l_d_mpi);
          mpi_clear_free(p_p_mpi, l_p_mpi);
          mpi_clear_free(p_q_mpi, l_q_mpi);
          mpi_clear_free(p_u_mpi, l_u_mpi);
          free(p_e_mpi);
          free(p_n_mpi);
          return GPGBIN_ERROR_INTERNAL;
        }

        mpi_clear_free(p_d_mpi, l_d_mpi);
        mpi_clear_free(p_p_mpi, l_p_mpi);
        mpi_clear_free(p_q_mpi, l_q_mpi);
        mpi_clear_free(p_u_mpi, l_u_mpi);
      }

      free(p_e_mpi);
      free(p_n_mpi);

      break;

    case EVP_PKEY_EC: // Elliptic Curve
      p_ec_key = EVP_PKEY_get0_EC_KEY(p_key);
      if (unlikely(NULL == p_ec_key))
        return GPGBIN_ERROR_INTERNAL;

      p_ec_group = EC_KEY_get0_group(p_ec_key);
      if (unlikely(NULL == p_ec_group))
        return GPGBIN_ERROR_INTERNAL;

      ec_curve_nid = EC_GROUP_get_curve_name(p_ec_group);

      switch(ec_curve_nid)
      {
        case NID_X9_62_prime256v1:
          curve_idx = CURVE_NIST_256;
          //comp_len = 32;
          break;
        case NID_secp384r1:
          curve_idx = CURVE_NIST_384;
          //comp_len = 48;
          break;
        case NID_secp521r1:
          curve_idx = CURVE_NIST_521;
          //comp_len = 66;
          break;
        case NID_brainpoolP256r1:
          curve_idx = CURVE_BRAINPOOL_256;
          //comp_len = 32;
          break;
        case NID_brainpoolP384r1:
          curve_idx = CURVE_BRAINPOOL_384;
          //comp_len = 48;
          break;
        case NID_brainpoolP512r1:
          curve_idx = CURVE_BRAINPOOL_512;
          //comp_len = 64;
          break;
        default:
          return GPGBIN_ERROR_UNSUPP_EC_ED_CURVE;
      }

      p_curve_oid = named_ec_curves[curve_idx].curve_oid;

      p_ec_point = EC_KEY_get0_public_key(p_ec_key);

      memset(ec_pubkey, 0x00, sizeof(ec_pubkey));
      l_ec_point = (uint32_t)EC_POINT_point2oct(p_ec_group, p_ec_point, POINT_CONVERSION_UNCOMPRESSED, ec_pubkey, sizeof(ec_pubkey), NULL);
      if (unlikely(0 == l_ec_point))
        return GPGBIN_ERROR_INTERNAL;

      p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_no_edwards(ec_pubkey, l_ec_point, &l_Q_mpi, -1 /* no prefix byte, 0x04 already included */, NULL/*public components NOT included in checksum*/);

      algo = (uint8_t)PUBKEY_ALGO_ECDSA;

      if (secret_key)
      {
        p_ec_priv_key = EC_KEY_get0_private_key(p_ec_key);
        if (unlikely(NULL == p_ec_priv_key))
        {
          free(p_Q_mpi);
          return GPGBIN_ERROR_PRIVKEY;
        }

        p_priv_mpi = _GPGBIN_format_ossl_bignum_as_mpi(p_ec_priv_key, &l_priv_mpi, &csum);
      }

CommonEC:
      if (unlikely(NULL == p_Q_mpi))
      {
        if (NULL != p_priv_mpi)
          mpi_clear_free(p_priv_mpi, l_priv_mpi);
        return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
      }

      if (secret_key && NULL == p_priv_mpi)
      {
        free(p_Q_mpi);
        return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
      }

      // Compute overhead and size of authentication information (2 bytes for plain csum or AES GCM TAG or AES-CFB128 SHA-1)

      l_enc_overhead = _GPGBIN_compute_secret_key_encrypted_packet_overhead(gpg_enc_algo, use_v5, &l_enc_auth);

      if (PUBKEY_ALGO_EDDSA_25519 == algo || PUBKEY_ALGO_EDDSA_448 == algo)
      {
        // No MPIs stored but just the plain octets... (all MPI lengths reduced by two)
        // No curve OID stored
        if (secret_key)
          l_packet = 6 /* overhead */ + (l_Q_mpi - 2) + l_enc_overhead + (l_priv_mpi - 2) + l_enc_auth;
        else
          l_packet = 6 /* overhead */ + (l_Q_mpi - 2);
      }
      else
      {
        if (secret_key)
          l_packet = (use_v5 ? 14 : 6) /* overhead */ +
                     1 /* curve OID length */ + p_curve_oid[0] + l_Q_mpi + l_enc_overhead + l_priv_mpi + l_enc_auth;
        else
          l_packet = (use_v5 ? 10 : 6) /* overhead */ + 1 /* curve OID length */ + p_curve_oid[0] + l_Q_mpi;
      }

      // add tag and length...

      if (!_GPGBIN_addpacket_tag_len(p_gpg, secret_key ? PKT_SECRET_KEY : PKT_PUBLIC_KEY, l_packet))
      {
        if (NULL != p_priv_mpi)
          mpi_clear_free(p_priv_mpi, l_priv_mpi);
        free(p_Q_mpi);
        return GPGBIN_ERROR_BUFFEROVERFLOW;
      }

      // the pack_key_idx is the index to the BODY of the packet omitting tag,len

      p_gpg->pack_key_idx = p_gpg->workarea_idx;

      p_gpg->aes_gcm_ad_index = p_gpg->workarea_idx; // associated data (if secret key encrypted), starts here

      p_gpg->p_workarea[p_gpg->workarea_idx++] = (use_v5 ? 0x05 : 0x04); // version 4/5
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 24);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 16);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(((uint32_t)creation_time) >> 8);
      p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)creation_time;
      p_gpg->p_workarea[p_gpg->workarea_idx++] = algo;

      if (use_v5) // add four more length bytes
      {
        v5_len = ((uint32_t)p_curve_oid[0] + 1) + l_Q_mpi;
        p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(v5_len >> 24);
        p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(v5_len >> 16);
        p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(v5_len >> 8);
        p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t) v5_len;
      }

      // care about curve OID (not for new ED25519/ED448)

      if (PUBKEY_ALGO_EDDSA_25519 != algo && PUBKEY_ALGO_EDDSA_448 != algo)
      {
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_curve_oid, p_curve_oid[0] + 1);
        p_gpg->workarea_idx += p_curve_oid[0] + 1;
      }

      // care about public key Q

      p_gpg->pack_key_mpi_idx[p_gpg->pack_key_num_mpis++] = p_gpg->workarea_idx;

      if (PUBKEY_ALGO_EDDSA_25519 != algo && PUBKEY_ALGO_EDDSA_448 != algo)
      {
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_Q_mpi, l_Q_mpi);
        p_gpg->workarea_idx += l_Q_mpi;
      }
      else // CAUTION: for new ED25519/ED448 not an MPI but the raw bytes are stored
      {
        memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_Q_mpi + 2, l_Q_mpi - 2);
        p_gpg->workarea_idx += l_Q_mpi - 2;
      }

      p_gpg->aes_gcm_ad_size = p_gpg->workarea_idx - p_gpg->aes_gcm_ad_index; // this is the size of the associated data

      if (secret_key)
      {
        saved_workarea_idx = p_gpg->workarea_idx;
        p_gpg->workarea_idx += l_enc_overhead;
        p_gpg->aes_gcm_pt_index = p_gpg->workarea_idx;

        if (PUBKEY_ALGO_EDDSA_25519 != algo && PUBKEY_ALGO_EDDSA_448 != algo)
        {
          if (use_v5)
          {
            p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_priv_mpi >> 24);
            p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_priv_mpi >> 16);
            p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t)(l_priv_mpi >> 8);
            p_gpg->p_workarea[p_gpg->workarea_idx++] = (uint8_t) l_priv_mpi;
            p_gpg->aes_gcm_pt_index = p_gpg->workarea_idx; // IMPORTANT: you have to update this or SHA-1 of AES-CFB128 is not correct
          }
          memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_priv_mpi, l_priv_mpi);
          p_gpg->workarea_idx += l_priv_mpi;
        }
        else
        {
          p_gpg->pack_key_mpi_idx[p_gpg->pack_key_num_mpis++] = p_gpg->workarea_idx; // for ED25519 (new) and ED448, this is also included

          memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_priv_mpi + 2, l_priv_mpi - 2);
          p_gpg->workarea_idx += l_priv_mpi - 2;
        }

        p_gpg->aes_gcm_pt_size = p_gpg->workarea_idx - p_gpg->aes_gcm_pt_index;
        saved_workarea_idx2 = p_gpg->workarea_idx;
        p_gpg->workarea_idx = saved_workarea_idx;

        if (!_GPGBIN_encryption_prologue(p_gpg, gpg_enc_algo, use_v5, (const uint8_t*)password, passwd_len, l_enc_overhead))
        {
          mpi_clear_free(p_priv_mpi, l_priv_mpi);
          free(p_Q_mpi);
          return GPGBIN_ERROR_INTERNAL;
        }

        p_gpg->workarea_idx = saved_workarea_idx2;

        if (!_GPGBIN_encryption_epilogue(p_gpg, gpg_enc_algo, csum))
        {
          mpi_clear_free(p_priv_mpi, l_priv_mpi);
          free(p_Q_mpi);
          return GPGBIN_ERROR_INTERNAL;
        }
      }

      if (NULL != p_priv_mpi)
        mpi_clear_free(p_priv_mpi, l_priv_mpi);

      free(p_Q_mpi);

      break;

    case EVP_PKEY_ED25519:
      curve_idx = CURVE_ED25519;
      p_curve_oid = named_ec_curves[curve_idx].curve_oid;
      algo = (uint8_t)(edwards_legacy ? PUBKEY_ALGO_EDDSA_LEGACY : PUBKEY_ALGO_EDDSA_25519);
      //comp_len = 32;
      goto EdwardsContinue;
    case EVP_PKEY_ED448:
      curve_idx = CURVE_ED448;
      algo = (uint8_t)(edwards_legacy ? PUBKEY_ALGO_EDDSA_LEGACY : PUBKEY_ALGO_EDDSA_448);
      //comp_len = 57;
      if (edwards_legacy)
      {
        p_curve_oid = ed448_legacy_oid;
        use_v5 = true;
      }
      else
        p_curve_oid = named_ec_curves[curve_idx].curve_oid;

EdwardsContinue:
      l_ed_pubkey = sizeof(ed_pubkey);
      memset(ed_pubkey, 0x00, sizeof(ed_pubkey));
      if (unlikely(1 != EVP_PKEY_get_raw_public_key(p_key, &ed_pubkey[1], &l_ed_pubkey)))
        return GPGBIN_ERROR_INTERNAL;

      if (PUBKEY_ALGO_EDDSA_LEGACY == algo)
      {
        if (!use_v5)
        {
          ed_pubkey[0] = 0x40; // this is GPG-specific...
          l_ed_pubkey++;
          p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(ed_pubkey, (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
        else
        {
          p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
        }
      }
      else
      {
        p_Q_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(&ed_pubkey[1], (uint32_t)l_ed_pubkey, &l_Q_mpi, -1 /* no prefix byte, 0x40 already included */, NULL/*public components NOT included in checksum*/);
      }

      if (secret_key)
      {
        if (unlikely(1 != EVP_PKEY_get_raw_private_key(p_key, ed_privkey, &l_ed_privkey)))
          return GPGBIN_ERROR_PRIVKEY;

        if (PUBKEY_ALGO_EDDSA_25519 == algo || PUBKEY_ALGO_EDDSA_448 == algo)
        {
          p_priv_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(ed_privkey, (uint32_t)l_ed_privkey, &l_priv_mpi, -1 /* no prefix byte */, NULL);
          p_gpg->eddsa_csum = csum = _GPGBIN_compute_checksum(ed_privkey, (uint32_t)l_ed_privkey);
        }
        else
          p_priv_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(ed_privkey, (uint32_t)l_ed_privkey, &l_priv_mpi, -1 /* no prefix byte */, &csum);

        _memset_secure((volatile uint8_t*)ed_privkey, 0x00, sizeof(ed_privkey));
      }

      goto CommonEC;

    default:
      return GPGBIN_ERROR_UNSUPP_KEYTYPE;
  }

  p_gpg->pack_key_len = p_gpg->workarea_idx - p_gpg->pack_key_idx;

  // sanity check

  if (unlikely(l_packet != p_gpg->pack_key_len))
    return GPGBIN_ERROR_INTERNAL;

  p_gpg->creation_ts = (uint32_t)creation_time;

  return GPGBIN_ERROR_OK;
}

static const uint32_t dayspermonth[12] =
{
  31,28,31,30,31,30,31,31,30,31,30,31
};

static bool _is_leap_year ( uint32_t year )
{
  if (year & 3)
    return false;
  if (!(year % 100))
  {
    if (!(year % 400))
      return true;
    else
      return false;
  }
  return true;
}

static int32_t _time_date2day(int32_t year, int32_t month, int32_t mday)
{
  int32_t  y, m;

  m = (month + 9) % 12;                /* mar=0, feb=11 */
  y = year - m / 10;                     /* if Jan/Feb, year-- */

  return y * 365 + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + (mday - 1);
}

#define GREGORIAN_DAY_1582_10_01          578027
#define GREGORIAN_DAY_1970_01_01          719468

static bool _time_date2systime(uint64_t* systime,
                               uint32_t year, uint32_t month, uint32_t mday,
                               uint32_t hour, uint32_t minute, uint32_t second)
{
  int64_t  gday;
  uint32_t daypermonth;

  if (hour > 23 || minute > 59 || second > 59)
    return false;

  if (year < 1582)
    return false;

  if (1582 == year)
  {
    if (month < 10)
      return false;
  }

  if (month < 1 || month>12)
    return false;

  daypermonth = dayspermonth[month - 1];

  if (2 == month)
  {
    if (_is_leap_year(year))
      daypermonth++;
  }

  if (mday<1 || mday>daypermonth)
    return false;

  gday = (int64_t)_time_date2day(year, month, mday);

  //gday -= GREGORIAN_DAY_1582_10_01;
  gday -= GREGORIAN_DAY_1970_01_01;

  gday *= 86400;

  *systime = gday + hour * 3600 + minute * 60 + second;

  return true;
}

static int _decodeLen ( const unsigned char *der, unsigned int len, unsigned int *derlen, unsigned int *idx )
{
  uint32_t         i;
  uint8_t          value;

  if (unlikely(*idx>=len))
    return -1;

  value = (uint8_t)der[*idx];
  (*idx)++;
  if (value<=127)
    *derlen = value;
  else
    if (128==value)
      return -1; // only finite derlen!!!
    else
    {
      *derlen = 0;
      value -= 128;
      if (value>4)
        return -1; // too big
      if (unlikely((*idx+value)>len))
        return -1;
      for (i=0;i<value;i++)
      {
        *derlen <<= 8;
        *derlen |= der[*idx];
        (*idx)++;
      }
    }
  return ((*idx+*derlen)<=len) ? 0 : -1;
}

uint32_t GPGBIN_addpacket_x509_sign_public_key ( gpg_binary_ptr p_gpg, const X509 *p_x509, time_t creation_time, time_t expiration_time )
{
  char                     *subjectDN;
  int                       extId;
  X509_EXTENSION           *ext;
  const ASN1_OCTET_STRING  *exValue;
  const ASN1_BIT_STRING    *p_spki;
  const EVP_PKEY           *p_evp_key;
  const ASN1_TIME          *p_time;
  struct tm                 tm_notBefore;
  uint64_t                  systime;

  if (unlikely(NULL == p_gpg || NULL == p_x509))
    return GPGBIN_ERROR_PARAMETERS;

  if (((uint64_t)creation_time) > 0xFFFFFFFF)
    return GPGBIN_ERROR_TIME_OUTOFBOUNDS;

  // if creation time is zero, get it from the notBefore of X.509v3

  if (0 == creation_time)
  {
    p_time = X509_get0_notBefore(p_x509);

    if (unlikely(NULL == p_time))
      return GPGBIN_ERROR_INTERNAL;

    memset(&tm_notBefore, 0x00, sizeof(tm_notBefore));

    ASN1_TIME_to_tm(p_time, &tm_notBefore);

    if (!_time_date2systime(&systime, tm_notBefore.tm_year + 1900, tm_notBefore.tm_mon + 1, tm_notBefore.tm_mday,
        tm_notBefore.tm_hour, tm_notBefore.tm_min, tm_notBefore.tm_sec))
      return GPGBIN_ERROR_INTERNAL;

    if (systime > 0xFFFFFFFF)
      return GPGBIN_ERROR_TIME_OUTOFBOUNDS;

    creation_time = (time_t)systime;
  }

  if (0 != expiration_time)
  {
    if (1 == expiration_time) // get from cert
    {
      p_time = X509_get0_notAfter(p_x509);

      if (unlikely(NULL == p_time))
        return GPGBIN_ERROR_INTERNAL;

      memset(&tm_notBefore, 0x00, sizeof(tm_notBefore));

      ASN1_TIME_to_tm(p_time, &tm_notBefore);

      if (!_time_date2systime(&systime, tm_notBefore.tm_year + 1900, tm_notBefore.tm_mon + 1, tm_notBefore.tm_mday,
          tm_notBefore.tm_hour, tm_notBefore.tm_min, tm_notBefore.tm_sec))
        return GPGBIN_ERROR_INTERNAL;

      if (systime > 0xFFFFFFFF)
        //return GPGBIN_ERROR_TIME_OUTOFBOUNDS;
        systime = 0xFFFFFFFF; // if expiry got from X.509v3, limit to 32bit MAX integer here...

      expiration_time = (time_t)systime;
    }
    else
    if (expiration_time > 0xFFFFFFFF)
      return GPGBIN_ERROR_TIME_OUTOFBOUNDS;

    p_gpg->key_expiration_ts = (uint32_t)expiration_time;
  }

  // try to get commonName of subject DN for possible later use:

  subjectDN = X509_NAME_oneline(X509_get_subject_name(p_x509), NULL, 0);

  if (likely(NULL != subjectDN))
  {
    char *p2, *p = strstr(subjectDN, "/CN=");
    if (NULL != p)
    {
      if (0 != p_gpg->l_user)
      {
        free (p_gpg->p_user);
        p_gpg->p_user = NULL;
        p_gpg->l_user = 0;
      }

      p2 = strchr(p + 4, '/');

      if (NULL != p2)
      {
        p_gpg->l_user = (uint32_t)( p2 - p - 4);
        goto GoOnUser;
      }
      else
      {
        p_gpg->l_user = (uint32_t)strlen(p + 4);
GoOnUser:
        if (0 != p_gpg->l_user)
        {
          p_gpg->p_user = (uint8_t *)malloc(p_gpg->l_user + 1);
          if (likely(NULL != p_gpg->p_user))
          {
            memcpy(p_gpg->p_user, p + 4, p_gpg->l_user);
            p_gpg->p_user[p_gpg->l_user] = 0x00; // zero-terminator
          }
          else
            p_gpg->l_user = 0;
        }
      }
    }
    OPENSSL_free(subjectDN);
  }

  // iterate over all X.509v3 extensions; look for SubjectKeyIdentifier, SubjectAlternativeNames, and keyUsage

  extId = X509_get_ext_by_NID( p_x509, NID_key_usage, -1);
  if ( -1 != extId)
  {
    ASN1_OCTET_STRING *exValue;
    ext = X509_get_ext(p_x509, extId);
    if (NULL != ext && NULL != (exValue = X509_EXTENSION_get_data(ext)))
    {
      if (exValue->length>3) // TAG 03 (BIT STRING), <len>, <unused bits in final octet>, <content>
      {
        if (0x03==exValue->data[0] && 2==exValue->data[1])
        {
          p_gpg->key_usage = 0x00;
          if (exValue->data[2] & 0x80) // digitalSignature
            p_gpg->key_usage |= 0x02;  // This key may be used to sign data
          if (exValue->data[2] & 0x20) // keyEncipherment
            p_gpg->key_usage |= 0x04;  // This key may be used to encrypt communications
          if (exValue->data[2] & 0x10) // dataEncipherment
            p_gpg->key_usage |= 0x04;  // This key may be used to encrypt communications
          if (exValue->data[2] & 0x04) // keyCertSign
            p_gpg->key_usage |= 0x01;  // This key may be used to make User ID certifications

          if (0x00 == p_gpg->key_usage)
            p_gpg->key_usage = 0x02; // at least: SIGN
        }
      }
    }
  }

  extId = X509_get_ext_by_NID( p_x509, NID_subject_key_identifier, -1);
  if ( -1 != extId)
  {
    ASN1_OCTET_STRING *exValue;
    ext = X509_get_ext(p_x509, extId);
    if (NULL != ext && NULL != (exValue = X509_EXTENSION_get_data(ext)))
    {
      if (exValue->length>2)
      {
        if (0x04==exValue->data[0]) // OCTET STRING, WHICH CONTAINS THE HASH
        {
          if (exValue->data[1] >= MIN_KID_SIZE && exValue->data[1] <= MAX_KID_SIZE)
          {
            if (exValue->data[1]==(exValue->length-2))
            {
              p_gpg->l_subkid = (uint32_t)exValue->data[1];
              memcpy(p_gpg->subkid, exValue->data + 2, p_gpg->l_subkid);
            }
          }
        }
      }
    }
  }

  extId = X509_get_ext_by_NID(p_x509, NID_subject_alt_name, -1); // GeneralNames ::= SEQUENCE OF GeneralName
  if ( -1 != extId )
  {
    ext = X509_get_ext(p_x509, extId);
    if (NULL != ext && NULL != (exValue = X509_EXTENSION_get_data(ext)))
    {
      uint32_t fulllen = (uint32_t)exValue->length, idx = 0, derlen, end_idx;

      if (fulllen > 1)
      {
        if (0x30 == exValue->data[idx]) // outer SEQUENCE
        {
          idx++;
          if (0 == _decodeLen(exValue->data, fulllen, &derlen, &idx)) // length of SEQUENCE = length of GeneralNames
          {
            end_idx = idx + derlen;
            while (idx != end_idx)
            {
              // check if this tag is 0x81: rfc822Name [1] IMPLICIT IA5String

              if (0x81 == exValue->data[idx]) // yes, this is an IA5String, which is the email address
              {
                idx++;
                if (0 != _decodeLen(exValue->data, fulllen, &derlen, &idx))
                  break;

                if (NULL != p_gpg->p_email)
                  free(p_gpg->p_email), p_gpg->p_email = NULL, p_gpg->l_email = 0;

                p_gpg->p_email = (uint8_t*)malloc(derlen + 1);
                if (NULL != p_gpg->p_email)
                {
                  p_gpg->l_email = derlen;
                  memcpy(p_gpg->p_email, exValue->data + idx, derlen);
                  p_gpg->p_email[derlen] = 0x00; // zero-terminator
                }
                break;
              }
              else
              {
                idx++;
                if (0 != _decodeLen(exValue->data, fulllen, &derlen, &idx))
                  break;
                idx += derlen;
              }
            }
          }
        }
      }
    }
  }

  // if SubjectKeyIdentifier was not found (see above), then compute SHA-1 over SubjectPublicKeyInfo BIT STRING
  // excluding ASN.1 tag, length, and unused bits in final octet:

  if (0 == p_gpg->l_subkid)
  {
    p_spki = X509_get0_pubkey_bitstr(p_x509);

    if (p_spki->length > 1) // first octet is number of unused bits in final octet
    {
      SHA1(&p_spki->data[1],p_spki->length - 1, p_gpg->subkid);
      p_gpg->l_subkid = SHA_DIGEST_LENGTH;
    }
  }

  // get public key as EVP_KEY*

  p_evp_key = X509_get0_pubkey(p_x509);
  if (unlikely(NULL == p_evp_key))
    return GPGBIN_ERROR_INTERNAL;

  return GPGBIN_addpacket_sign_key(p_gpg, p_evp_key, creation_time, expiration_time, false);
}

uint32_t GPGBIN_addpacket_user_id ( gpg_binary_ptr p_gpg, const char *p_user, uint32_t l_user, const char *p_email, uint32_t l_email )
{
  uint32_t                  l_packet;

  if (unlikely(NULL == p_gpg))
    return GPGBIN_ERROR_PARAMETERS;

  if ((NULL == p_user || 0 == l_user) && (0 == p_gpg->l_user))
    return GPGBIN_ERROR_PARAMETERS;

  if ((NULL == p_email || 0 == l_email) && (0 == p_gpg->l_email))
    return GPGBIN_ERROR_PARAMETERS;

  if (NULL != p_user && 0 != l_user)
  {
    if (NULL != p_gpg->p_user)
      free(p_gpg->p_user), p_gpg->p_user = NULL, p_gpg->l_user = 0;

    p_gpg->p_user = (uint8_t*)malloc(l_user + 1);
    if (unlikely(NULL == p_gpg->p_user))
      return GPGBIN_ERROR_INSUFFICIENT_MEMORY;

    memcpy(p_gpg->p_user, p_user, l_user);
    p_gpg->p_user[l_user] = 0x00;
    p_gpg->l_user = l_user;
  }

  if (NULL != p_email && 0 != l_email)
  {
    if (NULL != p_gpg->p_email)
      free(p_gpg->p_email), p_gpg->p_email = NULL, p_gpg->l_email = 0;

    p_gpg->p_email = (uint8_t*)malloc(l_email + 1);
    if (unlikely(NULL == p_gpg->p_email))
      return GPGBIN_ERROR_INSUFFICIENT_MEMORY;

    memcpy(p_gpg->p_email, p_email, l_email);
    p_gpg->p_email[l_email] = 0x00;
    p_gpg->l_email = l_email;
  }

  if (0 == p_gpg->l_user || 0 == p_gpg->l_email)
    return GPGBIN_ERROR_PARAMETERS;

  p_gpg->pack_user_id_idx = p_gpg->workarea_idx;

  l_packet = p_gpg->l_user + p_gpg->l_email + 3 /* one space, one '<' and one '>' */;

  if (!_GPGBIN_addpacket_tag_len(p_gpg, (uint8_t)PKT_USER_ID, l_packet))
    return GPGBIN_ERROR_BUFFEROVERFLOW;

  p_gpg->pack_user_id_data_idx = p_gpg->workarea_idx;

  memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_gpg->p_user, p_gpg->l_user);
  p_gpg->workarea_idx += p_gpg->l_user;
  p_gpg->p_workarea[p_gpg->workarea_idx++] = ' ';
  p_gpg->p_workarea[p_gpg->workarea_idx++] = '<';
  memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_gpg->p_email, p_gpg->l_email);
  p_gpg->workarea_idx += p_gpg->l_email;
  p_gpg->p_workarea[p_gpg->workarea_idx++] = '>';

  p_gpg->pack_user_id_data_len = p_gpg->workarea_idx - p_gpg->pack_user_id_data_idx;

  p_gpg->pack_user_id_len = p_gpg->workarea_idx - p_gpg->pack_user_id_idx;

  return GPGBIN_ERROR_OK;
}

uint32_t GPGBIN_addpacket_signature ( gpg_binary_ptr  p_gpg,
                                      uint8_t        *p_tbs,
                                      uint32_t        l_tbs,
                                      uint32_t        digest_algo,
                                      const EVP_PKEY *p_evp_key,
                                      const char     *p_pkcs11_label,
                                      const uint8_t  *p_fingerprint,
                                      uint32_t        l_fingerprint,
                                      time_t          expiration_time,
                                      const char     *p_email,
                                      uint32_t        l_email,
                                      bool            do_verify )
{
  uint32_t                  i, idx, len, to_be_hashed_size = 0, l_fpr = 0;
  uint8_t                   sig_type = 0x00; // raw binary is default
  uint8_t                  *p_tbh, saved_unhashed[16];
  uint32_t                  md_type, sig_pack_idx, hashed_sp_idx, unhashed_sp_idx, digest_fp_idx, sig_mpi_idx, l_sig_packet_hash_size;
  time_t                    t = time(NULL);
  uint8_t                   md[SHA512_DIGEST_LENGTH], *p_sig = NULL, *p_mpi;
  uint32_t                  l_sig = 0, lib_sig_type = 0xFFFFFFFF, l_mpi = 0;
  bool                      tbs_allocated = false;
  uint32_t                  err = GPGBIN_ERROR_OK, md_size = 0;
  gpg_evp_key_ptr           p_gekp = NULL;

  if (unlikely(NULL == p_gpg || NULL == p_evp_key || digest_algo < 8 || digest_algo > 11)) // only SHA2-224|256|384|512 supported
    return GPGBIN_ERROR_PARAMETERS;

  switch(digest_algo) // we need md_type for our signature implementation...
  {
    case DIGEST_ALGO_SHA256:
      md_type = MD_TYPE_SHA2_256;
      break;
    case DIGEST_ALGO_SHA384:
      md_type = MD_TYPE_SHA2_384;
      break;
    case DIGEST_ALGO_SHA512:
      md_type = MD_TYPE_SHA2_512;
      break;
    default: // case DIGEST_ALGO_SHA224:
      md_type = MD_TYPE_SHA2_224;
      break;
  }

  p_gekp = GPGBIN_ossl_evp_pkey_to_gpg_evp_key(p_evp_key, p_gpg->creation_ts);
  if (unlikely(NULL == p_gekp))
    return GPGBIN_ERROR_INTERNAL;

  switch(p_gekp->pubkey_algo)
  {
    case RSA_GPG_ALGO:
      lib_sig_type = SIG_TYPE_RSA_PKCS1_V15;
      break;
    case PUBKEY_ALGO_ECDSA:
      switch(p_gekp->curve_idx)
      {
        case CURVE_NIST_256:
          if (digest_algo < DIGEST_ALGO_SHA256 || digest_algo > DIGEST_ALGO_SHA512)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use one of SHA2-256, SHA2-384 or SHA2-512 message digests for the NIST curve (256bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_SECP256R1;
          break;
        case CURVE_NIST_384:
          if (digest_algo < DIGEST_ALGO_SHA384 || digest_algo > DIGEST_ALGO_SHA512)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use one of SHA2-384 or SHA2-512 message digests for the NIST curve (384bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_SECP384R1;
          break;
        case CURVE_NIST_521:
          if (DIGEST_ALGO_SHA512 != digest_algo)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use SHA2-512 message digest for the NIST curve (521bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_SECP521R1;
          break;
        case CURVE_BRAINPOOL_256:
          if (digest_algo < DIGEST_ALGO_SHA256 || digest_algo > DIGEST_ALGO_SHA512)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use one of SHA2-256, SHA2-384 or SHA2-512 message digests for the Brainpool curve (256bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_BRAINPOOLP256R1;
          break;
        case CURVE_BRAINPOOL_384:
          if (digest_algo < DIGEST_ALGO_SHA384 || digest_algo > DIGEST_ALGO_SHA512)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use one of SHA2-384 or SHA2-512 message digests for the Brainpool curve (384bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_BRAINPOOLP384R1;
          break;
        case CURVE_BRAINPOOL_512:
          if (DIGEST_ALGO_SHA512 != digest_algo)
          {
            if (!be_quiet)
              fprintf(stderr,"ERROR: You HAVE TO use SHA2-512 message digest for the Brainpool curve (512bit).\n");
            GPGBIN_gpg_evp_key_free(p_gekp);
            return GPGBIN_ERROR_PARAMETERS;
          }
          lib_sig_type = SIG_TYPE_ECDSA_BRAINPOOLP512R1;
          break;
        default:
          GPGBIN_gpg_evp_key_free(p_gekp);
          return GPGBIN_ERROR_UNSUPP_EC_ED_CURVE;
      }
      break;

    case PUBKEY_ALGO_EDDSA_LEGACY:
      if (32 == p_gekp->comp_len) // ED25519
      {
        if (digest_algo < DIGEST_ALGO_SHA256 || digest_algo > DIGEST_ALGO_SHA512) // RFC 9580 says: at least hash with 256 bits
        {
          if (!be_quiet)
            fprintf(stderr,"ERROR: ED25519 can only work with either SHA2-256, SHA2-384 or SHA2-512 message digests.\n");
          GPGBIN_gpg_evp_key_free(p_gekp);
          return GPGBIN_ERROR_PARAMETERS;
        }
        lib_sig_type = SIG_TYPE_EDDSA_25519;
      }
      else
      if (57 == p_gekp->comp_len) // ED448
      {
        if (DIGEST_ALGO_SHA512 != digest_algo) // only 512bit hashes allowed (RFC 9580), which is currently SHA-512 only
        {
          if (!be_quiet)
            fprintf(stderr,"ERROR: ED448 can only work with SHA2-512 message digest.\n");
          GPGBIN_gpg_evp_key_free(p_gekp);
          return GPGBIN_ERROR_PARAMETERS;
        }
        lib_sig_type = SIG_TYPE_EDDSA_448;
      }
      else
      {
        GPGBIN_gpg_evp_key_free(p_gekp);
        return GPGBIN_ERROR_UNSUPP_EC_ED_CURVE;
      }
      break;

    case PUBKEY_ALGO_EDDSA_25519:
      if (digest_algo < DIGEST_ALGO_SHA256 || digest_algo > DIGEST_ALGO_SHA512) // RFC 9580 says: at least hash with 256 bits
      {
        if (!be_quiet)
          fprintf(stderr,"ERROR: ED25519 can only work with either SHA2-256, SHA2-384 or SHA2-512 message digests.\n");
        GPGBIN_gpg_evp_key_free(p_gekp);
        return GPGBIN_ERROR_PARAMETERS;
      }
      lib_sig_type = SIG_TYPE_EDDSA_25519;
      break;

    case PUBKEY_ALGO_EDDSA_448:
      if (DIGEST_ALGO_SHA512 != digest_algo) // only 512bit hashes allowed (RFC 9580), which is currently SHA-512 only
      {
        if (!be_quiet)
          fprintf(stderr,"ERROR: ED448 can only work with SHA2-512 message digest.\n");
        GPGBIN_gpg_evp_key_free(p_gekp);
        return GPGBIN_ERROR_PARAMETERS;
      }
      lib_sig_type = SIG_TYPE_EDDSA_448;
      break;

    default:
      GPGBIN_gpg_evp_key_free(p_gekp);
      return GPGBIN_ERROR_INTERNAL;
  }

  // if no To-Be-Signed specified, then assume that a key packet and a user ID are 'there'

  if (NULL == p_tbs || 0 == l_tbs)
  {
    if (0 == p_gpg->pack_user_id_len || 0 == p_gpg->pack_key_len || 0 == p_gpg->pack_user_id_data_len)
    {
      GPGBIN_gpg_evp_key_free(p_gekp);
      return GPGBIN_ERROR_PARAMETERS;
    }

    l_tbs = p_gekp->l_md_buffer + 1/*0xB4*/ + 4/*four length octets*/ + p_gpg->pack_user_id_data_len;

    tbs_allocated = true;

    p_tbs = (uint8_t*)malloc(l_tbs);
    if (unlikely(NULL == p_tbs))
    {
      GPGBIN_gpg_evp_key_free(p_gekp);
      return GPGBIN_ERROR_INSUFFICIENT_MEMORY;
    }

    idx = 0;
    memcpy(p_tbs, p_gekp->p_md_buffer, p_gekp->l_md_buffer);
    idx += p_gekp->l_md_buffer;

    // add the byte 0xB4

    p_tbs[idx++] = 0xB4;

    // add the length

    p_tbs[idx++] = (uint8_t)(p_gpg->pack_user_id_data_len >> 24);
    p_tbs[idx++] = (uint8_t)(p_gpg->pack_user_id_data_len >> 16);
    p_tbs[idx++] = (uint8_t)(p_gpg->pack_user_id_data_len >> 8);
    p_tbs[idx++] = (uint8_t)p_gpg->pack_user_id_data_len;

    memcpy(p_tbs + idx, p_gpg->p_workarea + p_gpg->pack_user_id_data_idx, p_gpg->pack_user_id_data_len);
    idx += p_gpg->pack_user_id_data_len;

    if (unlikely(idx != l_tbs)) // sanity check
    {
      err = GPGBIN_ERROR_INTERNAL;
CommonExit:
      if (tbs_allocated)
        free(p_tbs);
      GPGBIN_gpg_evp_key_free(p_gekp);
      return err;
    }

    // end of new p_tbs for positive auth.

    sig_type = 0x13;

    // check expiration time

    if (0 != p_gpg->key_expiration_ts)
      expiration_time = p_gpg->key_expiration_ts;

    if (0 != expiration_time)
    {
      if (((uint64_t)expiration_time) > 0xFFFFFFFF)
      {
        err = GPGBIN_ERROR_TIME_OUTOFBOUNDS;
        goto CommonExit;
      }
    }
  }

  // check E-mail if signature packet type 0x00

  if (0x00 == sig_type)
  {
    if ((NULL == p_email || 0 == l_email) && (0 == p_gpg->l_email))
    {
      err = GPGBIN_ERROR_SIGN_USER_ID_MISS;
      goto CommonExit;
    }

    if (NULL != p_email && 0 != l_email)
    {
      if (NULL != p_gpg->p_email)
        free(p_gpg->p_email), p_gpg->p_email = NULL, p_gpg->l_email = 0;

      p_gpg->p_email = (uint8_t*)malloc(l_email + 1);
      if (unlikely(NULL == p_gpg->p_email))
      {
        err = GPGBIN_ERROR_INSUFFICIENT_MEMORY;
        goto CommonExit;
      }

      memcpy(p_gpg->p_email, p_email, l_email);
      p_gpg->p_email[l_email] = 0x00;

      p_gpg->l_email = l_email;
    }
  }

  // check/compute fingerprint

  if (NULL == p_fingerprint || 0 == l_fingerprint)
  {
    if ((0 == sig_type) || (0 == p_gpg->l_subkid))
    {
      p_gpg->l_subkid = p_gekp->use_v5 ? SHA256_DIGEST_LENGTH : SHA_DIGEST_LENGTH;
      memcpy(p_gpg->subkid, p_gekp->fipr, p_gpg->l_subkid);
    }
  }
  else
  {
    if (l_fingerprint < SHA_DIGEST_LENGTH || l_fingerprint > SHA512_DIGEST_LENGTH)
    {
      err = GPGBIN_ERROR_FP_SIZE;
      goto CommonExit;
    }
    p_gpg->l_subkid = l_fingerprint;
    memcpy(p_gpg->subkid, p_fingerprint, l_fingerprint);
  }

  // We have to create a new To-Be-Signed or To-Be-Hashed memory region, respectively because we cannot perform
  // hashing in the begin, next, next, ..., final way because especially PKCS#11 performs the hashing itself and
  // requires us to present the entire To-Be-Signed as a single piece of memory.
  // In fact, which is a nightmare for any computer scientist, we need twice the memory of the TBS size, which could
  // become a problem if very large payloads have to be hashed = signed... keep it in mind, folks!

  // this becomes TBH = To-Be-Hashed beside TBS = To-Be-Signed

  p_tbh = (uint8_t*)malloc(l_tbs + 65536); // we just use 64KB here, we do not know how big the hashed/unhashed subpackets become (but this is more than enough)

  if (unlikely(NULL == p_tbh))
  {
    err = GPGBIN_ERROR_INSUFFICIENT_MEMORY;
    goto CommonExit;
  }

  // 1.) Copy the original To-Be-Signed

  memcpy(p_tbh, p_tbs, l_tbs);
  idx = sig_pack_idx = l_tbs;

  // the tag and possibly two length bytes follow here (NOT hashed!!!)
  // {...}

  p_tbh[idx++] = p_gekp->use_v5 ? 0x05: 0x04; // version 4/5
  p_tbh[idx++] = sig_type; // either 0x00 or 0x13
  p_tbh[idx++] = p_gekp->pubkey_algo;
  p_tbh[idx++] = (uint8_t)digest_algo;

  hashed_sp_idx = idx;
  p_tbh[idx++] = 0x00; // two-octet size of hashed subpackets
  p_tbh[idx++] = 0x00;

  // hashed subpacket(s) follow:

  // Issuer Fingerprint is always 'there'

  if (!p_gekp->use_v5)
  {
    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_ISSUER_FPR, false/*not critical*/, SHA_DIGEST_LENGTH+1);
    p_tbh[idx++] = 0x04; // v4
    memcpy(p_tbh + idx, &p_gpg->subkid[p_gpg->l_subkid - SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH);
    l_fpr = SHA_DIGEST_LENGTH;
  }
  else
  {
    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_ISSUER_FPR, false/*not critical*/, SHA256_DIGEST_LENGTH+1);
    p_tbh[idx++] = 0x05; // v5
    memcpy(p_tbh + idx, &p_gpg->subkid[p_gpg->l_subkid - SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH);
    l_fpr = SHA256_DIGEST_LENGTH;
  }
  idx += l_fpr;

  if (!be_quiet)
  {
    fprintf(stdout,"  Key fingerprint ......: ");
    for (i=0;i<l_fpr;i++)
      fprintf(stdout,(0 == i) ? "%02x" : ":%02x", p_tbh[idx - l_fpr + i]);
    fprintf(stdout,"\n");
    fprintf(stdout,"  Key ID ...............: ");
    if (!p_gekp->use_v5)
    {
      for (i=0;i<8;i++)
        fprintf(stdout,(0 == i) ? "%02x" : ":%02x", p_tbh[idx - 8 + i]);
    }
    else
    {
      for (i=0;i<8;i++)
        fprintf(stdout,(0 == i) ? "%02x" : ":%02x", p_tbh[idx - l_fpr + i]);
    }
    fprintf(stdout,"\n");
  }

  // Signature Creation Time is always 'there'

  idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_SIG_CREATED, false/*not critical*/, 4);
  p_tbh[idx++] = (uint8_t)(t >> 24);
  p_tbh[idx++] = (uint8_t)(t >> 16);
  p_tbh[idx++] = (uint8_t)(t >> 8);
  p_tbh[idx++] = (uint8_t)t;

  if (0x13 == sig_type)
  {
    // sig-type 0x13: Key Flags

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_KEY_FLAGS, false/*not critical*/, 1);
    //p_tbh[idx++] = 0x03; // 0x01 = can make user ID certifications, 0x02 = can sign
    p_tbh[idx++] = p_gpg->key_usage;

    // sig-type 0x13: Key Expiration Time (if desired)

    if (0 != expiration_time)
    {
      idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_KEY_EXPIRE, false/*not critical*/, 4);
      p_tbh[idx++] = (uint8_t)(expiration_time >> 24);
      p_tbh[idx++] = (uint8_t)(expiration_time >> 16);
      p_tbh[idx++] = (uint8_t)(expiration_time >> 8);
      p_tbh[idx++] = (uint8_t)expiration_time;
    }

    // sig-type 0x13: Preferred Symmetric Ciphers

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_PREF_SYM, false/*not critical*/, 3);
    p_tbh[idx++] = (uint8_t)CIPHER_ALGO_AES256;
    p_tbh[idx++] = (uint8_t)CIPHER_ALGO_AES192;
    p_tbh[idx++] = (uint8_t)CIPHER_ALGO_AES; // 128bit

    // sig-type 0x13: Preferred AEAD Ciphers

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_PREF_AEAD, false/*not critical*/, 1);
    p_tbh[idx++] = (uint8_t)AEAD_ALGO_OCB;

    // sig-type 0x13: Preferred Hash Algorithms

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_PREF_HASH, false/*not critical*/, 4);
    p_tbh[idx++] = (uint8_t)DIGEST_ALGO_SHA512;
    p_tbh[idx++] = (uint8_t)DIGEST_ALGO_SHA384;
    p_tbh[idx++] = (uint8_t)DIGEST_ALGO_SHA256;
    p_tbh[idx++] = (uint8_t)DIGEST_ALGO_SHA224;

    // sig-type 0x13: Preferred Compression Algorithms

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_PREF_COMPR, false/*not critical*/, 3);
    p_tbh[idx++] = (uint8_t)COMPRESS_ALGO_ZLIB;
    p_tbh[idx++] = (uint8_t)COMPRESS_ALGO_BZIP2;
    p_tbh[idx++] = (uint8_t)COMPRESS_ALGO_ZIP;

    // sig-type 0x13: Features

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_FEATURES, false/*not critical*/, 1);
    p_tbh[idx++] = 0x07; // taken from current gpg 2.4.7, see RFC 9580, section 5.2.3.32

    // sig-type 0x13: Key Server Preferences

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_KS_FLAGS, false/*not critical*/, 1);
    p_tbh[idx++] = 0x80; // RFC 9580: No-modify: The keyholder requests that this key only be modified or updated
                         // --------- by the keyholder or an administrator of the key server.

#if 0
    // sig-type 0x13: Trust level

    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_TRUST, false/*not critical*/, 2);
    p_tbh[idx++] = 0; // level 0
    p_tbh[idx++] = 120; // trust amount
#endif
  } // of sig_type == 0x13
  else // sig_type == 0: Signer's User ID
  {
    idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_SIGNERS_UID, false/*not critical*/, p_gpg->l_email);

    memcpy(p_tbh + idx, p_gpg->p_email, p_gpg->l_email);
    idx += p_gpg->l_email;
  }

  len = idx - hashed_sp_idx - 2;
  p_tbh[hashed_sp_idx + 0] = (uint8_t)(len >> 8);
  p_tbh[hashed_sp_idx + 1] = (uint8_t)len;

  ////////////////////// UNHASHED:

  unhashed_sp_idx = idx; // Hint: unhashed_sp_idx is also the l_sig_packet_hash_size

  p_tbh[idx++] = 0x00; // two-octet size of unhashed subpackets
  p_tbh[idx++] = 0x00;

  // unhashed subpacket(s) follow: we only include one unhashed subpacket, which is 0x10 (Issuer Key ID)
  // trailing eight (8) bytes of SubjectKeyIdentifier, which is the key fingerprint here...

  idx = _GPGBIN_addsubpacket_tag_len_buffer(p_tbh, idx, (uint8_t)SIGSUBPKT_ISSUER, false/*not critical*/, 8);
  memcpy(p_tbh + idx, p_gekp->keyid, 8);
  idx += 8;

  len = idx - unhashed_sp_idx - 2;

  p_tbh[unhashed_sp_idx + 0] = (uint8_t)(len >> 8);
  p_tbh[unhashed_sp_idx + 1] = (uint8_t)len;

  // two bytes room for first 16 bits of hash

  digest_fp_idx = idx;
  p_tbh[idx++] = 0x00;
  p_tbh[idx++] = 0x00;

  // two bytes will receive the signature length in bits

  sig_mpi_idx = idx;  // this is the index where we will put the signature

  // signature follows here...

  // we have to hash also a six bytes footer:

  l_sig_packet_hash_size = unhashed_sp_idx - l_tbs;

  memcpy(saved_unhashed, p_tbh + unhashed_sp_idx, 16); // save sixteen bytes from the To-Be-Hashed buffer

  if (p_gekp->use_v5) // nobody (no RFCs, seen in the GnuPG source) told us that a 64bit counter is used here... ...anyway, the upper 32bit are always zero, though
  {
    // Another 'code obfuscation' from the GnuPG source: if this is v5 signature AND signature type 0x00 (raw binary), add
    // six stupid zero bytes here (who the hell specified this ugly stuff?):

    if (0x00 == sig_type)
    {
      p_tbh[unhashed_sp_idx + 0] = 0x00; // if you don't do this, none of your ED448 signatures (type 0x00) can be verified...
      p_tbh[unhashed_sp_idx + 1] = 0x00;
      p_tbh[unhashed_sp_idx + 2] = 0x00;
      p_tbh[unhashed_sp_idx + 3] = 0x00;
      p_tbh[unhashed_sp_idx + 4] = 0x00;
      p_tbh[unhashed_sp_idx + 5] = 0x00; // ... wtf???

      p_tbh[unhashed_sp_idx + 6] = 0x05; // V5
      p_tbh[unhashed_sp_idx + 7] = 0xFF; // just 0xFF (sentinel octet)
      p_tbh[unhashed_sp_idx + 8] = 0x00;
      p_tbh[unhashed_sp_idx + 9] = 0x00;
      p_tbh[unhashed_sp_idx +10] = 0x00;
      p_tbh[unhashed_sp_idx +11] = 0x00;
      p_tbh[unhashed_sp_idx +12] = (uint8_t)(l_sig_packet_hash_size >> 24);
      p_tbh[unhashed_sp_idx +13] = (uint8_t)(l_sig_packet_hash_size >> 16);
      p_tbh[unhashed_sp_idx +14] = (uint8_t)(l_sig_packet_hash_size >> 8);
      p_tbh[unhashed_sp_idx +15] = (uint8_t)l_sig_packet_hash_size;

      to_be_hashed_size = unhashed_sp_idx + 16;
    }
    else
    {
      p_tbh[unhashed_sp_idx + 0] = 0x05; // V5
      p_tbh[unhashed_sp_idx + 1] = 0xFF; // just 0xFF (sentinel octet)
      p_tbh[unhashed_sp_idx + 2] = 0x00;
      p_tbh[unhashed_sp_idx + 3] = 0x00;
      p_tbh[unhashed_sp_idx + 4] = 0x00;
      p_tbh[unhashed_sp_idx + 5] = 0x00;
      p_tbh[unhashed_sp_idx + 6] = (uint8_t)(l_sig_packet_hash_size >> 24);
      p_tbh[unhashed_sp_idx + 7] = (uint8_t)(l_sig_packet_hash_size >> 16);
      p_tbh[unhashed_sp_idx + 8] = (uint8_t)(l_sig_packet_hash_size >> 8);
      p_tbh[unhashed_sp_idx + 9] = (uint8_t)l_sig_packet_hash_size;

      to_be_hashed_size = unhashed_sp_idx + 10;
    }
  }
  else // v4
  {
    p_tbh[unhashed_sp_idx + 0] = 0x04; // V4
    p_tbh[unhashed_sp_idx + 1] = 0xFF; // just 0xFF (sentinel octet)

    p_tbh[unhashed_sp_idx + 2] = (uint8_t)(l_sig_packet_hash_size >> 24);
    p_tbh[unhashed_sp_idx + 3] = (uint8_t)(l_sig_packet_hash_size >> 16);
    p_tbh[unhashed_sp_idx + 4] = (uint8_t)(l_sig_packet_hash_size >> 8);
    p_tbh[unhashed_sp_idx + 5] = (uint8_t)l_sig_packet_hash_size;

    to_be_hashed_size = unhashed_sp_idx + 6;
  }

  // we are now ready to hash (recall: if PKCS#11 is being used for signing, we just do this here to
  // get the first 16 bits of the hash, which we have to add to the binary GPG structure

  switch(digest_algo)
  {
    case DIGEST_ALGO_SHA256:
      SHA256(p_tbh, to_be_hashed_size, md);
      md_size = SHA256_DIGEST_LENGTH;
      break;
    case DIGEST_ALGO_SHA384:
      SHA384(p_tbh, to_be_hashed_size, md);
      md_size = SHA384_DIGEST_LENGTH;
      break;
    case DIGEST_ALGO_SHA512:
      SHA512(p_tbh, to_be_hashed_size, md);
      md_size = SHA512_DIGEST_LENGTH;
      break;
    default: // case DIGEST_ALGO_SHA224:
      SHA224(p_tbh, to_be_hashed_size, md);
      md_size = SHA224_DIGEST_LENGTH;
      break;
  }

  // add the first 16 bits of the message digest to the PGP binary structure

  p_tbh[digest_fp_idx + 0] = md[0];
  p_tbh[digest_fp_idx + 1] = md[1];

  // create the digital signature

  // HACK for Edwards Curves and GnuPG: PGP uses pureEdDSA but still just uses the pre-hashed message digest... this is odd...

  if (PUBKEY_ALGO_EDDSA_LEGACY == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_25519 == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_448 == p_gekp->pubkey_algo)
  {
    if (0 == pkcs11_label[0]) // use OpenSSL
    {
      if (!ossl_create_digital_signature((EVP_PKEY*)p_evp_key, lib_sig_type, md_type,
          md, md_size,
          &p_sig, &l_sig, false/*raw ECDSA signature*/, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_CREATION_FAILED;
        goto CommonExit;
      }
    }
    else // use PKCS#11
    {
      if (!pkcs11_create_signature(p_pkcs11_label, lib_sig_type, md_type,
          md, md_size,
          &p_sig, &l_sig, false/*raw ECDSA signature*/, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_CREATION_FAILED;
        goto CommonExit;
      }
    }

    // if loop-back verification desired, do it

    if (do_verify)
    {
      if (!ossl_verify_digital_signature((EVP_PKEY*)p_evp_key, lib_sig_type, md_type,
          md, md_size,
          p_sig, l_sig, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_VERIFY_FAILED;
        goto CommonExit;
      }
    }
  }

  // END OF HACK FOR GNUPG

  else
  {
    if (0 == pkcs11_label[0]) // use OpenSSL
    {
      if (!ossl_create_digital_signature((EVP_PKEY*)p_evp_key, lib_sig_type, md_type, p_tbh, to_be_hashed_size, &p_sig, &l_sig, false/*raw ECDSA signature*/, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_CREATION_FAILED;
        goto CommonExit;
      }
    }
    else // use PKCS#11
    {
      if (!pkcs11_create_signature(p_pkcs11_label, lib_sig_type, md_type, p_tbh, to_be_hashed_size, &p_sig, &l_sig, false/*raw ECDSA signature*/, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_CREATION_FAILED;
        goto CommonExit;
      }
    }

    // if loop-back verification desired, do it

    if (do_verify)
    {
      if (!ossl_verify_digital_signature((EVP_PKEY*)p_evp_key, lib_sig_type, md_type, p_tbh, to_be_hashed_size, p_sig, l_sig, USE_ED_PH))
      {
        free(p_tbh);
        err = GPGBIN_ERROR_SIG_VERIFY_FAILED;
        goto CommonExit;
      }
    }
  }

  // restore the sixteen previously saved bytes from the To-Be-Hashed buffer

  memcpy(p_tbh + unhashed_sp_idx, saved_unhashed, 16);

  // store the digital signature: for RSA, this is just one MPI, for ECDSA/EdDSA, these are two MPIs (R,S)

  if (RSA_GPG_ALGO == p_gekp->pubkey_algo)
  {
    p_mpi = _GPGBIN_format_byte_number_as_mpi_no_edwards(p_sig, l_sig, &l_mpi, -1, NULL);
    if (unlikely(NULL == p_mpi))
    {
      free(p_sig);
      free(p_tbh);
      err = GPGBIN_ERROR_INSUFFICIENT_MEMORY;
      goto CommonExit;
    }

    memcpy(p_tbh + sig_mpi_idx, p_mpi, l_mpi);
    idx = sig_mpi_idx + l_mpi;

    free(p_mpi);
  }
  else
  {
    if (PUBKEY_ALGO_EDDSA_25519 == p_gekp->pubkey_algo || PUBKEY_ALGO_EDDSA_448 == p_gekp->pubkey_algo)
    {
      if (unlikely(l_sig != (p_gekp->comp_len << 1)))
      {
        free(p_sig);
        free(p_tbh);
        err = GPGBIN_ERROR_INTERNAL;
        goto CommonExit;
      }

      memcpy(p_tbh + sig_mpi_idx, p_sig, l_sig);
      idx = sig_mpi_idx + l_sig;
    }
    else
    {
      if (PUBKEY_ALGO_EDDSA_LEGACY != p_gekp->pubkey_algo)
        p_mpi = _GPGBIN_format_byte_number_as_mpi_no_edwards(p_sig, p_gekp->comp_len, &l_mpi, -1, NULL);
      else
        p_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(p_sig, p_gekp->comp_len, &l_mpi, -1, NULL);
      if (unlikely(NULL == p_mpi))
      {
        free(p_sig);
        free(p_tbh);
        err = GPGBIN_ERROR_INSUFFICIENT_MEMORY;
        goto CommonExit;
      }

      memcpy(p_tbh + sig_mpi_idx, p_mpi, l_mpi);
      free(p_mpi);
      idx = sig_mpi_idx + l_mpi;

      if (PUBKEY_ALGO_EDDSA_LEGACY != p_gekp->pubkey_algo)
        p_mpi = _GPGBIN_format_byte_number_as_mpi_no_edwards(p_sig + p_gekp->comp_len, p_gekp->comp_len, &l_mpi, -1, NULL);
      else
        p_mpi = _GPGBIN_format_byte_number_as_mpi_edwards(p_sig + p_gekp->comp_len, p_gekp->comp_len, &l_mpi, -1, NULL);
      if (unlikely(NULL == p_mpi))
      {
        free(p_sig);
        free(p_tbh);
        err = GPGBIN_ERROR_INSUFFICIENT_MEMORY;
        goto CommonExit;
      }

      memcpy(p_tbh + idx, p_mpi, l_mpi);
      free(p_mpi);
      idx += l_mpi;
    }
  }

  free(p_sig);

  // the full signature packet except for the initial tag and length is ready now (current length is 'idx')

  if (unlikely(!_GPGBIN_addpacket_tag_len(p_gpg, (uint8_t)PKT_SIGNATURE, idx - l_tbs)))
  {
    free(p_tbh);
    err = GPGBIN_ERROR_BUFFEROVERFLOW;
    goto CommonExit;
  }

  memcpy(p_gpg->p_workarea + p_gpg->workarea_idx, p_tbh + l_tbs, idx - l_tbs);
  p_gpg->workarea_idx += idx - l_tbs;

  free(p_tbh);

  err = GPGBIN_ERROR_OK;
  goto CommonExit;
}
