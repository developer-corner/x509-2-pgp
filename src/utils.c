/**
 * @file   utils.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implementation of utility functions
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

#include <utils.h>

const char digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

char ctrlReset[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlRed[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlGreen[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlYellow[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlBlue[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlMagenta[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
char ctrlCyan[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

const char g_szAsn1UniversalTagNames[NUM_UNIV_ASN1_TAG_NAMES][32] =
{
  "<END-MARKER>_00",          ///< 0x00
  "BOOLEAN",                  ///< 0x01
  "INTEGER",                  ///< 0x02
  "BIT STRING",               ///< 0x03
  "OCTET STRING",             ///< 0x04
  "NULL",                     ///< 0x05
  "OBJECT IDENTIFIER",        ///< 0x06
  "OBJECT DESCRIPTOR",        ///< 0x07
  "EXTERNAL",                 ///< 0x08
  "REAL",                     ///< 0x09
  "ENUMERATED",               ///< 0x0A
  "EMBEDDED",                 ///< 0x0B
  "UTF8String",               ///< 0x0C
  "RELATIVE-OID",             ///< 0x0D
  "TIME",                     ///< 0x0E
  "RFU_0F",                   ///< 0x0F
  "SEQUENCE",                 ///< 0x10
  "SET",                      ///< 0x11
  "NumericString",            ///< 0x12
  "PrintableString",          ///< 0x13
  "TeletexString",            ///< 0x14 (also T61String)
  "VideotexString",           ///< 0x15
  "IA5String",                ///< 0x16
  "UTCTime",                  ///< 0x17
  "GeneralizedTime",          ///< 0x18
  "GraphicString",            ///< 0x19
  "VisibleString",            ///< 0x1A (also ISO646String)
  "GeneralString",            ///< 0x1B
  "UniversalString",          ///< 0x1C
  "CHARACTER STRING",         ///< 0x1D
  "BMPString",                ///< 0x1E
  "DATE",                     ///< 0x1F
  "TIME-OF-DAY",              ///< 0x20
  "DATE-TIME",                ///< 0x21
  "DURATION",                 ///< 0x22
  "OID-IRI",                  ///< 0x23
  "RELATIVE-OID-IRI"          ///< 0x24
};

#ifdef _WINDOWS

static const unsigned __int64 epoch = ((unsigned __int64)116444736000000000ULL);

int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
  (void)tzp;
  FILETIME    file_time;
  SYSTEMTIME  system_time;
  ULARGE_INTEGER ularge;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);
  ularge.LowPart = file_time.dwLowDateTime;
  ularge.HighPart = file_time.dwHighDateTime;

  tp->tv_sec = (long)((ularge.QuadPart - epoch) / 10000000L);
  tp->tv_usec = (long)(system_time.wMilliseconds * 1000);

  return 0;
}

#endif // of _WINDOWS (does not have a gettimeofday)

uint32_t sigtype2keybits ( uint32_t sig_type, uint32_t rsa_key_bits )
{
  switch(sig_type)
  {
    case SIG_TYPE_RSA_PKCS1_V15:
    case SIG_TYPE_RSA_PSS_SHA256:
    case SIG_TYPE_RSA_PSS_SHA384:
    case SIG_TYPE_RSA_PSS_SHA512:
      return rsa_key_bits;
    case SIG_TYPE_ECDSA_SECP256R1:
      return 256;
    case SIG_TYPE_ECDSA_SECP384R1:
      return 384;
    case SIG_TYPE_ECDSA_SECP521R1:
      return 521;
    case SIG_TYPE_ECDSA_SECT571R1:
      return 571;
    case SIG_TYPE_ECDSA_BRAINPOOLP256R1:
      return 256;
    case SIG_TYPE_ECDSA_BRAINPOOLP384R1:
      return 384;
    case SIG_TYPE_ECDSA_BRAINPOOLP512R1:
      return 512;
    case SIG_TYPE_EDDSA_25519:
      return 255;
    case SIG_TYPE_EDDSA_448:
      return 448;
    default:
      return 0;
  }
}

bool asn1_encodelen(uint8_t* der, uint64_t derlen, uint64_t len, uint64_t* idx)
{
  if (unlikely(NULL == der || NULL == idx))
    return false;

  if (ASN1_INDEFINITE_LENGTH == derlen)
  {
    if (unlikely(*idx >= len))
      return false;
    der[*idx] = (uint8_t)0x80;
    (*idx)++;
  }
  else
  {
    if (derlen <= 127)
    {
      if (unlikely( (*idx + 1 + derlen) > len))
        return false;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x00000000000000FFL)
    {
      if (unlikely((*idx + 2 + derlen) > len))
        return false;
      der[*idx] = 0x81;
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x000000000000FFFFL)
    {
      if (unlikely((*idx + 3 + derlen) > len))
        return false;
      der[*idx] = 0x82;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x0000000000FFFFFFL)
    {
      if (unlikely((*idx + 4 + derlen) > len))
        return false;
      der[*idx] = 0x83;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x00000000FFFFFFFFL)
    {
      if (unlikely((*idx + 5 + derlen) > len))
        return false;
      der[*idx] = 0x84;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 24);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x000000FFFFFFFFFFL)
    {
      if (unlikely((*idx + 6 + derlen) > len))
        return false;
      der[*idx] = 0x85;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 32);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 24);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x0000FFFFFFFFFFFFL)
    {
      if (unlikely((*idx + 7 + derlen) > len))
        return false;
      der[*idx] = 0x86;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 40);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 32);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 24);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    if (derlen <= 0x00FFFFFFFFFFFFFFL)
    {
      if (unlikely((*idx + 8 + derlen) > len))
        return false;
      der[*idx] = 0x87;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 48);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 40);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 32);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 24);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
    else
    {
      if (unlikely((*idx + 9 + derlen) > len))
        return false;
      der[*idx] = 0x88;
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 56);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 48);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 40);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 32);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 24);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 16);
      (*idx)++;
      der[*idx] = (uint8_t)(derlen >> 8);
      (*idx)++;
      der[*idx] = (uint8_t)derlen;
      (*idx)++;
    }
  }
  return true;
}

uint32_t asn1_getlengthencodinglength(uint64_t derlen)
{
  if (ASN1_INDEFINITE_LENGTH == derlen)
    return 1;
  if (derlen <= 127)
    return 1;
  if (derlen <= 0x00000000000000FFL)
    return 2;
  if (derlen <= 0x000000000000FFFFL)
    return 3;
  if (derlen <= 0x0000000000FFFFFFL)
    return 4;
  if (derlen <= 0x00000000FFFFFFFFL)
    return 5;
  if (derlen <= 0x000000FFFFFFFFFFL)
    return 6;
  if (derlen <= 0x0000FFFFFFFFFFFFL)
    return 7;
  if (derlen <= 0x00FFFFFFFFFFFFFFL)
    return 8;
  return 9; // assuming that nothing exceeds 64bit...
}

bool asn1_decodelen(const uint8_t* der, uint64_t len, uint64_t* derlen, uint64_t* idx)
{
  uint64_t          maxidx;
  uint32_t          i;
  uint8_t           value;

  if (unlikely(*idx >= len))
    return false;//PrintMessage(ASN1_ERROR_INSUFFICIENT_INPUT_DATA); // not enough data available

  value = (uint8_t)der[*idx];
  (*idx)++;
  if (value < 128)
    *derlen = (uint64_t)value;
  else
  if (128 == value) // 128 = 0x80 = infinite length (BER)
  {
    *derlen = ASN1_INDEFINITE_LENGTH;
    return true;
  }
  else
  {
    *derlen = 0;
    value -= 128;
    if (value > 8)
      return false;//PrintMessage(ASN1_ERROR_LENGTH_EXCEEDS_64BIT); // too big

    if (unlikely((*idx + value) > len))
      return false;//PrintMessage(ASN1_ERROR_INSUFFICIENT_INPUT_DATA); // not enough data available

    for (i = 0; i < value; i++)
    {
      *derlen <<= 8;
      *derlen |= der[*idx];
      (*idx)++;
    }

    if (unlikely(8==value && ASN1_INDEFINITE_LENGTH == *derlen)) // (uint64_t)-1 is reserved for infinite length, sorry...
      return false;//PrintMessage(ASN1_ERROR_LENGTH_EXCEEDS_64BIT); // too big
  }

  maxidx = (*idx) + (*derlen);

  return (maxidx > len || maxidx < *idx) ? false : true;
}

#if !defined(_WINDOWS) && !defined(O_BINARY)
#define O_BINARY 0
#endif

uint8_t *read_file ( const char *filename, uint32_t *size )
{
  int           fd = open(filename,O_RDONLY | O_BINARY); // never forget O_BINARY on Windows or it ends up with a mess...
  uint8_t      *buffer;
  struct stat   st;

  *size = 0;

  if (-1 == fd)
    return NULL;

  if (-1 == fstat(fd,&st))
  {
    close(fd);
    return NULL;
  }

  if (0 == st.st_size)
  {
    close(fd);
    return NULL;
  }

  *size = (uint32_t)st.st_size;

  buffer = (uint8_t*)malloc(*size + 1);
  if (unlikely(NULL == buffer))
  {
    *size = 0;
    close(fd);
    return NULL;
  }

  if ( (*size) != read(fd, buffer, *size) )
  {
    free(buffer);
    *size = 0;
    close(fd);
    return NULL;
  }

  close(fd);

  buffer[*size] = 0x00; // if this is a text file, perform zero-termination

  return buffer;
}

bool write_file ( const char *filename, const uint8_t *data, uint32_t size )
{
  int fd = open(filename, O_BINARY | O_WRONLY | O_CREAT | O_TRUNC, 0664); // never forget O_BINARY on Windows or it ends up with a mess...

  if (fd < 0)
    return false;

  if (size != ((uint32_t)write(fd, data, size)))
  {
    close(fd);
    unlink(filename);
    return false;
  }

  close(fd);

  return true;
}

static const uint32_t dayspermonth[12] =
{
  31,28,31,30,31,30,31,31,30,31,30,31
};

bool is_leap_year ( uint32_t year )
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

int32_t time_date2day(int32_t year, int32_t month, int32_t mday)
{
  int32_t  y, m;

  m = (month + 9) % 12;                /* mar=0, feb=11 */
  y = year - m / 10;                     /* if Jan/Feb, year-- */

  return y * 365 + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + (mday - 1);
}

#define GREGORIAN_DAY_1582_10_01          578027
#define GREGORIAN_DAY_1970_01_01          719468

bool time_date2systime(uint64_t* systime,
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
    if (is_leap_year(year))
      daypermonth++;
  }

  if (mday<1 || mday>daypermonth)
    return false;

  gday = (int64_t)time_date2day(year, month, mday);

  //gday -= GREGORIAN_DAY_1582_10_01;
  gday -= GREGORIAN_DAY_1970_01_01;

  gday *= 86400;

  *systime = gday + hour * 3600 + minute * 60 + second;

  return true;
}

void hexdump ( FILE *f, const uint8_t *data, uint32_t size, bool hex_upper, uint32_t indent )
{
  char                szHexLine[88], szIndent[64];
  uint8_t             x;
  int                 i,j;
  static const char   hexupper_table[16] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46 };
  static const char   hexlower_table[16] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66 };
  const char         *hex_table = hex_upper ? hexupper_table : hexlower_table;
  uint32_t            ofs = 0;

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

bool asn1ECDSAASN1RSSequence2RawSignature(const uint8_t* sig, uint32_t sig_size, uint8_t *raw, uint32_t raw_size)
{
  uint32_t              comp_len;
  uint64_t              idx = 0, derlen, tmplen;
  uint32_t              i, tag;

  if (unlikely(NULL == sig || 0 == sig_size || NULL == raw || 0 == raw_size))
    return false;

  if (unlikely(0 != (raw_size & 1)))
    return false;

  comp_len = raw_size >> 1;

  memset(raw, 0, raw_size);

  derlen = (uint64_t)sig_size;
  if (idx == derlen)
    return false;
  tag = sig[idx++];
  if (unlikely(0x30 != tag)) // must begin with ASN.1 SEQUENCE
    return false;
  if (unlikely(!asn1_decodelen(sig, derlen, &tmplen, &idx)))
    return false;
  if (unlikely((idx + tmplen) != derlen))
    return false;

  if (idx == derlen)
    return false;
  tag = sig[idx++];
  if (unlikely(0x02 != tag)) // INTEGER r
    return false;
  if (unlikely(!asn1_decodelen(sig, derlen, &tmplen, &idx)))
    return false;

  // r can be > comp_len if leading zeros are part of r OR r can be < comp_len if component was trimmed and is shorted OR r may equal comp_len

  if (((uint32_t)tmplen) > comp_len) // leading zeros (cut!)
  {
    for (i = 0; i < ((uint32_t)tmplen) - comp_len; i++) // ensure that there are indeed leading zeros (sanity check)
      if (unlikely(0x00 != sig[idx + i]))
        return false;

    memcpy(raw, sig + idx + (((uint32_t)tmplen) - comp_len), comp_len);
  }
  else
  if (((uint32_t)tmplen) < comp_len) // trimmed r, i.e. we have to zero-fill on the 'left' side of the big integer (this is implicitly done because raw was zero-initialized above)
  {
    memcpy(raw + comp_len - ((uint32_t)tmplen), sig + idx, tmplen);
  }
  else // equal
  {
    memcpy(raw, sig + idx, tmplen);
  }
  idx += tmplen;

  if (idx == derlen)
    return false;
  tag = sig[idx++];
  if (unlikely(0x02 != tag)) // INTEGER s
    return false;
  if (unlikely(!asn1_decodelen(sig, derlen, &tmplen, &idx)))
    return false;

  if (((uint32_t)tmplen) > comp_len) // leading zeros (cut!)
  {
    for (i = 0; i < ((uint32_t)tmplen) - comp_len; i++) // ensure that there are indeed leading zeros (sanity check)
      if (unlikely(0x00 != sig[idx + i]))
        return false;

    memcpy(raw + comp_len, sig + idx + (((uint32_t)tmplen) - comp_len), comp_len);
  }
  else
  if (((uint32_t)tmplen) < comp_len) // trimmed s, i.e. we have to zero-fill on the 'left' side of the big integer (this is implicitly done because raw was zero-initialized above)
  {
    memcpy(raw + (comp_len << 1) - ((uint32_t)tmplen), sig + idx, tmplen);
  }
  else // equal
  {
    memcpy(raw + comp_len, sig + idx, tmplen);
  }

  return true;
}

uint8_t* asn1ECDSARawSignature2ASN1RSSequence(const uint8_t* raw, uint32_t raw_size, uint32_t* sig_size)
{
  uint32_t                r_size, s_size, r_size_enc_size, s_size_enc_size, r_and_s_size, seq_size_enc_size, len, comp_len;
  uint64_t                idx;
  int32_t                 r_index, s_index;
  uint8_t* sig = NULL;

  if (unlikely(NULL == raw || 0 == raw_size || NULL == sig_size))
    return NULL;

  *sig_size = 0;

  // raw_size must be divisible by two (two components r and s)

  if (unlikely(0 != (raw_size & 1)))
    return NULL;

  comp_len = raw_size >> 1;

  r_index = s_index = 0;
  r_size = s_size = comp_len;

  if (0 != (raw[r_index] & 0x80)) // r seems to be negative, which means we have to add another zero in front of r
  {
    r_size++;
    r_index--; // is -1 now
  }
  else
  {
    while (r_index < (((int32_t)comp_len) - 1))
    {
      if (0 == raw[r_index] && (0 == (0x80 & raw[r_index + 1])))
      {
        r_index++;
        r_size--;
      }
      else
        break;
    }
  }

  if (0 != (raw[s_index + ((int32_t)comp_len)] & 0x80)) // s seems to be negative, which means we have to add another zero in front of s
  {
    s_size++;
    s_index--; // is -1 now
  }
  else
  {
    while (s_index < (((int32_t)comp_len) - 1))
    {
      if (0 == raw[s_index + ((int32_t)comp_len)] && (0 == (0x80 & raw[s_index + ((int32_t)comp_len) + 1])))
      {
        s_index++;
        s_size--;
      }
      else
        break;
    }
  }

  // 0x30,<len>,{0x02,<len>,<data>,0x02,<len>,<data>}

  r_size_enc_size = asn1_getlengthencodinglength(r_size);
  s_size_enc_size = asn1_getlengthencodinglength(s_size);

  r_and_s_size = 1 + r_size_enc_size + r_size + 1 + s_size_enc_size + s_size;

  seq_size_enc_size = asn1_getlengthencodinglength(r_and_s_size);

  len = 1 + seq_size_enc_size + r_and_s_size;

  sig = (uint8_t*)malloc(len);
  if (unlikely(NULL == sig))
    return NULL;

  idx = 0;

  sig[idx++] = 0x30;

  if (unlikely(!asn1_encodelen(sig, r_and_s_size, len, &idx)))
  {
out:
    if (NULL != sig)
      free(sig);
    return NULL;
  }

  sig[idx++] = 0x02;
  if (unlikely(!asn1_encodelen(sig, r_size, len, &idx)))
    goto out;
  if (r_index < 0)
  {
    sig[idx++] = 0x00;
    r_index = 0;
    r_size--;
  }
  memcpy(sig + idx, raw + r_index, r_size);
  idx += r_size;

  sig[idx++] = 0x02;
  if (unlikely(!asn1_encodelen(sig, s_size, len, &idx)))
    goto out;
  if (s_index < 0)
  {
    sig[idx++] = 0x00;
    s_index = 0;
    s_size--;
  }
  memcpy(sig + idx, raw + s_index + ((uint32_t)comp_len), s_size);

  *sig_size = len;

  return sig;
}

/////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                         //
//                                      A1T - ASN.1 TREE                                   //
//                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////

bool a1t_decodetag(const uint8_t* der, uint32_t len, uint32_t* tag, uint32_t* idx)
{
  uint8_t         _tag;
  uint32_t        maxlen = 3; // only up to three tag bytes supported because most significant byte is used to store metadata of ASN.1 tag
  uint32_t        flags, taglen = 0;

  if (unlikely(NULL == der || NULL == tag || NULL == idx))
    return false;

  if (unlikely(*idx >= len))
    return false;

  _tag = der[*idx];
  (*idx)++;

  flags = (((uint32_t)_tag) & (TAG_CLASS_PRIVATE | TAG_CONSTRUCTED)) << 24;

  if (!(TAG_MASK == (_tag & TAG_MASK)))
  {
    *tag = ((uint32_t)_tag) | 0x01000000 | flags; // store the one and only byte (together with the tag length 1)
    return true;
  }
  else // if all five LSBs are set 11111, then compose tag from multiple bytes
  {
    (*tag) = (uint32_t)_tag; // store first (header byte)
    taglen++;
    maxlen--;

    if (unlikely(*idx >= len))
      return false;

    // second byte = first tag requires special processing

    _tag = der[*idx];
    (*idx)++;

    if (0 == (_tag & 0x7F))
      return false; // according to ITU-T X.690, first seven bits MUST NOT be zero

    (*tag) <<= 8;
    (*tag) |= (uint32_t)_tag; // store second byte
    taglen++;
    maxlen--;

    while (0x80 == (_tag & 0x80)) // more to come...
    {
      if (unlikely(*idx >= len))
        return false;
      if (0 == maxlen)
        return false;

      _tag = der[*idx];
      (*idx)++;

      (*tag) <<= 8;
      (*tag) |= (uint32_t)_tag; // store subsequent byte
      taglen++;
      maxlen--;
    }
  }

  (*tag) = (*tag) | flags | (taglen << 24);

  return true;
}

uint32_t a1t_decodetag_value(uint32_t tag)
{
  uint32_t      retval = 0;
  uint8_t       taglen = (uint8_t)TAG_GET_LENGTH(tag);

  if (1 == taglen && (TAG_MASK != (TAG_MASK & tag)))
    return tag & TAG_MASK;

  switch (taglen)
  {
    case 3:
      retval |= (tag & 0x7F00) >> 1;
      // fall through
    case 2:
      retval |= tag & 0x7F;
      break;
    default:
      return (uint32_t)-1; // error
  }
  return retval;
}

bool a1t_printtag(uint32_t tag, char* tagstr, uint32_t tagstr_size)
{
  uint32_t        raw = a1t_decodetag_value(tag);

  if (unlikely(NULL == tagstr || 0 == tagstr_size))
    return false;

  switch (TAG_GET_CLASS(tag))
  {
    case 0x00: // UNIVERSAL
      if (raw < NUMBER_OF_TAGS)
        snprintf(tagstr, tagstr_size, "%s", g_szAsn1UniversalTagNames[raw]);
      else
        snprintf(tagstr, tagstr_size, "[UNIVERSAL %u]", raw);
      break;

    case 0x40: // APPLICATION
      snprintf(tagstr, tagstr_size, "[APPLICATION %u]", raw);
      break;

    case 0x80: // CONTEXT-SPECIFIC
      snprintf(tagstr, tagstr_size, "[%u]", raw);
      break;

    default:   // 0xC0 = PRIVATE
      snprintf(tagstr, tagstr_size, "[PRIVATE %u]", raw);
      break;
  }

  return true;
}

uint32_t a1t_gettagencodinglength(const uint8_t* der, uint32_t len, uint32_t idx)
{
  uint32_t          taglen = 1;
  uint8_t           tag, value;

  if (unlikely(NULL == der || idx >= len))
    return 0;

  tag = der[idx++];

  if (TAG_MASK == (tag & TAG_MASK))
  {
    do
    {
      if (unlikely(idx >= len))
        return 0;
      taglen++;
      value = der[idx++];
    } while (0x80 == (value & 0x80));
  }

  return taglen;
}

bool a1t_encodetag(uint8_t* der, uint32_t tag, uint32_t len, uint32_t* idx)
{
  uint32_t taglen = TAG_GET_LENGTH(tag);
  uint8_t  cons_mask;

  if (unlikely(0 == taglen || NULL == der || NULL == idx))
    return false;

  if (((*idx) + taglen) > len)
    return false;

  // if a1t_encodetag has to encode IMPLICIT or EXPLICIT tags, then it might happen that the CONSTRUCTED global bit is set
  // but the CONSTRUCTED bit in the first tag byte is still not set (because it is overridden). In this case, we
  // get the CONSTRUCTED bit (global bit) and conditionally add it to the first tag byte being encoded

  cons_mask = TAG_IS_CONSTRUCTED(tag) ? TAG_CONSTRUCTED : 0;

  switch (taglen)
  {
    case 1:
      der[(*idx)++] = ((uint8_t)tag) | cons_mask;
      break;
    case 2:
      der[(*idx)++] = ((uint8_t)(tag >> 8)) | cons_mask;
      der[(*idx)++] = (uint8_t)tag;
      break;
    case 3:
      der[(*idx)++] = ((uint8_t)(tag >> 16)) | cons_mask;
      der[(*idx)++] = (uint8_t)(tag >> 8);
      der[(*idx)++] = (uint8_t)tag;
      break;
    default:
      return false;
  }

  return true;
}

bool a1t_decodelen(const uint8_t* der, uint32_t len, uint32_t* derlen, uint32_t* idx)
{
  uint32_t          maxidx;
  uint32_t          i;
  uint8_t           value;

  if (unlikely(*idx >= len))
    return false;

  value = (uint8_t)der[*idx];
  (*idx)++;
  if (value < 128)
    *derlen = (uint64_t)value;
  else
  if (128 == value) // 128 = 0x80 = infinite length (BER)
  {
    //*derlen = 0xFFFFFFFF; // infinite length
    //return true;
    return false; // only DER not BER allowed!
  }
  else
  {
    *derlen = 0;
    value -= 128;
    if (value > 4)
      return false; // too big

    if (unlikely((*idx + value) > len))
      return false; // not enough data available

    for (i = 0; i < value; i++)
    {
      *derlen <<= 8;
      *derlen |= der[*idx];
      (*idx)++;
    }

    if (unlikely(4 == value && 0xFFFFFFFF == *derlen)) // (uint32_t)-1 is reserved for infinite length, sorry...
      return false; // too big
  }

  maxidx = (*idx) + (*derlen);

  return (maxidx > len || maxidx < *idx) ? false : true;
}

bool a1t_encodelen(uint8_t* der, uint32_t derlen, uint32_t len, uint32_t* idx)
{
  if (unlikely(NULL == der || NULL == idx))
    return false;

  if (0xFFFFFFFF == derlen)
  {
    if (unlikely(*idx >= len))
      return false;
    der[*idx] = (uint8_t)0x80;
    (*idx)++;
  }
  else
  if (derlen <= 127)
  {
    if (unlikely(*idx >= len))
      return false;
    der[*idx] = (uint8_t)derlen;
    (*idx)++;
  }
  else
  if (derlen <= 0x000000FFL)
  {
    if (unlikely((*idx + 2) > len))
      return false;
    der[*idx] = 0x81;
    (*idx)++;
    der[*idx] = (uint8_t)derlen;
    (*idx)++;
  }
  else
  if (derlen <= 0x0000FFFFL)
  {
    if (unlikely((*idx + 3) > len))
      return false;
    der[*idx] = 0x82;
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 8);
    (*idx)++;
    der[*idx] = (uint8_t)derlen;
    (*idx)++;
  }
  else
  if (derlen <= 0x00FFFFFFL)
  {
    if (unlikely((*idx + 4) > len))
      return false;
    der[*idx] = 0x83;
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 16);
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 8);
    (*idx)++;
    der[*idx] = (uint8_t)derlen;
    (*idx)++;
  }
  else
  {
    if (unlikely((*idx + 5) > len))
      return false;
    der[*idx] = 0x84;
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 24);
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 16);
    (*idx)++;
    der[*idx] = (uint8_t)(derlen >> 8);
    (*idx)++;
    der[*idx] = (uint8_t)derlen;
    (*idx)++;
  }

  return true;
}

uint32_t a1t_getlengthencodinglength(uint32_t derlen)
{
  if (0xFFFFFFFF == derlen)
    return 1;
  if (derlen <= 127)
    return 1;
  if (derlen <= 0x000000FFL)
    return 2;
  if (derlen <= 0x0000FFFFL)
    return 3;
  if (derlen <= 0x00FFFFFFL)
    return 4;
  return 5; // assuming that nothing exceeds 32bit...
}

// CAUTION: If one arc overflows 32bit, then this is not recognized, i.e. a wrong string OID
// -------- is returned in this case.
uint32_t a1t_decode_object_identifier(const uint8_t* oid, uint32_t oidlen, char* oidstr, uint32_t oidstr_size, bool is_roid)
{
  uint32_t      res_size = 0;
  uint32_t      lval = 0;
  uint8_t       by;
  int           len;

  if (unlikely(NULL == oid || 0 == oidlen || NULL == oidstr || 0 == oidstr_size))
    return res_size;

  memset(oidstr, 0, oidstr_size * sizeof(char));

  oidstr_size--; // subtract the space for the trailing zero

  while (0 != oidlen)
  {
    by = *(oid++);
    oidlen--;
    lval <<= 7;
    lval += by & 0x7F;

    if (0 == (by & 0x80)) // first or final octet
    {
      if ((0 != res_size) || (is_roid)) // we have already something
      {
        if (!is_roid) // OID
        {
          if (0 == oidstr_size)
            goto errexit;
          *(oidstr++) = '.'; // append a dot
          oidstr_size--;
          res_size++;
        }
        else // relative OID
        {
          if (0 != oidstr_size)
          {
            *(oidstr++) = '.'; // append a dot if there was already an arc in the output buffer
            oidstr_size--;
            res_size++;
          }
        }

        // append the new arc

        len = snprintf(oidstr, (size_t)oidstr_size, "%u", lval);
        oidstr_size -= (uint32_t)len;
        res_size += (uint32_t)len;
        oidstr += len;
      }
      else // the oid string is still empty, treat the first octet in a special way (OID only!)
      {
        len = (int)(lval - 80); // 2*40
        if (len >= 0)
        {
          // append "2."

          if (oidstr_size < 2)
            goto errexit;
          *(oidstr++) = '2';
          *(oidstr++) = '.';
          oidstr_size -= 2;
          res_size += 2;

          // append the new arc

          len = snprintf(oidstr, (size_t)oidstr_size, "%u", len);
          oidstr_size -= (uint32_t)len;
          res_size += (uint32_t)len;
          oidstr += len;
        }
        else
        {
          len = (int)(lval - 40);
          if (len >= 0)
          {
            if (unlikely(len > 39))
              goto errexit;

            // append "1."

            if (oidstr_size < 2)
              goto errexit;
            *(oidstr++) = '1';
            *(oidstr++) = '.';
            oidstr_size -= 2;
            res_size += 2;

            // append the new arc

            len = snprintf(oidstr, (size_t)oidstr_size, "%u", len);
            oidstr_size -= (uint32_t)len;
            res_size += (uint32_t)len;
            oidstr += len;
          }
          else // 0*40
          {
            if (unlikely(lval > 39))
              goto errexit;

            // append "0."

            if (oidstr_size < 2)
              goto errexit;
            *(oidstr++) = '0';
            *(oidstr++) = '.';
            oidstr_size -= 2;
            res_size += 2;

            // append the new arc

            len = snprintf(oidstr, (size_t)oidstr_size, "%u", lval);
            oidstr_size -= (uint32_t)len;
            res_size += (uint32_t)len;
            oidstr += len;
          }
        }
      }

      lval = 0; // clear for next arc (if any)

    } // of if 0 == (by & 0x80)
  } // of while 0 != oidlen

  if (unlikely(0 != lval)) // this must not occur (not a full arc)
  {
errexit:
    return 0;
  }

  return res_size;
}

static int32_t decode_32_int(const uint8_t* p, uint32_t* idx)
{
  int32_t   x = -1;
  uint32_t  digits = 0;

  if (unlikely(NULL == p || NULL == idx))
    return x; // ERROR = EOF

  if (p[*idx] < '0' || p[*idx]>'9')
    return x; // EOF

  x = 0;
  while (p[*idx] >= '0' && p[*idx] <= '9' && digits < 19)
  {
    x *= 10;
    x += (int32_t)(p[(*idx)++] - 0x30);
    digits++;
  }

  return x;
}

uint32_t a1t_encode_object_identifier(const char* oidstr, uint8_t* buffer, uint32_t buffer_size, bool is_roid)
{
  uint32_t      idx = 0, srcidx = 0;
  int64_t       d1, d2;

  if (unlikely(buffer_size < 2 || buffer_size > 128))
    return 0; // error (not supported by this simple encoding function)

  buffer[idx++] = is_roid ? RELATIVE_OID_TAG_CODE : OID_TAG_CODE;
  buffer[idx++] = 0x00; // this octet is used to count the real number of octets (up to 127 = 0x7F)

  // decode the first two digits (treated in a special way!)

  if (!is_roid)
  {
    d1 = decode_32_int((const uint8_t*)oidstr, &srcidx);
    if (unlikely(-1 == d1))
      return 0; // error
    if (unlikely('.' != oidstr[srcidx]))
      return 0; // error
    srcidx++;

    d2 = decode_32_int((const uint8_t*)oidstr, &srcidx);
    if (unlikely(-1 == d2 || d2 >= 40))
      return 0; // error

    d1 *= 40;
    d1 += d2;

    if (unlikely(d1 > 255))
      return 0; // error

    if (unlikely(idx == buffer_size))
      return 0; // error (overflow)

    buffer[idx++] = (uint8_t)d1;
    buffer[1]++;
  }

  // go on with all remaining numbers

  while (0 != oidstr[srcidx])
  {
    if (unlikely('.' != oidstr[srcidx]))
    {
      if (!is_roid)
        return 0; // error (syntax)
      else // check ROID
      {
        if (0 != buffer[1]) // output is not empty but a dot '.' is missing
          return 0; // error (syntax)
      }
    }
    srcidx++;
    d1 = decode_32_int((const uint8_t*)oidstr, &srcidx);
    if (unlikely(-1 == d1))
      return 0; // error

    if (d1 <= 127) // encode in one byte
    {
      if (unlikely(idx == buffer_size))
        return 0; // error (overflow)

      buffer[idx++] = (uint8_t)d1;
      buffer[1]++;
    }
    else
    if (d1 > 2097151) // 4 x 7 bits
    {
      if (unlikely((idx + 4) > buffer_size))
        return 0; // error (overflow)
      buffer[1] += 4;

      buffer[idx++] = ((uint8_t)((d1 >> 21) & 0x7F)) | 0x80;
      buffer[idx++] = ((uint8_t)((d1 >> 14) & 0x7F)) | 0x80;
      buffer[idx++] = ((uint8_t)((d1 >> 7) & 0x7F)) | 0x80;
      buffer[idx++] = (uint8_t)(d1 & 0x7F);
    }
    else
    if (d1 > 16383) // 3 x 7 bits
    {
      if (unlikely((idx + 3) > buffer_size))
        return 0; // error (overflow)
      buffer[1] += 3;

      buffer[idx++] = ((uint8_t)((d1 >> 14) & 0x7F)) | 0x80;
      buffer[idx++] = ((uint8_t)((d1 >> 7) & 0x7F)) | 0x80;
      buffer[idx++] = (uint8_t)(d1 & 0x7F);
    }
    else //if (d1 > 127) // 2 x 7 bits
    {
      if (unlikely((idx + 2) > buffer_size))
        return 0; // error (overflow)
      buffer[1] += 2;

      buffer[idx++] = ((uint8_t)((d1 >> 7) & 0x7F)) | 0x80;
      buffer[idx++] = (uint8_t)(d1 & 0x7F);
    }
  }

  if (unlikely(0 != oidstr[srcidx]))
    return 0; // error (syntax)

  return idx;
}

bool a1t_mempool_alloc ( mempool_ptr p_mp, uint32_t size )
{
  if (unlikely(NULL == p_mp || 0 == size || 0 != (size & 7)))
    return false;

  p_mp->used = p_mp->avail = 0;

  p_mp->p_memory = malloc(size);
  if (unlikely(NULL == p_mp->p_memory))
    return false;

  p_mp->avail = size;

  memset(p_mp->p_memory,0x00,size);

  return true;
}

void *a1t_malloc ( mempool_ptr p_mp, uint32_t size )
{
  uint32_t      needed;
  void         *p_memory;

  if (unlikely(NULL == p_mp || 0 == size || 0 == p_mp->avail))
    return NULL;

  needed = (size + 7) & (~7);

  if ((p_mp->used + needed) > p_mp->avail)
    return NULL;

  p_memory = (void*)(((uint8_t*)p_mp->p_memory) + p_mp->used);

  p_mp->used += needed;

  return p_memory;
}

static deritem_ptr _a1t_decode_structure ( mempool_ptr p_mp, const uint8_t *p_der, uint32_t l_der, uint32_t *idx, deritem_ptr parent, bool decode_encap )
{
  uint32_t            taglen, lenlen, tag, len, diplen, next_idx;
  deritem_ptr         dip = NULL, lookahead;

  taglen = *idx; // temporarily use this to store the current index

  if (unlikely(!a1t_decodetag(p_der,l_der,&tag,idx)))
    return NULL;

  taglen = *idx - taglen;

  lenlen = *idx; // temporarily use this to store the current index

  if (unlikely(!a1t_decodelen(p_der, l_der, &len,idx)))
    return NULL;

  lenlen = *idx - lenlen;

  if (TAG_IS_CONSTRUCTED(tag)) // we have to dive
  {
    diplen = ((sizeof(deritem) - 4) + 7) & (~7);

    dip = (deritem_ptr)a1t_malloc(p_mp,diplen);
    if (unlikely(NULL == dip))
      return NULL;

    dip->tag = tag;
    dip->len = len;
    dip->prefixlen = taglen + lenlen;
    dip->parent = parent;

    next_idx = (*idx) + len;

    if (0 != len)
    {
      dip->child = _a1t_decode_structure(p_mp, p_der,next_idx/*l_der*/,idx,dip,decode_encap);
      if (unlikely(NULL == dip->child))
        return NULL;
    }

    if (unlikely(next_idx != *idx))
      return NULL;

    if ((*idx) != l_der)
      goto parse_next_item;
  }
  else // no constructed tag but check for BIT STRING and OCTET STRING together with decode_encap
  {
    if (decode_encap && (MAKE_TAG1(false,OCTETSTRING_TAG_CODE)==tag || MAKE_TAG1(false,BITSTRING_TAG_CODE)==tag) )
    {
      // allocate our item now and store full value in it even if we can decode the encapsulated stuff

      diplen = ((sizeof(deritem) - 4 + len + 1) + 7) & (~7); // len + 1 to always have zero-terminated strings (if it is a string)

      dip = (deritem_ptr)a1t_malloc(p_mp,diplen);
      if (unlikely(NULL == dip))
        return NULL;

      dip->tag = tag;
      dip->len = len;
      dip->prefixlen = taglen + lenlen;
      dip->parent = parent;

      if (0 != len)
        memcpy(dip->value, p_der + (*idx), len);

      // this is a TEST: we try to decode this stuff but if it fails, this function does not fail

      if (MAKE_TAG1(false,BITSTRING_TAG_CODE)==tag)
      {
        if (len < 3)  // at least tag with length zero plus one byte 'unused bits in final octet'
          goto continue_not_constructed;
        if (0 != p_der[*idx]) // number of unused bits in final octet must be zero here
          goto continue_not_constructed;

        next_idx = *idx;

        (*idx)++; // skip the unused bits here

        lookahead = _a1t_decode_structure(p_mp, p_der, next_idx + len/*l_der*/, idx, NULL/*has to be replaced later on by dip!!!*/,true);

        if (NULL == lookahead) // OK, the child item seems NOT to be encapsulated
        {
          *idx = next_idx;
          goto continue_not_constructed;
        }

        if (*idx != (next_idx+len))
        {
          *idx = next_idx;
          goto continue_not_constructed;
        }

        // yes, there is an encapsulated DER item

        dip->child = lookahead;
        while (NULL != lookahead)
        {
          lookahead->parent = dip;
          lookahead = lookahead->next;
        }

        if ((*idx) != l_der)
          goto parse_next_item;
      }
      else // OCTET STRING
      {
        if (len < 2)  // at least tag with length zero must be available in the OCTET STRING
          goto continue_not_constructed;

        next_idx = *idx;

        lookahead = _a1t_decode_structure(p_mp, p_der, next_idx + len/*l_der*/, idx, NULL/*has to be replaced later on by dip!!!*/,true);

        if (NULL == lookahead) // OK, the child item seems NOT to be encapsulated
        {
          *idx = next_idx;
          goto continue_not_constructed;
        }

        if (*idx != (next_idx+len))
        {
          *idx = next_idx;
          goto continue_not_constructed;
        }

        // yes, there is an encapsulated DER item

        dip->child = lookahead;
        while (NULL != lookahead)
        {
          lookahead->parent = dip;
          lookahead = lookahead->next;
        }

        if ((*idx) != l_der)
          goto parse_next_item;
      }
    }
    else // no encapsulation or constructed at all, this is plain
    {
      diplen = ((sizeof(deritem) - 4 + len + 1) + 7) & (~7); // len + 1 to always have zero-terminated strings (if it is a string)

      dip = (deritem_ptr)a1t_malloc(p_mp,diplen);
      if (unlikely(NULL == dip))
        return NULL;

      dip->tag = tag;
      dip->len = len;
      dip->prefixlen = taglen + lenlen;
      dip->parent = parent;

      if (0 != len)
        memcpy(dip->value, p_der + (*idx), len);

continue_not_constructed:
      (*idx) += len;

      if ((*idx) != l_der) // there seems to be a 'next' item
      {
parse_next_item:
        dip->next = _a1t_decode_structure(p_mp, p_der,l_der,idx,parent,decode_encap);
        if (unlikely(NULL == dip->next))
        {
          //free(dip);
          return NULL;
        }

        dip->next->prev = dip;
        dip->next->parent = parent; // same parent as previous item!
      }
    }
  }

  return dip;
}

deritem_ptr a1t_decode_structure ( mempool_ptr p_mp, const uint8_t *p_der, uint32_t l_der, bool decode_encap )
{
  uint32_t              idx;
  deritem_ptr           root;

  if (unlikely(NULL == p_der || 0 == l_der))
    return NULL;

  idx = 0;

  root = _a1t_decode_structure(p_mp, p_der, l_der, &idx, NULL, decode_encap);

  if (likely(idx == l_der))
    return root;

  a1t_free_structure(p_mp, root);

  return NULL;
}

static bool _a1t_encode_structure ( deritem_ptr dip, uint8_t *p_der, uint32_t l_der, uint32_t *idx )
{
  uint32_t          next_idx;

  if (unlikely(!a1t_encodetag(p_der, dip->tag, l_der, idx)))
    return false;

  if (unlikely(!a1t_encodelen(p_der, dip->len, l_der, idx)))
    return false;

  if (NULL == dip->child) // this is plain
  {
    if (0 != dip->len)
    {
      if ((*idx + dip->len) > l_der)
        return false;
      memcpy(p_der + *idx, dip->value, dip->len);
      (*idx) += dip->len;
    }
  }
  else // this is either constructed or encapsulated
  {
    next_idx = *idx + dip->len;

    if (MAKE_TAG1(false,BITSTRING_TAG_CODE) == dip->tag) // a zero byte is missing here
    {
      if (*idx == l_der)
        return false;

      p_der[*idx] = 0x00;
      (*idx)++;
    }

    if (unlikely(!_a1t_encode_structure(dip->child, p_der, l_der, idx)))
      return false;

    if (unlikely(*idx != next_idx))
      return false;
  }

  // check for next element

  if (NULL != dip->next)
    return _a1t_encode_structure(dip->next, p_der, l_der, idx);
  else
    return true;
}

uint8_t *a1t_encode_structure ( deritem_ptr dip, uint32_t *p_l_der )
{
  uint8_t          *p_der;
  uint32_t          idx;

  if (unlikely(NULL == dip || NULL == p_l_der))
    return NULL;

  p_der = (uint8_t*)malloc(dip->len + dip->prefixlen);
  if (unlikely(NULL == p_der))
    return NULL;

  *p_l_der = dip->len + dip->prefixlen;

  idx = 0;

  if (unlikely(!_a1t_encode_structure(dip, p_der, *p_l_der, &idx)))
  {
    free(p_der);
    *p_l_der = 0;
    return NULL;
  }

  return p_der;
}

bool a1t_encode_structure_to_buffer ( deritem_ptr dip, uint8_t *p_der, uint32_t l_der )
{
  uint32_t          idx;

  if (unlikely(NULL == dip || NULL == p_der || 0 == l_der))
    return false;

  idx = 0;

  return _a1t_encode_structure(dip, p_der, l_der, &idx);
}

void a1t_free_structure ( mempool_ptr p_mp, deritem_ptr dip )
{
  if (NULL != dip)
  {
    if (((void*)dip) == p_mp->p_memory) // free if and only if this is the root pointer
    {
      free(p_mp->p_memory);
      p_mp->p_memory = NULL;
      p_mp->avail = p_mp->used = 0;
    }
  }
}

deritem_ptr a1t_search_tag ( deritem_ptr dip, uint32_t tag )
{
  if (NULL == dip)
    return NULL;

  if (dip->tag == tag)
    return dip;

  if (NULL != dip->child)
  {
    deritem_ptr found = a1t_search_tag(dip->child,tag);
    if (NULL != found)
      return found;
  }

  if (NULL != dip->next)
    return a1t_search_tag(dip->next,tag);

  return NULL;
}

deritem_ptr a1t_search_tlv ( deritem_ptr dip, uint32_t tag, uint32_t len, const uint8_t *value )
{
  if (NULL == dip)
    return NULL;

  if (dip->tag == tag && dip->len == len && !memcmp(dip->value,value,len))
    return dip;

  if (NULL != dip->child)
  {
    deritem_ptr found = a1t_search_tag(dip->child,tag);
    if (NULL != found)
      return found;
  }

  if (NULL != dip->next)
    return a1t_search_tag(dip->next,tag);

  return NULL;
}


deritem_ptr a1t_seek_item ( deritem_ptr dip, const char *p_derpath )
{
  uint32_t      cnt = 1;

  if (unlikely(NULL == dip))
    return NULL;

  if (NULL == p_derpath)
    return dip;

  while (0 != *p_derpath)
  {
    switch(*p_derpath)
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        cnt = ((uint8_t)(*p_derpath))-0x30;
        p_derpath++;
        while (0 != *p_derpath && *p_derpath >= '0' && *p_derpath <= '9')
        {
          cnt *= 10;
          cnt += ((uint8_t)(*p_derpath))-0x30;
          p_derpath++;
        }
        if ('+' == *p_derpath)
          goto handle_plus;
        if ('*' == *p_derpath)
          goto handle_star;

        return NULL;

      case '+':
handle_plus:
        p_derpath++;
        while (0 != cnt && NULL != dip)
        {
          dip = dip->next;
          cnt--;
        }
        if (0 != cnt || NULL == dip )
          return NULL;
        cnt = 1; // re-init count
        break;

      case '*':
handle_star:
        p_derpath++;
        while (0 != cnt && NULL != dip)
        {
          dip = dip->child;
          cnt--;
        }
        if (0 != cnt || NULL == dip )
          return NULL;
        cnt = 1; // re-init count
        break;

      default:
        return NULL; // error
    }
  } // outer while; until string completely processed

  return dip;
}

static deritem_ptr _a1t_copy_structure ( mempool_ptr p_mp, deritem_ptr dip, deritem_ptr parent )
{
  uint32_t      diplen;
  deritem_ptr   copy_dip;

  diplen = ((sizeof(deritem) - 4 + (NULL == dip->child ? dip->len : 0) ) + 7) & (~7);

  copy_dip = (deritem_ptr)a1t_malloc(p_mp, diplen);

  if (unlikely(NULL == copy_dip))
    return NULL;

  memcpy(copy_dip, dip, diplen);

  copy_dip->prev = NULL;
  copy_dip->parent = parent;

  if (NULL != copy_dip->child)
  {
    copy_dip->child = _a1t_copy_structure(p_mp, copy_dip->child, copy_dip);
    if (unlikely(NULL == copy_dip->child))
      return false;
  }

  if (NULL != copy_dip->next)
  {
    copy_dip->next = _a1t_copy_structure(p_mp, copy_dip->next, parent);
    if (unlikely(NULL == copy_dip->next))
      return false;
    copy_dip->next->prev = copy_dip;
  }

  return copy_dip;
}

deritem_ptr a1t_copy_structure ( mempool_ptr p_mp, deritem_ptr dip )
{
  if (unlikely(NULL == p_mp || NULL == dip))
    return NULL;

  return _a1t_copy_structure(p_mp, dip, NULL/*parent*/);
}

deritem_ptr a1t_create_simple_item ( mempool_ptr p_mp, uint32_t tag, uint32_t len, const uint8_t *value )
{
  uint32_t        lenlen;
  deritem_ptr     newitem;

  if (unlikely(NULL == p_mp))
    return NULL;

  if (len < 128)
    lenlen = 1;
  else
  if (len < 256)
    lenlen = 2;
  else
    lenlen = 3;

  newitem = (deritem_ptr)a1t_malloc(p_mp, sizeof(deritem) - 4 + len);

  if (unlikely(NULL == newitem))
    return NULL;

  newitem->tag = tag;
  newitem->len = len;
  newitem->prefixlen = ((tag >> 24) & 15) + lenlen;

  if (0 != len && NULL != value)
    memcpy(newitem->value, value, len);

  return newitem;
}

bool a1t_paste_item ( mempool_ptr p_mp, deritem_ptr dip_target, deritem_ptr dip_source, bool duplicate_source )
{
  deritem_ptr       copy_dip, run_dip, last_dip;
  uint32_t          old_length, new_length, prefixlen;

  if (unlikely( NULL == p_mp || NULL == dip_target || NULL == dip_source ))
    return false;

  if (!duplicate_source)
    copy_dip = dip_source;
  else
  {
    copy_dip = a1t_copy_structure(p_mp, dip_source);
    if (unlikely(NULL == copy_dip))
      return false;
  }

  run_dip = last_dip = copy_dip;
  while (NULL != run_dip)
  {
    run_dip->parent = dip_target->parent;
    if (NULL == run_dip->next)
      last_dip = run_dip;
    run_dip = run_dip->next;
  }

  if (NULL != dip_target->parent)
  {
    if (dip_target->parent->child == dip_target )
      dip_target->parent->child = copy_dip;
  }

  copy_dip->prev = dip_target->prev;

  if (NULL != copy_dip->prev)
    copy_dip->prev->next = copy_dip;

  last_dip->next = dip_target->next;

  if (NULL != last_dip->next)
    last_dip->next->prev = last_dip;

  // the total length of a possibly available parent item is possibly wrong, we have to fix it

  old_length = dip_target->prefixlen + dip_target->len;
  new_length = copy_dip->prefixlen + copy_dip->len;

  while (NULL != copy_dip->parent)
  {
    copy_dip = copy_dip->parent;

    copy_dip->len -= old_length;
    copy_dip->len += new_length;

    if (copy_dip->len < 128)
      prefixlen = 1;
    else
    if (copy_dip->len < 256)
      prefixlen = 2;
    else
      prefixlen = 3;

    prefixlen += (copy_dip->tag >> 24) & 15;

    if (prefixlen != copy_dip->prefixlen)
    {
      new_length += prefixlen - copy_dip->prefixlen;
      copy_dip->prefixlen = prefixlen;
    }
  }

  return true;
}

bool a1t_append_sequence_item ( mempool_ptr p_mp, deritem_ptr dip_target, deritem_ptr dip_source, bool duplicate_source )
{
  deritem_ptr       copy_dip, run_dip;
  uint32_t          new_length, prefixlen;

  if (unlikely( NULL == p_mp || NULL == dip_target || NULL == dip_source ))
    return false;

  // go to the end of the current sequence of elements

  while (NULL != dip_target->next)
    dip_target = dip_target->next;

  if (!duplicate_source)
    copy_dip = dip_source;
  else
  {
    copy_dip = a1t_copy_structure(p_mp, dip_source);
    if (unlikely(NULL == copy_dip))
      return false;
  }

  // establish correct parent pointers

  run_dip = copy_dip;
  while (NULL != run_dip)
  {
    run_dip->parent = dip_target->parent;
    run_dip = run_dip->next;
  }

  // link the new item to the last item in the sequence

  dip_target->next = copy_dip;
  copy_dip->prev = dip_target;

  // we have to take the newly added element into account at all (grand-)parents of this item

  new_length = copy_dip->prefixlen + copy_dip->len;

  while (NULL != copy_dip->parent)
  {
    copy_dip = copy_dip->parent;

    copy_dip->len += new_length;

    if (copy_dip->len < 128)
      prefixlen = 1;
    else
    if (copy_dip->len < 256)
      prefixlen = 2;
    else
      prefixlen = 3;

    prefixlen += (copy_dip->tag >> 24) & 15;

    if (prefixlen != copy_dip->prefixlen)
    {
      new_length += prefixlen - copy_dip->prefixlen;
      copy_dip->prefixlen = prefixlen;
    }
  }

  return true;
}

bool a1t_recompute_sequence_length ( deritem_ptr dip )
{
  uint32_t        full_length;
  deritem_ptr     work;

  if (unlikely(NULL == dip || MAKE_TAG1(true,SEQ_TAG_CODE) != dip->tag ))
    return false;

  // compute full length of all sequence items

  full_length = 0;
  work = dip->child;
  while (NULL != work)
  {
    full_length += work->prefixlen + work->len;
    work = work->next;
  }

  dip->len = full_length;

  if (full_length < 128)
    dip->prefixlen = 1;
  else
  if (full_length < 256)
    dip->prefixlen = 2;
  else
    dip->prefixlen = 3;

  dip->prefixlen += (dip->tag >> 24) & 15;

  return true;
}

void a1t_hexdump(const unsigned char  *data, unsigned int size, unsigned int offset, unsigned int indent)
{
  char szHexLine[80], szHex[32], szIndent[128+8];
  unsigned char x;
  int i, j;

  if (!size)
    return;

  if (indent > 128)
    indent = 128;

  memset(szIndent,0x20,indent);
  szIndent[indent]=0;

  while (size > 0)
  {
    memset(szHexLine, 0x20, sizeof(szHexLine));
    szHexLine[77] = 0x0A;
    szHexLine[78] = 0x00;
    if (size > 8)
      szHexLine[34] = '-';

    sprintf(szHex, "%08X", offset);
    offset += 16;
    memcpy(szHexLine, szHex, 8);

    i = 0;
    j = 0;
    while (size > 0)
    {
      x = *(data++);
      size--;
      szHexLine[i * 3 + 10 + j] = digits[x >> 4];
      szHexLine[i * 3 + 11 + j] = digits[x & 0xF];

      if ((x < 32) || (x >= 127))
        x = '.';

      szHexLine[i + 61] = (char) x;

      i++;
      if (i == 8)
        j = 2;
      if (i == 16)
        break;
    }

    fprintf(stdout,"%s%s", szIndent, szHexLine);
  }
}

static void _print_indent ( uint32_t indent )
{
  char      str[128+8];
  uint32_t  i;

  if (indent > 128)
    indent = 128;

  memset(str,0x20,128);
  str[indent] = 0;

  for (i=0;i<indent;i+=2)
    str[i] = '.';

  fprintf(stdout,"%s",str);
}

static void _print_compact_asn1path(char *asn1path)
{
  char               *p, c_last = 0;
  char                buffer[128];
  uint32_t            idx = 0, cnt;

  if (NULL == asn1path || 0 == *asn1path)
    return;

  p = asn1path;

  while (0 != *p)
  {
    cnt = 1;
    c_last = *(p++);
    while (0 != *p && c_last == *p)
    {
      p++;
      cnt++;
    }

    if (1 == cnt)
      buffer[idx++] = c_last;
    else
      idx += (uint32_t)snprintf(&buffer[idx],sizeof(buffer)-idx,"%u%c",cnt,c_last);
  }

  buffer[idx] = 0;

  fprintf(stdout,"%s",buffer);
}

static void _a1t_dump_tree ( deritem_ptr dip, uint32_t ofs, uint32_t indent, char *asn1path )
{
  char          tagstr[64], oidstr[128];
  uint32_t      l = (uint32_t)strlen(asn1path);

  if (l>126)
    l = 126;

  fprintf(stdout,"%c%c%c%c  tag:", digits[(ofs>>12)&15], digits[(ofs>>8)&15], digits[(ofs>>4)&15], digits[ofs&15]);

  if (0x01000000 == (dip->tag & 0x03000000))
    fprintf(stdout,"  %c%c, len:",digits[(dip->tag>>4)&15], digits[dip->tag&15]);
  else
    fprintf(stdout,"%c%c%c%c, len:",digits[(dip->tag>>12)&15], digits[(dip->tag>>8)&15], digits[(dip->tag>>4)&15], digits[dip->tag&15]);

  fprintf(stdout,"%c%c%c%c  ", digits[(dip->len>>12)&15], digits[(dip->len>>8)&15], digits[(dip->len>>4)&15], digits[dip->len&15]);

  _print_indent(indent);

  // "0000  tag:0000, len:0000  " = 26 chars

  if (a1t_printtag(dip->tag,tagstr,sizeof(tagstr)))
    fprintf(stdout,"%s", tagstr);

  if (NULL != dip->child && ((dip->tag & 0xFFFF)>=0x03) && ((dip->tag & 0xFFFF)<=0x04))
    fprintf(stdout,", encapsulates:");

  if (0x06 == (dip->tag & 0xFFFF)) // OID
  {
    memset(oidstr,0,sizeof(oidstr));
    if (0 != a1t_decode_object_identifier(dip->value, dip->len, oidstr, sizeof(oidstr), false))
      fprintf(stdout," = %s",oidstr);
  }

  fprintf(stdout," [");
  _print_compact_asn1path(asn1path);
  fprintf(stdout,"] = [%s] -> prefix length = 0x%08X\n",asn1path, dip->prefixlen);

  if (NULL == dip->child)
  {
    if (0 != dip->len)
    {
      a1t_hexdump(dip->value, dip->len, 0x0000, 26 + indent);
    }
  }
  else // yes, dive
  {
    asn1path[l] = '*';
    _a1t_dump_tree(dip->child,ofs + dip->prefixlen + (0x01000003 == dip->tag ? 1 : 0), indent + 2, asn1path);
    asn1path[l] = 0x00;
  }

  if (NULL != dip->next)
  {
    asn1path[l] = '+';
    _a1t_dump_tree(dip->next,ofs + dip->prefixlen + dip->len, indent, asn1path);
    asn1path[l] = 0x00;
  }
}

void a1t_dump_tree ( deritem_ptr dip )
{
  char      asn1path[128];

  if (NULL == dip)
  {
    fprintf(stdout,"<empty>\n");
    return;
  }

  memset(asn1path,0,sizeof(asn1path));
  _a1t_dump_tree (dip, 0x0000, 0, asn1path);
}

static bool _a1t_check_structure ( deritem_ptr dip, deritem_ptr parent )
{
  deritem_ptr             work;
  uint32_t                i, cnt = 0, full_length = 0;
  deritem_ptr            *array;

  // 1.) count the number of items on this level

  work = dip;
  while (NULL != work)
  {
    full_length += work->prefixlen + work->len;
    cnt++;
    work = work->next;
  }

  if (NULL != parent)
  {
    if (MAKE_TAG1(false,BITSTRING_TAG_CODE) == parent->tag) // this is BIT STRING with encapsulation
    {
      if (parent->len != (full_length + 1)) // +1 for the unsed bits octet!
        return false;
    }
    else
    {
      if (parent->len != full_length)
        return false;
    }
  }

  // 2.) allocate helper array and collect all items on this level

  array = (deritem_ptr*)malloc(sizeof(deritem_ptr)*cnt);
  if (unlikely(NULL == array))
    return false;

  cnt = 0;
  work = dip;
  while (NULL != work)
  {
    array[cnt++] = work;
    work = work->next;
  }

  // 3.) check prev|next|parent

  for (i=0;i<cnt;i++)
  {
    if (array[i]->parent!=parent)
    {
errexit:
      free(array);
      return false;
    }

    if (0==i)
    {
      if (NULL != array[i]->prev)
        goto errexit;
      if (cnt > 1)
      {
        if (array[i]->next != array[i+1])
          goto errexit;
      }
    }
    else
    if ((cnt-1)==i)
    {
      if (NULL != array[i]->next)
        goto errexit;
      if (cnt > 1)
      {
        if (array[i]->prev != array[i-1])
          goto errexit;
      }
    }
    else
    {
      if (array[i]->prev != array[i-1])
        goto errexit;
      if (array[i]->next != array[i+1])
        goto errexit;
    }
  }
  free(array);

  if (NULL != dip->child)
    return _a1t_check_structure(dip->child,dip);

  return true;
}

bool a1t_check_structure ( deritem_ptr dip )
{
  if (unlikely(NULL==dip))
    return false;

  return _a1t_check_structure(dip,NULL);
}

uint64_t get_system_time ( uint32_t *p_msecs )
{
  struct timeval      tv;

  gettimeofday(&tv,NULL);

  if (NULL != p_msecs)
    *p_msecs = (uint32_t)(tv.tv_usec / 1000);

  return ((uint64_t)tv.tv_sec) + SYSTIME_BASE_1970;
}

static void time_day2date(int32_t day, int32_t* year, int32_t* month, int32_t* mday)
{
  int64_t y, ddd, mi;

  y = (10000 * ((int64_t)day) + 14780) / 3652425;
  ddd = day - (y * 365 + y / 4 - y / 100 + y / 400);
  if (ddd < 0)
  {
    y--;
    ddd = day - (y * 365 + y / 4 - y / 100 + y / 400);
  }

  mi = (52 + 100 * ddd) / 3060;

  *year = (int32_t)(y + (mi + 2) / 12);
  *month = (mi + 2) % 12 + 1;
  *mday = (int32_t)(ddd - (mi * 306 + 5) / 10 + 1);
}

#define GREGORIAN_DAY_1582_10_01          578027
#define GREGORIAN_DAY_1970_01_01          719468

bool time_systime2date(uint64_t systime,
                       uint32_t* year, uint32_t* month, uint32_t* mday,
                       uint32_t* hour, uint32_t* minute, uint32_t* second)
{
  int64_t       gday, rem;
  int32_t       rem32;

  // 1.) Calculate the Gregorian calendar day from the systime

  gday = systime / 86400 + GREGORIAN_DAY_1970_01_01; //GREGORIAN_DAY_1582_10_01;
  rem = systime % 86400;

  if (gday > 0x7FFFFFFF)
    return false;

  time_day2date((int32_t)gday, (int32_t*)year, (int32_t*)month, (int32_t*)mday);

  *hour = ((uint32_t)rem) / 3600;
  rem32 = ((int32_t)rem) % 3600;
  *minute = rem32 / 60;
  *second = rem32 % 60;

  return true;
}

extern const uint32_t md_sizes[];

extern uint32_t ossl_hash ( uint32_t md_type, const uint8_t *data, uint32_t data_size, uint8_t *md );

bool a1t_compute_hash_over_structure ( deritem_ptr dip, uint32_t md_type, uint8_t *hash )
{
  uint32_t      l_tbs, md_size = md_sizes[md_type];
  uint8_t      *p_tbs;

  if (unlikely(NULL == dip || NULL == hash || 0 == md_size))
    return false;

  // DER-encode the DER tree

  p_tbs = a1t_encode_structure(dip,&l_tbs);
  if (unlikely(NULL == p_tbs))
    return false;

  if (unlikely(0 == ossl_hash(md_type, p_tbs, l_tbs, hash)))
  {
    free(p_tbs);
    return false;
  }

  free(p_tbs);

  return true;
}

bool a1t_explore_x509 ( deritem_ptr dip, explore_x509_ptr p_explore )
{
  deritem_ptr             dip2;

  if (unlikely(NULL == dip || NULL == p_explore))
    return false;

  memset(p_explore, 0, sizeof(explore_x509));

  if (unlikely(NULL == dip->child))
    return false;

  dip = dip->child; // skip outer SEQUENCE, the whole certificate

  p_explore->tbs_cert = dip;

  dip2 = dip->next;
  if (unlikely(NULL == dip2))
  {
ErrorExit:
    memset(p_explore, 0, sizeof(explore_x509));
    return false;
  }

  p_explore->sig_algo2 = dip2;
  dip2 = dip2->next;
  if (unlikely(NULL == dip2))
    goto ErrorExit;
  p_explore->sigval_bs = dip2;
  if (unlikely(NULL != dip2->next))
    goto ErrorExit;

  dip = dip->child;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  dip = dip->next; // skip version
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->serialno = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->sig_algo1 = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->issuer_name = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->validity = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->subject_name = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;
  p_explore->spki = dip;
  dip = dip->next;
  if (unlikely(NULL == dip))
    goto ErrorExit;

  while (NULL != dip && 0xA10000A3 != dip->tag)
    dip = dip->next;

  if (NULL != dip)
  {
    if (unlikely(NULL == dip->child))
      goto ErrorExit;
    p_explore->extensions = dip->child;
  }

  return true;
}

static uint64_t _a1t_retrieve_seconds_1970 ( deritem_ptr p_datetime )
{
  uint64_t            systime;
  uint32_t            i, year, month, mday, hour, minute, second;

  if (0x01000017 == p_datetime->tag) // UTCTime
  {
    if (13 != p_datetime->len)
      return 0;
    if ('Z' != p_datetime->value[12])
      return 0;
    for (i=0;i<12;i++)
      if (p_datetime->value[i] < 0x30 || p_datetime->value[i] > 0x39)
        return 0;

    year = (((uint32_t)p_datetime->value[0])-0x30) * 10 + (((uint32_t)p_datetime->value[1])-0x30);
    if (year < 50)
      year += 2000;
    else
      year += 1900;

    month = (((uint32_t)p_datetime->value[2])-0x30) * 10 + (((uint32_t)p_datetime->value[3])-0x30);
    mday = (((uint32_t)p_datetime->value[4])-0x30) * 10 + (((uint32_t)p_datetime->value[5])-0x30);

    hour = (((uint32_t)p_datetime->value[6])-0x30) * 10 + (((uint32_t)p_datetime->value[7])-0x30);
    minute = (((uint32_t)p_datetime->value[8])-0x30) * 10 + (((uint32_t)p_datetime->value[9])-0x30);
    second = (((uint32_t)p_datetime->value[10])-0x30) * 10 + (((uint32_t)p_datetime->value[11])-0x30);
  }
  else
  if (0x01000018 == p_datetime->tag) // GeneralizedTime
  {
    if (15 != p_datetime->len)
      return 0;
    if ('Z' != p_datetime->value[14])
      return 0;
    for (i=0;i<14;i++)
      if (p_datetime->value[i] < 0x30 || p_datetime->value[i] > 0x39)
        return 0;

    year = (((uint32_t)p_datetime->value[0])-0x30) * 1000 + (((uint32_t)p_datetime->value[1])-0x30) * 100 +
        (((uint32_t)p_datetime->value[2])-0x30) * 10 + (((uint32_t)p_datetime->value[3])-0x30);
    month = (((uint32_t)p_datetime->value[4])-0x30) * 10 + (((uint32_t)p_datetime->value[5])-0x30);
    mday = (((uint32_t)p_datetime->value[6])-0x30) * 10 + (((uint32_t)p_datetime->value[7])-0x30);

    hour = (((uint32_t)p_datetime->value[8])-0x30) * 10 + (((uint32_t)p_datetime->value[9])-0x30);
    minute = (((uint32_t)p_datetime->value[10])-0x30) * 10 + (((uint32_t)p_datetime->value[11])-0x30);
    second = (((uint32_t)p_datetime->value[12])-0x30) * 10 + (((uint32_t)p_datetime->value[13])-0x30);
  }
  else
    return 0; // error

  if (!time_date2systime(&systime, year, month, mday, hour, minute, second))
    return 0;

  return systime;
}

static deritem_ptr _a1t_create_datetime ( mempool_ptr p_mp, uint64_t systime )
{
  uint32_t                year, month, mday, hour, minute, second;
  char                    buffer[32];
  deritem_ptr             res;

  if (!time_systime2date(systime,&year,&month,&mday,&hour,&minute,&second))
    return NULL;

  if (year >= 1950 && year <= 2049) // make UTCTime
  {
    snprintf(buffer,sizeof(buffer),"%02u%02u%02u%02u%02u%02uZ", year % 100, month, mday, hour, minute, second);
    res = a1t_create_simple_item(p_mp, 0x01000017, 13, (const uint8_t*)buffer);
  }
  else // make GeneralizedTime
  {
    snprintf(buffer,sizeof(buffer),"%04u%02u%02u%02u%02u%02uZ", year, month, mday, hour, minute, second);
    res = a1t_create_simple_item(p_mp, 0x01000017, 15, (const uint8_t*)buffer);
  }

  return res;
}

bool a1t_modify_x509_validity ( mempool_ptr p_mp, deritem_ptr p_validity, uint32_t expiration_days )
{
  deritem_ptr           p_val, p_new_notBefore, p_new_notAfter;
  uint64_t              notBefore_seconds, notAfter_seconds, validity_seconds;
  time_t                notBefore, notAfter;

  if (unlikely(NULL == p_mp || NULL == p_validity))
    return false;

  // get notBefore and notAfter first

  if (unlikely(NULL == p_validity->child))
    return false;

  p_val = p_validity->child;

  if (unlikely(NULL == p_val->next || NULL != p_val->next->next))
    return false;

  // compute number of seconds since 1970 for notBefore

  notBefore_seconds = _a1t_retrieve_seconds_1970(p_val);
  if (unlikely(0 == notBefore_seconds))
    return false;

  notAfter_seconds = _a1t_retrieve_seconds_1970(p_val->next);
  if (unlikely(0 == notAfter_seconds))
    return false;

  if (unlikely( ((int64_t)(notAfter_seconds - notBefore_seconds)) <= 0 ))
    return false;

  if (0 == expiration_days)
    validity_seconds = notAfter_seconds - notBefore_seconds;
  else
    validity_seconds = ((uint64_t)expiration_days) * 86400;

  time(&notBefore);
  notAfter = notBefore + validity_seconds;

  p_new_notBefore = _a1t_create_datetime(p_mp, notBefore);
  p_new_notAfter = _a1t_create_datetime(p_mp, notAfter);

  if (unlikely(NULL == p_new_notBefore || NULL == p_new_notAfter))
    return false;

  if (unlikely(!a1t_paste_item(p_mp, p_validity->child, p_new_notBefore, false)))
    return false;

  if (unlikely(!a1t_paste_item(p_mp, p_validity->child->next, p_new_notAfter, false)))
    return false;

  return true;
}

uint32_t get_executable_path ( char *buffer, uint32_t buffer_size, bool cut_exe )
{
  char *p;

  if (unlikely(NULL == buffer || 0 == buffer_size))
    return 0;

  memset(buffer,0,buffer_size);

#if defined(_LINUX)
  (void)readlink("/proc/self/exe",buffer, (size_t)(buffer_size -1));
#elif defined(_MACOS)
  buffer_size--;
  (void)_NSGetExecutablePath(buffer, &buffer_size);
#elif defined(_WINDOWS)
  (void)GetModuleFileNameA(NULL,buffer,(DWORD)(buffer_size - 1));
#endif

  if (cut_exe)
  {
    p = strrchr(buffer, PATHSEP_CHAR);
    if (NULL != p)
      *p = 0;
  }

  return (uint32_t)strlen(buffer);
}

#define CTRL_RESET   "\033[0;0;0m"
#define CTRL_RED     "\033[1;31m"
#define CTRL_GREEN   "\033[1;32m"
#define CTRL_YELLOW  "\033[1;33m"
#define CTRL_BLUE    "\033[1;34m"
#define CTRL_MAGENTA "\033[1;35m"
#define CTRL_CYAN    "\033[1;36m"

#ifdef _WINDOWS
static int reset_console = 0;
#endif

void init_colored_console ( bool no_colors )
{
#ifdef _WINDOWS
  HANDLE        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD         dwMode = 0;
#endif

  if (!no_colors)
  {
    strcpy(ctrlReset, CTRL_RESET);
    strcpy(ctrlRed, CTRL_RED);
    strcpy(ctrlGreen, CTRL_GREEN);
    strcpy(ctrlYellow, CTRL_YELLOW);
    strcpy(ctrlBlue, CTRL_BLUE);
    strcpy(ctrlMagenta, CTRL_MAGENTA);
    strcpy(ctrlCyan, CTRL_CYAN);

#ifdef _WINDOWS
    if (GetConsoleMode(hConsole, &dwMode))
    {
      dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      SetConsoleMode(hConsole, dwMode);
      reset_console = 1;
    }
#endif
  }
}

void fini_colored_console ( void )
{
#ifdef _WINDOWS
  HANDLE        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD         dwMode = 0;

  if (0 != reset_console)
  {
    if (GetConsoleMode(hConsole, &dwMode))
    {
      dwMode &= ~ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      SetConsoleMode(hConsole, dwMode);
      reset_console = 0;
    }
  }
#endif
}

/**
 * CAUTION: Linux does not seem to copy the environment string but just
 * -------- takes its pointer to add it to char **environ.
 */
int putenv_fmt(char* buffer, size_t buffer_len, const char* fmt, ...)
{
  va_list     ap;

  va_start(ap, fmt);
  vsnprintf(buffer, buffer_len, fmt, ap);
  va_end(ap);

  return putenv(buffer);
}
