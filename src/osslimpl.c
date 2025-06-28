/**
 * @file   osslimpl.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implementation of all OpenSSL 3 specific stuff
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

#include <osslimpl.h>
#include <utils.h>

#define NAME_FLAGS ( ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | /* XN_FLAG_DN_REV | */ XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS )

static    ENGINE                 *rand_eng              = NULL;
static    int                     haveIntelRNG          = 0;
#ifdef _WINDOWS
static    volatile LONG           g_init = 0;
#else
static    volatile uint32_t       g_init                = 0;
#endif
static    UI_METHOD              *g_ui_method           = NULL;
          const uint32_t          md_sizes[] = { 20, 20, 28, 32, 48, 64, 28, 32, 48, 64, 64 };

extern const uint8_t unused_most_significant_bits[256];

// X.509v3 signature AlgorithmIdentifier DER encodings:

static const uint8_t sigalgo_rsa_pkcs1_v15_sha256[15] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 };
static const uint8_t sigalgo_rsa_pkcs1_v15_sha384[15] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00 };
static const uint8_t sigalgo_rsa_pkcs1_v15_sha512[15] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0x05, 0x00 };
static const uint8_t sigalgo_rsa_pss_sha256[67] = { 0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x20 };
static const uint8_t sigalgo_rsa_pss_sha384[67] = { 0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x30 };
static const uint8_t sigalgo_rsa_pss_sha512[67] = { 0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x40 };
static const uint8_t sigalgo_ecdsa_sha256[12] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t sigalgo_ecdsa_sha384[12] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
static const uint8_t sigalgo_ecdsa_sha512[12] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 };
static const uint8_t sigalgo_eddsa_ed25519[7] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
static const uint8_t sigalgo_eddsa_ed448[7] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71 };

static const uint8_t *x509_sigalgos[11] = {
  sigalgo_rsa_pkcs1_v15_sha256,
  sigalgo_rsa_pkcs1_v15_sha384,
  sigalgo_rsa_pkcs1_v15_sha512,
  sigalgo_rsa_pss_sha256,
  sigalgo_rsa_pss_sha384,
  sigalgo_rsa_pss_sha512,
  sigalgo_ecdsa_sha256,
  sigalgo_ecdsa_sha384,
  sigalgo_ecdsa_sha512,
  sigalgo_eddsa_ed25519,
  sigalgo_eddsa_ed448
};

static const size_t x509_sigalgos_len[11] = {
  sizeof(sigalgo_rsa_pkcs1_v15_sha256),
  sizeof(sigalgo_rsa_pkcs1_v15_sha384),
  sizeof(sigalgo_rsa_pkcs1_v15_sha512),
  sizeof(sigalgo_rsa_pss_sha256),
  sizeof(sigalgo_rsa_pss_sha384),
  sizeof(sigalgo_rsa_pss_sha512),
  sizeof(sigalgo_ecdsa_sha256),
  sizeof(sigalgo_ecdsa_sha384),
  sizeof(sigalgo_ecdsa_sha512),
  sizeof(sigalgo_eddsa_ed25519),
  sizeof(sigalgo_eddsa_ed448)
};

const char x509_sig_algo_names[X509_SIG_ALGO_EDDSA_ED448 + 1][64] =
{
  "sha256WithRsaEncryption (PKCS#1 v1.5, SHA2-256)",
  "sha384WithRsaEncryption (PKCS#1 v1.5, SHA2-384)",
  "sha512WithRsaEncryption (PKCS#1 v1.5, SHA2-512)",
  "rsa (PSS, SHA2-256, MGF-1(SHA2-256), salt: 32 bytes, trailer BC",
  "rsa (PSS, SHA2-384, MGF-1(SHA2-384), salt: 48 bytes, trailer BC",
  "rsa (PSS, SHA2-512, MGF-1(SHA2-512), salt: 64 bytes, trailer BC",
  "ecdsaWithSha256 (SHA2-256)",
  "ecdsaWithSha384 (SHA2-384)",
  "ecdsaWithSha512 (SHA2-512)",
  "EdDSA, Edwards Curve ED25519 (implicit SHA2-512, pure EdDSA)",
  "EdDSA, Edwards Curve ED448 (implicit SHAKE-256(64), pure EdDSA)"
};

const char elliptic_curve_names[NUM_NAMED_EC_CURVES][32] =
{
  "NIST prime256v1 (secp256r1)",
  "NIST secp384r1",
  "NIST secp521r1",
  "BPOOL brainpoolP256R1",
  "BPOOL brainpoolP384R1",
  "BPOOL brainpoolP512R1",
  "Edwards ED25519",
  "Edwards ED448"
};

const char public_key_algorithm[3][32] =
{
  "RSA",
  "Elliptic Curve",
  "Edwards Curve"
};

static const int int_one = 1;

static const OSSL_PARAM params25519[] =
{
  OSSL_PARAM_utf8_string ("instance", "Ed25519ph", 9),
  OSSL_PARAM_int("eddsa_ph_by_caller", (int*)&int_one),
  // OSSL_PARAM_octet_string("context-string", (unsigned char *)"A protocol defined context string", 33),
  OSSL_PARAM_END
};
static const OSSL_PARAM params448[] =
{
  OSSL_PARAM_utf8_string ("instance", "Ed448ph", 7),
  OSSL_PARAM_int("eddsa_ph_by_caller", (int*)&int_one),
  // OSSL_PARAM_octet_string("context-string", (unsigned char *)"A protocol defined context string", 33),
  OSSL_PARAM_END
};

static int ui_open(UI *ui)
{
  (void)ui;
  return 1;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
  char password[PEM_BUFSIZE];
  int passwd_size;

  memset(password, 0, sizeof(password));

  if ((UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD) /*&& UI_get0_user_data(ui)*/)
  {
    switch (UI_get_string_type(uis))
    {
      case UIT_PROMPT:
      case UIT_VERIFY:
      {
        //passwd_size = pem_password_callback(password, PEM_BUFSIZE, 0, UI_get0_user_data(ui));

        passwd_size = EVP_read_pw_string(password, sizeof(password), "Enter pass phrase:", 0);

        if (passwd_size <= 0)
          return 0; // error

        if (passwd_size < PEM_BUFSIZE)
          password[passwd_size] = 0;

        UI_set_result_ex(ui, uis, password, passwd_size);

        return 1; // OK
      }
      case UIT_NONE:
      case UIT_BOOLEAN:
      case UIT_INFO:
      case UIT_ERROR:
        return 1; // OK
    }
  }

  return 0; // error
}

static int ui_write(UI *ui, UI_STRING *uis)
{
  (void)ui;
  (void)uis;
  return 1;
}

static int ui_close(UI *ui)
{
  (void)ui;
  return 1;
}

static UI_METHOD *setup_ui_method(void)
{
  UI_METHOD *ui_method = UI_create_method("EFI Tools using OpenSSL");
  UI_method_set_opener(ui_method, ui_open);
  UI_method_set_reader(ui_method, ui_read);
  UI_method_set_writer(ui_method, ui_write);
  UI_method_set_closer(ui_method, ui_close);
  return ui_method;
}

static void destroy_ui_method(UI_METHOD *ui_method)
{
  if (NULL != ui_method)
    UI_destroy_method(ui_method);
}

bool ossl_init ( void )
{
  //int           rc = 0;

  if (0 != __sync_fetch_and_and(&g_init,0xFFFFFFFF))
    return true;

  if (unlikely(0 == OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
    OPENSSL_INIT_ADD_ALL_CIPHERS |
    OPENSSL_INIT_ADD_ALL_DIGESTS |
    OPENSSL_INIT_ENGINE_RDRAND |
    OPENSSL_INIT_ENGINE_DYNAMIC /* |
    OPENSSL_INIT_NO_LOAD_CONFIG*/, NULL)))
    return false;

  ERR_clear_error();

#if 0
  rand_eng = ENGINE_by_id("rdrand");
  (void)ERR_get_error();

  if (NULL != rand_eng)
  {
    rc = ENGINE_init(rand_eng);
    (void)ERR_get_error();

    if (0 != rc)
    {
      rc = ENGINE_set_default(rand_eng, ENGINE_METHOD_RAND);
      (void)ERR_get_error();

      if (0 != rc)
      {
        haveIntelRNG = 1;
      }
    }
  }
#endif

  RAND_poll();

  g_ui_method = setup_ui_method();
  if (unlikely(NULL == g_ui_method))
    return false;

  __sync_fetch_and_or(&g_init,0xFFFFFFFF);

  return true;
}

void ossl_fini ( void )
{
  if (0 == __sync_fetch_and_and(&g_init,0xFFFFFFFF))
    return;

  if (NULL != rand_eng)
  {
#ifdef _OPENSSL_1_1_X
    // global_engine_lock = CRYPTO_THREAD_lock_new();
#endif
    ENGINE_finish(rand_eng);
    ENGINE_free(rand_eng);
    rand_eng = NULL;
    haveIntelRNG = 0;
  }

  if (NULL != g_ui_method)
    destroy_ui_method(g_ui_method);

  OPENSSL_cleanup();

  __sync_fetch_and_and(&g_init,0);
}

uint32_t ossl_hash ( uint32_t md_type, const uint8_t *data, uint32_t data_size, uint8_t *md )
{
  const EVP_MD       *algo = NULL;

  if (unlikely(md_type > MD_TYPE_SHAKE_256))
    return 0;

  if (NULL == md)
    return md_sizes[md_type];

  if (unlikely(NULL == data && 0 != data_size))
    return 0;

  switch(md_type)
  {
    case MD_TYPE_SHA1:
      SHA1(data,(size_t)data_size,md);
      break;
    case MD_TYPE_RIPEMD160:
      RIPEMD160(data,(size_t)data_size,md);
      break;
    case MD_TYPE_SHA2_224:
      algo = EVP_sha224();
      break;
    case MD_TYPE_SHA2_256:
      algo = EVP_sha256();
      break;
    case MD_TYPE_SHA2_384:
      algo = EVP_sha384();
      break;
    case MD_TYPE_SHA2_512:
      algo = EVP_sha512();
      break;
    case MD_TYPE_SHA3_224:
      algo = EVP_sha3_224();
      break;
    case MD_TYPE_SHA3_256:
      algo = EVP_sha3_256();
      break;
    case MD_TYPE_SHA3_384:
      algo = EVP_sha3_384();
      break;
    case MD_TYPE_SHA3_512:
      algo = EVP_sha3_512();
      break;
    case MD_TYPE_SHAKE_256:
      algo = EVP_shake256();
      break;
    default: // never reached
      return 0;
  }

  if (NULL != algo)
  {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    uint32_t md_size;

    if (unlikely(NULL == mdctx))
      return 0;

    if (unlikely(1 != EVP_DigestInit(mdctx,algo)))
    {
ErrorExit:
      EVP_MD_CTX_destroy(mdctx);
      return 0;
    }

    if (unlikely(1 != EVP_DigestUpdate(mdctx, data, (size_t)data_size)))
      goto ErrorExit;

    md_size = md_sizes[md_type];
    if (unlikely(1 != EVP_DigestFinal(mdctx, md, &md_size)))
        goto ErrorExit;

    EVP_MD_CTX_destroy(mdctx);
  }

  return md_sizes[md_type];
}

EVP_PKEY *ossl_generate_openssl_keypair ( uint32_t key_type, uint64_t rsa_pubexp )
{
  EVP_PKEY           *pkey = NULL;
  EVP_PKEY_CTX       *ctx = NULL;
  BIGNUM             *bn = NULL;
  int                 nid;
  uint32_t            key_bits;

  switch(key_type)
  {
    case KEY_TYPE_RSA2048:
      key_bits = 2048;
      goto GoOn;
    case KEY_TYPE_RSA3072:
      key_bits = 3072;
      goto GoOn;
    case KEY_TYPE_RSA4096:
      key_bits = 4096;
GoOn:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
      if (unlikely(NULL == ctx))
        return NULL;
      if (unlikely(EVP_PKEY_keygen_init(ctx) <= 0))
      {
RSAErrorExit:
        if (NULL != bn)
          BN_free(bn);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)key_bits)))
        goto RSAErrorExit;
      bn = BN_new();
      if (unlikely(NULL == bn))
        goto RSAErrorExit;
      BN_set_word(bn, 0 == rsa_pubexp ? 65537 : rsa_pubexp);
      if (unlikely(1 != EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn)))
        goto RSAErrorExit;
      BN_free(bn), bn = NULL;

      if (unlikely(EVP_PKEY_keygen(ctx, &pkey) <= 0))
        goto RSAErrorExit;
      break;

    case KEY_TYPE_ECNIST256:
      nid = NID_X9_62_prime256v1;
      goto GenECCurve;
    case KEY_TYPE_ECNIST384:
      nid = NID_secp384r1;
      goto GenECCurve;
    case KEY_TYPE_ECNIST521:
      nid = NID_secp521r1;
      goto GenECCurve;
#if 0
    case SIG_TYPE_ECDSA_SECT571R1:
      nid = NID_sect571r1;
      goto GenECCurve;
#endif
    case KEY_TYPE_ECBPOOL256:
      nid = NID_brainpoolP256r1;
      goto GenECCurve;
    case KEY_TYPE_ECBPOOL384:
      nid = NID_brainpoolP384r1;
      goto GenECCurve;
    case KEY_TYPE_ECBPOOL512:
      nid = NID_brainpoolP512r1;
GenECCurve:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
      if (unlikely(NULL == ctx))
        return NULL;
      if (unlikely(EVP_PKEY_keygen_init(ctx) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      if (unlikely(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,nid)))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      if (unlikely(EVP_PKEY_keygen(ctx, &pkey) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      break;

    case KEY_TYPE_ED25519:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
      if (unlikely(NULL == ctx))
        return NULL;
      if (unlikely(EVP_PKEY_keygen_init(ctx) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      if (unlikely(EVP_PKEY_keygen(ctx, &pkey) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      break;

    case KEY_TYPE_ED448:
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
      if (unlikely(NULL == ctx))
        return NULL;
      if (unlikely(EVP_PKEY_keygen_init(ctx) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      if (unlikely(EVP_PKEY_keygen(ctx, &pkey) <= 0))
      {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
      }
      break;

    default:
      break;
  }

  if (NULL != ctx)
    EVP_PKEY_CTX_free(ctx);

  return pkey;
}

bool ossl_store_keypair ( const char *filename, EVP_PKEY *pkey )
{
  FILE       *f;
  uint8_t     password[PEM_BUFSIZE];
  uint32_t    passwd_len;

  if (unlikely(NULL == filename || NULL == pkey))
    return false;

  f = fopen(filename,"wb");
  if (NULL == f)
    return false;

  memset(password, 0, sizeof(password));

  if (secret_set || (0 != secret[0]))
    strncpy((char*)password, secret, sizeof(password) - 1);
  else
  {
    fprintf(stdout,"Please enter password twice for key pair enciphering (leave empty for plain storage).\n");
    EVP_read_pw_string((char*)password, sizeof(password), "Private key (key pair) password:", 1);
  }
  passwd_len = (uint32_t)strlen((const char*)password);

  if (0 == passwd_len)
  {
    if (!be_quiet)
      fprintf(stdout,"CAUTION: The generated key pair is being written to disk UNENCRYPTED (PLAIN)!\n");

    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
    {
      fclose(f);
      unlink(filename);
      return false;
    }
  }
  else
  {
    if (!PEM_write_PrivateKey(f, pkey, EVP_aes_256_cbc(),password, passwd_len, NULL, NULL))
    {
      fclose(f);
      unlink(filename);
      return false;
    }
  }

  fclose(f);

  return true;
}

EVP_PKEY *ossl_load_openssl_key ( const char *filename, bool *is_keypair, time_t *p_key_creation_ts )
{
  FILE       *f;
  EVP_PKEY   *pkey = NULL;
  uint8_t    *p_pem;
  uint32_t    l_pem;
  char       *p;
  uint64_t    systime = 0;

  if (unlikely(NULL == filename || NULL == is_keypair))
    return NULL;

  if (NULL != p_key_creation_ts)
    *p_key_creation_ts = 0;

  f = fopen(filename,"rb");

  if (NULL == f)
    return NULL;

  if (!PEM_read_PrivateKey(f, &pkey, NULL, (0 != secret[0] || secret_set) ? secret : NULL))
  {
    fseek(f,0L,SEEK_SET);
    if (!PEM_read_PUBKEY(f, &pkey, NULL, NULL))
    {
      fclose(f);
      return NULL;
    }

    fclose(f);
    *is_keypair = false;
    return pkey;
  }

  fclose(f);

  // try to read the key creation timestamp

  if (NULL != p_key_creation_ts)
  {
    p_pem = read_file(filename, &l_pem);
    if (NULL != p_pem)
    {
      p = strstr((const char*)p_pem, "KEY-CREATION-TIMESTAMP: ");
      if (NULL != p)
      {
        p += sizeof("KEY-CREATION-TIMESTAMP: ") - 1;
        if (IS_DDIGIT(p[0]) && IS_DDIGIT(p[1]) && IS_DDIGIT(p[2]) && IS_DDIGIT(p[3]) &&
          IS_DDIGIT(p[4]) && IS_DDIGIT(p[5]) &&
          IS_DDIGIT(p[6]) && IS_DDIGIT(p[7]) &&
          IS_DDIGIT(p[8]) && IS_DDIGIT(p[9]) &&
          IS_DDIGIT(p[10]) && IS_DDIGIT(p[11]) &&
          IS_DDIGIT(p[12]) && IS_DDIGIT(p[13]) &&
          'Z' == p[14])
        {
          if (time_date2systime(&systime,
            ((uint32_t)(p[0] - 0x30)) * 1000 + ((uint32_t)(p[1] - 0x30)) * 100 + ((uint32_t)(p[2] - 0x30)) * 10 + ((uint32_t)(p[3] - 0x30)),
            ((uint32_t)(p[4] - 0x30)) * 10 + ((uint32_t)(p[5] - 0x30)),
            ((uint32_t)(p[6] - 0x30)) * 10 + ((uint32_t)(p[7] - 0x30)),
            ((uint32_t)(p[8] - 0x30)) * 10 + ((uint32_t)(p[9] - 0x30)),
            ((uint32_t)(p[10] - 0x30)) * 10 + ((uint32_t)(p[11] - 0x30)),
            ((uint32_t)(p[12] - 0x30)) * 10 + ((uint32_t)(p[13] - 0x30))))
          {
            *p_key_creation_ts = (time_t)systime;
          }
        }
      }
      free(p_pem);
    }
  }

  *is_keypair = true;
  return pkey;
}

x509parsed_ptr ossl_parse_x509 ( const uint8_t *p_input, uint32_t l_input, bool is_pem )
{
  x509parsed_ptr            p_res;
  X509_NAME                *subjectDName;
  X509_NAME                *issuerDName;
  BIO                      *bio = NULL;
  char                     *pBio = NULL;
  long                      lenBio = 0;
  const unsigned char      *p;
  char                     *p_ossl;
  const ASN1_INTEGER       *p_serial;
  char                     *subjectDN, *p_attr, *p_attr2;
  const ASN1_TIME          *p_time;
  struct tm                 tm_datetime;
  int                       extId;
  X509_EXTENSION           *ext;
  const ASN1_OCTET_STRING  *exValue;
  const X509_ALGOR         *sig_algo;
  uint8_t                   sig_algo_der[4096];
  unsigned char            *p_sig_algo_der;
  uint32_t                  l_sig_algo_der, i;
  const ASN1_BIT_STRING    *p_x509_sig = NULL;
  uint64_t                  idx, derlen, derlen2;

  if (unlikely(NULL == p_input || 0 == l_input))
    return NULL;

  p_res = (x509parsed_ptr)malloc(sizeof(x509parsed));
  if (unlikely(NULL == p_res))
    return NULL;

  memset(p_res, 0x00, sizeof(x509parsed));

  p_res->key_usage = 0x02; // at least: SIGN

  if (!is_pem)
  {
    p = p_input;
    p_res->p_cert = d2i_X509(NULL, &p, (long)l_input);
    if (unlikely(NULL == p_res->p_cert || p != (p_input+l_input) ))
    {
ErrorExit:
      if (NULL != bio)
        BIO_free(bio);
      ossl_free_x509(p_res);
      return NULL;
    }
  }
  else // read X.509 from PEM
  {
    BIO *bio = BIO_new(BIO_s_mem());
    if (unlikely(NULL == bio))
      goto ErrorExit;
    BIO_write(bio, p_input, l_input);
    p_res->p_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (unlikely(NULL == p_res->p_cert))
      goto ErrorExit;
  }

  // get serial number

  p_serial = X509_get0_serialNumber(p_res->p_cert);
  if (unlikely(NULL == p_serial))
    goto ErrorExit;

  p_res->p_serialno = ASN1_INTEGER_to_BN(p_serial, NULL);
  if (unlikely(NULL == p_res->p_serialno))
    goto ErrorExit;

  p_ossl = BN_bn2dec(p_res->p_serialno);
  if (NULL != p_ossl)
  {
    strncpy(p_res->serialno_dec, p_ossl, sizeof(p_res->serialno_dec) - 1);
    OPENSSL_free(p_ossl);
  }

  p_ossl = BN_bn2hex(p_res->p_serialno);
  if (NULL != p_ossl)
  {
    p_res->serialno_hex[0] = '0';
    p_res->serialno_hex[1] = 'x';
    strncpy(&p_res->serialno_hex[2], p_ossl, sizeof(p_res->serialno_hex) - 3);
    OPENSSL_free(p_ossl);
  }

  // get subject DN -> get commonName -> get emailAddress

  subjectDN = X509_NAME_oneline(X509_get_subject_name(p_res->p_cert), NULL, 0);
  if (unlikely(NULL == subjectDN))
    goto ErrorExit;

  p_attr = strstr(subjectDN, "/CN=");
  if (NULL != p_attr)
  {
    p_attr2 = strchr(p_attr + 4, '/');

    if (NULL != p_attr2)
      p_res->l_commonName = (uint32_t)(p_attr2 - p_attr - 4);
    else
      p_res->l_commonName = (uint32_t)strlen(p_attr + 4);

    memcpy(p_res->commonName, p_attr + 4, p_res->l_commonName);
  }

  p_attr = strstr(subjectDN, "/emailAddress=");
  if (NULL != p_attr)
  {
    p_attr2 = strchr(p_attr + 14, '/');

    if (NULL != p_attr2)
      p_res->l_emailaddr = (uint32_t)(p_attr2 - p_attr - 14);
    else
      p_res->l_emailaddr = (uint32_t)strlen(p_attr + 14);

    memcpy(p_res->emailaddr, p_attr + 4, p_res->l_emailaddr);
  }

  OPENSSL_free(subjectDN);

  // get subjectDN and issuerDN

  subjectDName = X509_get_subject_name(p_res->p_cert); // MUST NOT be freed, is an OpenSSL-internal pointer
  issuerDName  = X509_get_issuer_name(p_res->p_cert);  // MUST NOT be freed, is an OpenSSL-internal pointer

  if (likely(NULL != subjectDName))
  {
    bio = BIO_new(BIO_s_mem());
    if ( NULL == bio )
      goto ErrorExit;

    X509_NAME_print_ex(bio,subjectDName,0,NAME_FLAGS);

    pBio = NULL;
    lenBio = BIO_get_mem_data(bio, &pBio);

    if ( pBio == NULL || lenBio <= 0 )
      goto ErrorExit;

    if (lenBio >= ((long)sizeof(p_res->subjectDN)))
      lenBio = (long)(sizeof(p_res->subjectDN) - 1);

    p_res->l_subjectDN = (uint32_t)lenBio;
    memcpy(p_res->subjectDN, pBio, (size_t)lenBio);

    BIO_free(bio), bio = NULL;
  }

  if (likely(NULL != issuerDName))
  {
    bio = BIO_new(BIO_s_mem());
    if ( NULL == bio )
      goto ErrorExit;

    X509_NAME_print_ex(bio,issuerDName,0,NAME_FLAGS);

    pBio = NULL;
    lenBio = BIO_get_mem_data(bio, &pBio);

    if ( pBio == NULL || lenBio <= 0 )
      goto ErrorExit;

    if (lenBio >= ((long)sizeof(p_res->issuerDN)))
      lenBio = (long)(sizeof(p_res->issuerDN) - 1);

    p_res->l_issuerDN = (uint32_t)lenBio;
    memcpy(p_res->issuerDN, pBio, (size_t)lenBio);

    BIO_free(bio), bio = NULL;
  }

  // get notBefore and notAfter

  p_time = X509_get0_notBefore(p_res->p_cert);
  if (unlikely(NULL == p_time))
    goto ErrorExit;
  memset(&tm_datetime, 0x00, sizeof(tm_datetime));
  ASN1_TIME_to_tm(p_time, &tm_datetime);

  if (!time_date2systime(&p_res->notBefore, tm_datetime.tm_year + 1900, tm_datetime.tm_mon + 1, tm_datetime.tm_mday,
      tm_datetime.tm_hour, tm_datetime.tm_min, tm_datetime.tm_sec))
    goto ErrorExit;

  p_time = X509_get0_notAfter(p_res->p_cert);
  if (unlikely(NULL == p_time))
    goto ErrorExit;
  memset(&tm_datetime, 0x00, sizeof(tm_datetime));
  ASN1_TIME_to_tm(p_time, &tm_datetime);

  if (!time_date2systime(&p_res->notAfter, tm_datetime.tm_year + 1900, tm_datetime.tm_mon + 1, tm_datetime.tm_mday,
      tm_datetime.tm_hour, tm_datetime.tm_min, tm_datetime.tm_sec))
    goto ErrorExit;

  // handle subjectKeyIdentifier

  extId = X509_get_ext_by_NID( p_res->p_cert, NID_subject_key_identifier, -1);
  if ( -1 != extId)
  {
    ASN1_OCTET_STRING *exValue;
    ext = X509_get_ext(p_res->p_cert, extId);
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
              p_res->l_subkid = (uint32_t)exValue->data[1];
              memcpy(p_res->subkid, exValue->data + 2, p_res->l_subkid);
            }
          }
        }
      }
    }
  }

  // handle keyUsage

  extId = X509_get_ext_by_NID( p_res->p_cert, NID_key_usage, -1);
  if ( -1 != extId)
  {
    ASN1_OCTET_STRING *exValue;
    ext = X509_get_ext(p_res->p_cert, extId);
    if (NULL != ext && NULL != (exValue = X509_EXTENSION_get_data(ext)))
    {
      if (exValue->length>3) // TAG 03 (BIT STRING), <len>, <unused bits in final octet>, <content>
      {
        if (0x03==exValue->data[0] && 2==exValue->data[1])
        {
          p_res->key_usage = 0x00;
          if (exValue->data[3] & 0x80) // digitalSignature
            p_res->key_usage |= 0x02;  // This key may be used to sign data
          if (exValue->data[3] & 0x20) // keyEncipherment
            p_res->key_usage |= 0x04;  // This key may be used to encrypt communications
          if (exValue->data[3] & 0x10) // dataEncipherment
            p_res->key_usage |= 0x04;  // This key may be used to encrypt communications
          if (exValue->data[3] & 0x04) // keyCertSign
            p_res->key_usage |= 0x01;  // This key may be used to make User ID certifications

          if (0x00 == p_res->key_usage)
            p_res->key_usage = 0x02; // at least: SIGN
        }
      }
    }
  }

  // handle subjectAlternativeNames to get E-mail address (info: this overwrites any E-mail address extracted from the subject DN!)

  extId = X509_get_ext_by_NID(p_res->p_cert, NID_subject_alt_name, -1); // GeneralNames ::= SEQUENCE OF GeneralName
  if ( -1 != extId )
  {
    ext = X509_get_ext(p_res->p_cert, extId);
    if (NULL != ext && NULL != (exValue = X509_EXTENSION_get_data(ext)))
    {
      uint64_t fulllen = (uint32_t)exValue->length, idx = 0, derlen, end_idx;

      if (fulllen > 1)
      {
        if (0x30 == exValue->data[idx]) // outer SEQUENCE
        {
          idx++;
          if (asn1_decodelen(exValue->data, fulllen, &derlen, &idx)) // length of SEQUENCE = length of GeneralNames
          {
            end_idx = idx + derlen;
            while (idx != end_idx)
            {
              // check if this tag is 0x81: rfc822Name [1] IMPLICIT IA5String

              if (0x81 == exValue->data[idx]) // yes, this is an IA5String, which is the email address
              {
                idx++;
                if (!asn1_decodelen(exValue->data, fulllen, &derlen, &idx))
                  break;

                memset(p_res->emailaddr, 0x00, sizeof(p_res->emailaddr));
                p_res->l_emailaddr = (uint32_t)derlen;
                memcpy(p_res->emailaddr, exValue->data + idx, derlen);
                break;
              }
              else
              {
                idx++;
                if (!asn1_decodelen(exValue->data, fulllen, &derlen, &idx))
                  break;
                idx += derlen;
              }
            }
          }
        }
      }
    }
  }

  // get public key

  p_res->p_pubkey = X509_get0_pubkey(p_res->p_cert);
  if (unlikely(NULL == p_res->p_pubkey))
    goto ErrorExit;

  if (!ossl_pubkey_algo_from_evp(p_res->p_pubkey, &p_res->pk_algo, &p_res->pk_key_bits, &p_res->pk_ec_curve, &p_res->pk_ec_complen, &p_res->pk_rsa_pubexp))
    goto ErrorExit;

  // get signature algorithm

  //sig_algo = X509_get0_tbs_sigalg(p_res->p_cert);
  X509_get0_signature(&p_x509_sig, &sig_algo, p_res->p_cert);

  if (unlikely(NULL == p_x509_sig || NULL == sig_algo))
    goto ErrorExit;

  p_sig_algo_der = sig_algo_der;
  memset(sig_algo_der, 0x00, sizeof(sig_algo_der));
  l_sig_algo_der = (uint32_t)i2d_X509_ALGOR(sig_algo, &p_sig_algo_der);

  if (unlikely(0 == l_sig_algo_der))
    goto ErrorExit;

  for (i = 0; i < sizeof(x509_sigalgos) / sizeof(x509_sigalgos[0]); i++)
  {
    if ((l_sig_algo_der == x509_sigalgos_len[i]) && (!memcmp(sig_algo_der, x509_sigalgos[i], l_sig_algo_der)))
      break;
  }

  if (i == (sizeof(x509_sigalgos) / sizeof(x509_sigalgos[0])))
    goto ErrorExit; // X.509 parsing OK but unsupported X.509 signature algorithm found

  p_res->x509_sig_algo = i;

  switch(p_res->x509_sig_algo)
  {
    case X509_SIG_ALGO_PKCS1_V15_SHA256:
    case X509_SIG_ALGO_PKCS1_V15_SHA384:
    case X509_SIG_ALGO_PKCS1_V15_SHA512:
    case X509_SIG_ALGO_RSAPSS_SHA256:
    case X509_SIG_ALGO_RSAPSS_SHA384:
    case X509_SIG_ALGO_RSAPSS_SHA512:
      switch(p_x509_sig->length)
      {
        case 256:
        case 384:
        case 512:
          p_res->sig_bit_size = p_x509_sig->length << 3;
          break;
        default:
          goto ErrorExit;
      }
      break;

    case X509_SIG_ALGO_ECDSA_SHA256:
    case X509_SIG_ALGO_ECDSA_SHA384:
    case X509_SIG_ALGO_ECDSA_SHA512:
      idx = 0;
      if (0x30 != p_x509_sig->data[idx]) // ASN.1 SEQUENCE
        goto ErrorExit;
      idx++;
      if (!asn1_decodelen(p_x509_sig->data, p_x509_sig->length, &derlen, &idx))
        goto ErrorExit;
      if (0x02 != p_x509_sig->data[idx]) // INTEGER R in ASN.1 SEQUENCE
        goto ErrorExit;
      idx++;
      if (!asn1_decodelen(p_x509_sig->data, p_x509_sig->length, &derlen, &idx))
        goto ErrorExit;
      if (0x00 == p_x509_sig->data[idx])
        p_res->sig_bit_size = ((uint32_t)(derlen - 1)) << 3;
      else
      {
        p_res->sig_bit_size = ((uint32_t)derlen) << 3;
      }
      idx += derlen;
      if (0x02 != p_x509_sig->data[idx]) // INTEGER S in ASN.1 SEQUENCE
        goto ErrorExit;
      idx++;
      if (!asn1_decodelen(p_x509_sig->data, p_x509_sig->length, &derlen2, &idx))
        goto ErrorExit;
      if (0x00 == p_x509_sig->data[idx])
        p_res->sig_bit_size2 = ((uint32_t)(derlen - 1)) << 3;
      else
      {
        p_res->sig_bit_size2 = ((uint32_t)derlen) << 3;
      }
      idx += derlen2;
      if (idx != ((uint64_t)p_x509_sig->length))
        goto ErrorExit;
      if (p_res->sig_bit_size > p_res->sig_bit_size2)
        p_res->sig_bit_size2 = p_res->sig_bit_size;
      else
      if (p_res->sig_bit_size2 > p_res->sig_bit_size)
        p_res->sig_bit_size = p_res->sig_bit_size2;
      break;

    case X509_SIG_ALGO_EDDSA_ED25519:
      if ((2*32) != p_x509_sig->length)
        goto ErrorExit;
      p_res->sig_bit_size = 255;
      p_res->sig_bit_size2 = 255;
      break;

    case X509_SIG_ALGO_EDDSA_ED448:
      if ((2*57) != p_x509_sig->length)
        goto ErrorExit;
      p_res->sig_bit_size = 448;
      p_res->sig_bit_size2 = 448;
      break;

    default:
      goto ErrorExit;
  }

  return p_res;
}

void ossl_free_x509 ( x509parsed_ptr p_cert )
{
  if (NULL != p_cert)
  {
    if (NULL != p_cert->p_cert)
      X509_free(p_cert->p_cert);
    if (NULL != p_cert->p_serialno)
      BN_free(p_cert->p_serialno);
    free(p_cert);
  }
}

const EVP_MD* ossl_get_evp_md_by_type ( uint32_t md_type )
{
  switch (md_type)
  {
    case MD_TYPE_SHA1:
      return EVP_sha1();
    case MD_TYPE_RIPEMD160:
      return EVP_ripemd160();
    case MD_TYPE_SHA2_224:
      return EVP_sha224();
    case MD_TYPE_SHA2_256:
      return EVP_sha256();
    case MD_TYPE_SHA2_384:
      return EVP_sha384();
    case MD_TYPE_SHA2_512:
      return EVP_sha512();
    case MD_TYPE_SHA3_224:
      return EVP_sha3_224();
    case MD_TYPE_SHA3_256:
      return EVP_sha3_256();
    case MD_TYPE_SHA3_384:
      return EVP_sha3_384();
    case MD_TYPE_SHA3_512:
      return EVP_sha3_512();
    case MD_TYPE_SHAKE_256:
      return EVP_shake256();
    default:
      return NULL;
  }
}

static uint32_t ossl_ecdsa_get_component_length ( uint32_t sig_type )
{
  uint32_t complen;

  switch(sig_type)
  {
    case SIG_TYPE_ECDSA_SECP256R1:
      complen = 32;
      break;
    case SIG_TYPE_ECDSA_SECP384R1:
      complen = 48;
      break;
    case SIG_TYPE_ECDSA_SECP521R1:
      complen = 66;
      break;
    case SIG_TYPE_ECDSA_SECT571R1:
      complen = 72;
      break;
    case SIG_TYPE_ECDSA_BRAINPOOLP256R1:
      complen = 32;
      break;
    case SIG_TYPE_ECDSA_BRAINPOOLP384R1:
      complen = 48;
      break;
    default: // case SIG_TYPE_ECDSA_BRAINPOOLP512R1:
      complen = 64;
      break;
  }
  return complen;
}

bool ossl_create_digital_signature ( EVP_PKEY *pkey, uint32_t sig_type, uint32_t md_type, const uint8_t *tbs, uint32_t tbs_size, uint8_t **sig, uint32_t *sig_size, bool ecdsaAsn1, bool edPh )
{
  bool                    status     = false;
  EVP_MD_CTX             *mdctx      = NULL;
  EVP_PKEY_CTX           *keyctx     = NULL;
  const EVP_MD           *md         = NULL;
  uint8_t                *sig_buffer = NULL;
  size_t                  siglen     = 0;
  uint32_t                max_sig_size;
  uint32_t                complen;
  uint8_t                 ecdsa_rawsig[72 * 2]; // 72 is for 571bit NIST curve (biggest)
  const OSSL_PARAM       *params = NULL;
  uint8_t                 hashval[SHA512_DIGEST_LENGTH];
  uint32_t                l_hashval;

  if (unlikely( NULL == pkey || NULL == tbs || 0 == tbs_size || NULL == sig || NULL == sig_size))
    return false;

  *sig = NULL;
  *sig_size = 0;

  if (unlikely(NULL == (mdctx = EVP_MD_CTX_new())))
  {
out:
    if (NULL != mdctx)
      EVP_MD_CTX_free(mdctx); // this also frees keyctx (if not NULL)
    if (NULL != sig_buffer)
      free(sig_buffer);
    return status;
  }

  // no MD for ED25519 and ED448!!!

  if (SIG_TYPE_EDDSA_25519 != sig_type && SIG_TYPE_EDDSA_448 != sig_type)
  {
    md = ossl_get_evp_md_by_type(md_type);
    if (1 != EVP_DigestSignInit(mdctx, &keyctx, md, NULL, pkey))
      goto out;
  }
  else
  {
    if (edPh)
    {
      if (SIG_TYPE_EDDSA_25519 == sig_type)
      {
        if (MD_TYPE_SHA2_256 != md_type && MD_TYPE_SHA2_512 != md_type)
          goto out;
        md = ossl_get_evp_md_by_type(md_type);
        params = params25519;
        l_hashval = sizeof(hashval);
        if (unlikely(1 != EVP_Digest(tbs, tbs_size, hashval, &l_hashval, md, NULL)))
          goto out;
      }
      else
      {
        if (MD_TYPE_SHA2_512 != md_type)
          goto out;
        md = ossl_get_evp_md_by_type(MD_TYPE_SHA2_512);
        params = params448;
        l_hashval = sizeof(hashval);
        if (unlikely(1 != EVP_Digest(tbs, tbs_size, hashval, &l_hashval, md, NULL)))
          goto out;
      }

      if (1 != EVP_DigestSignInit_ex(mdctx,NULL,NULL,NULL,NULL,pkey, params))
        goto out;
    }
    else
    {
      if (1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey))
        goto out;
    }
  }

  switch (sig_type)
  {
    case SIG_TYPE_RSA_PKCS1_V15:
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_padding(keyctx, RSA_PKCS1_PADDING)))
        goto out;
      break;

    case SIG_TYPE_RSA_PSS_SHA256:
    case SIG_TYPE_RSA_PSS_SHA384:
    case SIG_TYPE_RSA_PSS_SHA512:
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_padding(keyctx, RSA_PKCS1_PSS_PADDING)))
        goto out;
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_mgf1_md(keyctx, md)))
        goto out;
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(keyctx, EVP_MD_size(md) )))
        goto out;
      break;

    default:
      break;
  }

  max_sig_size = ((uint32_t)EVP_PKEY_size(pkey)) + 32;

  sig_buffer = (uint8_t*)malloc(max_sig_size);
  if (unlikely(NULL == sig_buffer))
    goto out;

  siglen = max_sig_size;

  if (edPh && NULL != params)
  {
    if (1 != EVP_DigestSign(mdctx, sig_buffer, &siglen, hashval, l_hashval))
      goto out;
  }
  else
  {
    if (1 != EVP_DigestSign(mdctx, sig_buffer, &siglen, tbs, tbs_size))
      goto out;
  }

  *sig = (uint8_t*)malloc(siglen);
  if (unlikely(NULL == *sig))
    goto out;
  memcpy(*sig, sig_buffer, siglen);

  *sig_size = (uint32_t)siglen;

  if ((!ecdsaAsn1) && (sig_type >= SIG_TYPE_ECDSA_SECP256R1) && (sig_type <= SIG_TYPE_ECDSA_BRAINPOOLP512R1)) // OpenSSL returns ASN.1, which we have to convert
  {
    complen = ossl_ecdsa_get_component_length(sig_type);

    if (!asn1ECDSAASN1RSSequence2RawSignature(*sig, *sig_size, ecdsa_rawsig, complen << 1))
    {
      free(*sig), *sig = NULL;
      *sig_size = 0;
      goto out;
    }

    memcpy(*sig, ecdsa_rawsig, complen << 1); // we can just copy the raw signature because it is SMALLER than the ASN.1 version...
    *sig_size = complen << 1;
  }

#if 0
  if (SIG_TYPE_EDDSA_25519 == sig_type)
  {
    if (unlikely(64 != *sig_size))
    {
      free(*sig), *sig = NULL;
      *sig_size = 0;
      goto out;
    }

    if (unlikely( 0 != (0xC0 & (*sig)[63]))) // most significant three bits in final octet have to be zero
    {
      free(*sig), *sig = NULL;
      *sig_size = 0;
      goto out;
    }
  }
#endif

  status = true;
  goto out;
}

bool ossl_verify_digital_signature ( EVP_PKEY *pkey, uint32_t sig_type, uint32_t md_type, const uint8_t *tbs, uint32_t tbs_size, const uint8_t *sig, uint32_t sig_size, bool edPh )
{
  bool                    status = false;
  int                     int_status;
  EVP_MD_CTX             *mdctx  = NULL;
  EVP_PKEY_CTX           *keyctx = NULL;
  const EVP_MD           *md     = NULL;
  const OSSL_PARAM       *params = NULL;
  uint8_t                 hashval[SHA512_DIGEST_LENGTH], *p_ecdsa_asn1sig = NULL;
  uint32_t                l_hashval, l_ecdsa_asn1sig = 0;

  if (unlikely( NULL == pkey || NULL == tbs || 0 == tbs_size || NULL == sig || 0 == sig_size))
    return false;

  if (unlikely(NULL == (mdctx = EVP_MD_CTX_create())))
  {
out:
    if (NULL != mdctx)
      EVP_MD_CTX_free(mdctx); // this also frees keyctx (if not NULL)
    if (NULL != p_ecdsa_asn1sig)
      free(p_ecdsa_asn1sig);
    return status;
  }

  // for ECDSA, we have to encode the digital signature as an ASN.1 structur

  if (IS_ECDSA(sig_type))
  {
    uint32_t complen = ossl_ecdsa_get_component_length(sig_type);

    if (sig_size == (complen << 1)) // this is kind of a stupid test, but anyway...
      p_ecdsa_asn1sig = asn1ECDSARawSignature2ASN1RSSequence(sig, sig_size, &l_ecdsa_asn1sig);
  }

  // no MD for ED25519 and ED448!!!

  if (SIG_TYPE_EDDSA_25519 != sig_type && SIG_TYPE_EDDSA_448 != sig_type)
  {
    md = ossl_get_evp_md_by_type(md_type);
    if (1 != EVP_DigestVerifyInit(mdctx, &keyctx, md, NULL, pkey))
      goto out;
  }
  else
  {
    if (edPh)
    {
      if (SIG_TYPE_EDDSA_25519 == sig_type)
      {
        if (MD_TYPE_SHA2_256 != md_type && MD_TYPE_SHA2_512 != md_type)
          goto out;
        md = ossl_get_evp_md_by_type(md_type);
        params = params25519;
        l_hashval = sizeof(hashval);
        if (unlikely(1 != EVP_Digest(tbs, tbs_size, hashval, &l_hashval, md, NULL)))
          goto out;
      }
      else
      {
        if (MD_TYPE_SHA2_512 != md_type)
          goto out;
        md = ossl_get_evp_md_by_type(MD_TYPE_SHA2_512);
        params = params448;
        l_hashval = sizeof(hashval);
        if (unlikely(1 != EVP_Digest(tbs, tbs_size, hashval, &l_hashval, md, NULL)))
          goto out;
      }

      if (1 != EVP_DigestVerifyInit_ex(mdctx,NULL,NULL,NULL,NULL,pkey, params))
        goto out;
    }
    else
    {
      if (1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey))
        goto out;
    }
  }

  switch (sig_type)
  {
    case SIG_TYPE_RSA_PKCS1_V15:
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_padding(keyctx, RSA_PKCS1_PADDING)))
        goto out;
      break;

    case SIG_TYPE_RSA_PSS_SHA256:
    case SIG_TYPE_RSA_PSS_SHA384:
    case SIG_TYPE_RSA_PSS_SHA512:
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_padding(keyctx, RSA_PKCS1_PSS_PADDING)))
        goto out;
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_mgf1_md(keyctx, md)))
        goto out;
      if (unlikely(1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(keyctx, EVP_MD_size(md) )))
        goto out;
      break;

    default:
      break;
  }

  if (edPh && NULL != params)
  {
    int_status = EVP_DigestVerify(mdctx, sig, (size_t)sig_size, hashval, (size_t)l_hashval); // 1 = OK, 0 = sig not valid, any other: error
  }
  else
  {
    if (NULL == p_ecdsa_asn1sig)
      int_status = EVP_DigestVerify(mdctx, sig, (size_t)sig_size, tbs, (size_t)tbs_size); // 1 = OK, 0 = sig not valid, any other: error
    else
      int_status = EVP_DigestVerify(mdctx, p_ecdsa_asn1sig, (size_t)l_ecdsa_asn1sig, tbs, (size_t)tbs_size);
  }

  if (1 == int_status) // OK
    status = true;
  else
  if (0 == int_status) // sig tastes bad
    status = false;
  else
    status = false; // full error, something terribly went wrong

  goto out;
}

bool ossl_pubkey_algo_from_evp ( const EVP_PKEY *p_evp_key, uint32_t *p_pk_algo, uint32_t *p_key_bits, uint32_t *p_ec_curve, uint32_t *p_ec_complen, uint64_t *p_rsa_pubexp )
{
  const RSA              *p_rsa_key;
  const EC_KEY           *p_ec_key;
  const EC_GROUP         *p_ec_group;
  const BIGNUM           *p_n, *p_e;
  int                     ec_curve_nid;
  uint32_t                num_bytes, num_bits, run, idx, num_copy_bytes;
  uint8_t                *p_bn_bytes;
  union
  {
    volatile uint64_t     ui64;
    volatile uint8_t      ui8[8];
  }                       u;

  if (unlikely(NULL == p_evp_key || NULL == p_pk_algo || NULL == p_key_bits))
  {
    if (NULL != p_pk_algo)
      *p_pk_algo = 0xFFFFFFFF;
    if (NULL != p_key_bits)
      *p_key_bits = 0xFFFFFFFF;
    return false;
  }

  *p_pk_algo = (uint32_t)-1;
  *p_key_bits = (uint32_t)-1;

  if (NULL != p_ec_curve)
    *p_ec_curve = (uint32_t)-1;

  if (NULL != p_ec_complen)
    *p_ec_complen = (uint32_t)-1;

  if (NULL != p_rsa_pubexp)
    *p_rsa_pubexp = (uint64_t)-1;

  switch(EVP_PKEY_id(p_evp_key))
  {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2: // this is an RSA (public) key
      p_rsa_key = EVP_PKEY_get0_RSA(p_evp_key);

      if (unlikely(NULL == p_rsa_key))
        return false;

      p_n = RSA_get0_n(p_rsa_key);
      p_e = RSA_get0_e(p_rsa_key);

      if (unlikely(NULL == p_n || NULL == p_e))
        return false;

      num_bytes = (uint32_t)BN_num_bytes(p_n);
      if (unlikely(0 == num_bytes))
        return false;

      p_bn_bytes = (uint8_t*)malloc(num_bytes);

      if (unlikely(NULL == p_bn_bytes))
        return false;

      BN_bn2bin(p_n, p_bn_bytes);

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

      free(p_bn_bytes);

      if (unlikely(0 == run))
        return false;

      *p_pk_algo = X509_PK_ALGO_RSA;
      *p_key_bits = num_bits;

      if (NULL != p_rsa_pubexp)
      {
        // get up to sizeof(uint64_t) from the big integer, most likely everything because 0x10001 or 0xC0000001 are quite often used (32bit)

        num_bytes = (uint32_t)BN_num_bytes(p_e);
        if (unlikely(0 == num_bytes))
          return false;

        p_bn_bytes = (uint8_t*)malloc(num_bytes);

        if (unlikely(NULL == p_bn_bytes))
          return false;

        BN_bn2bin(p_e, p_bn_bytes);

        num_copy_bytes = (num_bytes > sizeof(uint64_t)) ? sizeof(uint64_t) : num_bytes;

        u.ui64 = 0;
        memcpy((void*)&u.ui8[sizeof(uint64_t) - num_copy_bytes], p_bn_bytes + num_bytes - num_copy_bytes, num_copy_bytes);
        free(p_bn_bytes);
#ifdef DATA_ORDER_IS_BIG_ENDIAN
        *p_rsa_pubexp = u.ui64;
#else
        *p_rsa_pubexp = bswap_64(u.ui64);
#endif
      }
      break;

    case EVP_PKEY_EC: // Elliptic Curve
      p_ec_key = EVP_PKEY_get0_EC_KEY(p_evp_key);
      if (unlikely(NULL == p_ec_key))
        return false;

      p_ec_group = EC_KEY_get0_group(p_ec_key);
      if (unlikely(NULL == p_ec_group))
        return false;

      ec_curve_nid = EC_GROUP_get_curve_name(p_ec_group);

      *p_pk_algo = X509_PK_ALGO_EC;

      switch(ec_curve_nid)
      {
        case NID_X9_62_prime256v1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_NIST_256;
          *p_key_bits = 256;
          if (NULL != p_ec_complen)
            *p_ec_complen = 32;
          break;
        case NID_secp384r1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_NIST_384;
          *p_key_bits = 384;
          if (NULL != p_ec_complen)
            *p_ec_complen = 48;
          break;
        case NID_secp521r1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_NIST_521;
          *p_key_bits = 521;
          if (NULL != p_ec_complen)
            *p_ec_complen = 66;
          break;
        case NID_brainpoolP256r1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_BRAINPOOL_256;
          *p_key_bits = 256;
          if (NULL != p_ec_complen)
            *p_ec_complen = 32;
          break;
        case NID_brainpoolP384r1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_BRAINPOOL_384;
          *p_key_bits = 384;
          if (NULL != p_ec_complen)
            *p_ec_complen = 48;
          break;
        case NID_brainpoolP512r1:
          if (NULL != p_ec_curve)
              *p_ec_curve = CURVE_BRAINPOOL_512;
          *p_key_bits = 512;
          if (NULL != p_ec_complen)
            *p_ec_complen = 64;
          break;
        default:
          return false;
      }
      break;

    case EVP_PKEY_ED25519:
      *p_pk_algo = X509_PK_ALGO_ED;
      if (NULL != p_ec_curve)
          *p_ec_curve = CURVE_ED25519;
      *p_key_bits = 255;
      if (NULL != p_ec_complen)
        *p_ec_complen = 32;
      break;

    case EVP_PKEY_ED448:
      *p_pk_algo = X509_PK_ALGO_ED;
      if (NULL != p_ec_curve)
          *p_ec_curve = CURVE_ED448;
      *p_key_bits = 448;
      if (NULL != p_ec_complen)
        *p_ec_complen = 57;
      break;

    default:
      return false;
  }

  return true;
}
