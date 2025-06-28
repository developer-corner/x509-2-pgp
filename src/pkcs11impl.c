/**
 * @file   pkcs11impl.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implementation of all PKCS#11 specific stuff
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

#include <pkcs11impl.h>
#include <osslimpl.h>
#include <utils.h>

static void                    *g_pkcs11LibHandle     = NULL;
static CK_FUNCTION_LIST_PTR     g_pkcs11_functions    = NULL;
static CK_SESSION_HANDLE        g_pkcs11_session      = CK_INVALID_HANDLE;
static CK_SLOT_ID               g_pkcs11_slot         = 0;
extern bool                     be_quiet;

#define NUM_PKCS11_ELLIPTIC_CURVES                52

typedef struct _ellcurve          ellcurve;

struct _ellcurve
{
  int                         openssl_nid;
  char                        named_curve[24];
  char                        oid_curve[24];
  uint32_t                    bits;
  uint8_t                     oid_der[12];
};

static const ellcurve elliptic_curves[NUM_PKCS11_ELLIPTIC_CURVES] =
{
  /* 00 */{ NID_secp112r1,        "secp112r1",            "1.3.132.0.6",            112, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x06 } },
  /* 01 */{ NID_secp112r2,        "secp112r2",            "1.3.132.0.7",            112, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x07 } },
  /* 02 */{ NID_secp128r1,        "secp128r1",            "1.3.132.0.28",           128, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1C } },
  /* 03 */{ NID_secp128r2,        "secp128r2",            "1.3.132.0.29",           128, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1D } },
  /* 04 */{ NID_secp160k1,        "secp160k1",            "1.3.132.0.9",            160, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x09 } },
  /* 05 */{ NID_secp160r1,        "secp160r1",            "1.3.132.0.8",            160, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x08 } },
  /* 06 */{ NID_secp160r2,        "secp160r2",            "1.3.132.0.30",           160, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1E } },
  /* 07 */{ NID_secp192k1,        "secp192k1",            "1.3.132.0.31",           192, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1F } },
  /* 08 */{ NID_secp224k1,        "secp224k1",            "1.3.132.0.32",           224, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x20 } },
  /* 09 */{ NID_secp224r1,        "secp224r1",            "1.3.132.0.33",           224, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 } },
  /* 10 */{ NID_secp256k1,        "secp256k1",            "1.3.132.0.10",           256, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A } },
  /* 11 */{ NID_secp384r1,        "prime384v1/secp384r1", "1.3.132.0.34",           384, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 } },
  /* 12 */{ NID_secp521r1,        "secp521r1",            "1.3.132.0.35",           521, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 } },
  /* 13 */{ NID_sect113r1,        "sect113r1",            "1.3.132.0.4",            113, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x04 } },
  /* 14 */{ NID_sect113r2,        "sect113r2",            "1.3.132.0.5",            113, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x05 } },
  /* 15 */{ NID_sect131r1,        "sect131r1",            "1.3.132.0.22",           131, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x16 } },
  /* 16 */{ NID_sect131r2,        "sect131r2",            "1.3.132.0.23",           131, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x17 } },
  /* 17 */{ NID_sect163k1,        "sect163k1",            "1.3.132.0.1",            163, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x01 } },
  /* 18 */{ NID_sect163r1,        "sect163r1",            "1.3.132.0.2",            163, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x02 } },
  /* 19 */{ NID_sect163r2,        "sect163r2",            "1.3.132.0.15",           163, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0F } },
  /* 20 */{ NID_sect193r1,        "sect193r1",            "1.3.132.0.24",           193, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x18 } },
  /* 21 */{ NID_sect193r2,        "sect193r2",            "1.3.132.0.25",           193, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x19 } },
  /* 22 */{ NID_sect233k1,        "sect233k1",            "1.3.132.0.26",           233, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1A } },
  /* 23 */{ NID_sect233r1,        "sect233r1",            "1.3.132.0.27",           233, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1B } },
  /* 24 */{ NID_sect239k1,        "sect239k1",            "1.3.132.0.3",            239, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x03 } },
  /* 25 */{ NID_sect283k1,        "sect283k1",            "1.3.132.0.16",           283, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x10 } },
  /* 26 */{ NID_sect283r1,        "sect283r1",            "1.3.132.0.17",           283, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x11 } },
  /* 27 */{ NID_sect409k1,        "sect409k1",            "1.3.132.0.36",           409, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x24 } },
  /* 28 */{ NID_sect409r1,        "sect409r1",            "1.3.132.0.37",           409, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x25 } },
  /* 29 */{ NID_sect571k1,        "sect571k1",            "1.3.132.0.38",           571, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x26 } },
  /* 30 */{ NID_sect571r1,        "sect571r1",            "1.3.132.0.39",           571, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x27 } },
  /* 31 */{ NID_X9_62_prime192v1, "prime192v1/secp192r1", "1.2.840.10045.3.1.1",    192, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 } },
  /* 32 */{ NID_X9_62_prime192v2, "prime192v2",           "1.2.840.10045.3.1.2",    192, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x02 } },
  /* 33 */{ NID_X9_62_prime192v3, "prime192v3",           "1.2.840.10045.3.1.3",    192, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x03 } },
  /* 34 */{ NID_X9_62_prime239v1, "prime239v1",           "1.2.840.10045.3.1.4",    239, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x04 } },
  /* 35 */{ NID_X9_62_prime239v2, "prime239v2",           "1.2.840.10045.3.1.5",    239, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x05 } },
  /* 36 */{ NID_X9_62_prime239v3, "prime239v3",           "1.2.840.10045.3.1.6",    239, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x06 } },
  /* 37 */{ NID_X9_62_prime256v1, "prime256v1/secp256r1", "1.2.840.10045.3.1.7",    256, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 } },
  /* 38 */{ NID_brainpoolP160r1,  "brainpoolP160r1",      "1.3.36.3.3.2.8.1.1.1",   160, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 } },
  /* 39 */{ NID_brainpoolP160t1,  "brainpoolP160t1",      "1.3.36.3.3.2.8.1.1.2",   160, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02 } },
  /* 40 */{ NID_brainpoolP192r1,  "brainpoolP192r1",      "1.3.36.3.3.2.8.1.1.3",   192, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 } },
  /* 41 */{ NID_brainpoolP192t1,  "brainpoolP192t1",      "1.3.36.3.3.2.8.1.1.4",   192, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04 } },
  /* 42 */{ NID_brainpoolP224r1,  "brainpoolP224r1",      "1.3.36.3.3.2.8.1.1.5",   224, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 } },
  /* 43 */{ NID_brainpoolP224t1,  "brainpoolP224t1",      "1.3.36.3.3.2.8.1.1.6",   224, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06 } },
  /* 44 */{ NID_brainpoolP256r1,  "brainpoolP256r1",      "1.3.36.3.3.2.8.1.1.7",   256, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 } },
  /* 45 */{ NID_brainpoolP256t1,  "brainpoolP256t1",      "1.3.36.3.3.2.8.1.1.8",   256, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08 } },
  /* 46 */{ NID_brainpoolP320r1,  "brainpoolP320r1",      "1.3.36.3.3.2.8.1.1.9",   320, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 } },
  /* 47 */{ NID_brainpoolP320t1,  "brainpoolP320t1",      "1.3.36.3.3.2.8.1.1.10",  320, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0A } },
  /* 48 */{ NID_brainpoolP384r1,  "brainpoolP384r1",      "1.3.36.3.3.2.8.1.1.11",  384, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B } },
  /* 49 */{ NID_brainpoolP384t1,  "brainpoolP384t1",      "1.3.36.3.3.2.8.1.1.12",  384, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0C } },
  /* 50 */{ NID_brainpoolP512r1,  "brainpoolP512r1",      "1.3.36.3.3.2.8.1.1.13",  512, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D } },
  /* 51 */{ NID_brainpoolP512t1,  "brainpoolP512t1",      "1.3.36.3.3.2.8.1.1.14",  512, { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E } }
};

static const ellcurve edwards_curves[2] =
{
  { NID_ED25519, "ed25519",  "1.3.101.112", 255, { 0x06, 0x03, 0x2B, 0x65, 0x70 } },
  { NID_ED448,   "ed448",    "1.3.101.113", 448, { 0x06, 0x03, 0x2B, 0x65, 0x71 } }
};

#ifdef _LINUX

static CK_RV p11_createmutex(void **mutex)
{
  pthread_mutex_t *mut = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  if (unlikely(NULL == mut))
    return CKR_HOST_MEMORY;
  if (unlikely(0 != pthread_mutex_init(mut, NULL)))
  {
    free(mut);
    return CKR_MUTEX_BAD;
  }
  *mutex = (void*)mut;
  return CKR_OK;
}

static CK_RV p11_destroymutex(void *mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  pthread_mutex_destroy((pthread_mutex_t*)mutex);
  free(mutex);
  return CKR_OK;
}

static CK_RV p11_lockmutex(void *mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  return 0 == pthread_mutex_lock((pthread_mutex_t*)mutex) ? CKR_OK : CKR_MUTEX_NOT_LOCKED;
}

static CK_RV p11_unlockmutex(void *mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  return 0 == pthread_mutex_unlock((pthread_mutex_t*)mutex) ? CKR_OK : CKR_MUTEX_BAD;
}

#elif defined(_WINDOWS)

static CK_RV p11_createmutex(void** mutex)
{
  if (unlikely( NULL == (*mutex = CreateMutex(NULL, FALSE, NULL))))
    return CKR_MUTEX_BAD;
  return CKR_OK;
}

static CK_RV p11_destroymutex(void* mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  CloseHandle(mutex);
  return CKR_OK;
}

static CK_RV p11_lockmutex(void* mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  return WAIT_OBJECT_0 == WaitForSingleObject(mutex, INFINITE) ? CKR_OK : CKR_MUTEX_NOT_LOCKED;
}

static CK_RV p11_unlockmutex(void* mutex)
{
  if (unlikely(NULL == mutex))
    return CKR_MUTEX_BAD;
  return ReleaseMutex(mutex) ? CKR_OK : CKR_MUTEX_BAD;
}

#endif

bool pkcs11_init ( const char *pkcs11_lib_name, uint32_t pkcs11_slot )
{
  CK_C_GetFunctionList      p11GetFunctionList;
  int                       rv;
  CK_C_INITIALIZE_ARGS      init_args;
  struct stat               st;

  g_pkcs11_slot = (CK_SLOT_ID)pkcs11_slot;

  if (unlikely(NULL == pkcs11_lib_name))
    return false;

  if (NULL != g_pkcs11LibHandle)
    return true;

  if (0 != stat(pkcs11_lib_name, &st))
    return false;

#ifndef _WINDOWS
  g_pkcs11LibHandle = dlopen(pkcs11_lib_name, RTLD_LAZY);
#else
  g_pkcs11LibHandle = LoadLibraryA(pkcs11_lib_name);
#endif

  if (NULL == g_pkcs11LibHandle)
    return false;

#ifndef _WINDOWS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  p11GetFunctionList = (CK_C_GetFunctionList)dlsym(g_pkcs11LibHandle, "C_GetFunctionList");
#pragma GCC diagnostic pop
#else
  p11GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(g_pkcs11LibHandle, "C_GetFunctionList");
# define dlclose(_h) FreeLibrary(_h)
#endif

  if (unlikely(NULL == p11GetFunctionList))
  {
    dlclose(g_pkcs11LibHandle), g_pkcs11LibHandle = NULL;
    return false;
  }

  rv = p11GetFunctionList(&g_pkcs11_functions);

  if (CKR_OK != rv || NULL == g_pkcs11_functions)
  {
    dlclose(g_pkcs11LibHandle), g_pkcs11LibHandle = NULL;
    g_pkcs11_functions = NULL;
    return false;
  }

  memset(&init_args, 0, sizeof(init_args));

  init_args.CreateMutex  = p11_createmutex;
  init_args.DestroyMutex = p11_destroymutex;
  init_args.LockMutex    = p11_lockmutex;
  init_args.UnlockMutex  = p11_unlockmutex;

  init_args.flags        = CKF_OS_LOCKING_OK;

  rv = g_pkcs11_functions->C_Initialize(&init_args);
  if (CKR_CRYPTOKI_ALREADY_INITIALIZED != rv && CKR_OK != rv)
  {
    dlclose(g_pkcs11LibHandle), g_pkcs11LibHandle = NULL;
    g_pkcs11_functions = NULL;
    return false;
  }

  return true;
}

void pkcs11_fini ( void )
{
  if (NULL == g_pkcs11LibHandle)
    return;

  if (NULL != g_pkcs11_functions)
  {
    if (CK_INVALID_HANDLE != g_pkcs11_session)
    {
      g_pkcs11_functions->C_Logout(g_pkcs11_session);
      g_pkcs11_functions->C_CloseSession(g_pkcs11_session);
    }
    g_pkcs11_functions->C_Finalize(NULL_PTR);
  }

  dlclose(g_pkcs11LibHandle);

  g_pkcs11LibHandle = NULL;
  g_pkcs11_functions = NULL;
}

bool pkcs11_login ( const uint8_t *passwd, uint32_t passwd_len )
{
  CK_RV                       rv;
  CK_TOKEN_INFO               token_info;
  uint8_t                     password[PEM_BUFSIZE];

  if (unlikely(NULL == g_pkcs11LibHandle))
  {
    if (!be_quiet)
      fprintf(stdout,"%s[%u]: pkcs11_login: handle is NULL.\n", __func__, (uint32_t)__LINE__);
    return false;
  }

  // Do we have already a session?

  if (CK_INVALID_HANDLE != g_pkcs11_session)
    return true;

  if (NULL == passwd && 0 != passwd_len)
    return false;

  memset(&token_info, 0, sizeof(token_info));

  rv = g_pkcs11_functions->C_GetTokenInfo(g_pkcs11_slot, &token_info);
  if (unlikely(CKR_OK != rv))
  {
    if (!be_quiet)
      fprintf(stdout,"%s[%u]: pkcs11_login: GetTokenInfo FAILED.\n", __func__, (uint32_t)__LINE__);
    return false;
  }

  if (token_info.flags & CKF_USER_PIN_LOCKED)
  {
    if (!be_quiet)
      fprintf(stdout,"ERROR: PKCS#11 user PIN is LOCKED.\n");
    return false;
  }

  if (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED)
  {
    if (!be_quiet)
      fprintf(stdout,"ERROR: PKCS#11 user PIN has to be CHANGED.\n");
    return false;
  }

  if (token_info.flags & CKF_USER_PIN_FINAL_TRY)
  {
    if (!be_quiet)
      fprintf(stdout,"WARNING: PKCS#11 user PIN count is the FINAL try!\n");
  }
  else
  if (token_info.flags & CKF_USER_PIN_COUNT_LOW)
  {
    if (!be_quiet)
      fprintf(stdout,"WARNING: PKCS#11 user PIN count is LOW!\n");
  }

  if (NULL == passwd)
  {
    memset(password, 0, sizeof(password));

    if (0 != secret[0])
      strncpy((char *)password, secret, sizeof(password) - 1);
    else
    if (0 != pkcs11_pin[0])
      strncpy((char *)password, pkcs11_pin, sizeof(password) - 1);
    else
    {
      if (!(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
        EVP_read_pw_string((char*)password, sizeof(password), "Enter PKCS#11 user password/PIN:", 0);
    }

    passwd     = (const uint8_t*)password;
    passwd_len = (uint32_t)strlen((const char *)passwd);
  }

  if (0 == passwd_len)
  {
    passwd = NULL;
    if (!(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
      return false;
  }

  rv = g_pkcs11_functions->C_OpenSession(g_pkcs11_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &g_pkcs11_session);

  if (CKR_OK != rv)
  {
    g_pkcs11_session = CK_INVALID_HANDLE;
    return false;
  }

  rv = g_pkcs11_functions->C_Login(g_pkcs11_session, CKU_USER, (CK_UTF8CHAR *)passwd, passwd_len);

  if (CKR_OK != rv)
    return false;

  return true;
}

EVP_PKEY *pkcs11_get_ossl_public_evp_key_from_pubkey ( const uint8_t  *key_id,
                                                       uint32_t        key_id_length,
                                                       const uint8_t  *key_label,
                                                       uint32_t        key_label_length )
{
  EVP_PKEY               *pkey = NULL;
  CK_OBJECT_CLASS         pubkey_class = CKO_PUBLIC_KEY;
  CK_RV                   rv;
  CK_ATTRIBUTE            attr;
  uint8_t                *n_buffer = NULL, *e_buffer = NULL, *buffer = NULL;
  RSA                    *rsa = NULL;
  EC_KEY                 *ec = NULL;
  BIGNUM                 *bn_n = NULL, *bn_e = NULL;
  CK_OBJECT_HANDLE        hPublicKey = CK_INVALID_HANDLE;
  CK_ATTRIBUTE            attrs[3];
  CK_ULONG                keys_found = 0;
  uint64_t                idx = 0;
  const unsigned char    *p;
  uint32_t                i, comp_len = 0;
  bool                    is_ed25519 = false, is_ed448 = false;
  uint64_t                derlen = 0;

  // Locate public key in PKCS#11 module

  if (unlikely((NULL == key_id && 0!= key_id_length) || (NULL == key_label && 0 != key_label_length)))
    return NULL;

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return NULL;

  if (NULL != key_id)
  {
    attrs[idx].type = CKA_ID;
    attrs[idx].pValue = (CK_VOID_PTR)key_id;
    attrs[idx].ulValueLen = key_id_length;
    idx++;
  }

  if (NULL != key_label)
  {
    attrs[idx].type = CKA_LABEL;
    attrs[idx].pValue = (CK_VOID_PTR)key_label;
    attrs[idx].ulValueLen = key_label_length;
    idx++;
  }

  attrs[idx].type = CKA_CLASS;
  attrs[idx].pValue = &pubkey_class;
  attrs[idx].ulValueLen = sizeof(pubkey_class);
  idx++;

  if (unlikely(idx <= 1))
    return NULL;

  rv = g_pkcs11_functions->C_FindObjectsInit(g_pkcs11_session, attrs, (CK_ULONG)idx);
  if (CKR_OK != rv)
    return NULL;

  rv = g_pkcs11_functions->C_FindObjects(g_pkcs11_session, &hPublicKey, 1, &keys_found);

  g_pkcs11_functions->C_FindObjectsFinal(g_pkcs11_session);

  if (CKR_OK != rv)
    return NULL;

  if (1 != keys_found)
    return NULL;

  // 1st try: RSA

  // Get public modulus n

  // Get size of modulus first

  attr.type = CKA_MODULUS;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK == rv && 0 != attr.ulValueLen && ((CK_ULONG)-1) != attr.ulValueLen)
  {
    n_buffer = malloc(attr.ulValueLen + 1);
    if (unlikely(NULL == n_buffer))
      goto err;

    memset(n_buffer, 0, attr.ulValueLen + 1);

    attr.pValue = n_buffer + 1;

    rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
    if (CKR_OK != rv)
      goto err;

    rsa = RSA_new();
    if (unlikely(NULL == rsa))
      goto err;

    bn_n = BN_new();
    bn_e = BN_new();

    if (unlikely(NULL == bn_n || NULL == bn_e))
      goto err;

    if (0 != (0x80 & n_buffer[1]))
    {
      if (unlikely(NULL == BN_bin2bn(n_buffer, (int)attr.ulValueLen + 1, bn_n)))
        goto err;
    }
    else
    {
      if (unlikely(NULL == BN_bin2bn(n_buffer+1, (int)attr.ulValueLen, bn_n)))
        goto err;
    }

    // get public exponent

    attr.type = CKA_PUBLIC_EXPONENT;
    attr.pValue = NULL_PTR;
    attr.ulValueLen = 0;

    rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
    if (CKR_OK != rv || 0 == attr.ulValueLen)
      goto err;

    e_buffer = malloc(attr.ulValueLen + 1);
    if (unlikely(NULL == e_buffer))
      goto err;

    memset(e_buffer, 0, attr.ulValueLen + 1);

    attr.pValue = e_buffer + 1;

    rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
    if (CKR_OK != rv)
      goto err;

    if (0 != (0x80 & e_buffer[1]))
    {
      if (unlikely(NULL == BN_bin2bn(e_buffer, (int)attr.ulValueLen + 1, bn_e)))
        goto err;
    }
    else
    {
      if (unlikely(NULL == BN_bin2bn(e_buffer+1, (int)attr.ulValueLen, bn_e)))
        goto err;
    }

    if (unlikely(1 != RSA_set0_key(rsa, bn_n, bn_e, NULL)))
      goto err;

    bn_n = NULL;
    bn_e = NULL;

    pkey = EVP_PKEY_new();
    if (unlikely(NULL == pkey))
      goto err;

    if (1 != EVP_PKEY_set1_RSA(pkey, rsa))
      goto err;

    RSA_free(rsa);
    free(n_buffer);
    free(e_buffer);

    return pkey;
  }

  // 2nd try: Elliptic Curve / Edwards Curve

  attr.type = CKA_EC_PARAMS;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
    goto err;

  buffer = malloc(attr.ulValueLen);
  if (unlikely(NULL == buffer))
    goto err;

  memset(buffer, 0, attr.ulValueLen);

  attr.pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  for (i=0;i<NUM_PKCS11_ELLIPTIC_CURVES;i++)
  {
    if ( (((uint32_t)attr.ulValueLen) == (((uint32_t)elliptic_curves[i].oid_der[1]) + 2)) && (!memcmp(attr.pValue, elliptic_curves[i].oid_der, attr.ulValueLen)) )
    {
      comp_len = (elliptic_curves[i].bits + 7) >> 3;
      break;
    }
  }

  if (NUM_PKCS11_ELLIPTIC_CURVES == i) // check the two Edwards Curves
  {
    if ( (((uint32_t)attr.ulValueLen) == (((uint32_t)edwards_curves[0].oid_der[1] + 2))) && (!memcmp(attr.pValue, edwards_curves[0].oid_der, attr.ulValueLen)) )
    {
      is_ed25519 = true;
      comp_len = 32;
    }
    else
    if ( (((uint32_t)attr.ulValueLen) == (((uint32_t)edwards_curves[1].oid_der[1] + 2))) && (!memcmp(attr.pValue, edwards_curves[1].oid_der, attr.ulValueLen)) )
    {
      is_ed448 = true;
      comp_len = 57;
    }
    else
      goto err;
  }

  if (i != NUM_PKCS11_ELLIPTIC_CURVES)
  {
    ec = EC_KEY_new();
    if (unlikely(NULL == ec))
      goto err;

    p = buffer;

    if (unlikely(NULL == d2i_ECParameters(&ec, &p, (long)attr.ulValueLen)))
      goto err;
  }

  free(buffer), buffer = NULL;

  // Get size of Elliptic Curve point (= public key) first

  attr.type = CKA_EC_POINT;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
    goto err;

  buffer = malloc(attr.ulValueLen);
  if (unlikely(NULL == buffer))
    goto err;

  memset(buffer, 0, attr.ulValueLen);

  attr.pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  if (!is_ed25519 && !is_ed448)
  {
    // PKCS#11-compliant modules SHALL return ASN1_OCTET_STRING,
    //
    // "broken" PKCS#11 modules just return the byte 0x04 (which ALSO matches the ASN.1 tag for OCTET STRING)
    // meaning "uncompressed point", followed by X || Y
    // i.e. we have to find out if this is { 0x04,<ASN.1 length>,0x04 (uncompressed),X,Y } or
    // just { 0x04 (uncompressed),X,Y }

    idx = 0;

    if ((attr.ulValueLen == ((comp_len << 1)+1)) && (0x04 == buffer[idx])) // this is just 0x04 (uncompressed) followed by X followed by Y
    {
      p = buffer;
      if (unlikely(NULL == o2i_ECPublicKey(&ec, &p, (long)attr.ulValueLen)))
        goto err;
    }
    else // we have to ASN.1 decode an outer ASN.1 OCTET STRING (this is the 'good' case)
    {
      if (unlikely(0 == attr.ulValueLen))
        goto err;
      if (0x04/*ASN.1 tag OCTET STRING*/ != buffer[idx++])
        goto err;
      if (unlikely(!asn1_decodelen(buffer,(uint64_t)attr.ulValueLen,&derlen,&idx)))
        goto err;
      if (unlikely(derlen != ((comp_len << 1) + 1)))
        goto err;
      if (unlikely((idx + derlen) != attr.ulValueLen))
        goto err;
      p = buffer + idx;
      if (unlikely(NULL == o2i_ECPublicKey(&ec, &p, (long)derlen)))
        goto err;
    }

    pkey = EVP_PKEY_new();
    if (unlikely(NULL == pkey))
      goto err;

    if (1 != EVP_PKEY_set1_EC_KEY(pkey, ec))
      goto err;

    EC_KEY_free(ec);

    free(buffer);

    return pkey;
  }
  else
  {
    idx = 0;

    if ((idx < attr.ulValueLen) && (0x04 == buffer[idx]))
    {
      idx++;

      if (unlikely(!asn1_decodelen(buffer,(uint64_t)attr.ulValueLen,&derlen,&idx)))
        goto err;

      if (unlikely((idx + derlen) != attr.ulValueLen))
        goto err;

      if (comp_len != ((uint32_t)derlen))
        goto err;

      p = buffer + idx;
    }
    else // broken PKCS#11 implementation does not return an OCTET STRING
    {
      if (comp_len != ((uint32_t)attr.ulValueLen))
        goto err;

      p = buffer;
    }

    pkey = is_ed448 ? EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, p, 57) : EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, p, 32);

    if (unlikely(NULL == pkey))
      goto err;

    free(buffer);

    return pkey;
  }

err:
  if (NULL != n_buffer)
    free(n_buffer);
  if (NULL != e_buffer)
    free(e_buffer);
  if (NULL != bn_n)
    BN_free(bn_n);
  if (NULL != bn_e)
    BN_free(bn_e);
  if (NULL != rsa)
    RSA_free(rsa);
  if (NULL != buffer)
    free(buffer);
  if (NULL != ec)
    EC_KEY_free(ec);
  if (NULL != pkey)
    EVP_PKEY_free(pkey);
  return NULL;
}

EVP_PKEY *pkcs11_generate_rsa_keypair ( uint32_t        keybits,
                                        uint64_t        public_exponent,
                                        const uint8_t  *key_id,
                                        uint32_t        key_id_length,
                                        const uint8_t  *key_label,
                                        uint32_t        key_label_length )
{
  EVP_PKEY               *pkey = NULL;
  CK_MECHANISM            mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
  CK_BBOOL                _true = TRUE;
  CK_BBOOL                _false = FALSE;
  CK_ULONG                modulusBits;
  CK_BYTE                 publicExponent[16];
  CK_OBJECT_CLASS         pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE            publicKeyTemplate[8] =
  {
    /* 0*/{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    /* 3*/{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
    /* 4*/{CKA_VERIFY, &_true, sizeof(_true)},
    /* 5*/{CKA_PRIVATE, &_false, sizeof(_false)},
    /* 6*/{CKA_ID, NULL_PTR, 0 },
    /* 7*/{CKA_LABEL, NULL_PTR, 0 }
  };
  CK_ATTRIBUTE            privateKeyTemplate[7] =
  {
    /* 0*/{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_PRIVATE, &_true, sizeof(_true)},
    /* 3*/{CKA_SENSITIVE, &_true, sizeof(_true)},
    /* 4*/{CKA_SIGN,&_true,sizeof(_true)},
    /* 5*/{CKA_ID, NULL_PTR, 0 },
    /* 6*/{CKA_LABEL, NULL_PTR, 0 }
  };
  uint32_t                i, pubexp_size, pubexp_index = 0;
  CK_OBJECT_HANDLE        hPublicKey;
  CK_OBJECT_HANDLE        hPrivateKey;
  CK_RV                   rv;
  CK_ATTRIBUTE            attr;
  uint8_t                *n_buffer = NULL;;
  RSA                    *rsa = NULL;
  BIGNUM                 *bn_n = NULL, *bn_e = NULL;

  if (unlikely(NULL == g_pkcs11LibHandle))
    return pkey;

  if (unlikely(0 == keybits || 0 != (keybits & 7) || NULL == key_id || 0 == key_id_length || (NULL == key_label && 0 != key_label_length)))
    return pkey;

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return pkey;

  modulusBits = (CK_ULONG)keybits;

  memset(publicExponent, 0, sizeof(publicExponent));

  public_exponent = (0 == public_exponent) ? 65537 : public_exponent;

  pubexp_size = (((int64_t)public_exponent) < 0) ? 1 : 0;

  for (i = 0; i < 8; i++)
  {
    publicExponent[pubexp_size++] = (CK_BYTE)(public_exponent >> 56);
    public_exponent <<= 8;
  }

  while (0 == publicExponent[pubexp_index] && 0 == (publicExponent[pubexp_index + 1] & 0x80))
  {
    pubexp_index++;
    pubexp_size--;
  }

  publicKeyTemplate[3].pValue = &publicExponent[pubexp_index];
  publicKeyTemplate[3].ulValueLen = pubexp_size;

  publicKeyTemplate[6].pValue = (void*)key_id;
  publicKeyTemplate[6].ulValueLen = key_id_length;

  privateKeyTemplate[5].pValue = (void*)key_id;
  privateKeyTemplate[5].ulValueLen = key_id_length;

  if (NULL != key_label)
  {
    publicKeyTemplate[7].pValue = (void*)key_label;
    publicKeyTemplate[7].ulValueLen = key_label_length;

    privateKeyTemplate[6].pValue = (void*)key_label;
    privateKeyTemplate[6].ulValueLen = key_label_length;
  }

  rv = g_pkcs11_functions->C_GenerateKeyPair(g_pkcs11_session, &mechanism,
    publicKeyTemplate, NULL==key_label ? 7 : 8,
    privateKeyTemplate, NULL==key_label ? 6 : 7,
    &hPublicKey, &hPrivateKey);

  if (CKR_OK != rv)
    return pkey;

  // Get public modulus n

  // Get size of modulus first

  attr.type = CKA_MODULUS;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
  {
err:
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPrivateKey);
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPublicKey);

    if (NULL != n_buffer)
      free(n_buffer);

    if (NULL != bn_n)
      BN_free(bn_n);

    if (NULL != bn_e)
      BN_free(bn_e);

    if (NULL != rsa)
      RSA_free(rsa);

    if (NULL != pkey)
      EVP_PKEY_free(pkey);

    return NULL;
  }

  n_buffer = malloc(attr.ulValueLen + 1);
  if (unlikely(NULL == n_buffer))
    goto err;

  memset(n_buffer, 0, attr.ulValueLen + 1);

  attr.pValue = n_buffer + 1;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  rsa = RSA_new();
  if (unlikely(NULL == rsa))
    goto err;

  bn_n = BN_new();
  bn_e = BN_new();

  if (unlikely(NULL == bn_n || NULL == bn_e))
    goto err;

  if (0 != (0x80 & n_buffer[1]))
  {
    if (unlikely(NULL == BN_bin2bn(n_buffer, (int)attr.ulValueLen + 1, bn_n)))
      goto err;
  }
  else
  {
    if (unlikely(NULL == BN_bin2bn(n_buffer+1, (int)attr.ulValueLen, bn_n)))
      goto err;
  }

  if (unlikely(NULL == BN_bin2bn(publicKeyTemplate[3].pValue, publicKeyTemplate[3].ulValueLen, bn_e)))
    goto err;

  if (unlikely(1 != RSA_set0_key(rsa, bn_n, bn_e, NULL)))
    goto err;
  bn_n = NULL;
  bn_e = NULL;

  pkey = EVP_PKEY_new();
  if (unlikely(NULL == pkey))
    goto err;

  if (1 != EVP_PKEY_set1_RSA(pkey, rsa))
    goto err;

  RSA_free(rsa);
  free(n_buffer);

  return pkey;
}

EVP_PKEY *pkcs11_generate_ec_keypair ( uint32_t curve, const uint8_t *key_id, uint32_t key_id_length, const uint8_t *key_label, uint32_t key_label_length )
{
  EVP_PKEY               *pkey = NULL;
  CK_MECHANISM            mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
  CK_BBOOL                _true = TRUE;
  CK_BBOOL                _false = FALSE;
  CK_OBJECT_CLASS         pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE            publicKeyTemplate[7] =
  {
    /* 0*/{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_VERIFY, &_true, sizeof(_true)},
    /* 3*/{CKA_PRIVATE, &_false, sizeof(_false)},
    /* 4*/{CKA_EC_PARAMS, NULL_PTR, 0},
    /* 5*/{CKA_ID, NULL_PTR, 0 },
    /* 6*/{CKA_LABEL, NULL_PTR, 0 },
  };
  CK_ATTRIBUTE            privateKeyTemplate[7] =
  {
    /* 0*/{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_PRIVATE, &_true, sizeof(_true)},
    /* 3*/{CKA_SENSITIVE, &_true, sizeof(_true)},
    /* 4*/{CKA_SIGN,&_true,sizeof(_true)},
    /* 5*/{CKA_ID, NULL_PTR, 0 },
    /* 6*/{CKA_LABEL, NULL_PTR, 0 }
  };
  CK_OBJECT_HANDLE        hPublicKey;
  CK_OBJECT_HANDLE        hPrivateKey;
  CK_RV                   rv;
  CK_ATTRIBUTE            attr;
  uint8_t                *buffer = NULL;
  EC_KEY                 *ec = NULL;
  const unsigned char    *p;
  uint64_t                idx, derlen;
  uint32_t                comp_len;     // component length in bytes

  if (unlikely(NULL == g_pkcs11LibHandle))
    return pkey;

  if (unlikely(curve >= NUM_PKCS11_ELLIPTIC_CURVES || NULL == key_id || 0 == key_id_length || (NULL == key_label && 0 != key_label_length)))
    return pkey;

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return pkey;

  // Define Elliptic Curve parameters by its OID (namedCurve)

  publicKeyTemplate[4].pValue = (void*)elliptic_curves[curve].oid_der;
  publicKeyTemplate[4].ulValueLen = elliptic_curves[curve].oid_der[1] + 2; /*+2 because tag=0x06 plus DER length byte*/

  comp_len = (elliptic_curves[curve].bits + 7) >> 3;

  // set ID

  publicKeyTemplate[5].pValue = (void*)key_id;
  publicKeyTemplate[5].ulValueLen = key_id_length;

  privateKeyTemplate[5].pValue = (void*)key_id;
  privateKeyTemplate[5].ulValueLen = key_id_length;

  if (NULL != key_label)
  {
    publicKeyTemplate[6].pValue = (void*)key_label;
    publicKeyTemplate[6].ulValueLen = key_label_length;

    privateKeyTemplate[6].pValue = (void*)key_label;
    privateKeyTemplate[6].ulValueLen = key_label_length;
  }

  rv = g_pkcs11_functions->C_GenerateKeyPair(g_pkcs11_session, &mechanism,
    publicKeyTemplate, NULL == key_label ? 6 : 7,
    privateKeyTemplate, NULL == key_label ? 6 : 7,
    &hPublicKey, &hPrivateKey);

  if (CKR_OK != rv)
    return pkey;

  // Get size of Elliptic Curve parameters first

  attr.type = CKA_EC_PARAMS;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
  {
err:
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPrivateKey);
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPublicKey);

    if (NULL != buffer)
      free(buffer);

    if (NULL != ec)
      EC_KEY_free(ec);

    if (NULL != pkey)
      EVP_PKEY_free(pkey);

    return NULL;
  }

  buffer = malloc(attr.ulValueLen);
  if (unlikely(NULL == buffer))
    goto err;

  memset(buffer, 0, attr.ulValueLen);

  attr.pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  ec = EC_KEY_new();
  if (unlikely(NULL == ec))
    goto err;

  p = buffer;

  if (unlikely(NULL == d2i_ECParameters(&ec, &p, (long)attr.ulValueLen)))
    goto err;

  free(buffer), buffer = NULL;

  // Get size of Elliptic Curve point (= public key) first

  attr.type = CKA_EC_POINT;
  attr.pValue = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
    goto err;

  buffer = malloc(attr.ulValueLen);
  if (unlikely(NULL == buffer))
    goto err;

  memset(buffer, 0, attr.ulValueLen);

  attr.pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  // PKCS#11-compliant modules SHALL return ASN1_OCTET_STRING,
  //
  // "broken" PKCS#11 modules just return the byte 0x04 (which ALSO matches the ASN.1 tag for OCTET STRING)
  // meaning "uncompressed point", followed by X || Y
  // i.e. we have to find out if this is { 0x04,<ASN.1 length>,0x04 (uncompressed),X,Y } or
  // just { 0x04 (uncompressed),X,Y }

  idx = 0;

  if ((attr.ulValueLen == ((comp_len << 1)+1)) && (0x04 == buffer[idx])) // this is just 0x04 (uncompressed) followed by X followed by Y
  {
    p = buffer;
    if (unlikely(NULL == o2i_ECPublicKey(&ec, &p, (long)attr.ulValueLen)))
      goto err;
  }
  else // we have to ASN.1 decode an outer ASN.1 OCTET STRING (this is the 'good' case)
  {
    if (unlikely(0 == attr.ulValueLen))
      goto err;
    if (0x04/*ASN.1 tag OCTET STRING*/ != buffer[idx++])
      goto err;
    if (unlikely(!asn1_decodelen(buffer,attr.ulValueLen,&derlen,&idx)))
      goto err;
    if (unlikely(derlen != ((comp_len << 1) + 1)))
      goto err;
    if (unlikely((idx + derlen) != attr.ulValueLen))
      goto err;
    p = buffer + idx;
    if (unlikely(NULL == o2i_ECPublicKey(&ec, &p, (long)derlen)))
      goto err;
  }

  pkey = EVP_PKEY_new();
  if (unlikely(NULL == pkey))
    goto err;

  if (1 != EVP_PKEY_set1_EC_KEY(pkey, ec))
    goto err;

  EC_KEY_free(ec);

  free(buffer);

  return pkey;
}

EVP_PKEY *pkcs11_generate_edwards_keypair ( bool ed448, const uint8_t *key_id, uint32_t key_id_length, const uint8_t *key_label, uint32_t key_label_length )
{
  EVP_PKEY               *pkey = NULL;
  CK_MECHANISM            mechanism = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0 };
  CK_BBOOL                _true = TRUE;
  CK_BBOOL                _false = FALSE;
  CK_OBJECT_CLASS         pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE            publicKeyTemplate[7] =
  {
    /* 0*/{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_VERIFY, &_true, sizeof(_true)},
    /* 3*/{CKA_PRIVATE, &_false, sizeof(_false)},
    /* 4*/{CKA_EC_PARAMS, NULL_PTR, 0},
    /* 5*/{CKA_ID, NULL_PTR, 0 },
    /* 6*/{CKA_LABEL, NULL_PTR, 0 },
  };
  CK_ATTRIBUTE            privateKeyTemplate[7] =
  {
    /* 0*/{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
    /* 1*/{CKA_TOKEN, &_true, sizeof(_true)},
    /* 2*/{CKA_PRIVATE, &_true, sizeof(_true)},
    /* 3*/{CKA_SENSITIVE, &_true, sizeof(_true)},
    /* 4*/{CKA_SIGN,&_true,sizeof(_true)},
    /* 5*/{CKA_ID, NULL_PTR, 0 },
    /* 6*/{CKA_LABEL, NULL_PTR, 0 }
  };
  CK_OBJECT_HANDLE        hPublicKey;
  CK_OBJECT_HANDLE        hPrivateKey;
  CK_RV                   rv;
  CK_ATTRIBUTE            attr;
  uint8_t                *buffer = NULL;
  const unsigned char    *p;
  uint64_t                idx, derlen;

  if (unlikely(NULL == g_pkcs11LibHandle))
    return pkey;

  if (unlikely(NULL == key_id || 0 == key_id_length || (NULL == key_label && 0 != key_label_length)))
    return pkey;

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return pkey;

  // Define Elliptic Curve parameters by its OID (namedCurve)

  publicKeyTemplate[4].pValue = (void*)edwards_curves[ed448 ? 1 : 0].oid_der;
  publicKeyTemplate[4].ulValueLen = edwards_curves[ed448 ? 1 : 0].oid_der[1] + 2; /*+2 because tag=0x06 plus DER length byte*/

  // set ID

  publicKeyTemplate[5].pValue = (void*)key_id;
  publicKeyTemplate[5].ulValueLen = key_id_length;

  privateKeyTemplate[5].pValue = (void*)key_id;
  privateKeyTemplate[5].ulValueLen = key_id_length;

  if (NULL != key_label)
  {
    publicKeyTemplate[6].pValue = (void*)key_label;
    publicKeyTemplate[6].ulValueLen = key_label_length;

    privateKeyTemplate[6].pValue = (void*)key_label;
    privateKeyTemplate[6].ulValueLen = key_label_length;
  }

  rv = g_pkcs11_functions->C_GenerateKeyPair(g_pkcs11_session, &mechanism,
    publicKeyTemplate, NULL == key_label ? 6 : 7,
    privateKeyTemplate, NULL == key_label ? 6 : 7,
    &hPublicKey, &hPrivateKey);

  if (CKR_OK != rv)
    return pkey;

  // Get size of Elliptic Curve point (= public key) first

  attr.type       = CKA_EC_POINT;
  attr.pValue     = NULL_PTR;
  attr.ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);

  if (CKR_OK != rv || 0 == attr.ulValueLen)
  {
err:
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPrivateKey);
    g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, hPublicKey);

    if (NULL != buffer)
      free(buffer);

    if (NULL != pkey)
      EVP_PKEY_free(pkey);

    return NULL;
  }

  buffer = malloc(attr.ulValueLen);
  if (unlikely(NULL == buffer))
    goto err;

  memset(buffer, 0, attr.ulValueLen);

  attr.pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, hPublicKey, &attr, 1);
  if (CKR_OK != rv)
    goto err;

  // PKCS#11-compliant modules should return ASN1_OCTET_STRING

  idx = 0;

  if ((idx < attr.ulValueLen) && (0x04 == buffer[idx]))
  {
    idx++;

    if (unlikely(!asn1_decodelen(buffer,attr.ulValueLen,&derlen,&idx)))
      goto err;

    if (unlikely((idx + derlen) != attr.ulValueLen))
      goto err;

    if (((!ed448) && (32 != derlen)) || ((ed448) && (57 != derlen)))
      goto err;

    p = buffer + idx;
  }
  else // broken PKCS#11 implementation does not return an OCTET STRING
  {
    if (((!ed448) && (32 != attr.ulValueLen)) || ((ed448) && (57 != attr.ulValueLen)))
      goto err;

    p = buffer;
  }

  pkey = ed448 ? EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, p, 57) : EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, p, 32);

  if (unlikely(NULL == pkey))
    goto err;

  free(buffer);

  return pkey;
}

#ifdef _WINDOWS
#define STDIN_FILENO 0
#endif

bool pkcs11_delete_key(const uint8_t* key_id, uint32_t key_id_length, const uint8_t* key_label, uint32_t key_label_length, bool ask_confirmation)
{
  CK_RV                   rv;
  CK_ATTRIBUTE            attrs[3];
  CK_OBJECT_HANDLE        key;
  CK_ULONG                keys_found = 0, idx = 0;
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS         pubkey_class = CKO_PUBLIC_KEY;

  if (unlikely((NULL==key_id && 0!=key_id_length) || (NULL == key_label && 0 != key_label_length)))
    return false;

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return false;

  if (NULL != key_id)
  {
    attrs[idx].type = CKA_ID;
    attrs[idx].pValue = (CK_VOID_PTR)key_id;
    attrs[idx].ulValueLen = key_id_length;
    idx++;
  }

  if (NULL != key_label)
  {
    attrs[idx].type = CKA_LABEL;
    attrs[idx].pValue = (CK_VOID_PTR)key_label;
    attrs[idx].ulValueLen = key_label_length;
    idx++;
  }

  attrs[idx].type = CKA_CLASS;
  attrs[idx].pValue = &privkey_class;
  attrs[idx].ulValueLen = sizeof(privkey_class);
  idx++;

  if (unlikely(idx <= 1))
    return false;

  rv = g_pkcs11_functions->C_FindObjectsInit(g_pkcs11_session, attrs, idx);
  if (CKR_OK != rv)
    return false;

  key = CK_INVALID_HANDLE;
  keys_found = 0;
  rv = g_pkcs11_functions->C_FindObjects(g_pkcs11_session, &key, 1, &keys_found);

  g_pkcs11_functions->C_FindObjectsFinal(g_pkcs11_session);

  if (CKR_OK != rv)
    return false;

  if (1 != keys_found)
    return false;

  if (ask_confirmation)
  {
    char buf[64];
    fprintf(stdout,"About to delete PKCS#11 key with label '%.*s'. Are you sure (yes/no)? ", key_label_length, key_label);
    fflush(stdout);
    memset(buf,0,sizeof(buf));
    read(STDIN_FILENO,buf,sizeof(buf) - 1);
    if (memcmp(buf,"yes\n",5) && memcmp(buf,"YES\n",5))
      return false;
  }

  if (CKR_OK != g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, key))
    return false;

  attrs[idx - 1].pValue = &pubkey_class;
  attrs[idx - 1].ulValueLen = sizeof(pubkey_class);

  rv = g_pkcs11_functions->C_FindObjectsInit(g_pkcs11_session, attrs, idx);
  if (CKR_OK != rv)
    return false;

  key = CK_INVALID_HANDLE;
  keys_found = 0;
  rv = g_pkcs11_functions->C_FindObjects(g_pkcs11_session, &key, 1, &keys_found);

  g_pkcs11_functions->C_FindObjectsFinal(g_pkcs11_session);

  if (CKR_OK != rv)
    return false;

  if (1 != keys_found)
    return false;

  if (CKR_OK != g_pkcs11_functions->C_DestroyObject(g_pkcs11_session, key))
    return false;

  return true;
}

bool pkcs11_get_key_id_by_key_label(const uint8_t* key_label, uint32_t key_label_length, uint8_t* key_id, uint32_t *p_key_id_length)
{
  CK_RV                   rv;
  CK_ATTRIBUTE            attrs[2];
  CK_OBJECT_HANDLE        key;
  CK_ULONG                keys_found = 0;
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  uint8_t                *buffer;

  if (unlikely(NULL == key_label || 0 == key_label_length || NULL == key_id || NULL == p_key_id_length || 0 == *p_key_id_length))
    return false;

  memset(key_id, 0x00, *p_key_id_length);

  if (CK_INVALID_HANDLE == g_pkcs11_session)
    return false;

  attrs[0].type = CKA_LABEL;
  attrs[0].pValue = (CK_VOID_PTR)key_label;
  attrs[0].ulValueLen = key_label_length;

  attrs[1].type = CKA_CLASS;
  attrs[1].pValue = &privkey_class;
  attrs[1].ulValueLen = sizeof(privkey_class);

  rv = g_pkcs11_functions->C_FindObjectsInit(g_pkcs11_session, attrs, 2);
  if (CKR_OK != rv)
    return false;

  key = CK_INVALID_HANDLE;
  keys_found = 0;
  rv = g_pkcs11_functions->C_FindObjects(g_pkcs11_session, &key, 1, &keys_found);

  g_pkcs11_functions->C_FindObjectsFinal(g_pkcs11_session);

  if (CKR_OK != rv)
    return false;

  if (1 != keys_found)
    return false;

  attrs[0].type       = CKA_ID;
  attrs[0].pValue     = NULL_PTR;
  attrs[0].ulValueLen = 0;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, key, attrs, 1);

  if (CKR_OK != rv || 0 == attrs[0].ulValueLen)
    return false;

  buffer = malloc(attrs[0].ulValueLen);
  if (unlikely(NULL == buffer))
    return false;

  memset(buffer, 0, attrs[0].ulValueLen);

  attrs[0].pValue = buffer;

  rv = g_pkcs11_functions->C_GetAttributeValue(g_pkcs11_session, key, attrs, 1);
  if (CKR_OK != rv)
  {
    free(buffer);
    return false;
  }

  if (((uint32_t)attrs[0].ulValueLen) < *p_key_id_length)
    *p_key_id_length = (uint32_t)attrs[0].ulValueLen;

  memcpy(key_id, buffer, *p_key_id_length);

  free(buffer);

  return true;
}

bool pkcs11_create_signature ( const char *p11label, uint32_t sig_type, uint32_t md_type, const uint8_t *tbs, uint32_t tbs_size, uint8_t **sig, uint32_t *p_sig_size, bool ecdsaAsn1, bool edPh )
{
  CK_OBJECT_CLASS         privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE            attrs[2];
  CK_RV                   rv;
  CK_ULONG                count;
  CK_OBJECT_HANDLE        hPrivateKey;
  CK_MECHANISM            mech;
  uint32_t                sig_size, ec_md_size = 0;
  uint8_t                *sig_buffer, *sig_buffer2 = NULL;
  uint32_t                sig_size2;
  CK_ULONG                p11_sig_size;
  CK_RSA_PKCS_PSS_PARAMS  pss_params;
  CK_EDDSA_PARAMS         eddsa_params;
  uint8_t                 ec_md[SHA512_DIGEST_LENGTH];

  if (unlikely(NULL == g_pkcs11LibHandle || NULL == tbs || 0 == tbs_size || NULL == sig || NULL == p_sig_size))
    return false;

  *sig = NULL;
  *p_sig_size = 0;

  if (unlikely(CK_INVALID_HANDLE == g_pkcs11_session))
    return false;

  attrs[0].type = CKA_CLASS;
  attrs[0].pValue = &privkey_class;
  attrs[0].ulValueLen = sizeof(privkey_class);

  attrs[1].type = CKA_LABEL;
  attrs[1].pValue = (void *)p11label;
  attrs[1].ulValueLen = (CK_ULONG)strlen(p11label);

  // locate the private key

  rv = g_pkcs11_functions->C_FindObjectsInit(g_pkcs11_session, attrs, 2);
  if (CKR_OK != rv)
    return false;

  count = 0;
  rv = g_pkcs11_functions->C_FindObjects(g_pkcs11_session, &hPrivateKey, 1, &count);

  g_pkcs11_functions->C_FindObjectsFinal(g_pkcs11_session);

  if (CKR_OK != rv || 1 != count)
    return false;

  sig_size = 1024;

  sig_buffer = (uint8_t*)malloc(sig_size);
  if (unlikely(NULL == sig_buffer))
    return false;

  memset(sig_buffer, 0, sig_size);

  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;

  switch(sig_type)
  {
    case SIG_TYPE_RSA_PKCS1_V15:
      switch(md_type)
      {
        case MD_TYPE_SHA2_224:
          mech.mechanism = CKM_SHA224_RSA_PKCS;
          break;
        case MD_TYPE_SHA2_256:
          mech.mechanism = CKM_SHA256_RSA_PKCS;
          break;
        case MD_TYPE_SHA2_384:
          mech.mechanism = CKM_SHA384_RSA_PKCS;
          break;
        case MD_TYPE_SHA2_512:
          mech.mechanism = CKM_SHA512_RSA_PKCS;
          break;
        case MD_TYPE_SHA3_224:
          mech.mechanism = CKM_SHA3_224_RSA_PKCS_PSS;
          break;
        case MD_TYPE_SHA3_256:
          mech.mechanism = CKM_SHA3_256_RSA_PKCS_PSS;
          break;
        case MD_TYPE_SHA3_384:
          mech.mechanism = CKM_SHA3_384_RSA_PKCS_PSS;
          break;
        case MD_TYPE_SHA3_512:
          mech.mechanism = CKM_SHA3_512_RSA_PKCS_PSS;
          break;
        default:
          free(sig_buffer);
          return false;
      }
      break;

    case SIG_TYPE_RSA_PSS_SHA256:
      mech.pParameter = &pss_params;
      mech.ulParameterLen = sizeof(pss_params);
      mech.mechanism     = CKM_SHA256_RSA_PKCS_PSS;
      pss_params.hashAlg = CKM_SHA256;
      pss_params.mgf     = CKG_MGF1_SHA256;
      pss_params.sLen    = SHA256_DIGEST_LENGTH;
      break;

    case SIG_TYPE_RSA_PSS_SHA384:
      mech.pParameter = &pss_params;
      mech.ulParameterLen = sizeof(pss_params);
      mech.mechanism     = CKM_SHA384_RSA_PKCS_PSS;
      pss_params.hashAlg = CKM_SHA384;
      pss_params.mgf     = CKG_MGF1_SHA384;
      pss_params.sLen    = SHA384_DIGEST_LENGTH;
      break;

    case SIG_TYPE_RSA_PSS_SHA512:
      mech.pParameter = &pss_params;
      mech.ulParameterLen = sizeof(pss_params);
      mech.mechanism     = CKM_SHA512_RSA_PKCS_PSS;
      pss_params.hashAlg = CKM_SHA512;
      pss_params.mgf     = CKG_MGF1_SHA512;
      pss_params.sLen    = SHA512_DIGEST_LENGTH;
      break;

    case SIG_TYPE_ECDSA_SECP256R1:
    case SIG_TYPE_ECDSA_SECP384R1:
    case SIG_TYPE_ECDSA_SECP521R1:
    case SIG_TYPE_ECDSA_SECT571R1:
    case SIG_TYPE_ECDSA_BRAINPOOLP256R1:
    case SIG_TYPE_ECDSA_BRAINPOOLP384R1:
    case SIG_TYPE_ECDSA_BRAINPOOLP512R1:
      mech.mechanism = CKM_ECDSA;
      memset(ec_md, 0, sizeof(ec_md));
      ec_md_size = ossl_hash(md_type,tbs,tbs_size,ec_md);
      if (unlikely(0 == ec_md_size))
      {
        free(sig_buffer);
        return false;
      }
      break;

    case SIG_TYPE_EDDSA_25519:
    case SIG_TYPE_EDDSA_448:
      if (edPh) // pre-hashed is normally a really bad idea but if some software relies on it, e.g, GnuPG,
                // we just calculate the message digest now...
      {
        memset(&eddsa_params, 0, sizeof(eddsa_params));
        eddsa_params.phFlag = CK_TRUE;

        if (SIG_TYPE_EDDSA_25519 == sig_type)
        {
          if (MD_TYPE_SHA2_256 != md_type && MD_TYPE_SHA2_512 != md_type)
            goto out;
        }
        else
        {
          if (MD_TYPE_SHA2_512 != md_type)
            goto out;
        }

        memset(ec_md, 0, sizeof(ec_md));
        ec_md_size = ossl_hash(md_type,tbs,tbs_size,ec_md);
        if (unlikely(0 == ec_md_size))
        {
          free(sig_buffer);
          return false;
        }

        mech.pParameter     = &eddsa_params;
        mech.ulParameterLen = sizeof(eddsa_params);
        mech.mechanism      = CKM_EDDSA;
      }
      else
        mech.mechanism = CKM_EDDSA;
      break;

    default:
      free(sig_buffer);
      return false;
  }

  rv = g_pkcs11_functions->C_SignInit(g_pkcs11_session, &mech, hPrivateKey);
  if (CKR_OK != rv)
  {
    free(sig_buffer);
    return false;
  }

  p11_sig_size = sig_size;

  if ((SIG_TYPE_EDDSA_25519 == sig_type || SIG_TYPE_EDDSA_448 == sig_type) && (edPh)) // this is either for ED25519/ED448 pre-hashed
  {
    rv = g_pkcs11_functions->C_Sign(g_pkcs11_session, ec_md, ec_md_size, sig_buffer, &p11_sig_size);
  }
  else
  if (IS_ECDSA(sig_type))
  {
    rv = g_pkcs11_functions->C_Sign(g_pkcs11_session, ec_md, ec_md_size, sig_buffer, &p11_sig_size);

    /*
     * A PKCS#11 ECDSA signature just consists of exactly 2 * roundup(curve_bits/8)-many bytes.
     * We have to check for negative values (most significant bit is 1) and have to add a leading
     * zero byte in this case.
     * Furthermore, we have to 'trim' the two components (r,s), i.e. if there are leading zero
     * byte(s) and the most significant bit of the next byte is also zero, then this zero byte has
     * to be removed.
     */

    if (CKR_OK != rv || (0 != (p11_sig_size & 1))) // signature length must be divisible by two
    {
out:
      if (NULL != sig_buffer2)
        free(sig_buffer2);
      free(sig_buffer);
      return false;
    }

    if (ecdsaAsn1)
    {
      sig_buffer2 = asn1ECDSARawSignature2ASN1RSSequence(sig_buffer, (uint32_t)p11_sig_size, &sig_size2);
      if (unlikely(NULL == sig_buffer2))
        goto out;

      free(sig_buffer);
      sig_buffer = sig_buffer2;
      sig_buffer2 = NULL;
      p11_sig_size = (CK_ULONG)sig_size2;
    }
  }
  else
  {
    rv = g_pkcs11_functions->C_Sign(g_pkcs11_session, (unsigned char *)tbs, tbs_size, sig_buffer, &p11_sig_size);
    if (CKR_OK != rv)
    {
      free(sig_buffer);
      return false;
    }
  }

  *sig = sig_buffer;
  *p_sig_size = (uint32_t)p11_sig_size;

  return true;
}
