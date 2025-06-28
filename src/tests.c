/**
 * @file   tests.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implementation of the test suite
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

#ifdef _WITH_TESTS

#include <tests.h>

#define MAX_STDOUT_CAPTURE        65536
#define NUM_KEYS                  12
#define NUM_OVERALL_TESTS         547

static uint8_t    stdout_buffer[MAX_STDOUT_CAPTURE];
static char       szOSSLEXE[256];
static char       szGPGEXE[256], szGPGCONF[256], szPINENTRY[256];
static const char szP11KeyLabels[NUM_KEYS][16] = { "p11_rsa2048", "p11_rsa3072", "p11_rsa4096", "p11_ecnist256", "p11_ecnist384", "p11_ecnist521", "p11_ecbpool256", "p11_ecbpool384", "p11_ecbpool512", "p11_ed25519_1", "p11_ed25519_2", "p11_ed448" };
static const char szKeyNames[NUM_KEYS][16] = { "rsa2048", "rsa3072", "rsa4096", "ecnist256", "ecnist384", "ecnist521", "ecbpool256", "ecbpool384", "ecbpool512", "ed25519_1", "ed25519_2", "ed448" };
static const char szKeyTypes[NUM_KEYS][16] = { "rsa2048", "rsa3072", "rsa4096", "ecnist256", "ecnist384", "ecnist521", "ecbpool256", "ecbpool384", "ecbpool512", "ed25519", "ed25519", "ed448" };
static const struct
{
  char what[32];
  char cert_in[64];
  char p11_label[32];
  char serialno[8];
  uint32_t keyidx;

} p11_certs[] =
{
  { "RSA/2048/PKCS#1 v1.5", "cert_rsa2048_v15.pem", "p11_rsa2048"    , "2001", 0 },
  { "RSA/2048/PSS",         "cert_rsa2048_pss.pem", "p11_rsa2048"    , "2002", 0 },
  { "RSA/3072/PKCS#1 v1.5", "cert_rsa3072_v15.pem", "p11_rsa3072"    , "2003", 1 },
  { "RSA/3072/PSS",         "cert_rsa3072_pss.pem", "p11_rsa3072"    , "2004", 1 },
  { "RSA/4096/PKCS#1 v1.5", "cert_rsa4096_v15.pem", "p11_rsa4096"    , "2005", 2 },
  { "RSA/4096/PSS",         "cert_rsa4096_pss.pem", "p11_rsa4096"    , "2006", 2 },

  { "ECC/NIST256",          "cert_ecnist256.pem"  , "p11_ecnist256"  , "2007", 3 },
  { "ECC/NIST384",          "cert_ecnist384.pem"  , "p11_ecnist384"  , "2008", 4 },
  { "ECC/NIST521",          "cert_ecnist521.pem"  , "p11_ecnist521"  , "2009", 5 },

  { "ECC/BPOOL256",         "cert_ecbpool256.pem"  , "p11_ecbpool256", "2010", 6 },
  { "ECC/BPOOL384",         "cert_ecbpool384.pem"  , "p11_ecbpool384", "2011", 7 },
  { "ECC/BPOOL512",         "cert_ecbpool512.pem"  , "p11_ecbpool512", "2012", 8 },

  { "ED/ED25519 #1",        "cert_ed25519_1.pem"  , "p11_ed25519_1"  , "2013", 9 },
  { "ED/ED25519 #2",        "cert_ed25519_2.pem"  , "p11_ed25519_2"  , "2014", 10 },
  { "ED/ED448",             "cert_ed448.pem"      , "p11_ed448"      , "2015", 11 },
};
static const struct
{
  char        info[32];
  char        privkey_file[64];
  char        user_name[32];
  char        email_addr[32];
  char        digest[16];
  char        p11_info[32];
  uint32_t    keyidx;
  char        p11_label[32];
  char        p11_pubkey[64];
  char        p11_user_name[32];
  char        p11_email_addr[32];
} pgp_import_tests[] =
{
  { "RSA/2048 (OSSL)"           , "rsa2048.prv.pem"   , "test1" , "test1@company.org" , "sha256", "RSA/2048 (PKCS#11)"           , 0, "p11_rsa2048"   , "p11_rsa2048.pub.pem"   , "p11test1"  , "p11test1@company.org" },
  { "RSA/3072 (OSSL)"           , "rsa3072.prv.pem"   , "test2" , "test2@company.org" , "sha384", "RSA/3072 (PKCS#11)"           , 1, "p11_rsa3072"   , "p11_rsa3072.pub.pem"   , "p11test2"  , "p11test2@company.org"},
  { "RSA/4096 (OSSL)"           , "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha512", "RSA/4096 (PKCS#11)"           , 2, "p11_rsa4096"   , "p11_rsa4096.pub.pem"   , "p11test3"  , "p11test3@company.org"},
  { "ECC/NIST256 (OSSL)"        , "ecnist256.prv.pem" , "test4" , "test4@company.org" , "sha256", "ECC/NIST256 (PKCS#11)"        , 3, "p11_ecnist256" , "p11_ecnist256.pub.pem" , "p11test4"  , "p11test4@company.org"},
  { "ECC/NIST384 (OSSL)"        , "ecnist384.prv.pem" , "test5" , "test5@company.org" , "sha384", "ECC/NIST384 (PKCS#11)"        , 4, "p11_ecnist384" , "p11_ecnist384.pub.pem" , "p11test5"  , "p11test5@company.org"},
  { "ECC/NIST521 (OSSL)"        , "ecnist521.prv.pem" , "test6" , "test6@company.org" , "sha512", "ECC/NIST521 (PKCS#11)"        , 5, "p11_ecnist521" , "p11_ecnist521.pub.pem" , "p11test6"  , "p11test6@company.org"},
  { "ECC/BPOOL256 (OSSL)"       , "ecbpool256.prv.pem", "test7" , "test7@company.org" , "sha256", "ECC/BPOOL256 (PKCS#11)"       , 6, "p11_ecbpool256", "p11_ecbpool256.pub.pem", "p11test7"  , "p11test7@company.org"},
  { "ECC/BPOOL384 (OSSL)"       , "ecbpool384.prv.pem", "test8" , "test8@company.org" , "sha384", "ECC/BPOOL384 (PKCS#11)"       , 7, "p11_ecbpool384", "p11_ecbpool384.pub.pem", "p11test8"  , "p11test8@company.org"},
  { "ECC/BPOOL512 (OSSL)"       , "ecbpool512.prv.pem", "test9" , "test9@company.org" , "sha512", "ECC/BPOOL512 (PKCS#11)"       , 8, "p11_ecbpool512", "p11_ecbpool512.pub.pem", "p11test9"  , "p11test9@company.org"},
  { "ED/ED25519 (OSSL), SHA-256", "ed25519_1.prv.pem" , "test10", "test10@company.org", "sha256", "ED/ED25519 (PKCS#11), SHA-256", 9, "p11_ed25519_1" , "p11_ed25519_1.pub.pem" , "p11test10" , "p11test10@company.org"},
  { "ED/ED25519 (OSSL), SHA-384", "ed25519_1.prv.pem" , "test11", "test11@company.org", "sha384", "ED/ED25519 (PKCS#11), SHA-384", 9, "p11_ed25519_1" , "p11_ed25519_1.pub.pem" , "p11test11" , "p11test11@company.org"},
  { "ED/ED25519 (OSSL), SHA-512", "ed25519_1.prv.pem" , "test12", "test12@company.org", "sha512", "ED/ED25519 (PKCS#11), SHA-512", 9, "p11_ed25519_1" , "p11_ed25519_1.pub.pem" , "p11test12" , "p11test12@company.org"},
  { "ED/ED448 (OSSL), SHA-512"  , "ed448.prv.pem"     , "test13", "test13@company.org", "sha512", "ED/ED448 (PKCS#11)"           ,11, "p11_ed448"     , "p11_ed448.pub.pem"     , "p11test13" , "p11test13@company.org"}
};
static const struct
{
  char        info[32];
  char        privkey_file[64];
  char        user_name[32];
  char        email_addr[32];
  char        digest[16];
  char        pss[16];
  char        x509[64];
} ossl_tests[] =
{
  { "RSA/2048 (OSSL)"     , "rsa2048.prv.pem"   , "test1" , "test1@company.org" , "sha256", ""         , "cert_rsa2048_v15.pem" },
  { "RSA/3072 (OSSL)"     , "rsa3072.prv.pem"   , "test2" , "test2@company.org" , "sha256", ""         , "cert_rsa3072_v15.pem" },
  { "RSA/3072 (OSSL)"     , "rsa3072.prv.pem"   , "test2" , "test2@company.org" , "sha384", ""         , "cert_rsa3072_v15.pem" },
  { "RSA/4096 (OSSL)"     , "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha256", ""         , "cert_rsa4096_v15.pem" },
  { "RSA/4096 (OSSL)"     , "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha384", ""         , "cert_rsa4096_v15.pem" },
  { "RSA/4096 (OSSL)"     , "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha512", ""         , "cert_rsa4096_v15.pem" },
  { "RSA/2048 (OSSL, PSS)", "rsa2048.prv.pem"   , "test1" , "test1@company.org" , "sha256", "--use-pss", "cert_rsa2048_pss.pem" },
  { "RSA/3072 (OSSL, PSS)", "rsa3072.prv.pem"   , "test2" , "test2@company.org" , "sha256", "--use-pss", "cert_rsa3072_pss.pem" },
  { "RSA/3072 (OSSL, PSS)", "rsa3072.prv.pem"   , "test2" , "test2@company.org" , "sha384", "--use-pss", "cert_rsa3072_pss.pem" },
  { "RSA/4096 (OSSL, PSS)", "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha256", "--use-pss", "cert_rsa4096_pss.pem" },
  { "RSA/4096 (OSSL, PSS)", "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha384", "--use-pss", "cert_rsa4096_pss.pem" },
  { "RSA/4096 (OSSL, PSS)", "rsa4096.prv.pem"   , "test3" , "test3@company.org" , "sha512", "--use-pss", "cert_rsa4096_pss.pem" },
  { "ECC/NIST256 (OSSL)"  , "ecnist256.prv.pem" , "test4" , "test4@company.org" , "sha256", ""         , "cert_ecnist256.pem"   },
  { "ECC/NIST384 (OSSL)"  , "ecnist384.prv.pem" , "test5" , "test5@company.org" , "sha256", ""         , "cert_ecnist384.pem"   },
  { "ECC/NIST384 (OSSL)"  , "ecnist384.prv.pem" , "test5" , "test5@company.org" , "sha384", ""         , "cert_ecnist384.pem"   },
  { "ECC/NIST521 (OSSL)"  , "ecnist521.prv.pem" , "test6" , "test6@company.org" , "sha256", ""         , "cert_ecnist521.pem"   },
  { "ECC/NIST521 (OSSL)"  , "ecnist521.prv.pem" , "test6" , "test6@company.org" , "sha384", ""         , "cert_ecnist521.pem"   },
  { "ECC/NIST521 (OSSL)"  , "ecnist521.prv.pem" , "test6" , "test6@company.org" , "sha512", ""         , "cert_ecnist521.pem"   },
  { "ECC/BPOOL256 (OSSL)" , "ecbpool256.prv.pem", "test7" , "test7@company.org" , "sha256", ""         , "cert_ecbpool256.pem"  },
  { "ECC/BPOOL384 (OSSL)" , "ecbpool384.prv.pem", "test8" , "test8@company.org" , "sha256", ""         , "cert_ecbpool384.pem"  },
  { "ECC/BPOOL384 (OSSL)" , "ecbpool384.prv.pem", "test8" , "test8@company.org" , "sha384", ""         , "cert_ecbpool384.pem"  },
  { "ECC/BPOOL512 (OSSL)" , "ecbpool512.prv.pem", "test9" , "test9@company.org" , "sha256", ""         , "cert_ecbpool512.pem"  },
  { "ECC/BPOOL512 (OSSL)" , "ecbpool512.prv.pem", "test9" , "test9@company.org" , "sha384", ""         , "cert_ecbpool512.pem"  },
  { "ECC/BPOOL512 (OSSL)" , "ecbpool512.prv.pem", "test9" , "test9@company.org" , "sha512", ""         , "cert_ecbpool512.pem"  },
  { "ED/ED25519 (OSSL)"   , "ed25519_1.prv.pem" , "test10", "test10@company.org", ""      , ""         , "cert_ed25519_1.pem"   }, // this is SHA-512 implicitly
  { "ED/ED448 (OSSL)"     , "ed448.prv.pem"     , "test13", "test13@company.org", ""      , ""         , "cert_ed448.pem"       }  // this is SHAKE-256 (64 bytes = 512 bit) implicitly
};
static const struct
{
  uint32_t    keyidx;
  char        info[32];
  char        p11_label[64];
  char        user_name[32];
  char        email_addr[32];
  char        digest[16];
  char        pss[16];
  char        x509[64];
} p11_tests[] =
{
  { 0, "RSA/2048 (PKCS#11)"     , "p11_rsa2048"   , "p11test1" , "p11test1@company.org" , "sha256", ""         , "patched-cert_rsa2048_v15.pem" },
  { 1, "RSA/3072 (PKCS#11)"     , "p11_rsa3072"   , "p11test2" , "p11test2@company.org" , "sha256", ""         , "patched-cert_rsa3072_v15.pem" },
  { 1, "RSA/3072 (PKCS#11)"     , "p11_rsa3072"   , "p11test2" , "p11test2@company.org" , "sha384", ""         , "patched-cert_rsa3072_v15.pem" },
  { 2, "RSA/4096 (PKCS#11)"     , "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha256", ""         , "patched-cert_rsa4096_v15.pem" },
  { 2, "RSA/4096 (PKCS#11)"     , "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha384", ""         , "patched-cert_rsa4096_v15.pem" },
  { 2, "RSA/4096 (PKCS#11)"     , "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha512", ""         , "patched-cert_rsa4096_v15.pem" },
  { 0, "RSA/2048 (PKCS#11, PSS)", "p11_rsa2048"   , "p11test1" , "p11test1@company.org" , "sha256", "--use-pss", "patched-cert_rsa2048_pss.pem" },
  { 1, "RSA/3072 (PKCS#11, PSS)", "p11_rsa3072"   , "p11test2" , "p11test2@company.org" , "sha256", "--use-pss", "patched-cert_rsa3072_pss.pem" },
  { 1, "RSA/3072 (PKCS#11, PSS)", "p11_rsa3072"   , "p11test2" , "p11test2@company.org" , "sha384", "--use-pss", "patched-cert_rsa3072_pss.pem" },
  { 2, "RSA/4096 (PKCS#11, PSS)", "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha256", "--use-pss", "patched-cert_rsa4096_pss.pem" },
  { 2, "RSA/4096 (PKCS#11, PSS)", "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha384", "--use-pss", "patched-cert_rsa4096_pss.pem" },
  { 2, "RSA/4096 (PKCS#11, PSS)", "p11_rsa4096"   , "p11test3" , "p11test3@company.org" , "sha512", "--use-pss", "patched-cert_rsa4096_pss.pem" },
  { 3, "ECC/NIST256 (PKCS#11)"  , "p11_ecnist256" , "p11test4" , "p11test4@company.org" , "sha256", ""         , "patched-cert_ecnist256.pem"   },
  { 4, "ECC/NIST384 (PKCS#11)"  , "p11_ecnist384" , "p11test5" , "p11test5@company.org" , "sha256", ""         , "patched-cert_ecnist384.pem"   },
  { 4, "ECC/NIST384 (PKCS#11)"  , "p11_ecnist384" , "p11test5" , "p11test5@company.org" , "sha384", ""         , "patched-cert_ecnist384.pem"   },
  { 5, "ECC/NIST521 (PKCS#11)"  , "p11_ecnist521" , "p11test6" , "p11test6@company.org" , "sha256", ""         , "patched-cert_ecnist521.pem"   },
  { 5, "ECC/NIST521 (PKCS#11)"  , "p11_ecnist521" , "p11test6" , "p11test6@company.org" , "sha384", ""         , "patched-cert_ecnist521.pem"   },
  { 5, "ECC/NIST521 (PKCS#11)"  , "p11_ecnist521" , "p11test6" , "p11test6@company.org" , "sha512", ""         , "patched-cert_ecnist521.pem"   },
  { 6, "ECC/BPOOL256 (PKCS#11)" , "p11_ecbpool256", "p11test7" , "p11test7@company.org" , "sha256", ""         , "patched-cert_ecbpool256.pem"  },
  { 7, "ECC/BPOOL384 (PKCS#11)" , "p11_ecbpool384", "p11test8" , "p11test8@company.org" , "sha256", ""         , "patched-cert_ecbpool384.pem"  },
  { 7, "ECC/BPOOL384 (PKCS#11)" , "p11_ecbpool384", "p11test8" , "p11test8@company.org" , "sha384", ""         , "patched-cert_ecbpool384.pem"  },
  { 8, "ECC/BPOOL512 (PKCS#11)" , "p11_ecbpool512", "p11test9" , "p11test9@company.org" , "sha256", ""         , "patched-cert_ecbpool512.pem"  },
  { 8, "ECC/BPOOL512 (PKCS#11)" , "p11_ecbpool512", "p11test9" , "p11test9@company.org" , "sha384", ""         , "patched-cert_ecbpool512.pem"  },
  { 8, "ECC/BPOOL512 (PKCS#11)" , "p11_ecbpool512", "p11test9" , "p11test9@company.org" , "sha512", ""         , "patched-cert_ecbpool512.pem"  },
  { 9, "ED/ED25519 (PKCS#11)"   , "p11_ed25519_1" , "p11test10", "p11test10@company.org", ""      , ""         , "patched-cert_ed25519_1.pem"   }, // this is SHA-512 implicitly
  {11, "ED/ED448 (PKCS#11)"     , "p11_ed448"     , "p11test13", "p11test13@company.org", ""      , ""         , "patched-cert_ed448.pem"       }  // this is SHAKE-256 (64 bytes = 512 bit) implicitly
};
static bool       p11_key_available[NUM_KEYS];
static FILE      *_log = NULL;

#define ISSUE_CERT(_str,_prv,_crt,...) \
  do \
  { \
    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR,_prv); \
    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR,_crt); \
    log_message(true, _str); \
    exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, ##__VA_ARGS__, NULL); \
    if (0 == exitcode) \
    { \
      log_result(test_ok); \
      log_printf("Program stdout/stderr output was:\n"); \
      log_transfer_stdout(); \
    } \
    else \
    if (1 == exitcode) \
    { \
      log_result(test_failed); \
      log_printf("Program stdout/stderr output was:\n"); \
      log_transfer_stdout(); \
    } \
    else \
    { \
      log_result(test_failed); \
      log_transfer_stdout(); \
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode); \
      goto Exit; \
    } \
  } while (0)

#ifdef _WINDOWS
#define OSSL_DQUOTE "\""
#else
#define OSSL_DQUOTE ""
#endif

static void log_printf(const char* fmt, ...)
{
  char          buffer[1024];
  va_list       ap;
  size_t        len;

  va_start(ap, fmt);
  len = (size_t)vsnprintf(buffer, sizeof(buffer), fmt, ap);
  va_end(ap);

  fwrite(buffer, 1, len, _log);
}

static void log_transfer_stdout(void)
{
  uint8_t* p = stdout_buffer;
  uint8_t* p2 = p;

  while (0 != *p)
  {
    if ('\033' == p[0] && '[' == p[1])
    {
      p += 2;
      while ('m' != *p) p++;
      p++;
    }
    else
      *(p2++) = *(p++);
  }

  fwrite(stdout_buffer, 1, (size_t)(p2 - stdout_buffer), _log);
}

static uint32_t test_no = 0;

#define MAX_MSG 70

static void log_message(bool positive_test, const char* _msg, ...)
{
  uint32_t      len, copy_len;
  char          test_msg[MAX_MSG + 1];
  char          msg[MAX_MSG << 1];
  va_list       ap;

  va_start(ap, _msg);
  len = (uint32_t)vsnprintf(msg, sizeof(msg), _msg, ap);
  va_end(ap);

  memset(test_msg, '.', MAX_MSG);
  test_msg[MAX_MSG] = 0;

  copy_len = len <= (MAX_MSG - 2) ? len : (MAX_MSG - 2);

  memcpy(test_msg, msg, copy_len);
  test_msg[copy_len] = ' ';

  test_no++;

  if (positive_test)
    fprintf(stdout, "[%sTEST%04u%s] %s<pos>%s %s%s : %s", ctrlCyan, test_no, ctrlReset, ctrlGreen, ctrlReset, ctrlYellow, test_msg, ctrlReset);
  else
    fprintf(stdout, "[%sTEST%04u%s] %s<neg>%s %s%s : %s", ctrlCyan, test_no, ctrlReset, ctrlRed, ctrlReset, ctrlYellow, test_msg, ctrlReset);

  fflush(stdout);

  log_printf("[TEST%04u] <%s> %s : ", test_no, positive_test ? "pos" : "neg", msg);
  fflush(_log);
}

typedef enum
{
  test_ok = 0,
  test_failed = 1,
  test_skipped = 2,
  test_ignored = 3
} test_result;

static uint32_t test_stat[4] = { 0, 0, 0, 0 };

static void log_result(test_result res)
{
  switch (res)
  {
    case test_ok:
      test_stat[test_ok]++;
      fprintf(stdout, "%sOK%s\n", ctrlGreen, ctrlReset);
      log_printf("OK\n");
      break;
    case test_failed:
      test_stat[test_failed]++;
      fprintf(stdout, "%sFAILED%s\n", ctrlRed, ctrlReset);
      log_printf("FAILED\n");
      break;
    case test_skipped:
      test_stat[test_skipped]++;
      fprintf(stdout, "%sSKIPPED%s\n", ctrlYellow, ctrlReset);
      log_printf("SKIPPED\n");
      break;
    default: // ignored
      test_stat[test_ignored]++;
      fprintf(stdout, "%sN/A%s\n", ctrlMagenta, ctrlReset);
      log_printf("N/A\n");
      break;
  }
}

#ifdef _WINDOWS

extern bool APIENTRY IsUserAdmin(void);

/******************************************************************************\
*       This is a part of the Microsoft Source Code Samples.
*       Copyright 1995 - 1997 Microsoft Corporation.
*       All rights reserved.
*       This source code is only intended as a supplement to
*       Microsoft Development Tools and/or WinHelp documentation.
*       See these sources for detailed information regarding the
*       Microsoft samples programs.
\******************************************************************************/

/*++
Copyright (c) 1997  Microsoft Corporation
Module Name:
    pipeex.c
Abstract:
    CreatePipe-like function that lets one or both handles be overlapped
Author:
    Dave Hart  Summer 1997
Revision History:
--*/

#include <windows.h>
#include <stdio.h>

static volatile long PipeSerialNumber;

BOOL
APIENTRY
MyCreatePipeEx(
  OUT LPHANDLE lpReadPipe,
  OUT LPHANDLE lpWritePipe,
  IN LPSECURITY_ATTRIBUTES lpPipeAttributes,
  IN DWORD nSize,
  DWORD dwReadMode,
  DWORD dwWriteMode
)

/*++
Routine Description:
    The CreatePipeEx API is used to create an anonymous pipe I/O device.
    Unlike CreatePipe FILE_FLAG_OVERLAPPED may be specified for one or
    both handles.
    Two handles to the device are created.  One handle is opened for
    reading and the other is opened for writing.  These handles may be
    used in subsequent calls to ReadFile and WriteFile to transmit data
    through the pipe.
Arguments:
    lpReadPipe - Returns a handle to the read side of the pipe.  Data
        may be read from the pipe by specifying this handle value in a
        subsequent call to ReadFile.
    lpWritePipe - Returns a handle to the write side of the pipe.  Data
        may be written to the pipe by specifying this handle value in a
        subsequent call to WriteFile.
    lpPipeAttributes - An optional parameter that may be used to specify
        the attributes of the new pipe.  If the parameter is not
        specified, then the pipe is created without a security
        descriptor, and the resulting handles are not inherited on
        process creation.  Otherwise, the optional security attributes
        are used on the pipe, and the inherit handles flag effects both
        pipe handles.
    nSize - Supplies the requested buffer size for the pipe.  This is
        only a suggestion and is used by the operating system to
        calculate an appropriate buffering mechanism.  A value of zero
        indicates that the system is to choose the default buffering
        scheme.
Return Value:
    TRUE - The operation was successful.
    FALSE/NULL - The operation failed. Extended error status is available
        using GetLastError.
--*/

{
  HANDLE ReadPipeHandle, WritePipeHandle;
  DWORD dwError;
  UCHAR PipeNameBuffer[MAX_PATH];

  //
  // Only one valid OpenMode flag - FILE_FLAG_OVERLAPPED
  //

  if ((dwReadMode | dwWriteMode) & (~FILE_FLAG_OVERLAPPED)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  //
  //  Set the default timeout to 120 seconds
  //

  if (nSize == 0) {
    nSize = 4096;
  }

  snprintf((char*)PipeNameBuffer,sizeof(PipeNameBuffer),
    "\\\\.\\Pipe\\RemoteExeAnon.%08x.%08x",
    GetCurrentProcessId(),
    InterlockedIncrement(&PipeSerialNumber)
  );

  ReadPipeHandle = CreateNamedPipeA(
    (const char *)PipeNameBuffer,
    PIPE_ACCESS_INBOUND | dwReadMode,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,             // Number of pipes
    nSize,         // Out buffer size
    nSize,         // In buffer size
    120 * 1000,    // Timeout in ms
    lpPipeAttributes
  );

  if (!ReadPipeHandle) {
    return FALSE;
  }

  WritePipeHandle = CreateFileA(
    (const char*)PipeNameBuffer,
    GENERIC_WRITE,
    0,                         // No sharing
    lpPipeAttributes,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | dwWriteMode,
    NULL                       // Template file
  );

  if (INVALID_HANDLE_VALUE == WritePipeHandle) {
    dwError = GetLastError();
    CloseHandle(ReadPipeHandle);
    SetLastError(dwError);
    return FALSE;
  }

  *lpReadPipe = ReadPipeHandle;
  *lpWritePipe = WritePipeHandle;
  return(TRUE);
}

#endif // _WINDOWS

#ifdef _LINUX

#include <sys/wait.h>

/**********************************************************************************************//**
 * @fn  int execute_external_program(uint8_t stdout_buffer[MAX_STDOUT_CAPTURE], bool wait_for_child, const char* prog, ...)
 *
 * @brief This is the Linux version of executing an external executable as a forked child process.
 *
 * @author Ingo A. Kubbilun (www.devcorn.de)
 * @date   01.09.2021
 *
 * @param stdout_buffer   Buffer to 131072 characters receiving the zero-terminated output of the
 *                        child. NULL if the output is not required.
 * @param wait_for_child  true to wait for the child process to be terminated. If a stdout_buffer
 *                        is specified, then this flag is implicitly set to true.
 * @param prog            the fully qualified file name of the process to be executed.
 * @param ...             Variable arguments providing the child process command line arguments.
 *                        NULL has to be specified as the final parameter.
 *
 * @returns the exit code of the process. 127 is returned if an error (not originating from the
 *          child)
 *          occurs. If wait_for_child is false, then a successful fork() returns 0 (OK). The real
 *          exit code of the child process is lost in this case.
 **************************************************************************************************/

int execute_external_program(uint8_t stdout_buffer[MAX_STDOUT_CAPTURE], bool wait_for_child, const char* prog, ...)
{
  va_list                   ap;
  uint32_t                  i, num_args = 0, stdout_idx = 0;
  const char** prog_args;
  pid_t                     pid;
  int                       exit_code = 127;
  int                       j, fdlimit = (int)sysconf(_SC_OPEN_MAX);
  int                       pipe_desc[2] = { -1, -1 };
  FILE                     *f;

  if (NULL != stdout_buffer)
  {
    if (pipe(pipe_desc) < 0)
      return 127;

    wait_for_child = true; // if we want to read child's output, we HAVE TO wait
  }

  va_start(ap, prog);
  while (NULL != va_arg(ap, char* const))
    num_args++;
  va_end(ap);

  prog_args = (const char**)malloc(sizeof(const char*) * (num_args + 2));
  if (unlikely(NULL == prog_args))
  {
    if (-1 != pipe_desc[0])
      close(pipe_desc[0]);
    if (-1 != pipe_desc[1])
      close(pipe_desc[1]);
    return 127;
  }

  prog_args[0] = prog;

  va_start(ap, prog);
  for (i = 0; i < num_args; i++)
  {
    prog_args[i + 1] = va_arg(ap, char* const);
  }
  prog_args[i + 1] = NULL;
  va_end(ap);

  pid = fork();
  if (pid < 0)
    return exit_code;
  if (pid > 0) // parent
  {
    free(prog_args);

    if (-1 != pipe_desc[1])
      close(pipe_desc[1]);

    if (-1 != pipe_desc[0])
    {
      f = fdopen(pipe_desc[0], "rt");
      if (NULL == f)
      {
        close(pipe_desc[0]);
        waitpid(pid, &exit_code, 0);
        return 127;
      }

      memset(stdout_buffer, 0, MAX_STDOUT_CAPTURE);
      while (!feof(f))
      {
        if (fgets((char*)&stdout_buffer[stdout_idx], MAX_STDOUT_CAPTURE - stdout_idx - 1, f))
        {
          stdout_idx += (uint32_t)strlen((const char*)(&stdout_buffer[stdout_idx]));
          if (stdout_idx == (MAX_STDOUT_CAPTURE - 1))
            break;
        }
      }

      fclose(f);
    }

    if (wait_for_child)
    {
      do
      {
        pid = waitpid(pid, &exit_code, 0);
      }
      while (pid == -1 && EINTR == errno);

      if (WIFEXITED(exit_code))
        return WEXITSTATUS(exit_code);

      return 127;
    }
    else
      return 0; // child process keeps running, so we can only return 0 (OK) here...
  }
  else // child
  {
    if (-1 != pipe_desc[0])
      close(pipe_desc[0]);
    for (j = 0; j < fdlimit; j++)
    {
      if (-1 != pipe_desc[1] && j == pipe_desc[1])
        continue; // do NOT close the PIPE descriptor
      close(j);
    }

    open("/dev/null", O_RDONLY); // this is 0 (stdin)

    if (-1 != pipe_desc[1])
    {
      dup2(pipe_desc[1], STDOUT_FILENO/*1*/);
      dup2(pipe_desc[1], STDERR_FILENO/*2*/);
      close(pipe_desc[1]);
    }
    else
    {
      open("/dev/null", O_RDWR); // this is 1 = stdout
      dup2(STDOUT_FILENO/*1*/, STDERR_FILENO/*2*/); // this is 2 = stderr
    }

    (void)execv(prog, (char* const*)prog_args);
    free(prog_args);
    _exit(exit_code);
  }
}

#else

/**********************************************************************************************//**
 * @fn  int execute_external_program(uint8_t stdout_buffer[MAX_STDOUT_CAPTURE], bool wait_for_child, const char* prog, ...)
 *
 * @brief This is the Windows version of executing an external executable as a forked child process.
 *
 * @author Ingo A. Kubbilun (www.devcorn.de)
 * @date   01.09.2021
 *
 * @param stdout_buffer   Buffer to 4096 characters receiving the zero-terminated output of the
 *                        child. NULL if the output is not required.
 * @param wait_for_child  true to wait for the child process to be terminated. If a stdout_buffer
 *                        is specified, then this flag is implicitly set to true.
 * @param prog            the fully qualified file name of the process to be executed.
 * @param ...             Variable arguments providing the child process command line arguments.
 *                        NULL has to be specified as the final parameter.
 *
 * @returns the exit code of the process. 127 is returned if an error (not originating from the
 *          child)
 *          occurs. If wait_for_child is false, then a successful fork() returns 0 (OK). The real
 *          exit code of the child process is lost in this case.
 **************************************************************************************************/

int execute_external_program(uint8_t stdout_buffer[MAX_STDOUT_CAPTURE], bool wait_for_child, const char* prog, ...)
{
  va_list                   ap;
  uint32_t                  i, num_args = 0, stdout_idx = 0, bufferAvailable, toBeTransferred, all_args_len = 0, l;
  const char* arg;
  char* prog_args, * run;
  SECURITY_ATTRIBUTES       saAttr;
  HANDLE                    g_hChildStd_IN_Rd = INVALID_HANDLE_VALUE;
  HANDLE                    g_hChildStd_IN_Wr = INVALID_HANDLE_VALUE;
  HANDLE                    g_hChildStd_OUT_Rd = INVALID_HANDLE_VALUE;
  HANDLE                    g_hChildStd_OUT_Wr = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION       piProcInfo;
  STARTUPINFO               siStartInfo;
  OVERLAPPED                asyncRead;
  HANDLE                    hEvents[2];
  DWORD                     dwWaitResult, dwNumEvents = 1, dwExitCode = 0, dwRead;
  bool                      bProcessTerminated = false, bIoFailed = false;
  uint8_t                   read_buffer[512];
  bool                      spaces_in_prog = NULL != strchr(prog, ' ');

  memset(&saAttr, 0, sizeof(saAttr));
  memset(&piProcInfo, 0, sizeof(piProcInfo));
  memset(&siStartInfo, 0, sizeof(siStartInfo));
  memset(&asyncRead, 0, sizeof(asyncRead));

  if (NULL != stdout_buffer)
  {
    memset(stdout_buffer, 0, MAX_STDOUT_CAPTURE);
    wait_for_child = true; // if we want to read child's output, we HAVE TO wait
  }

  all_args_len += ((uint32_t)strlen(prog)) + 1 + 2/*two double quotes if process name contains nasty spaces*/;

  va_start(ap, prog);
  while (NULL != (arg = va_arg(ap, const char*)))
  {
    all_args_len += ((uint32_t)strlen(arg)) + 1; // either zero-terminator or space delimiter between arguments
    num_args++;
  }
  va_end(ap);

  prog_args = (char*)malloc(all_args_len);
  if (unlikely(NULL == prog_args))
    return 127;

  memset(prog_args, 0, all_args_len);
  va_start(ap, prog);
  run = prog_args;
  l = (uint32_t)strlen(prog);
  if (spaces_in_prog)
    *(run++) = '"';
  memcpy(run, prog, l);
  run += l;
  if (spaces_in_prog)
    *(run++) = '"';
  for (i = 0; i < num_args; i++)
  {
    *(run++) = 0x20; // space

    arg = va_arg(ap, const char*);

    l = (uint32_t)strlen(arg);
    memcpy(run, arg, l);
    run += l;
  }
  va_end(ap);

  //fprintf(stdout, "ARGS: %s\n", prog_args);

  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  // We DO need the special named pipe implementation to are able to use the FILE_FLAG_OVERLAPPED flag!
  // if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
  if (!MyCreatePipeEx(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, MAX_STDOUT_CAPTURE, FILE_FLAG_OVERLAPPED, 0/*FILE_FLAG_OVERLAPPED*/))
  {
ErrorExit:

    if (NULL != piProcInfo.hThread)
      CloseHandle(piProcInfo.hThread);

    if (NULL != piProcInfo.hProcess)
      CloseHandle(piProcInfo.hProcess);

    if (INVALID_HANDLE_VALUE != g_hChildStd_IN_Rd)
      CloseHandle(g_hChildStd_IN_Rd);
    if (INVALID_HANDLE_VALUE != g_hChildStd_IN_Wr)
      CloseHandle(g_hChildStd_IN_Wr);
    if (INVALID_HANDLE_VALUE != g_hChildStd_OUT_Rd)
      CloseHandle(g_hChildStd_OUT_Rd);
    if (INVALID_HANDLE_VALUE != g_hChildStd_OUT_Wr)
      CloseHandle(g_hChildStd_OUT_Wr);

    if (NULL != prog_args)
      free(prog_args);

    if (NULL != asyncRead.hEvent)
      CloseHandle(asyncRead.hEvent);

    return 127;
  }

  if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
    goto ErrorExit;

  if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
    goto ErrorExit;

  if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
    goto ErrorExit;

  if (NULL != stdout_buffer)
  {
    asyncRead.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // manual reset event
    if (NULL == asyncRead.hEvent)
      goto ErrorExit;
  }

  siStartInfo.cb = sizeof(STARTUPINFO);
  siStartInfo.hStdError = g_hChildStd_OUT_Wr;
  siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
  siStartInfo.hStdInput = g_hChildStd_IN_Rd;
  siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

  if (NULL != stdout_buffer)
  {
    if (!ReadFile(g_hChildStd_OUT_Rd, read_buffer, sizeof(read_buffer), NULL, &asyncRead))
    {
      if (ERROR_IO_PENDING != GetLastError())
        goto ErrorExit;
    }
    hEvents[1] = asyncRead.hEvent;
    dwNumEvents = 2;
  }

  // Create the child process.

  if (!CreateProcess(prog, prog_args, NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo))
  {
    LPVOID lpMsgBuf = NULL;
    DWORD dwLastError = GetLastError();
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
    fprintf(stderr, "%sERROR%s: Win32: CreateProcess() API call failed; last error=0x%08X: %s", ctrlRed, ctrlReset, dwLastError, NULL != lpMsgBuf ? ((const char *)lpMsgBuf) : "<no message>");
    if (NULL != lpMsgBuf)
      LocalFree(lpMsgBuf);
    goto ErrorExit;
  }

  free(prog_args), prog_args = NULL;

  CloseHandle(g_hChildStd_OUT_Wr), g_hChildStd_OUT_Wr = INVALID_HANDLE_VALUE;
  CloseHandle(g_hChildStd_IN_Rd), g_hChildStd_IN_Rd = INVALID_HANDLE_VALUE;

  CloseHandle(piProcInfo.hThread); // always close thread handle LWP 0 (not needed anymore in the following code)
  piProcInfo.hThread = NULL;

  if (!wait_for_child) // asyncRead.hEvent is NULL in this case
  {
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(g_hChildStd_OUT_Rd);
    CloseHandle(g_hChildStd_IN_Wr);
    return 0; // we do not wait for the child to be terminated, so just return 0 (OK) here
  }

  hEvents[0] = piProcInfo.hProcess;

  while (!bProcessTerminated && !bIoFailed)
  {
    dwWaitResult = WaitForMultipleObjects(dwNumEvents, hEvents, FALSE, INFINITE);
    switch (dwWaitResult)
    {
    case WAIT_OBJECT_0: // child process terminated
      if (!GetExitCodeProcess(piProcInfo.hProcess, &dwExitCode))
        dwExitCode = 127;
      bProcessTerminated = true;
      break;
    case WAIT_OBJECT_0 + 1: // stdout output from child is available (async. read)
      dwRead = 0;
      if ((GetOverlappedResult(g_hChildStd_OUT_Rd, &asyncRead, &dwRead, FALSE/*do not wait*/)) && (0 != dwRead))
      {
        bufferAvailable = MAX_STDOUT_CAPTURE - 1 - stdout_idx;
        toBeTransferred = (dwRead > bufferAvailable) ? bufferAvailable : dwRead;
        if (0 != toBeTransferred)
        {
          memcpy(&stdout_buffer[stdout_idx], read_buffer, toBeTransferred);
          stdout_idx += toBeTransferred;
        }
      }

      ResetEvent(asyncRead.hEvent); // should not be necessary (ReadFile normally does this) but anyway...
      asyncRead.Offset += dwRead; // maybe also not necessary for child process stdout reads but who knows...

      if (!ReadFile(g_hChildStd_OUT_Rd, read_buffer, sizeof(read_buffer), NULL, &asyncRead))
      {
        if (ERROR_IO_PENDING != GetLastError())
        {
          CancelIo(g_hChildStd_OUT_Rd);
          WaitForSingleObject(piProcInfo.hProcess, INFINITE);
          if (!GetExitCodeProcess(piProcInfo.hProcess, &dwExitCode))
            dwExitCode = 127;
          bIoFailed = true;
          break;
        }
      }

      break;

    default:
      CancelIo(g_hChildStd_OUT_Rd);
      WaitForSingleObject(piProcInfo.hProcess, INFINITE);
      if (!GetExitCodeProcess(piProcInfo.hProcess, &dwExitCode))
        dwExitCode = 127;
      bIoFailed = true;
      break;
    }
  }

  if (NULL != asyncRead.hEvent)
  {
    dwRead = 0;

    while ((GetOverlappedResult(g_hChildStd_OUT_Rd, &asyncRead, &dwRead, FALSE/*do not wait*/)) && (0 != dwRead))
    {
      bufferAvailable = MAX_STDOUT_CAPTURE - 1 - stdout_idx;
      toBeTransferred = (dwRead > bufferAvailable) ? bufferAvailable : dwRead;
      if (0 != toBeTransferred)
      {
        memcpy(&stdout_buffer[stdout_idx], read_buffer, toBeTransferred);
        stdout_idx += toBeTransferred;
      }

      ResetEvent(asyncRead.hEvent); // should not be necessary (ReadFile normally does this) but anyway...
      asyncRead.Offset += dwRead; // maybe also not necessary for child process stdout reads but who knows...
      dwRead = 0;

      if (!ReadFile(g_hChildStd_OUT_Rd, read_buffer, sizeof(read_buffer), NULL, &asyncRead))
      {
        if (ERROR_IO_PENDING != GetLastError())
          break;
      }
    }

    CancelIo(g_hChildStd_OUT_Rd); // for failsafe purposes...
    CloseHandle(asyncRead.hEvent);
  }

  CloseHandle(piProcInfo.hProcess);

  CloseHandle(g_hChildStd_OUT_Rd);
  CloseHandle(g_hChildStd_IN_Wr);

  return (int)dwExitCode;
}

#endif // _LINUX

int run_tests ( void )
{
  int           i, exitcode, rc = 1;
  char          x509_to_pgp[256];
  char         *env, *p;
  uint32_t      ossl_major = 0, ossl_minor = 0, ossl_patch = 0;
  uint32_t      gpg_major = 0, gpg_minor = 0, gpg_patch = 0;
  char          cwd[256];
  uint32_t      l_cwd;
  char          buffer[256], buffer2[256], buffer3[256], buffer4[256], buffer5[256], winsysfolder[256], pkcs11_slot_str[32];
  static char   env_pkcs11_pin[64]; // the damned putenv() uses given pointers, does not re-allocate
  static char   env_openssl_conf_file[256], env_gnupg_dir[256], pgp_random_file[256], pgp_random_file2[256];
  uint8_t      *p_random;
#ifdef _WINDOWS
  char          szCmdExe[256];
#endif
  FILE         *f;

  env = getenv("GNUPGHOME");
  if (NULL != env)
  {
    fprintf(stderr,"ERROR: environment variable GNUPGHOME is set. Please unset and try again.\n");
    return 1;
  }

  memset(szOSSLEXE, 0, sizeof(szOSSLEXE));
  memset(szGPGEXE, 0, sizeof(szGPGEXE));
  memset(szGPGCONF, 0, sizeof(szGPGCONF));
  memset(szPINENTRY, 0, sizeof(szPINENTRY));
  memset(cwd, 0, sizeof(cwd));
  memset(winsysfolder, 0, sizeof(winsysfolder));
  memset(p11_key_available, 0, sizeof(p11_key_available));

  env = getenv("OPENSSL_EXE");
  if (NULL == env || 0 == env[0])
  {
    fprintf(stderr,"%sERROR%s: Please define the environment variable 'OPENSSL_EXE'\n", ctrlRed, ctrlReset);
    return 1;
  }
  strncpy(szOSSLEXE, env, sizeof(szOSSLEXE) - 1);

  env = getenv("GPG_EXE");
  if (NULL == env || 0 == env[0])
  {
    fprintf(stderr,"%sERROR%s: Please define the environment variable 'GPG_EXE'\n", ctrlRed, ctrlReset);
    return 1;
  }
  strncpy(szGPGEXE, env, sizeof(szGPGEXE) - 1);

  memcpy(szGPGCONF, szGPGEXE, sizeof(szGPGCONF));
  p = strstr(szGPGCONF, ".exe");
  if (NULL != p)
    *p = 0;
  strncat(szGPGCONF, "conf", sizeof(szGPGCONF) - 1);
  if (NULL != p)
    strncat(szGPGCONF, ".exe", sizeof(szGPGCONF) - 1);

#ifndef _WINDOWS
  strncpy(szPINENTRY, "/usr/bin/pinentry", sizeof(szPINENTRY) - 1);
#else
  memcpy(szPINENTRY, szGPGEXE, sizeof(szPINENTRY));
  p = strstr(szPINENTRY, "gpg");
  if (NULL != p)
    *p = 0;
  strncat(szPINENTRY, "pinentry-basic.exe", sizeof(szPINENTRY) - 1);
#endif

  fprintf(stdout,"\n%sRunning%s %sx509-2-pgp%s %sTEST SUITE%s...\n\n", ctrlCyan, ctrlReset, ctrlYellow, ctrlReset, ctrlGreen, ctrlReset);

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "version", NULL);
  if (0 != exitcode)
  {
    fprintf(stderr,"%sERROR%s: Unable to execute (process exit code %i): %s\n", ctrlRed, ctrlReset, exitcode, szOSSLEXE);
    return rc;
  }

  if (memcmp(stdout_buffer,"OpenSSL ", sizeof("OpenSSL ")-1))
  {
NoOpenSSLVersion:
    fprintf(stderr,"%sERROR%s: Unable to execute openssl binary to get version or version not parseable.\n", ctrlRed, ctrlReset);
    return rc;
  }

  if (3 != sscanf((const char *)&stdout_buffer[sizeof("OpenSSL ")-1], "%u.%u.%u", &ossl_major, &ossl_minor, &ossl_patch))
    goto NoOpenSSLVersion;

  fprintf(stdout,"%sINFO%s: %sOpenSSL%s version is %s%u.%u.%u%s\n", ctrlYellow, ctrlReset, ctrlCyan, ctrlReset, ctrlGreen, ossl_major, ossl_minor, ossl_patch, ctrlReset);

  if (ossl_major < 3)
  {
    fprintf(stderr,"%sERROR%s: An OpenSSL version 3+ is required in order to run this test suite.\n", ctrlRed, ctrlReset);
    return rc;
  }

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE, "--version", NULL);
  if (0 != exitcode)
  {
    fprintf(stderr,"%sERROR%s: Unable to execute (process exit code %i): %s\n", ctrlRed, ctrlReset, exitcode, szGPGEXE);
    return rc;
  }

  if (memcmp(stdout_buffer,"gpg (GnuPG) ", sizeof("gpg (GnuPG) ")-1))
  {
NoGPGVersion:
    fprintf(stderr,"%sERROR%s: Unable to execute gpg binary to get version or version not parseable.\n", ctrlRed, ctrlReset);
    return rc;
  }

  if (3 != sscanf((const char *)&stdout_buffer[sizeof("gpg (GnuPG) ")-1], "%u.%u.%u", &gpg_major, &gpg_minor, &gpg_patch))
    goto NoGPGVersion;

  fprintf(stdout,"%sINFO%s: %sGnuPG%s version is %s%u.%u.%u%s\n", ctrlYellow, ctrlReset, ctrlCyan, ctrlReset, ctrlGreen, gpg_major, gpg_minor, gpg_patch, ctrlReset);

  if ((gpg_major < 2) || (2 == gpg_major && gpg_minor < 4))
  {
    fprintf(stderr,"%sERROR%s: A GnuPG version 2.4.x+ is required in order to run this test suite.\n", ctrlRed, ctrlReset);
    return rc;
  }

#if defined(_LINUX) || defined(_MACOS)
  getcwd(cwd, sizeof(cwd));
  l_cwd = (uint32_t)strlen(cwd);
#else
  l_cwd = (uint32_t)GetCurrentDirectoryA(sizeof(cwd), cwd);
#endif

  (void)l_cwd;

#ifdef _WINDOWS
  GetSystemDirectoryA(winsysfolder, sizeof(winsysfolder));
  snprintf(szCmdExe, sizeof(szCmdExe), "%s%ccmd.exe", winsysfolder, PATHSEP_CHAR);
#endif

  snprintf(buffer,sizeof(buffer),"%s%cX509_2_PGP_TESTDIR", cwd, PATHSEP_CHAR);

#if defined(_LINUX) || defined(_MACOS)
  (void)execute_external_program(stdout_buffer, true, "/usr/bin/rm","-rf", buffer, NULL);
#else
  (void)execute_external_program(stdout_buffer, true, szCmdExe, "/c", "del", "/q", "/s", buffer, NULL);
  (void)execute_external_program(stdout_buffer, true, szCmdExe, "/c", "rmdir", "/q", "/s", buffer, NULL);
#endif

  if (0 != mkdir(buffer,0775))
  {
    fprintf(stderr,"%sERROR%s: Unable to create the test working directory: %s\n", ctrlRed, ctrlReset, buffer);
    return rc;
  }

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.log", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  _log = fopen(buffer, "wt");
  if (NULL == _log)
  {
    fprintf(stderr, "%sERROR%s: Unable to create log file: %s\n", ctrlRed, ctrlReset, buffer);
    return rc;
  }

  log_printf("x509-2-pgp test suite run\n\n");

  log_printf("using OpenSSL v%u.%u.%u\n", ossl_major, ossl_minor, ossl_patch);
  log_printf("using GnuPG (gpg) v%u.%u.%u\n", gpg_major, gpg_minor, gpg_patch);

  if (0 != pkcs11_library[0])
  {
    fprintf(stdout, "%sINFO%s: including PKCS#11 tests using library: %s%s%s\n", ctrlYellow, ctrlReset, ctrlMagenta, pkcs11_library, ctrlReset);
    fprintf(stdout, "%sINFO%s: PKCS#11 slot: %s%u%s\n", ctrlYellow, ctrlReset, ctrlMagenta, pkcs11_slot, ctrlReset);
    log_printf("activated PKCS#11 library '%s', slot %u\n", pkcs11_library, pkcs11_slot);
  }
  else
  {
    fprintf(stdout, "%sINFO%s: All PKCS#11 tests %sDISABLED%s\n", ctrlYellow, ctrlReset, ctrlMagenta, ctrlReset);
    log_printf("no PKCS#11 library -> disabled all PKCS#11 tests\n");
  }

  // if PKCS#11 library specified, then we DO NEED a PKCS#11 PIN

  if (0 != pkcs11_library[0] && 0 == pkcs11_pin[0])
  {
    log_printf("ERROR: PKCS#11 library specified but no PKCS#11 PIN available. Aborting.\n");
    fprintf(stderr, "%sERROR%s: PKCS#11 library specified but no PKCS#11 PIN available. Aborting.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // Get executable file (self) and initialize environment for tests

  memset(x509_to_pgp, 0, sizeof(x509_to_pgp));
  get_executable_path(x509_to_pgp, sizeof(x509_to_pgp),false);

  (void)unsetenv("PKCS11_PIN");
  (void)unsetenv("PKCS11_SLOT");
  (void)unsetenv("PKCS11_LIBRARY");
  (void)unsetenv("SECRET");
  (void)unsetenv("PGP_SECRET");

  // Delete all PKCS#11 test keys in the PKCS#11 module (if desired)

  (void)putenv_fmt(env_pkcs11_pin, sizeof(env_pkcs11_pin), "PKCS11_PIN=%s", pkcs11_pin);
  snprintf(pkcs11_slot_str, sizeof(pkcs11_slot_str), "%u", pkcs11_slot);

  for (i = 0; i < NUM_KEYS; i++)
  {
    log_message(true, "Deleting PKCS#11 key pair '%s'", szP11KeyLabels[i]);
    if (0 == pkcs11_library[0])
      log_result(test_skipped);
    else
    {
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "deletepkcs11key", "--p11lib", pkcs11_library, "--p11slot", pkcs11_slot_str, "--p11label", szP11KeyLabels[i], "--iknowwhatiamdoing", NULL);
      if (0 == exitcode)
      {
        log_result(test_ok);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
      }
      else
      if (1 == exitcode)
      {
        log_result(test_ignored);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }
    }
  }

  (void)unsetenv("PKCS11_PIN");

  // Generate key pairs in software (using OpenSSL), use the secret "123456" for rsa3072, for ecbpool512, and for ed25519_1 (i.e. encrypted PEM files)
  // indices 1, 8, 9

  for (i = 0; i < NUM_KEYS; i++)
  {
    if (1 == i || 2 == i)
      log_message(true, "Generating OpenSSL key pair '%s', public exp. 0xC0000001", szKeyTypes[i]);
    else
      log_message(true, "Generating OpenSSL key pair '%s'", szKeyTypes[i]);
    if (1 == i || 8 == i || 9 == i)
      (void)putenv("SECRET=123456");
    else
      (void)putenv("SECRET=\"\"");

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, szKeyNames[i]);

    if (1 == i || 2 == i) // for RSA3072/4096 use an alternative public exponent e:
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "genkeypair", szKeyTypes[i], "-o", buffer, "--rsaexp", "0xC0000001", NULL);
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "genkeypair", szKeyTypes[i], "-o", buffer, NULL);
    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  // Generate key pairs in hardware (using PKCS#11), if any key generations fail (e.g. if Edwards Curves not supported), this is ignored (and of course, those key pairs are not used in subsequent tests)
  // indices 1, 8, 9

  (void)putenv(env_pkcs11_pin);
  for (i = 0; i < NUM_KEYS; i++)
  {
    if (1 == i || 2 == i)
      log_message(true, "Generating PKCS#11 key pair '%s', public exp. 0xC0000001", szKeyTypes[i]);
    else
      log_message(true, "Generating PKCS#11 key pair '%s'", szKeyTypes[i]);

    if (0 == pkcs11_library[0])
    {
      log_result(test_skipped);
      continue;
    }

#if 0
    if (8 == i) // just here for testing what happens if a specify PKCS#11 key pair cannot be generated
    {
      log_result(test_skipped);
      continue;
    }
#endif

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, szP11KeyLabels[i]);

    if (1 == i || 2 == i) // for RSA3072/4096 use an alternative public exponent e:
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "genkeypair", szKeyTypes[i], "-o", buffer, "--rsaexp", "0xC0000001", "--p11slot", pkcs11_slot_str, "--p11lib", pkcs11_library, "--p11label", szP11KeyLabels[i], NULL);
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "genkeypair", szKeyTypes[i], "-o", buffer, "--p11slot", pkcs11_slot_str, "--p11lib", pkcs11_library, "--p11label", szP11KeyLabels[i], NULL);
    if (0 == exitcode)
    {
      log_result(test_ok);
      p11_key_available[i] = true;
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_skipped);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }
  (void)unsetenv("PKCS11_PIN");

  //
  // Issue OpenSSL X.509v3 certificates for all software keys

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%copenssl.conf", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  f = fopen(buffer, "wt");
  if (NULL != f)
    fclose(f);
  putenv_fmt(env_openssl_conf_file, sizeof(env_openssl_conf_file), "OPENSSL_CONF=%s", buffer);

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/2048bit, PKCS#1 v1.5", "rsa2048.prv.pem", "cert_rsa2048_v15.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha256", "-days", "3650", "-set_serial", "1001", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA2048 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa2048_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa2048_v15@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/2048bit, PSS", "rsa2048.prv.pem", "cert_rsa2048_pss.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha256", "-days", "3650", "-set_serial", "1001", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA2048 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa2048_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa2048_v15@test.com", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/3072bit, PKCS#1 v1.5", "rsa3072.prv.pem", "cert_rsa3072_v15.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha384", "-days", "3650", "-set_serial", "1003", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA3072 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa3072_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa3072_v15@test.com", "-passin", "pass:123456",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/3072bit, PSS", "rsa3072.prv.pem", "cert_rsa3072_pss.pem", 
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha384", "-days", "3650", "-set_serial", "1004", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA3072 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa3072_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa3072_v15@test.com","-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:48", "-passin", "pass:123456",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/4096bit, PKCS#1 v1.5", "rsa4096.prv.pem", "cert_rsa4096_v15.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha512", "-days", "3650", "-set_serial", "1005", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA4096 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa4096_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa4096_v15@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), RSA/4096bit, PSS", "rsa4096.prv.pem", "cert_rsa4096_pss.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha512", "-days", "3650", "-set_serial", "1006", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (RSA4096 PKCS #1 1.5)/O=organization/OU=orgunit/emailAddress=rsa4096_v15@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rsa4096_v15@test.com", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:64",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/NIST/256bit", "ecnist256.prv.pem", "cert_ecnist256.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha256", "-days", "3650", "-set_serial", "1007", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC NIST256)/O=organization/OU=orgunit/emailAddress=ecnist256@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecnist256@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/NIST/384bit", "ecnist384.prv.pem", "cert_ecnist384.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha384", "-days", "3650", "-set_serial", "1008", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC NIST384)/O=organization/OU=orgunit/emailAddress=ecnist384@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecnist384@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/NIST/521bit", "ecnist521.prv.pem", "cert_ecnist521.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha512", "-days", "3650", "-set_serial", "1009", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC NIST521)/O=organization/OU=orgunit/emailAddress=ecnist521@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecnist521@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/BPOOL/256bit", "ecbpool256.prv.pem", "cert_ecbpool256.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha256", "-days", "3650", "-set_serial", "1010", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC BPOOL256)/O=organization/OU=orgunit/emailAddress=ecbpool256@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecbpool256@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/BPOOL/384bit", "ecbpool384.prv.pem", "cert_ecbpool384.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha384", "-days", "3650", "-set_serial", "1011", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC BPOOL384)/O=organization/OU=orgunit/emailAddress=ecbpool384@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecbpool384@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ECC/BPOOL/512bit", "ecbpool512.prv.pem", "cert_ecbpool512.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-sha512", "-days", "3650", "-set_serial", "1012", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ECC BPOOL521)/O=organization/OU=orgunit/emailAddress=ecbpool512@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ecbpool512@test.com", "-passin", "pass:123456",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ED25519 #1", "ed25519_1.prv.pem", "cert_ed25519_1.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "3650", "-set_serial", "1013", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ED25519-1)/O=organization/OU=orgunit/emailAddress=ed25519_1@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ed25519_1@test.com", "-passin", "pass:123456",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ED25519 #2", "ed25519_2.prv.pem", "cert_ed25519_2.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "3650", "-set_serial", "1014", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ED25519-2)/O=organization/OU=orgunit/emailAddress=ed25519_2@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ed25519_2@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), ED448", "ed448.prv.pem", "cert_ed448.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "3650", "-set_serial", "1015", "-subj", OSSL_DQUOTE "/C=DE/CN=codesigner (ED448)/O=organization/OU=orgunit/emailAddress=ed448@test.com" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ed448@test.com",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  (void)putenv("SECRET=123456");

  for (i = 0; i < ((int)((sizeof(p11_certs) / sizeof(p11_certs[0])))); i++)
  {
    log_message(true, "Patching X.509v3 '%s' for PKCS#11", p11_certs[i].what);

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR,p11_certs[i].cert_in);
    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%cpatched-%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR,p11_certs[i].cert_in);

    if (!p11_key_available[p11_certs[i].keyidx])
    {
      log_result(test_skipped);
      log_message(true, "Verifying self-signed X.509v3 '%s'", p11_certs[i].what);
      log_result(test_skipped);
      continue;
    }
    exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "patchx509",
                                        "--p11slot", pkcs11_slot_str,
                                        "--p11lib", pkcs11_library,
                                        "--p11label", p11_certs[i].p11_label,
                                        "-i", buffer,
                                        "-o", buffer2,
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "Verifying self-signed X.509v3 '%s'", p11_certs[i].what);

    exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer2, buffer2, NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  // unsetenv("SECRET");

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c.gnupg", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  if (0 != mkdir(buffer, 0775))
  {
    fprintf(stderr, "%sERROR%s: Unable to create the .gnupg directory inside the test working directory: %s\n", ctrlRed, ctrlReset, buffer);
    goto Exit;
  }

  snprintf(env_gnupg_dir,sizeof(env_gnupg_dir), "GNUPGHOME=%s%cX509_2_PGP_TESTDIR%c.gnupg", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  (void)putenv(env_gnupg_dir);

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c.gnupg%cgpg-agent.conf", cwd, PATHSEP_CHAR, PATHSEP_CHAR, PATHSEP_CHAR);
  f = fopen(buffer, "wt");
  if (NULL != f)
  {
    fprintf(f, "pinentry-program %s\n", szPINENTRY);
    fclose(f);
  }

  log_message(true, "Killing gpg-agent (if any)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGCONF, "--kill", "gpg-agent", NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

  log_message(true, "Starting gpg-agent");

  exitcode = execute_external_program(stdout_buffer, true, szGPGCONF, "--launch", "gpg-agent", NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to continue without having a gpg-agent running in the background.\n", ctrlRed, ctrlReset);
    goto Exit;
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Generating random test data");

  p_random = (uint8_t*)malloc(65536);
  if (unlikely(NULL == p_random))
  {
    log_result(test_failed);
    fprintf(stderr, "%sERROR%s: insufficient memory available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  RAND_pseudo_bytes(p_random, 65536);

  snprintf(pgp_random_file, sizeof(pgp_random_file), "%s%cX509_2_PGP_TESTDIR%ctestpgp64k.dat", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  if (!write_file(pgp_random_file,p_random, 65536))
  {
    free(p_random);
    log_result(test_failed);
    fprintf(stderr, "%sERROR%s: Unable to create random data file: %s\n", ctrlRed, ctrlReset, pgp_random_file);
    goto Exit;
  }

  snprintf(pgp_random_file2, sizeof(pgp_random_file2), "%s%cX509_2_PGP_TESTDIR%ctestpgp1k.dat", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  if (!write_file(pgp_random_file2,p_random+32768, 1024))
  {
    free(p_random);
    log_result(test_failed);
    fprintf(stderr, "%sERROR%s: Unable to create random data file: %s\n", ctrlRed, ctrlReset, pgp_random_file2);
    goto Exit;
  }

  free(p_random);
  log_result(test_ok);

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  (void)putenv("PGP_SECRET=123456");

  for (i = 0; i < ((int)(sizeof(pgp_import_tests)/sizeof(pgp_import_tests[0]))); i++)
  {
    log_message(true, "Creating PGP binary import for %s", pgp_import_tests[i].info);

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, pgp_import_tests[i].privkey_file);

    exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                        "pgpimport",
                                        "-o", buffer,
                                        "--prv", buffer2,
                                        "--user", pgp_import_tests[i].user_name,
                                        "--email", pgp_import_tests[i].email_addr,
                                        "--digest", pgp_import_tests[i].digest,
                                        "--do-verify",
                                        "--enc-aescfb",
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "Performing PGP import for %s", pgp_import_tests[i].info);
    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                        "--import",
                                        "--batch",
                                        buffer,
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%ctestpgp.sig", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    (void)unlink(buffer2);

    log_message(true, "PGP test detached signature for %s", pgp_import_tests[i].info);
    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                        "-v",
                                        "-b",
                                        "-o", buffer2,
                                        "-u", pgp_import_tests[i].email_addr,
                                        pgp_random_file,
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "PGP detached signature verification for %s", pgp_import_tests[i].info);
    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                        "--verify", buffer2, pgp_random_file, NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  (void)unsetenv("PGP_SECRET");
  // SECRET still set, which acts as PKCS#11 PIN here

  for (i = 0; i < ((int)(sizeof(pgp_import_tests)/sizeof(pgp_import_tests[0]))); i++)
  {
    log_message(true, "Creating PGP binary import for %s", pgp_import_tests[i].p11_info);

    if (!p11_key_available[pgp_import_tests[i].keyidx])
    {
      log_result(test_skipped);
      log_message(true, "Performing PGP import for %s", pgp_import_tests[i].p11_info);
      log_result(test_skipped);
      continue;
    }

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, pgp_import_tests[i].p11_pubkey);

    exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                        "pgpimport",
                                        "-o", buffer,
                                        // "--pub", buffer2,
                                        "--user", pgp_import_tests[i].p11_user_name,
                                        "--email", pgp_import_tests[i].p11_email_addr,
                                        "--digest", pgp_import_tests[i].digest,
                                        "--do-verify",
                                        "--p11slot", pkcs11_slot_str,
                                        "--p11lib", pkcs11_library,
                                        "--p11label", pgp_import_tests[i].p11_label,
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "Performing PGP import for %s", pgp_import_tests[i].p11_info);
    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                        "--import",
                                        "--batch",
                                        buffer,
                                        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  for (i = 0; i < ((int)(sizeof(ossl_tests)/sizeof(ossl_tests[0]))); i++)
  {
    log_message(true, "OSSL signing test %s", ossl_tests[i].info);

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, ossl_tests[i].privkey_file);
    snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, ossl_tests[i].x509);
    memcpy(buffer2, buffer, sizeof(buffer2));
    p = strstr(buffer2,"prv");
    if (NULL != p)
    {
      p[1] = 'u'; // make pub from prv file name...
      p[2] = 'b';
    }

    if (0 != ossl_tests[i].digest[0])
    {
      if (0 == ossl_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "sign",
                                            "--prv", buffer,
                                            "--digest", ossl_tests[i].digest,
                                            pgp_random_file,
                                            pgp_random_file2,
                                            NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "sign",
                                            "--prv", buffer,
                                            "--digest", ossl_tests[i].digest,
                                            "--use-pss",
                                            pgp_random_file,
                                            pgp_random_file2,
                                            NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                          "sign",
                                          "--prv", buffer,
                                          pgp_random_file,
                                          pgp_random_file2,
                                          NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "OSSL verification test 1/4 %s", ossl_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);
    if (0 != ossl_tests[i].digest[0])
    {
      if (0 == ossl_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "verify",
                                            pgp_random_file,
                                            buffer3,
                                            buffer2,
                                            "--digest", ossl_tests[i].digest,
                                            NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "verify",
                                            pgp_random_file,
                                            buffer3,
                                            buffer2,
                                            "--digest", ossl_tests[i].digest,
                                            "--use-pss",
                                            NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                          "verify",
                                          pgp_random_file,
                                          buffer3,
                                          buffer2,
                                          NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "OSSL verification test 2/4 %s", ossl_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);
    if (0 != ossl_tests[i].digest[0])
    {
      if (0 == ossl_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "verify",
                                             pgp_random_file2,
                                            buffer3,
                                            buffer2,
                                            "--digest", ossl_tests[i].digest,
                                            NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                            "verify",
                                             pgp_random_file2,
                                            buffer3,
                                            buffer2,
                                            "--use-pss",
                                            "--digest", ossl_tests[i].digest,
                                            NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                          "verify",
                                           pgp_random_file2,
                                          buffer3,
                                          buffer2,
                                          NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "OSSL verification test 3/4 (X.509v3) %s", ossl_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);
    if (0 != ossl_tests[i].digest[0])
    {
      if (0 == ossl_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer4,
          "--digest", ossl_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer4,
          "--digest", ossl_tests[i].digest,
          "--use-pss",
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "verify",
        pgp_random_file,
        buffer3,
        buffer4,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "OSSL verification test 4/4 (X.509v3) %s", ossl_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);
    if (0 != ossl_tests[i].digest[0])
    {
      if (0 == ossl_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer4,
          "--digest", ossl_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer4,
          "--use-pss",
          "--digest", ossl_tests[i].digest,
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "verify",
        pgp_random_file2,
        buffer3,
        buffer4,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  for (i = 0; i < ((int)(sizeof(p11_tests) / sizeof(p11_tests[0]))); i++)
  {
    log_message(true, "PKCS#11 signing test %s", p11_tests[i].info);

    if (!p11_key_available[p11_tests[i].keyidx])
    {
      log_result(test_skipped);
      log_message(true, "OSSL verification test 1/4 %s", p11_tests[i].info);
      log_result(test_skipped);
      log_message(true, "OSSL verification test 2/4 %s", p11_tests[i].info);
      log_result(test_skipped);
      log_message(true, "OSSL verification test 3/4 %s", p11_tests[i].info);
      log_result(test_skipped);
      log_message(true, "OSSL verification test 4/4 %s", p11_tests[i].info);
      log_result(test_skipped);
      continue;
    }

    snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%c%s.pub.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR, p11_tests[i].p11_label);
    snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, p11_tests[i].x509);

    if (0 != p11_tests[i].digest[0])
    {
      if (0 == p11_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "sign",
          "--p11slot", pkcs11_slot_str,
          "--p11lib", pkcs11_library,
          "--p11label", p11_tests[i].p11_label,
          "--digest", p11_tests[i].digest,
          pgp_random_file,
          pgp_random_file2,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "sign",
          "--p11slot", pkcs11_slot_str,
          "--p11lib", pkcs11_library,
          "--p11label", p11_tests[i].p11_label,
          "--digest", p11_tests[i].digest,
          "--use-pss",
          pgp_random_file,
          pgp_random_file2,
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "sign",
        "--p11slot", pkcs11_slot_str,
        "--p11lib", pkcs11_library,
        "--p11label", p11_tests[i].p11_label,
        pgp_random_file,
        pgp_random_file2,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
      if (1 == exitcode)
      {
        log_result(test_failed);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
        continue;
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }

    log_message(true, "OSSL verification test 1/4 %s", p11_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);
    if (0 != p11_tests[i].digest[0])
    {
      if (0 == p11_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer2,
          "--digest", p11_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer2,
          "--digest", p11_tests[i].digest,
          "--use-pss",
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "verify",
        pgp_random_file,
        buffer3,
        buffer2,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
      if (1 == exitcode)
      {
        log_result(test_failed);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
        continue;
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }

    log_message(true, "OSSL verification test 2/4 %s", p11_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);
    if (0 != p11_tests[i].digest[0])
    {
      if (0 == p11_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer2,
          "--digest", p11_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer2,
          "--use-pss",
          "--digest", p11_tests[i].digest,
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "verify",
        pgp_random_file2,
        buffer3,
        buffer2,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
      if (1 == exitcode)
      {
        log_result(test_failed);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
        continue;
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }

    log_message(true, "OSSL verification test 3/4 (X.509v3) %s", p11_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);
    if (0 != p11_tests[i].digest[0])
    {
      if (0 == p11_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer4,
          "--digest", p11_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file,
          buffer3,
          buffer4,
          "--digest", p11_tests[i].digest,
          "--use-pss",
          NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "verify",
        pgp_random_file,
        buffer3,
        buffer4,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
      if (1 == exitcode)
      {
        log_result(test_failed);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
        continue;
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }

    log_message(true, "OSSL verification test 4/4 (X.509v3) %s", p11_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);
    if (0 != p11_tests[i].digest[0])
    {
      if (0 == p11_tests[i].pss[0])
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer4,
          "--digest", p11_tests[i].digest,
          NULL);
      else
        exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
          "verify",
          pgp_random_file2,
          buffer3,
          buffer4,
          "--use-pss",
          "--digest", p11_tests[i].digest,
          NULL);
    }
    else
    exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
      "verify",
      pgp_random_file2,
      buffer3,
      buffer4,
      NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  for (i = 0; i < ((int)(sizeof(pgp_import_tests) / sizeof(pgp_import_tests[0]))); i++)
  {
    log_message(true, "PGP detached signing test %s", pgp_import_tests[i].info);

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c%s", cwd, PATHSEP_CHAR, PATHSEP_CHAR, pgp_import_tests[i].privkey_file);

    if (0 != pgp_import_tests[i].digest[0])
    {
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "pgpsign",
        "--email", pgp_import_tests[i].email_addr,
        "--prv", buffer,
        "--digest", pgp_import_tests[i].digest,
        pgp_random_file,
        pgp_random_file2,
        NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "pgpsign",
        "--email", pgp_import_tests[i].email_addr,
        "--prv", buffer,
        pgp_random_file,
        pgp_random_file2,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "GPG verification test 1/2 %s", pgp_import_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);

    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
      "--verify",
      buffer3,
      pgp_random_file,
      NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "GPG verification test 2/2 %s", pgp_import_tests[i].info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);

    // execute_external_program(stdout_buffer, true, "/usr/bin/pgpdump", "-ilmpu", buffer3, NULL);
    // log_transfer_stdout();

    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
      "--verify",
      buffer3,
      pgp_random_file2,
      NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  for (i = 0; i < ((int)(sizeof(pgp_import_tests) / sizeof(pgp_import_tests[0]))); i++)
  {
    log_message(true, "PGP detached signing test %s", pgp_import_tests[i].p11_info);

    if (!p11_key_available[pgp_import_tests[i].keyidx])
    {
      log_result(test_skipped);
      log_message(true, "GPG verification test 1/2 %s", pgp_import_tests[i].p11_info);
      log_result(test_skipped);
      log_message(true, "GPG verification test 2/2 %s", pgp_import_tests[i].p11_info);
      log_result(test_skipped);
      continue;
    }

    if (0 != pgp_import_tests[i].digest[0])
    {
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "pgpsign",
        "--email", pgp_import_tests[i].p11_email_addr,
        "--digest", pgp_import_tests[i].digest,
        "--p11slot", pkcs11_slot_str,
        "--p11lib", pkcs11_library,
        "--p11label", pgp_import_tests[i].p11_label,
        pgp_random_file,
        pgp_random_file2,
        NULL);
    }
    else
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
        "pgpsign",
        "--email", pgp_import_tests[i].p11_email_addr,
        "--p11slot", pkcs11_slot_str,
        "--p11lib", pkcs11_library,
        "--p11label", pgp_import_tests[i].p11_label,
        pgp_random_file,
        pgp_random_file2,
        NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
      if (1 == exitcode)
      {
        log_result(test_failed);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
        continue;
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }

    log_message(true, "GPG verification test 1/2 %s", pgp_import_tests[i].p11_info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file);

    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
      "--verify",
      buffer3,
      pgp_random_file,
      NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }

    log_message(true, "GPG verification test 2/2 %s", pgp_import_tests[i].p11_info);

    snprintf(buffer3, sizeof(buffer3), "%s.sig", pgp_random_file2);

    exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
      "--verify",
      buffer3,
      pgp_random_file2,
      NULL);

    if (0 == exitcode)
    {
      log_result(test_ok);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
    }
    else
    if (1 == exitcode)
    {
      log_result(test_failed);
      log_printf("Program stdout/stderr output was:\n");
      log_transfer_stdout();
      continue;
    }
    else
    {
      log_result(test_failed);
      log_transfer_stdout();
      fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
      goto Exit;
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c.gnupg", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  log_message(true, "Killing gpg-agent (if any)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGCONF, "--kill", "gpg-agent", NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

#if defined(_LINUX) || defined(_MACOS)
  (void)execute_external_program(stdout_buffer, true, "/usr/bin/rm", "-rf", buffer, NULL);
#else
  (void)execute_external_program(stdout_buffer, true, szCmdExe, "/c", "del", "/q", "/s", buffer, NULL);
  (void)execute_external_program(stdout_buffer, true, szCmdExe, "/c", "rmdir", "/q", "/s", buffer, NULL);
#endif

  if (0 != mkdir(buffer, 0775))
  {
    fprintf(stderr, "%sERROR%s: Unable to re-create the .gnupg directory inside the test working directory: %s\n", ctrlRed, ctrlReset, buffer);
    goto Exit;
  }

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%c.gnupg%cgpg-agent.conf", cwd, PATHSEP_CHAR, PATHSEP_CHAR, PATHSEP_CHAR);
  f = fopen(buffer, "wt");
  if (NULL != f)
  {
    fprintf(f, "pinentry-program %s\n", szPINENTRY);
    fclose(f);
  }

  log_message(true, "Starting gpg-agent");

  exitcode = execute_external_program(stdout_buffer, true, szGPGCONF, "--launch", "gpg-agent", NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to continue without having a gpg-agent running in the background.\n", ctrlRed, ctrlReset);
    goto Exit;
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), Root-CA (ED448)", "ed448.prv.pem", "rootca_ossl.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "7000", "-set_serial", "10001", "-subj", OSSL_DQUOTE "/C=DE/CN=Root-CA (OSSL)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rootca-ossl@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  log_message(true, "Using OpenSSL to verify self-signed Root-CA");

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer2, buffer2, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%crootca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%ced448.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), Sub-CA (RSA4096)", "rsa4096.prv.pem", "subca_ossl.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "5000", "-set_serial", "10002", "-subj", OSSL_DQUOTE "/C=DE/CN=Sub-CA (OSSL)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:subca-ossl@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
    "-CA", buffer3, "-CAkey", buffer4);

  log_message(true, "Using OpenSSL to verify Sub-CA");

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer3, buffer2, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%csubca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%crsa4096.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), End-Entity (BPOOL384)", "ecbpool384.prv.pem", "ee_ossl.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "3000", "-set_serial", "10003", "-subj", OSSL_DQUOTE "/C=DE/CN=End Entity (OSSL)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ee-ossl@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature",
    "-CA", buffer3, "-CAkey", buffer4,
    "-sha512", "-sigopt", "rsa_padding_mode:pss", "-sigopt","rsa_pss_saltlen:64");

  log_message(true, "Using OpenSSL to verify End-Entity");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ccacerts-ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  f = fopen(buffer, "wt");
  if (NULL != f)
  {
    FILE *g;
    char filebuf[1024];

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%crootca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    g = fopen(buffer, "rt");
    if (NULL != g)
    {
      memset(filebuf, 0, sizeof(filebuf));
      while (fgets(filebuf, sizeof(filebuf), g))
      {
        fprintf(f, "%s", filebuf);
        memset(filebuf, 0, sizeof(filebuf));
      }
      fclose(g);
    }

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%csubca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    g = fopen(buffer, "rt");
    if (NULL != g)
    {
      memset(filebuf, 0, sizeof(filebuf));
      while (fgets(filebuf, sizeof(filebuf), g))
      {
        fprintf(f, "%s", filebuf);
        memset(filebuf, 0, sizeof(filebuf));
      }
      fclose(g);
    }
    fclose(f);
  }

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%ccacerts-ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer3, buffer2, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  if (0 == pkcs11_library[0])
  {
    log_message(true, "Generating X.509v3 certificate(OpenSSL), Root-CA (ED448)");
    log_result(test_skipped);
    log_message(true, "Patching PKCS#11 key into Root-CA");
    log_result(test_skipped);
    log_message(true, "Using OpenSSL to verify self-signed Root-CA (PKCS#11)");
    log_result(test_skipped);
    log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
    log_result(test_skipped);
    log_message(true, "Generating X.509v3 certificate(OpenSSL), Sub-CA (RSA4096)");
    log_result(test_skipped);
    log_message(true, "Patching PKCS#11 key into Sub-CA");
    log_result(test_skipped);
    log_message(true, "Using OpenSSL to verify Sub-CA (PKCS#11)");
    log_result(test_skipped);
    log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
    log_result(test_skipped);
    log_message(true, "Generating X.509v3 certificate(OpenSSL), End-Entity (BPOOL384)");
    log_result(test_skipped);
    log_message(true, "Patching PKCS#11 key into End-Entity");
    log_result(test_skipped);
    log_message(true, "Using OpenSSL to verify End-Entity (PKCS#11)");
    log_result(test_skipped);
  }
  else
  {
  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), Root-CA (ED448)", "ed448.prv.pem", "rootca_p11_template.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "7000", "-set_serial", "20001", "-subj", OSSL_DQUOTE "/C=DE/CN=Root-CA (PKCS#11)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:rootca-pkcs11@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign");

  log_message(true, "Patching PKCS#11 key into Root-CA");

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%crootca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "patchx509",
    "--p11slot", pkcs11_slot_str,
    "--p11lib", pkcs11_library,
    "--p11label", "p11_ed448",
    "-i", buffer2,
    "-o", buffer3, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Using OpenSSL to verify self-signed Root-CA (PKCS#11)");

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer3, buffer3, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%crootca_p11_template.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%ced448.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), Sub-CA (RSA4096)", "rsa4096.prv.pem", "subca_p11_template.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "5000", "-set_serial", "20002", "-subj", OSSL_DQUOTE "/C=DE/CN=Sub-CA (PKCS#11)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:subca-pkcs11@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
    "-CA", buffer3, "-CAkey", buffer4);

  log_message(true, "Patching PKCS#11 key into Sub-CA");

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%csubca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%crootca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "patchx509",
    "--p11slot", pkcs11_slot_str,
    "--p11lib", pkcs11_library,
    "--p11label", "p11_rsa4096",
    "--pubcert", buffer4,
    "--p11labelcert", "p11_ed448",
    "-i", buffer2,
    "-o", buffer3, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Using OpenSSL to verify Sub-CA (PKCS#11)");

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer4, buffer3, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Sleeping two (2) seconds circumventing shell model problems");
#ifdef _WINDOWS
  Sleep(2000);
#else
  sleep(2);
#endif
  log_result(test_ok);

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%csubca_p11_template.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%crsa4096.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  ISSUE_CERT("Generating X.509v3 certificate(OpenSSL), End-Entity (BPOOL384)", "ecbpool384.prv.pem", "ee_p11_template.pem",
    "req", "-x509", "-key", buffer, "-out", buffer2,
    "-days", "3000", "-set_serial", "20003", "-subj", OSSL_DQUOTE "/C=DE/CN=End Entity (PKCS#11)/O=organization/OU=orgunit" OSSL_DQUOTE,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=email:ee-pkcs11@company.org",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,digitalSignature",
    "-CA", buffer3, "-CAkey", buffer4,
    "-sha512", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:64");

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%csubca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%cee_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  log_message(true, "Patching PKCS#11 key into End-Entity");

  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "patchx509",
    "--p11slot", pkcs11_slot_str,
    "--p11lib", pkcs11_library,
    "--p11label", "p11_ecbpool384",
    "--pubcert", buffer3,
    "--p11labelcert", "p11_rsa4096",
    "-i", buffer2,
    "-o", buffer4, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Using OpenSSL to verify End-Entity (PKCS#11)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ccacerts-p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  f = fopen(buffer, "wt");
  if (NULL != f)
  {
    FILE* g;
    char filebuf[1024];

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%crootca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    g = fopen(buffer, "rt");
    if (NULL != g)
    {
      memset(filebuf, 0, sizeof(filebuf));
      while (fgets(filebuf, sizeof(filebuf), g))
      {
        fprintf(f, "%s", filebuf);
        memset(filebuf, 0, sizeof(filebuf));
      }
      fclose(g);
    }

    snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%csubca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
    g = fopen(buffer, "rt");
    if (NULL != g)
    {
      memset(filebuf, 0, sizeof(filebuf));
      while (fgets(filebuf, sizeof(filebuf), g))
      {
        fprintf(f, "%s", filebuf);
        memset(filebuf, 0, sizeof(filebuf));
      }
      fclose(g);
    }
    fclose(f);
  }

  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%ccacerts-p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, szOSSLEXE, "verify", "-CAfile", buffer3, buffer4, NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  (void)putenv("PGP_SECRET=123456");

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (Root-CA, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%crootca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%ced448.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--prv", buffer3,
                                      "--digest", "sha512",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (Root-CA, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (Sub-CA, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%csubca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%crsa4096.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%crootca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer5, sizeof(buffer5), "%s%cX509_2_PGP_TESTDIR%ced448.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--prv", buffer3,
                                      "--pubcert", buffer4,
                                      "--prvcert", buffer5,
                                      "--digest", "sha512",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (Sub-CA, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE, "-v", "--allow-non-selfsigned-uid",
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (End-Entity, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%cee_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer3, sizeof(buffer3), "%s%cX509_2_PGP_TESTDIR%cecbpool384.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%csubca_ossl.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer5, sizeof(buffer5), "%s%cX509_2_PGP_TESTDIR%crsa4096.prv.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--prv", buffer3,
                                      "--pubcert", buffer4,
                                      "--prvcert", buffer5,
                                      "--digest", "sha384",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing OpenSSL CA hierarchy into GnuPG (End-Entity, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE, "-v", "--allow-non-selfsigned-uid",
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  if (0 == pkcs11_library[0])
  {
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Root-CA, create import)");
    log_result(test_skipped);
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Root-CA, perform import)");
    log_result(test_skipped);
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Sub-CA, create import)");
    log_result(test_skipped);
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Sub-CA, perform import)");
    log_result(test_skipped);
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (End-Entity, create import)");
    log_result(test_skipped);
    log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (End-Entity, perform import)");
    log_result(test_skipped);
  }
  else
  {
  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Root-CA, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%crootca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);

  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--digest", "sha512",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      "--p11slot", pkcs11_slot_str,
                                      "--p11lib", pkcs11_library,
                                      "--p11label", "p11_ed448",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Root-CA, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE,
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Sub-CA, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%csubca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%crootca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--pubcert", buffer4,
                                      "--digest", "sha512",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      "--p11slot", pkcs11_slot_str,
                                      "--p11lib", pkcs11_library,
                                      "--p11label", "p11_rsa4096",
                                      "--p11labelcert", "p11_ed448",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (Sub-CA, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE, "-v", "--allow-non-selfsigned-uid",
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (End-Entity, create import)");

  snprintf(buffer, sizeof(buffer), "%s%cX509_2_PGP_TESTDIR%ctest.pgp", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer2, sizeof(buffer2), "%s%cX509_2_PGP_TESTDIR%cee_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  snprintf(buffer4, sizeof(buffer4), "%s%cX509_2_PGP_TESTDIR%csubca_p11.pem", cwd, PATHSEP_CHAR, PATHSEP_CHAR);
  exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp,
                                      "pgpimport",
                                      "-o", buffer,
                                      "--pub", buffer2,
                                      "--pubcert", buffer4,
                                      "--digest", "sha384",
                                      "--do-verify",
                                      "--enc-aescfb",
                                      "--p11slot", pkcs11_slot_str,
                                      "--p11lib", pkcs11_library,
                                      "--p11label", "p11_ecbpool384",
                                      "--p11labelcert", "p11_rsa4096",
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }

  log_message(true, "Importing PKCS#11 CA hierarchy into GnuPG (End-Entity, perform import)");

  exitcode = execute_external_program(stdout_buffer, true, szGPGEXE, "-v", "--allow-non-selfsigned-uid",
                                      "--import",
                                      "--batch",
                                      buffer,
                                      NULL);

  if (0 == exitcode)
  {
    log_result(test_ok);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  if (1 == exitcode)
  {
    log_result(test_failed);
    log_printf("Program stdout/stderr output was:\n");
    log_transfer_stdout();
  }
  else
  {
    log_result(test_failed);
    log_transfer_stdout();
    fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
    goto Exit;
  }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Delete all PKCS#11 test keys in the PKCS#11 module (if desired)

  (void)putenv_fmt(env_pkcs11_pin, sizeof(env_pkcs11_pin), "PKCS11_PIN=%s", pkcs11_pin);
  snprintf(pkcs11_slot_str, sizeof(pkcs11_slot_str), "%u", pkcs11_slot);

  for (i = 0; i < NUM_KEYS; i++)
  {
    log_message(true, "Deleting PKCS#11 key pair '%s'", szP11KeyLabels[i]);
    if (0 == pkcs11_library[0])
      log_result(test_skipped);
    else
    {
      exitcode = execute_external_program(stdout_buffer, true, x509_to_pgp, "deletepkcs11key", "--p11lib", pkcs11_library, "--p11slot", pkcs11_slot_str, "--p11label", szP11KeyLabels[i], "--iknowwhatiamdoing", NULL);
      if (0 == exitcode)
      {
        log_result(test_ok);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
      }
      else
      if (1 == exitcode)
      {
        log_result(test_ignored);
        log_printf("Program stdout/stderr output was:\n");
        log_transfer_stdout();
      }
      else
      {
        log_result(test_failed);
        log_transfer_stdout();
        fprintf(stderr, "%sERROR%s: unable to execute program as sub-process: process exit code: %i\n", ctrlRed, ctrlReset, exitcode);
        goto Exit;
      }
    }
  }

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  fprintf(stdout,"%s%u%s test(s) %sOK%s, %s%u%s test(s) %sFAILED%s, %s%u%s test(s) %sSKIPPED%s, %s%u%s test(s) %sIGNORED%s => %u overall (SHALL BE %u).\n",
      ctrlCyan,test_stat[test_ok],ctrlReset, ctrlGreen, ctrlReset,
      ctrlCyan,test_stat[test_failed],ctrlReset, ctrlRed, ctrlReset,
      ctrlCyan,test_stat[test_skipped],ctrlReset, ctrlYellow, ctrlReset,
      ctrlCyan,test_stat[test_ignored],ctrlReset, ctrlMagenta, ctrlReset,
      test_stat[test_ok] + test_stat[test_failed] + test_stat[test_skipped] + test_stat[test_ignored],
      NUM_OVERALL_TESTS);

  rc = (0 == test_stat[test_failed]) ? 0 : 1;

Exit:
  fclose(_log);
  return rc;
}


#else

#include <x509-2-pgp.h>

int run_tests ( void )
{
  fprintf(stderr,"%sERROR%s: This program was compiled WITHOUT test suite.\n", ctrlRed, ctrlReset);
  return 1;
}

#endif // _WITH_TESTS
