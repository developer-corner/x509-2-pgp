/**
 * @file   x509-to-pgp.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  implements main function for importing X.509v3 / public /
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

#include <osslimpl.h>
#include <pkcs11impl.h>
#include <pgpimpl.h>
#include <utils.h>
#include <x509-2-pgp.h>

bool                edwards_legacy = true;                      ///< true if use PGP legacy Edwards Curves (new format not yet tested!)
bool                do_verify = false;                          ///< true if all created signatures are verified in a loopback style
bool                use_rsa_pss = false;                        ///< only for non-PGP RSA signatures: use RSA-PSS instead of PKCS#1 v1.5
bool                use_ed_ph = false;                          ///< only for non-PGP EdDSA signatures: use pre-hashed (see RFC 8032)
bool                pgp_new_packet_format = false;              ///< use new PGP packet format; defaults to old format
bool                force = false;                              ///< true (force) if no confirmation asked before deleting PKCS#11 keys
bool                be_quiet = false;                           ///< be quiet, only display error messages, no progress or informational stuff
bool                dryrun = false;                             ///< dry run, output what would have been done but do nothing, not supported by all applets!
uint32_t            gpg_enc_algo = SECRET_KEY_ENCR_NONE;        ///< GPG encryption algorithm for SECRET KEY PACKETs
char                pkcs11_library[256];                        ///< PKCS#11 library name (.so|.dll); either via command line or environment
char                pkcs11_pin[256];                            ///< PKCS#11 PIN (environment)
uint32_t            pkcs11_slot = 0;                            ///< PKCS#11 slot (default: 0); either via command line or environment
char                secret[256];                                ///< (environment); pass phrase for PEM files or used as PKCS#11 PIN
char                serial[256];                                ///< X.509v3 serial number patching
char                pgp_secret[256];                            ///< PGP pass phrase (environment)
bool                secret_set = false;                         ///< true if secret variable was set via the environment; this Boolean is here because you may define 'SECRET' empty meaning 'no password' (do not ask on console)
time_t              key_creation_ts = 0;                        ///< explicit key creation timestamp set via command line
bool                convert_pubkey_only = false;                ///< if someone specified a private instead of a public key, use only the public part for the PGP import
char                user_name[256];                             ///< user name (PGP), aka 'user ID'
char                email_addr[256];                            ///< user's E-mail address (PGP)
char                pkcs11_label[256];                          ///< PKCS#11 key label (subject)
uint32_t            expiry_days = 0;                            ///< number of expiry days, 0 if 'does not expire'
bool                expiry_days_set = false;                    ///< Boolean telling us if the expiry days (also if zero) were specified on the command line
char                pkcs11_label_cert[256];                     ///< PKCS#11 key label (issuer)
char                input_filename[256];                        ///< input file name
char                output_filename[256];                       ///< output file name
char                private_key_file[256];                      ///< private key PEM file
char                public_key_file[256];                       ///< public key PEM file (you may also specify a private key PEM file without encryption here, then, only the public part is used)
                                                                ///< alternatively, this may be an X.509v3 certificate (PEM format)
char                private_key_cert_file[256];                 ///< private key PEM file (issuer)
char                public_key_cert_file[256];                  ///< public key PEM file (issuer)
char                email_addr_cert[256];                       ///< E-mail address of issuer (PGP)
uint32_t            md_type = MD_TYPE_SHA2_256;                 ///< message digest (SHA-224|256|384|512); RFC 9580 also defines SHA-3, which is not implemented here (only partly but no full support)
uint32_t            pgp_digest_algo = DIGEST_ALGO_SHA256;       ///< message digest as specified on the command line; the previous md_type is for internal usage!
uint64_t            rsa_pubexp = 65537;                         ///< public RSA exponen e, which defaults to 65.537 and may be changed on the command line, e.g. 0xC0000001 (has to be prime, which is NOT checked)
bool                colored_output = false;                     ///< enable/disable colored console output

extern int run_tests ( void );

/**
 * @brief applet for deleting PKCS#11 key pairs in the module
 *
 * PKCS#11 label and PKCS#11 library are required, which can also be
 * specified in the environment.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int OnDeletePKCS11Key ( int argc, char *argv[] )
{
  (void)argc;
  (void)argv;
  int           rc = 0;

  if (be_quiet && !force) // because WE HAVE TO ASK for a confirmation, quiet mode is not allowed
  {
    fprintf(stderr,"%sERROR%s: This applet is not executable in quiet mode ('force' specified).\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == pkcs11_label[0])
  {
    fprintf(stderr,"%sERROR%s: PKCS#11 label of key to be deleted has to be specified.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == pkcs11_library[0])
  {
    fprintf(stderr,"%sERROR%s: PKCS#11 library name has to be specified.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (!be_quiet)
  {
    fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot);
    if (0 != secret[0] || 0 != pkcs11_pin[0])
      fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
  }

  if (dryrun)
  {
    fprintf(stdout,"DRYRUN: I would delete the PKCS#11 key pair '%s'.\n", pkcs11_label);
    fprintf(stdout,"------- I would %sask for confirmation.\n", force ? "NOT " : "");
    fprintf(stdout,"        Hint: The key pair has to be singular in the module.\n");
    fprintf(stdout,"        ----- This tool never removes multiple occurrences\n");
    fprintf(stdout,"              (same PKCS#11 label).\n");
    return 0;
  }

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (!pkcs11_init(pkcs11_library, pkcs11_slot))
  {
    ossl_fini();
    fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
    return 1;
  }

  if (!pkcs11_login(NULL, 0))
  {
    pkcs11_fini();
    ossl_fini();
    fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (pkcs11_delete_key(NULL, 0, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label), force ? false : true))
    fprintf(stdout,"PKCS#11 key with label '%s' deleted.\n", pkcs11_label);
  else
  {
    fprintf(stderr,"%sERROR%s: PKCS#11 key with label '%s' NOT deleted (not found or multiple occurrences).\n", ctrlRed, ctrlReset, pkcs11_label);
    rc = 1;
  }

  pkcs11_fini();
  ossl_fini();

  return rc;
}

/**
 * @brief applet for generating key pairs either in software (OpenSSL)
 *        or in a PKCS#11 module (smartcard, HSM, USB token, ...).
 *
 * Supported algorithms are RSA2048, RSA3072, RSA4096, ECC with NIST
 * curves prime256v1, secp384r1, secp521r1, ECC with Brainpool curves
 * brainpoolP256R1, brainpoolP384R1, brainpoolP512R1.
 * Edwards Curves ED25519 and ED448.
 *
 * Please DO NOTE that your PKCS#11 implementation has to support the
 * cipher suites, which is not always the case especially for Edwards
 * Curves.
 *
 * If the PKCS#11 library is specified, then the applet operates in P11
 * mode.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onGenKeyPair ( int argc, char *argv[] )
{
  int             i;
  bool            have_type = false;
  uint32_t        key_type = 0;
  char            outp_file[256];
  EVP_PKEY       *p_evp_pkey = NULL;
  bool            only_pubkey = false;
  FILE           *f;
  uint8_t         p11_key_id[8];
  char            msg[256];
  time_t          now;

  if (0 == output_filename[0])
  {
    fprintf(stderr,"%sERROR%s: An output file name is required, use '-o' or '--out'.\n", ctrlRed, ctrlReset);
    return 1;
  }

  for (i = 2; i < argc; i++)
  {
    if ((0 != argv[i][0]) && (('-' == argv[i][0] && 0 == argv[i][1]) || (('-' != argv[i][0]) && (0 != argv[i][0]))))
    {
      if (!have_type)
      {
        if (!strcasecmp(argv[i],"rsa2048"))
        {
          key_type = KEY_TYPE_RSA2048;
          snprintf(msg,sizeof(msg),"RSA, 2048 bits, public exponent e = %" FMT64_PREFIX "u (0x%" FMT64_PREFIX "x)", rsa_pubexp, rsa_pubexp);
        }
        else
        if (!strcasecmp(argv[i],"rsa3072"))
        {
          key_type = KEY_TYPE_RSA3072;
          snprintf(msg,sizeof(msg),"RSA, 3072 bits, public exponent e = %" FMT64_PREFIX "u (0x%" FMT64_PREFIX "x)", rsa_pubexp, rsa_pubexp);
        }
        else
        if (!strcasecmp(argv[i],"rsa4096"))
        {
          key_type = KEY_TYPE_RSA4096;
          snprintf(msg,sizeof(msg),"RSA, 4096 bits, public exponent e = %" FMT64_PREFIX "u (0x%" FMT64_PREFIX "x)", rsa_pubexp, rsa_pubexp);
        }
        else
        if (!strcasecmp(argv[i],"ecnist256"))
        {
          key_type = KEY_TYPE_ECNIST256;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'prime256v1' (aka 'secp256r1')");
        }
        else
        if (!strcasecmp(argv[i],"ecnist384"))
        {
          key_type = KEY_TYPE_ECNIST384;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'secp384r1'");
        }
        else
        if (!strcasecmp(argv[i],"ecnist521"))
        {
          key_type = KEY_TYPE_ECNIST521;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'secp521r1'");
        }
        else
        if (!strcasecmp(argv[i],"ecbpool256"))
        {
          key_type = KEY_TYPE_ECBPOOL256;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'brainpoolP256R1'");
        }
        else
        if (!strcasecmp(argv[i],"ecbpool384"))
        {
          key_type = KEY_TYPE_ECBPOOL384;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'brainpoolP384R1'");
        }
        else
        if (!strcasecmp(argv[i],"ecbpool512"))
        {
          key_type = KEY_TYPE_ECBPOOL512;
          snprintf(msg,sizeof(msg),"Elliptic Curve 'brainpoolP512R1'");
        }
        else
        if (!strcasecmp(argv[i],"ed25519"))
        {
          key_type = KEY_TYPE_ED25519;
          snprintf(msg,sizeof(msg),"Edwards Curve 'ED25519'");
        }
        else
        if (!strcasecmp(argv[i],"ed448"))
        {
          key_type = KEY_TYPE_ED448;
          snprintf(msg,sizeof(msg),"Edwards Curve 'ED448'");
        }
        else
        {
          fprintf(stderr,"%sERROR%s: key type '%s' unsupported.\n", ctrlRed, ctrlReset, argv[i]);
          return 1;
        }
        have_type = true;
      }
    }
  }

  // ensure type given

  if (!have_type)
  {
    fprintf(stderr,"%sERROR%s: Please specify a key type right behind the applet name.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // ensure PKCS#11 label given if PKCS#11 mode

  if (0 != pkcs11_library[0] && 0 == pkcs11_label[0])
  {
    fprintf(stderr,"%sERROR%s: In PKCS#11 mode, please specify a PKCS#11 label (--p11label or environment).\n", ctrlRed, ctrlReset);
    return 1;
  }

  // check dry run

  if (dryrun)
  {
    fprintf(stdout,"DRYRUN: I would generate a key pair...\n");
    fprintf(stdout,"------  ...in %s\n", 0 != pkcs11_library[0] ? "hardware (PKCS#11)" : "software (OpenSSL)");
    fprintf(stdout,"        ...algorithm: %s\n", msg);
    fprintf(stdout,"        ...storing the public key (PEM) to %s.pub.pem\n", output_filename);
    if (0 == pkcs11_library[0])
    {
      fprintf(stdout,"        ...storing the private key (PEM) to <timestamp>-%s.prv.pem\n", output_filename);
      if (0 != secret[0])
        fprintf(stdout,"        ...protecting the private key with secret from environment.\n");
      else
      {
        if (secret_set)
          fprintf(stdout,"        ...NOT using a password for private key protection (plain storage).\n");
        else
          fprintf(stdout,"        ...querying password on the console (leave empty for plain storage).\n");
      }
    }
    else
    {
      fprintf(stdout,"        ...labeling it '%s'\n", pkcs11_label);
      fprintf(stdout,"        ...creating it in PKCS#11 slot %u\n", pkcs11_slot);
      if ((0 == secret[0]) && (0 == pkcs11_pin[0]))
        fprintf(stdout,"        ...querying the PKCS#11 PIN on the console.\n");
      else
        fprintf(stdout,"        ...using the PKCS#11 PIN from the environment.\n");
    }
    return 0;
  }

  // Initialize OpenSSL in any case

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  time(&now);

  if (0 != pkcs11_library[0])
  {
    if (!be_quiet)
    {
      fprintf(stdout,"PKCS#11 mode, label = '%s', library = '%s', slot = %u\n", pkcs11_label, pkcs11_library, pkcs11_slot);
      if (0 != secret[0] || 0 != pkcs11_pin[0])
        fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
    }

    if (!pkcs11_init(pkcs11_library, pkcs11_slot))
    {
      ossl_fini();
      fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
      return 1;
    }

    // use one of the RSA, ECC or ED functions to generate the desired key pair; all functions return the EVP_PKEY* (OpenSSL) public key

    if (!pkcs11_login(NULL, 0))
    {
      pkcs11_fini();
      ossl_fini();
      fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
      return 1;
    }

    only_pubkey = true; // private key is in PKCS#11 module, not here...

    p11_key_id[0] = (uint8_t)(((uint64_t)now) >> 56);
    p11_key_id[1] = (uint8_t)(((uint64_t)now) >> 48);
    p11_key_id[2] = (uint8_t)(((uint64_t)now) >> 40);
    p11_key_id[3] = (uint8_t)(((uint64_t)now) >> 32);
    p11_key_id[4] = (uint8_t)(((uint64_t)now) >> 24);
    p11_key_id[5] = (uint8_t)(((uint64_t)now) >> 16);
    p11_key_id[6] = (uint8_t)(((uint64_t)now) >> 8);
    p11_key_id[7] = (uint8_t)((uint64_t)now);

    if (!be_quiet)
    {
      fprintf(stdout,"Generating key pair in PKCS#11 token...\n  %s\n", msg);
      fprintf(stdout,"  Using label '%s'\n", pkcs11_label);
      fprintf(stdout,"(PKCS#11 key ID becomes key creation timestamp)\n");
    }

    switch(key_type)
    {
      case KEY_TYPE_RSA2048:
        p_evp_pkey = pkcs11_generate_rsa_keypair(2048, rsa_pubexp, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_RSA3072:
        p_evp_pkey = pkcs11_generate_rsa_keypair(3072, rsa_pubexp, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_RSA4096:
        p_evp_pkey = pkcs11_generate_rsa_keypair(4096, rsa_pubexp, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECNIST256:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_X9_62_PRIME256V1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECNIST384:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_SECP384R1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECNIST521:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_SECP521R1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECBPOOL256:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_BRAINPOOLP256R1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECBPOOL384:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_BRAINPOOLP384R1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ECBPOOL512:
        p_evp_pkey = pkcs11_generate_ec_keypair(P11_CURVE_BRAINPOOLP512R1, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ED25519:
        p_evp_pkey = pkcs11_generate_edwards_keypair(false, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
      case KEY_TYPE_ED448:
        p_evp_pkey = pkcs11_generate_edwards_keypair(true, p11_key_id, sizeof(p11_key_id), (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
        break;
    }

    if (unlikely(NULL == p_evp_pkey))
    {
      pkcs11_fini();
      ossl_fini();
      fprintf(stderr,"%sERROR%s: Unable to generate key pair using PKCS#11 hardware token.\n", ctrlRed, ctrlReset);
      return 1;
    }

    if (!be_quiet)
      fprintf(stdout,"Key pair successfully generated in PKCS#11 token.\n");

    pkcs11_fini();
  }
  else // Generate key pair with OpenSSL
  {
    if (!be_quiet)
      fprintf(stdout,"Generating key pair in software using OpenSSL...\n  %s\n", msg);

    p_evp_pkey = ossl_generate_openssl_keypair ( key_type, rsa_pubexp );

    if (unlikely(NULL == p_evp_pkey))
    {
      ossl_fini();
      fprintf(stderr,"%sERROR%s: Unable to generate key pair using OpenSSL.\n", ctrlRed, ctrlReset);
      return 1;
    }

    if (!be_quiet)
      fprintf(stdout,"Key pair successfully generated using OpenSSL.\n");
  }

  // common code for OpenSSL and PKCS#11 (serialization of key material)

  if (!only_pubkey)
  {
    FILE     *f;
    uint32_t  year, month, mday, hour, minute, second;

    snprintf(outp_file, sizeof(outp_file), "%s.prv.pem", output_filename);
    if (!ossl_store_keypair(outp_file, p_evp_pkey))
    {
      EVP_PKEY_free(p_evp_pkey);
      ossl_fini();
      fprintf(stderr,"%sERROR%s: unable to store private key (key pair) to: %s\n", ctrlRed, ctrlReset, outp_file);
      return 1;
    }

    f = fopen(outp_file, "at");
    if (NULL == f)
    {
      EVP_PKEY_free(p_evp_pkey);
      ossl_fini();
      fprintf(stderr, "%sERROR%s: unable to re-open file for append operation: %s\n", ctrlRed, ctrlReset, outp_file);
      return 1;
    }

    if (!time_systime2date((uint64_t)now, &year,&month,&mday,&hour,&minute,&second))
    {
      fclose(f);
      EVP_PKEY_free(p_evp_pkey);
      ossl_fini();
      fprintf(stderr, "%sERROR%s: unable to convert current system time to string.\n", ctrlRed, ctrlReset);
      return 1;
    }

    fprintf(f, "KEY-CREATION-TIMESTAMP: %04u%02u%02u%02u%02u%02uZ\n", year, month, mday, hour, minute, second);
    fclose(f);
  }

  snprintf(outp_file, sizeof(outp_file), "%s.pub.pem", output_filename);

  f = fopen(outp_file, "wb");

  if (NULL == f)
  {
    EVP_PKEY_free(p_evp_pkey);
    ossl_fini();
    fprintf(stderr,"%sERROR%s: unable to store public key to: %s\n", ctrlRed, ctrlReset, outp_file);
    return 1;
  }

  if (1 != PEM_write_PUBKEY(f, p_evp_pkey))
  {
    fclose(f);
    EVP_PKEY_free(p_evp_pkey);
    ossl_fini();
    fprintf(stderr,"%sERROR%s: unable to store public key to: %s\n", ctrlRed, ctrlReset, outp_file);
    return 1;
  }

  fclose(f);

  EVP_PKEY_free(p_evp_pkey);

  ossl_fini();

  return 0;
}

/**
 * @brief (convenience function) Converts the command line parameter
 *        specifying a an Elliptic Curve or Edwards Curve to the
 *        internal SIG_TYPE_xxx constant.
 *
 * @param [in]  ec_curve    curve from command line
 *
 * @return internal SIG_TYPE_xxx constant or (uint32_t)-1 on error.
 */
static uint32_t _ec_curve_to_sig_type ( uint32_t ec_curve )
{
  switch(ec_curve)
  {
    case CURVE_NIST_256:
      return SIG_TYPE_ECDSA_SECP256R1;
    case CURVE_NIST_384:
      return SIG_TYPE_ECDSA_SECP384R1;
    case CURVE_NIST_521:
      return SIG_TYPE_ECDSA_SECP521R1;
    case CURVE_BRAINPOOL_256:
      return SIG_TYPE_ECDSA_BRAINPOOLP256R1;
    case CURVE_BRAINPOOL_384:
      return SIG_TYPE_ECDSA_BRAINPOOLP384R1;
    case CURVE_BRAINPOOL_512:
      return SIG_TYPE_ECDSA_BRAINPOOLP512R1;
    case CURVE_ED25519:
      return SIG_TYPE_EDDSA_25519;
    case CURVE_ED448:
      return SIG_TYPE_EDDSA_448;
    default:
      break;
  }

  return 0xFFFFFFFF;
}

/**
 * @brief applet for patching an X.509v3 certification, i.e. patching of
 *        public key, X.509v3 extensions SubjectKeyIdentifier and
 *        AuthorityKeyIdentifier. serial number and validity may be
 *        patched, too.
 *
 * This function can create self-signed certificates as well as certificates
 * signed by another issuer.
 *
 * The reason why this function is 'here' is simple: No need to set up
 * PKCS#11 software stacks in order to equip OpenSSL with PKCS#11 support.
 * You may just issue a certificate with an 'alibi' key, then patching it
 * with a PKCS#11 key.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onPatchX509 ( int argc, char *argv[] )
{
  (void)argc;
  (void)argv;
  int               rc = 1;
  bool              pkcs11_init_done = false;
  EVP_PKEY         *p_priv_evp_key = NULL, *p_priv_evp_key_cert = NULL, *p_pub_evp_key = NULL, *p_pub_evp_key_cert = NULL, *p_evp_key;
  EVP_PKEY         *p_sign_evp_key, *p_verify_evp_key;
  x509parsed_ptr    p_input_x509 = NULL, p_input_x509_cert = NULL;
  bool              is_keypair, patched_subkid = false, patched_authkid = false;
  uint32_t          l_input, pk_algo, key_bits, ec_curve, ec_complen;
  uint64_t          rsa_pubexp;
  uint8_t          *p_input;
  mempool           mp;
  uint32_t          l_x509_der, l_x509_der_cert, l_pubkey_der, l_tbs, l_sig, l_output;
  uint8_t          *p_x509_der = NULL, *p_x509_der_cert = NULL, *p_pubkey_der = NULL, *p_tbs = NULL, *p_sig = NULL, *p_output = NULL;
  deritem_ptr       x509_root, x509_root_cert = NULL, p_pubkey_tree, p_run, p_temp, p_new_sig_bs;
  explore_x509      exp, exp_cert;
  uint8_t           subkid[SHA_DIGEST_LENGTH]; // updated (new) SubjectKeyIdentifier computed from the new public key injected into X.509v3
  uint8_t           authkid[SHA_DIGEST_LENGTH];
  bool              have_authkid = false;
  uint32_t          md_type = 0xFFFFFFFF, sig_type = 0xFFFFFFFF;
  const uint8_t    *p;
  X509             *out_x509 = NULL;
  FILE             *f;
  uint8_t           subkid_der[SHA_DIGEST_LENGTH + 4];
  uint8_t           authkid_der[SHA_DIGEST_LENGTH + 6];
  deritem_ptr       subkid_tree;
  deritem_ptr       authkid_tree;
  uint8_t           serial_bin[256];
  uint32_t          l_serial_bin = 0;
  deritem_ptr       serial_tree;

  memset(&mp, 0, sizeof(mp));
  memset(serial_bin, 0, sizeof(serial_bin));

  // Check prerequisites

  if (0 == input_filename[0])
  {
    fprintf(stderr,"%sERROR%s: You have to specify an input file (-i|--in), an X.509v3 PEM file, the template to be patched.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == output_filename[0])
  {
    fprintf(stderr,"%sERROR%s: You have to specify an output file (-o|--out).\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == pkcs11_library[0])
  {
    if (0 == private_key_file[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a private key (key pair) file (--prv).\n", ctrlRed, ctrlReset);
      return 1;
    }
  }
  else
  {
    if (0 == pkcs11_label[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a PKCS#11 label (--p11label or environment).\n", ctrlRed, ctrlReset);
      return 1;
    }
  }

  // Initialize OpenSSL

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // pull-in certificates and other stuff

  p_input = read_file(input_filename, &l_input);
  if (NULL == p_input || 0 == l_input)
  {
    fprintf(stderr,"%sERROR%s: Unable to read input file: %s (or file empty)\n", ctrlRed, ctrlReset, input_filename);
    goto Exit;
  }
  p_input_x509 = ossl_parse_x509(p_input,l_input,true);
  free(p_input), p_input = NULL;
  if (NULL == p_input_x509)
  {
    fprintf(stderr,"%sERROR%s: Unable to parse X.509v3 input (template, PEM format) file: %s\n", ctrlRed, ctrlReset, input_filename);
    goto Exit;
  }

  if (0 == pkcs11_library[0]) // OpenSSL for the to-be-patched certificate itself
  {
    if (0 != public_key_file[0])
    {
      p_pub_evp_key = ossl_load_openssl_key(public_key_file, &is_keypair, NULL); // is_keypair output ignored here!
      if (NULL == p_pub_evp_key)
      {
        fprintf(stderr,"%sERROR%s: Unable to load public key file (has to be public/private PEM key file): %s\n", ctrlRed, ctrlReset, public_key_file);
        goto Exit;
      }
    }

    if (0 != private_key_file[0])
    {
      p_priv_evp_key = ossl_load_openssl_key(private_key_file, &is_keypair, NULL);
      if (NULL == p_pub_evp_key)
      {
        fprintf(stderr,"%sERROR%s: Unable to load private key file (PEM): %s\n", ctrlRed, ctrlReset, private_key_file);
        goto Exit;
      }
      if (!is_keypair)
      {
        fprintf(stderr,"%sERROR%s: Private key file contains a public key only.\n", ctrlRed, ctrlReset);
        goto Exit;
      }
    }
  }
  else // PKCS#11 mode
  {
    if (0 == pkcs11_label[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a PKCS#11 label.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // check if we have more input for the issuer (else: self-signed)

  if (0 != public_key_cert_file[0])
  {
    p_input = read_file(public_key_cert_file, &l_input);
    if (NULL == p_input || 0 == l_input)
    {
      fprintf(stderr,"%sERROR%s: Unable to read input file: %s (or file empty)\n", ctrlRed, ctrlReset, public_key_cert_file);
      goto Exit;
    }
    p_input_x509_cert = ossl_parse_x509(p_input,l_input,true);
    free(p_input), p_input = NULL;
    if (NULL == p_input_x509_cert)
    {
      fprintf(stderr,"%sERROR%s: Unable to parse X.509v3 input (PEM format, ISSUER) file: %s\n", ctrlRed, ctrlReset, public_key_cert_file);
      goto Exit;
    }
  }

  if (0 != pkcs11_label_cert[0])
  {
    if (0 == pkcs11_library[0])
    {
      fprintf(stderr,"%sERROR%s: You have specified a PKCS#11 label (ISSUER) but no PKCS#11 library.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }
  else
  {
    if (0 != private_key_cert_file[0])
    {
      p_priv_evp_key_cert = ossl_load_openssl_key(private_key_cert_file, &is_keypair, NULL);
      if (NULL == p_priv_evp_key_cert)
      {
        fprintf(stderr,"%sERROR%s: Unable to load private key file (ISSUER): %s\n", ctrlRed, ctrlReset, private_key_cert_file);
        goto Exit;
      }
      if (!is_keypair)
      {
        fprintf(stderr,"%sERROR%s: Private key file (ISSUER) contains a public key only.\n", ctrlRed, ctrlReset);
        goto Exit;
      }
    }
  }

  // input validation:
  // =================
  //
  // Case 1: SELF SIGNING
  // =======
  //
  // input X.509v3 required, output X.509v3 required, private key file or PKCS#11 label required (self-signature),
  // public key ignored if specified (because public key part of private key file or can be recovered from PKCS#11 module,
  // NO EXPLICIT cross-check between such a public key and the private key performed!)
  //
  // Case 2: NON-SELF SIGNING
  // =======
  //
  // input X.509v3 required, output X.509v3 required, either private key file or PKCS#11 label or public key file
  // required (i.e. public key from private key file, public key from PKCS#11 module (recovery) or public key file
  // used for the SubjectPublicKeyInfo patching; plus: private key file of issuer or PKCS#11 issuer label required
  // (digital signature)

  if (0 == private_key_cert_file[0] && 0 == pkcs11_label_cert[0]) // no issuer stuff...
  {
    if (NULL == p_priv_evp_key && 0 == pkcs11_label[0])
    {
      fprintf(stderr,"%sERROR%s: Need private key / PKCS#11 label in order to create self-signature.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
    else
    if (NULL != p_pub_evp_key)
    {
      if (!be_quiet)
        fprintf(stdout,"%sWARNING%s: public key file in addition to private key file specified but IGNORED (no cross-check with private key).\n", ctrlYellow, ctrlReset);
      EVP_PKEY_free(p_pub_evp_key), p_pub_evp_key = NULL;
    }
  }
  else // yes, we have issuer stuff on the command line
  {
    if (NULL == p_priv_evp_key && 0 == pkcs11_label[0] && NULL == p_pub_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Need public key source for SubjectPublicKeyInfo (either priv or pub or PKCS#11 label).\n", ctrlRed, ctrlReset);
      goto Exit;
    }
    if ((NULL != p_priv_evp_key || 0 != pkcs11_label[0]) && (NULL != p_pub_evp_key))
    {
      if (!be_quiet)
        fprintf(stdout,"%sWARNING%s: public key file in addition to private key file specified but IGNORED (no cross-check with private key).\n", ctrlYellow, ctrlReset);
      EVP_PKEY_free(p_pub_evp_key), p_pub_evp_key = NULL;
    }
  }

  if (0 != private_key_cert_file[0] || 0 != pkcs11_label_cert[0]) // not self-signed
  {
    if (NULL == p_input_x509_cert)
    {
      fprintf(stderr,"%sERROR%s: Unable to proceed because not self-signed and no issuer X.509v3 specified.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // dryrun?

  if (dryrun)
  {
    fprintf(stdout,"DRYRUN: patching input X.509v3 certificate with new public key.\n");
    fprintf(stdout,"------- ...using X.509v3 input '%s'\n", input_filename);
    fprintf(stdout,"        ...outputting new X.509v3 to '%s'\n", output_filename);
    if (0 == private_key_cert_file[0] && 0 == pkcs11_label_cert[0])
    {
      fprintf(stdout,"        ...will be SELF-SIGNED.\n");
      fprintf(stdout,"        ...subject = issuer: %s\n", p_input_x509->subjectDN);
    }
    else
    {
      fprintf(stdout,"        ...will be NON-SELF-SIGNED.\n");
      fprintf(stdout,"        ...subject DN: %s\n", p_input_x509->subjectDN);
      fprintf(stdout,"        ...issuer  DN: %s\n", p_input_x509_cert->subjectDN);
    }
    if (0 != serial[0])
      fprintf(stdout,"        ...serial number patched to %s\n", serial);
    else
      fprintf(stdout,"        ...serial number remains: %s\n", p_input_x509->serialno_dec);

    goto Exit;
  }

  // initialize PKCS#11 module and retrieve OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module

  if (0 != pkcs11_label[0] || 0 != pkcs11_label_cert[0])
  {
    if (0 == pkcs11_library[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a PKCS#11 library.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    if (!be_quiet)
    {
      fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot);
      if (0 != secret[0] || 0 != pkcs11_pin[0])
        fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
    }

    if (!pkcs11_init(pkcs11_library, pkcs11_slot))
    {
      fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
      goto Exit;
    }

    if (!pkcs11_login(NULL, 0))
    {
      pkcs11_fini();
      fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    pkcs11_init_done = true;

    if (0 != pkcs11_label[0])
    {
      p_pub_evp_key = pkcs11_get_ossl_public_evp_key_from_pubkey(NULL, 0, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
      if (NULL == p_pub_evp_key)
      {
        fprintf(stderr,"%sERROR%s: Unable to derive OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module (label: %s)\n", ctrlRed, ctrlReset, pkcs11_label);
        goto Exit;
      }
    }

    if (0 != pkcs11_label_cert[0])
    {
      p_pub_evp_key_cert = pkcs11_get_ossl_public_evp_key_from_pubkey(NULL, 0, (const uint8_t*)pkcs11_label_cert, (uint32_t)strlen(pkcs11_label_cert));
      if (NULL == p_pub_evp_key_cert)
      {
        fprintf(stderr,"%sERROR%s: Unable to derive OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module (label: %s)\n", ctrlRed, ctrlReset, pkcs11_label_cert);
        goto Exit;
      }
    }
  }

  // output some information if not quiet

  if (!be_quiet)
  {
    fprintf(stdout,"INFO: about to re-create/re-sign X.509v3 certificate:\n");
    fprintf(stdout,"-----\n\n");
    fprintf(stdout,"  output file ..............: %s\n", output_filename);
    fprintf(stdout,"  input X.509v3 ............:\n");
    fprintf(stdout,"    subject DN .............: %s\n", p_input_x509->subjectDN);
    fprintf(stdout,"    issuer DN ..............: %s\n", p_input_x509->issuerDN);
    fprintf(stdout,"    serial number ..........: %s\n", p_input_x509->serialno_dec);
    fprintf(stdout,"    signature algorithm ....: %s\n", x509_sig_algo_names[p_input_x509->x509_sig_algo]);
    fprintf(stdout,"    public key algorithm ...: %s\n", public_key_algorithm[p_input_x509->pk_algo]);
    fprintf(stdout,"    public key strength ....: %u bits\n", p_input_x509->pk_key_bits);
    if (0 != p_input_x509->pk_algo)
      fprintf(stdout,"    curve ..................: %s (component length: %u)\n", elliptic_curve_names[p_input_x509->pk_ec_curve], p_input_x509->pk_ec_complen);
    else
      fprintf(stdout,"    RSA public exponent ....: 0x%"FMT64_PREFIX"X\n", p_input_x509->pk_rsa_pubexp);

    if (NULL != p_input_x509_cert)
    {
      fprintf(stdout,"  input X.509v3 (signer) ...:\n");
      fprintf(stdout,"    subject DN .............: %s\n", p_input_x509_cert->subjectDN);
      fprintf(stdout,"    issuer DN ..............: %s\n", p_input_x509_cert->issuerDN);
      fprintf(stdout,"    serial number ..........: %s\n", p_input_x509_cert->serialno_dec);
      fprintf(stdout,"    signature algorithm ....: %s\n", x509_sig_algo_names[p_input_x509_cert->x509_sig_algo]);
      fprintf(stdout,"    public key algorithm ...: %s\n", public_key_algorithm[p_input_x509_cert->pk_algo]);
      fprintf(stdout,"    public key strength ....: %u bits\n", p_input_x509_cert->pk_key_bits);
      if (0 != p_input_x509_cert->pk_algo)
        fprintf(stdout,"    curve ..................: %s (component length: %u)\n",
            elliptic_curve_names[p_input_x509_cert->pk_ec_curve], p_input_x509_cert->pk_ec_complen);
      else
        fprintf(stdout,"    RSA public exponent ....: 0x%"FMT64_PREFIX"X\n", p_input_x509_cert->pk_rsa_pubexp);
    }
  }

  // does input X.509v3 public key algorithm is compatible (either checked with private key or with public key coming from the PKCS#11 module)

  p_evp_key = NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key;

  if (unlikely(NULL == p_evp_key))
  {
    fprintf(stderr,"%sERROR%s: Do not have a public key for comparison with SubjectPublicKeyInfo in input X.509v3.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (!ossl_pubkey_algo_from_evp(p_evp_key, &pk_algo, &key_bits, &ec_curve, &ec_complen, &rsa_pubexp))
  {
    fprintf(stderr,"%sERROR%s: unable to determine public key algorithm\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (pk_algo != p_input_x509->pk_algo)
  {
    fprintf(stderr,"%sERROR%s: public key algorithms (input key and input certificate) do NOT match.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (((uint32_t)-1) != key_bits)
  {
    if ( ((key_bits + 7) & (~7)) != ((p_input_x509->pk_key_bits + 7) & (~7)) )
    {
      fprintf(stderr,"%sERROR%s: number of key bits do NOT match.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  if (((uint32_t)-1) != ec_curve)
  {
    if ( ((key_bits + 7) & (~7)) != ((p_input_x509->pk_key_bits + 7) & (~7)) )
    {
      fprintf(stderr,"%sERROR%s: Elliptic Curves do NOT match.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
    if ( ec_complen != p_input_x509->pk_ec_complen)
    {
      fprintf(stderr,"%sERROR%s: Elliptic Curves do NOT match.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  if (((uint64_t)-1) != rsa_pubexp)
  {
    if (rsa_pubexp != p_input_x509->pk_rsa_pubexp)
    {
      fprintf(stderr,"%sERROR%s: RSA public exponents do NOT match.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // ensure that signature schema in template X.509v3 matches the private key used to sign the template X.509v3 becoming the new X.509v3 certificate

  p_evp_key = NULL != p_priv_evp_key_cert ? p_priv_evp_key_cert : p_pub_evp_key_cert;
  if (NULL == p_evp_key) // self-signed
    p_evp_key = NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key;

  if (unlikely(NULL == p_evp_key))
  {
    fprintf(stderr,"%sERROR%s: Do not have two public keys for comparison (signature scheme validation).\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (!ossl_pubkey_algo_from_evp(p_evp_key, &pk_algo, &key_bits, &ec_curve, &ec_complen, &rsa_pubexp))
  {
    fprintf(stderr,"%sERROR%s: unable to determine public key algorithm\n", ctrlRed, ctrlReset);
    goto Exit;
  }

#if 0 // too many special cases here, user has to ensure she uses correct input...
  switch(p_input_x509->x509_sig_algo)
  {
    case X509_SIG_ALGO_PKCS1_V15_SHA256:
    case X509_SIG_ALGO_PKCS1_V15_SHA384:
    case X509_SIG_ALGO_PKCS1_V15_SHA512:
    case X509_SIG_ALGO_RSAPSS_SHA256:
    case X509_SIG_ALGO_RSAPSS_SHA384:
    case X509_SIG_ALGO_RSAPSS_SHA512:
      if (p_input_x509->sig_bit_size != ((key_bits + 7) & (~7)))
      {
        fprintf(stderr,"%sERROR%s: unable to patch new digital signature into this X.509v3 template because of bit size mismatch\n", ctrlRed, ctrlReset);
        fprintf(stderr,"------ X.509v3 template has %u bits, signing key has %u bits (comparison performed with round-up value)\n", p_input_x509->sig_bit_size, key_bits);
        goto Exit;
      }
      break;
    case X509_SIG_ALGO_ECDSA_SHA256:
    case X509_SIG_ALGO_ECDSA_SHA384:
    case X509_SIG_ALGO_ECDSA_SHA512:
    case X509_SIG_ALGO_EDDSA_ED25519:
      if ((p_input_x509->sig_bit_size != key_bits) && (p_input_x509->sig_bit_size != ((key_bits + 7) & (~7))))
      {
        fprintf(stderr,"%sERROR%s: unable to patch new digital signature into this X.509v3 template because of bit size mismatch\n", ctrlRed, ctrlReset);
        fprintf(stderr,"------ X.509v3 template has %u bits (1st component), signing key has %u bits (comparison performed with round-up value)\n", p_input_x509->sig_bit_size, key_bits);
        goto Exit;
      }
      if (((p_input_x509->sig_bit_size2 != key_bits) && p_input_x509->sig_bit_size2 != ((key_bits + 7) & (~7))))
      {
        fprintf(stderr,"%sERROR%s: unable to patch new digital signature into this X.509v3 template because of bit size mismatch\n", ctrlRed, ctrlReset);
        fprintf(stderr,"------ X.509v3 template has %u bits (2nd component), signing key has %u bits (comparison performed with round-up value)\n", p_input_x509->sig_bit_size, key_bits);
        goto Exit;
      }
      break;

    case X509_SIG_ALGO_EDDSA_ED448:
      if (p_input_x509->sig_bit_size != key_bits)
      {
        fprintf(stderr,"%sERROR%s: unable to patch new digital signature into this X.509v3 template because of bit size mismatch\n", ctrlRed, ctrlReset);
        fprintf(stderr,"------ X.509v3 template has %u bits (1st component), signing key has %u bits\n", p_input_x509->sig_bit_size, key_bits);
        fprintf(stderr,"       (hint: added eight bits for ED448)\n");
        goto Exit;
      }
      if (p_input_x509->sig_bit_size2 != key_bits)
      {
        fprintf(stderr,"%sERROR%s: unable to patch new digital signature into this X.509v3 template because of bit size mismatch\n", ctrlRed, ctrlReset);
        fprintf(stderr,"------ X.509v3 template has %u bits (2nd component), signing key has %u bits\n", p_input_x509->sig_bit_size, key_bits);
        fprintf(stderr,"       (hint: added eight bits for ED448)\n");
        goto Exit;
      }
      break;

    default:
      break;
  }
#endif

  // everything checked, go on with certificate patching...

  // prepare the patching of the serial number if desired...

  if (0 != serial[0])
  {
    if (!be_quiet)
      fprintf(stdout,"INFO: patching new serial number '%s' into certificate.\n", serial);

    BIGNUM *p_bn = BN_new();

    if (unlikely(NULL == p_bn))
    {
      fprintf(stderr,"%sERROR%s: Unable to create new OpenSSL big number\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    if ('0' == serial[0] && 'x' == serial[1])
      BN_hex2bn(&p_bn, &serial[2]);
    else
      BN_dec2bn(&p_bn, serial);

    l_serial_bin = (uint32_t) BN_bn2bin(p_bn, &serial_bin[2]);

    BN_free(p_bn);

    if (unlikely(0 == l_serial_bin || l_serial_bin > 126))
    {
      fprintf(stderr,"%sERROR%s: Unable to convert textual serial number to raw binary\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    serial_bin[0] = 0x02;

    if (0x80 & serial_bin[2]) // ensure that ASN.1 INTEGER is POSITIVE
    {
      memmove(&serial_bin[3], &serial_bin[2], l_serial_bin);
      l_serial_bin++;
      serial_bin[2] = 0x00;
      serial_bin[1] = (uint8_t)l_serial_bin;
    }
    else
      serial_bin[1] = (uint8_t)l_serial_bin;
  }

  if (unlikely(!a1t_mempool_alloc(&mp, 262144)))
  {
    fprintf(stderr,"%sERROR%s: Insufficient memory available\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // use OpenSSL to der-encode the X509* structure

  l_x509_der = (uint32_t)i2d_X509(p_input_x509->p_cert, &p_x509_der);

  if (unlikely(0 == l_x509_der || NULL == p_x509_der))
  {
    fprintf(stderr,"%sERROR%s: Internal OpenSSL X.509v3 encoding error (DER)\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // parse the X.509 DER encoding (ITU-T X.690) into a DER tree...

  x509_root = a1t_decode_structure(&mp, p_x509_der, l_x509_der, true/*yes, decode encapsulated crap*/);
  if (unlikely(NULL == x509_root))
  {
    fprintf(stderr,"%sERROR%s: Internal ASN.1 tree parser error - unable to DER-decode\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (!a1t_explore_x509(x509_root,&exp))
  {
    fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (NULL != p_input_x509_cert)
  {
    l_x509_der_cert = (uint32_t)i2d_X509(p_input_x509_cert->p_cert, &p_x509_der_cert);

    if (unlikely(0 == l_x509_der_cert || NULL == p_x509_der_cert))
    {
      fprintf(stderr,"%sERROR%s: Internal OpenSSL X.509v3 encoding error (DER, issuer certificate)\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    // parse the X.509 DER encoding (ITU-T X.690) into a DER tree...

    x509_root_cert = a1t_decode_structure(&mp, p_x509_der_cert, l_x509_der_cert, true/*yes, decode encapsulated crap*/);
    if (unlikely(NULL == x509_root_cert))
    {
      fprintf(stderr,"%sERROR%s: Internal ASN.1 tree parser error - unable to DER-decode (issuer certificate)\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    if (!a1t_explore_x509(x509_root_cert,&exp_cert))
    {
      fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed (issuer certificate)\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // modify serial number if desired

  if (0 != l_serial_bin)
  {
    serial_tree = a1t_decode_structure(&mp, serial_bin, l_serial_bin + 2, false);
    if (unlikely(NULL == serial_tree))
    {
      fprintf(stderr,"%sERROR%s: Unable to render serial number subtree\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    if (!a1t_paste_item(&mp, exp.serialno, serial_tree, false))
    {
      fprintf(stderr,"%sERROR%s: Unable to patch new serial number into certificate\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    // re-new the exploration because we changed things...

    if (!a1t_explore_x509(x509_root,&exp))
    {
      fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // modify notBefore and notAfter:

  if (!a1t_modify_x509_validity(&mp, exp.validity, expiry_days_set ? expiry_days : 0))
  {
    fprintf(stderr,"%sERROR%s: Unable to patch new validity into certificate\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // re-new the exploration because we changed things...

  if (!a1t_explore_x509(x509_root,&exp))
  {
    fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // DER-encode the public key

  p_evp_key = NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key;

  l_pubkey_der = (uint32_t)i2d_PUBKEY(p_evp_key, &p_pubkey_der);

  if (unlikely(0 == l_pubkey_der || NULL == p_pubkey_der))
  {
    fprintf(stderr,"%sERROR%s: Unable to DER-encode public key\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // parse this sub-DER-structure into an ASN.1 tree

  p_pubkey_tree = a1t_decode_structure(&mp, p_pubkey_der, l_pubkey_der, false/* do not check encapsulated stuff so that we end up with an integral BIT STRING,
  which we need for the SubjectKeyIdentifier computation using the SHA-1 hash function*/);
  if (unlikely(NULL == p_pubkey_tree))
  {
    fprintf(stderr,"%sERROR%s: Unable to TREE-encode public key DER data\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // check the just decoded tree; go down to child of toplevel SEQUENCE, skip AlgorithmIdentifier (another SEQUENCE), seek BIT STRING
  // for SubjectKeyIdentifier SHA-1 calculation

  if (unlikely(0x21000030 != p_pubkey_tree->tag))
  {
SPKIError:
    fprintf(stderr,"%sERROR%s: Bad SubjectPublicKeyInfo found, unable to proceed\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p_run = p_pubkey_tree->child;
  if (unlikely(NULL == p_run))
    goto SPKIError;
  if (unlikely(0x21000030 != p_run->tag))
    goto SPKIError;
  p_run = p_run->next;
  if (unlikely(NULL == p_run || 0x01000003 != p_run->tag || NULL != p_run->child || p_run->len < 16/*arbitrary check value, no public key is so small*/))
    goto SPKIError;
  if (unlikely(0x00 != p_run->value[0])) // unused bits in final octet has to be zero!
    goto SPKIError;

  SHA1(&p_run->value[1], p_run->len - 1, subkid);

  // patch the new public key into the X.509 ASN.1 tree

  if (!a1t_paste_item(&mp, exp.spki, p_pubkey_tree, false))
  {
    fprintf(stderr,"%sERROR%s: Unable to paste the new SubjectPublicKeyInfo into the X.509 DER tree\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // re-new the exploration because we changed things...

  if (!a1t_explore_x509(x509_root,&exp))
  {
    fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // if not self-signed, then exchange the issuer DN by the subject DN of the issuer certificate

  if (NULL != p_input_x509_cert)
  {
    p_temp = exp_cert.subject_name->next;
    exp_cert.subject_name->next = NULL;
    if (!a1t_paste_item(&mp, exp.issuer_name, exp_cert.subject_name, true/* yes, copy this subtree */))
    {
      exp_cert.subject_name->next = p_temp;
      fprintf(stderr,"%sERROR%s: Unable to exchange the issuer DN by the subject DN of the issuer certificate\n", ctrlRed, ctrlReset);
      goto Exit;
    }
    exp_cert.subject_name->next = p_temp;

    // re-new the exploration because we changed things...

    if (!a1t_explore_x509(x509_root,&exp))
    {
      fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    // we also have to exchange the AuthorityKeyIdentifier by the SubjectKeyIdentifier of the issuer certificate

    p_run = exp_cert.extensions;
    if (NULL != p_run)
      p_run = p_run->child;
    while (NULL != p_run)
    {
      if (0x21000030 == p_run->tag)
      {
        if (NULL != p_run->child && 0x01000006 == p_run->child->tag)
        {
          if (3 == p_run->child->len && !memcmp(p_run->child->value, "\x55\x1D\x0E", 3)) // this is SubjectKeyIdentifier
          {
            if (NULL != p_run->child->next && 0x01000004 == p_run->child->next->tag &&
                NULL != p_run->child->next->child && 0x01000004 == p_run->child->next->child->tag)
            {
              if (SHA_DIGEST_LENGTH == p_run->child->next->child->len)
              {
                memcpy(authkid, p_run->child->next->child->value, SHA_DIGEST_LENGTH);
                have_authkid = true;
                break;
              }
            }
          }
        }
      }
      p_run = p_run->next;
    }

    if (!have_authkid)
    {
      fprintf(stderr,"%sERROR%s: Either did NOT find subjectKeyIdentifier of issuer certificate or size mismatch\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  } // of have issuer certificate
  else // SELF-SIGNED:
  {
    memcpy(authkid, subkid, SHA_DIGEST_LENGTH); // self-signed, i.e. AuthorityKeyIdentifier matches SubjectKeyIdentifier
  }

  // traverse all X.509v3 extensions, look for SubjectKeyIdentifier and AuthorityKeyIdentifier and patch the contained data
  // using subkid or authkid, respectively

  // first create the X.509v3 extension OCTET STRINGs for SubjectKeyIdentifier and AuthorityKeyIdentifier

  subkid_der[0] = 0x04;
  subkid_der[1] = (uint8_t)(SHA_DIGEST_LENGTH + 2);
  subkid_der[2] = 0x04;
  subkid_der[3] = (uint8_t)SHA_DIGEST_LENGTH;
  memcpy(&subkid_der[4], subkid, SHA_DIGEST_LENGTH);

  authkid_der[0] = 0x04;
  authkid_der[1] = (uint8_t)(SHA_DIGEST_LENGTH + 4);
  authkid_der[2] = 0x30;
  authkid_der[3] = (uint8_t)(SHA_DIGEST_LENGTH + 2);
  authkid_der[4] = 0x80;
  authkid_der[5] = (uint8_t)SHA_DIGEST_LENGTH;
  memcpy(&authkid_der[6], authkid, SHA_DIGEST_LENGTH);

  subkid_tree = a1t_decode_structure(&mp, subkid_der, sizeof(subkid_der), false);
  authkid_tree = a1t_decode_structure(&mp, authkid_der, sizeof(authkid_der), false);

  if (unlikely(NULL == subkid_tree || NULL == authkid_tree))
  {
    fprintf(stderr,"%sERROR%s: Unable to render ASN.1 sub structures (SubjectKeyIdentifier and/or AuthorityKeyIdentifier)\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p_run = exp.extensions;
  if (NULL != p_run)
    p_run = p_run->child;
  while ((NULL != p_run) && ((!patched_authkid) || (!patched_subkid)))
  {
    if (0x21000030 == p_run->tag)
    {
      if (NULL != p_run->child && 0x01000006 == p_run->child->tag)
      {
        if (3 == p_run->child->len && !memcmp(p_run->child->value, "\x55\x1D\x0E", 3)) // this is SubjectKeyIdentifier
        {
          if (NULL != p_run->child->next && 0x01000004 == p_run->child->next->tag)
          {
            if (a1t_paste_item(&mp, p_run->child->next, subkid_tree, false))
            {
              patched_subkid = true;

              // re-new the exploration because we changed things...

              if (!a1t_explore_x509(x509_root,&exp))
              {
                fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
                goto Exit;
              }
            }
          }
        }
        else
        if (3 == p_run->child->len && !memcmp(p_run->child->value, "\x55\x1D\x23", 3)) // this is AuthorityKeyIdentifier
        {
          if (NULL != p_run->child->next && 0x01000004 == p_run->child->next->tag)
          {
            if (a1t_paste_item(&mp, p_run->child->next, authkid_tree, false))
            {
              patched_authkid = true;

              // re-new the exploration because we changed things...

              if (!a1t_explore_x509(x509_root,&exp))
              {
                fprintf(stderr,"%sERROR%s: Incompatible X.509v3 structure found, unable to proceed\n", ctrlRed, ctrlReset);
                goto Exit;
              }
            }
          }
        }
      }
    }
    p_run = p_run->next;
  }

  if (!patched_subkid)
  {
    fprintf(stderr,"%sERROR%s: Unable to patch the SubjectKeyIdentifier - please cross-check the X.509v3 template.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (!patched_authkid)
  {
    fprintf(stderr,"%sERROR%s: Unable to patch the AuthorityKeyIdentifier - please cross-check the X.509v3 template.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // DER-encode the To-Be-Signed part, i.e. the TBSCertificate

  p_temp = exp.tbs_cert->next; // we have to temporarily cut everything beyond TBSCertificate
  exp.tbs_cert->next = NULL;
  p_tbs = a1t_encode_structure(exp.tbs_cert, &l_tbs);
  exp.tbs_cert->next = p_temp;
  if (unlikely(NULL == p_tbs || 0 == l_tbs))
  {
    fprintf(stderr,"%sERROR%s: Unable to DER-encode the certificate TBS part\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // compute digital signature over To-Be-Signed = TBSCertificate structure

  switch(p_input_x509->x509_sig_algo)
  {
    case X509_SIG_ALGO_PKCS1_V15_SHA256:
      md_type = MD_TYPE_SHA2_256;
      sig_type = SIG_TYPE_RSA_PKCS1_V15;
      break;
    case X509_SIG_ALGO_PKCS1_V15_SHA384:
      md_type = MD_TYPE_SHA2_384;
      sig_type = SIG_TYPE_RSA_PKCS1_V15;
      break;
    case X509_SIG_ALGO_PKCS1_V15_SHA512:
      md_type = MD_TYPE_SHA2_512;
      sig_type = SIG_TYPE_RSA_PKCS1_V15;
      break;
    case X509_SIG_ALGO_RSAPSS_SHA256:
      md_type = MD_TYPE_SHA2_256;
      sig_type = SIG_TYPE_RSA_PSS_SHA256;
      break;
    case X509_SIG_ALGO_RSAPSS_SHA384:
      md_type = MD_TYPE_SHA2_384;
      sig_type = SIG_TYPE_RSA_PSS_SHA384;
      break;
    case X509_SIG_ALGO_RSAPSS_SHA512:
      md_type = MD_TYPE_SHA2_512;
      sig_type = SIG_TYPE_RSA_PSS_SHA512;
      break;
    case X509_SIG_ALGO_ECDSA_SHA256:
      md_type = MD_TYPE_SHA2_256;
      sig_type = NULL == p_input_x509_cert ? _ec_curve_to_sig_type(p_input_x509->pk_ec_curve) : _ec_curve_to_sig_type(p_input_x509_cert->pk_ec_curve);
      break;
    case X509_SIG_ALGO_ECDSA_SHA384:
      md_type = MD_TYPE_SHA2_384;
      sig_type = NULL == p_input_x509_cert ? _ec_curve_to_sig_type(p_input_x509->pk_ec_curve) : _ec_curve_to_sig_type(p_input_x509_cert->pk_ec_curve);
      break;
    case X509_SIG_ALGO_ECDSA_SHA512:
      md_type = MD_TYPE_SHA2_512;
      sig_type = NULL == p_input_x509_cert ? _ec_curve_to_sig_type(p_input_x509->pk_ec_curve) : _ec_curve_to_sig_type(p_input_x509_cert->pk_ec_curve);
      break;
    case X509_SIG_ALGO_EDDSA_ED25519:
      md_type = MD_TYPE_SHA2_512;
      sig_type = NULL == p_input_x509_cert ? _ec_curve_to_sig_type(p_input_x509->pk_ec_curve) : _ec_curve_to_sig_type(p_input_x509_cert->pk_ec_curve);
      break;
    case X509_SIG_ALGO_EDDSA_ED448: // special here: key_bits 448 but 57 instead of 56 bytes components
      md_type = MD_TYPE_SHAKE_256;
      sig_type = NULL == p_input_x509_cert ? _ec_curve_to_sig_type(p_input_x509->pk_ec_curve) : _ec_curve_to_sig_type(p_input_x509_cert->pk_ec_curve);
      break;
    default:
      break;
  }

  if (unlikely(0xFFFFFFFF == md_type || 0xFFFFFFFF == sig_type))
  {
    fprintf(stderr,"%sERROR%s: Internal error occurred determining the md and the sig types\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p_sign_evp_key = NULL != p_input_x509_cert ? p_priv_evp_key_cert : p_priv_evp_key;
  p_verify_evp_key = NULL != p_input_x509_cert ? p_pub_evp_key_cert : p_pub_evp_key;

  if (unlikely(NULL == p_verify_evp_key))
  {
    fprintf(stderr,"%sERROR%s: Internal error occurred: no public OpenSSL EVP verification key\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (NULL != p_sign_evp_key) // use OpenSSL
  {
    if (!ossl_create_digital_signature(p_sign_evp_key, sig_type, md_type, p_tbs, l_tbs, &p_sig, &l_sig, true/*ASN.1 ECDSA signature*/, false))
    {
      fprintf(stderr,"%sERROR%s: Unable to create digital signature using OpenSSL\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }
  else // use PKCS#11
  {
    if (!pkcs11_create_signature(NULL != p_input_x509_cert ? pkcs11_label_cert : pkcs11_label,
                                 sig_type, md_type, p_tbs, l_tbs, &p_sig, &l_sig, true/*ASN.1 ECDSA signature*/, false))
    {
      fprintf(stderr,"%sERROR%s: Unable to create digital signature using PKCS #11\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // if loop-back verification desired, do it

  if (do_verify)
  {
    if (!ossl_verify_digital_signature(p_verify_evp_key, sig_type, md_type, p_tbs, l_tbs, p_sig, l_sig, false))
    {
      fprintf(stderr,"%sERROR%s: Unable to verify digital signature using OpenSSL\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // create simple BIT STRING with signature, patch X.509v3 structure, and DER-encode it to get the new certificate

  p_new_sig_bs = a1t_create_simple_item(&mp, 0x01000003, l_sig + 1, NULL);
  if (unlikely(NULL == p_new_sig_bs))
  {
    fprintf(stderr,"%sERROR%s: Unable to create new ASN.1 BIT STRING containing new certificate signature\n", ctrlRed, ctrlReset);
    goto Exit;
  }
  memcpy(&p_new_sig_bs->value[1], p_sig, l_sig);
  p_new_sig_bs->value[0] = 0x00; // unused bits in final octet

  if (!a1t_paste_item(&mp, exp.sigval_bs, p_new_sig_bs, false))
  {
    fprintf(stderr,"%sERROR%s: Unable to paste new ASN.1 BIT STRING (certificate signature) into X.509v3 structure\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p_output = a1t_encode_structure(x509_root, &l_output);
  if (NULL == p_output)
  {
    fprintf(stderr,"%sERROR%s: Unable to DER-encode new (patched) X.509v3 certificate\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p = p_output;
  out_x509 = d2i_X509(NULL, &p, (long)l_output);
  if (unlikely(NULL == out_x509))
  {
    fprintf(stderr,"%sERROR%s: OpenSSL is unable to parse new (patched) X.509v3 certificate\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  f = fopen(output_filename,"wb");
  if (NULL == f)
  {
    fprintf(stderr,"%sERROR%s: Unable to create/open for writing: %s\n", ctrlRed, ctrlReset, output_filename);
    goto Exit;
  }

  if (1 != PEM_write_X509(f, out_x509))
  {
    fclose(f);
    fprintf(stderr,"%sERROR%s: Unable to serialize PEM output certificate: %s\n", ctrlRed, ctrlReset, output_filename);
    goto Exit;
  }

  fclose(f);

  if (!be_quiet)
    fprintf(stdout,"%sGOOD%s: Successfully wrote PEM encoded X.509v3 certificate: %s\n", ctrlGreen, ctrlReset, output_filename);

  rc = 0;

Exit:

  if (NULL != out_x509)
    X509_free(out_x509);
  if (NULL != p_output)
    free(p_output);
  if (NULL != p_sig)
    free(p_sig);
  if (NULL != p_tbs)
    free(p_tbs);
  if (NULL != p_pubkey_der)
    OPENSSL_free(p_pubkey_der);
  if (NULL != p_x509_der_cert)
    OPENSSL_free(p_x509_der_cert);
  if (NULL != p_x509_der)
    OPENSSL_free(p_x509_der);
  if (NULL != mp.p_memory)
    free(mp.p_memory);
  if (NULL != p_pub_evp_key_cert)
    EVP_PKEY_free(p_pub_evp_key_cert);
  if (NULL != p_pub_evp_key)
    EVP_PKEY_free(p_pub_evp_key);
  if (NULL != p_priv_evp_key)
    EVP_PKEY_free(p_priv_evp_key);
  if (NULL != p_priv_evp_key_cert)
    EVP_PKEY_free(p_priv_evp_key_cert);
  if (NULL != p_input_x509)
    ossl_free_x509(p_input_x509);
  if (NULL != p_input_x509_cert)
    ossl_free_x509(p_input_x509_cert);

  if (pkcs11_init_done)
    pkcs11_fini();

  ossl_fini();

  return rc;
}

#define INIT_AND_LOGIN_PKCS11_LIBRARY \
do \
{ \
  if (!pkcs11_init_done) \
  { \
    if (0 == pkcs11_library[0]) \
    { \
      fprintf(stderr,"%sERROR%s: No PKCS#11 library specified.\n", ctrlRed, ctrlReset); \
      goto Exit; \
    } \
    if (!be_quiet) \
    { \
      fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot); \
      if (0 != secret[0] || 0 != pkcs11_pin[0]) \
        fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n"); \
    } \
    if (!pkcs11_init(pkcs11_library, pkcs11_slot)) \
    { \
      fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library); \
      goto Exit; \
    } \
    pkcs11_init_done = true; \
    if (!pkcs11_login(NULL, 0)) \
    { \
      fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset); \
      goto Exit; \
    } \
  } \
} while (0)

/**
 * @brief applet for creating a binary PGP packet structure file suitable to be
 *        imported, e.g. by the GnuPG "gpg --import" workflow.
 *        This may be just a public key (PGP: "PUBLIC KEY PACKET") or a full
 *        key pair, GPG aka "SECRET KEY PACKET".
 *
 * This function does NOT combine two key pairs (e.g. one for signature and one
 * for encryption) into one PGP packet structure. Instead, it just transfers
 * one public key or one key pair into the "PGP world". This is mainly for
 * signing (e.g. code signing using the gpg or gpgv command line tools and/or
 * the GRUB2 bootloader, which is also equipped with GnuPG.
 *
 * Please note that PGP defines 'keys' (primary) and 'subkeys' (secondary), i.e.
 * the 'key' is a signature key and an optional 'subkey' is an encryption or
 * key exchange key, respectively.
 *
 * This applet can only transfer 'keys', not 'subkeys' (not yet). The 'key'
 * may either be an ASN.1 DER-encoded key on disk (PEM format, BASE64) or
 * may reside in a PKCS#11 module. In the latter case, only the public part
 * of the key pair (again: PUBLIC KEY PACKET) is transferred to PGP, not the
 * private (in the PGP jargon: secret) key.
 *
 * A SECRET KEY PACKET may be either transferred in plaintext or symmetrically
 * enciphered using AES-CFB128 with a 256bit key, 128bit IV, and an additional
 * SHA-1 for integrity protection. Another algorithm would be AES-GCM (Galois
 * Counter Mode) with 256bit key, 96bit IV, 128bit AES-GCM-TAG. It is implemented
 * but NOT YET TESTED because no other PGP implementation could be found so far,
 * which fully implements RFC 9280, the latest PGP RFC.
 *
 * 'Positive certification signatures' can be either self-signed or non-self-
 * signed. In the latter case, another issuer/signer key or PKCS#11 label is
 * required.
 *
 * Please also note that PGP key fingerprints can only be computed if the key
 * creation timestamp is available. Because this timestamp is normally not
 * provided in the ASN.1/X.509v3 domain, we do the following:
 * (a) if a private key (key pair) gets generated in software, then the key
 *     creation timestamp (number of seconds since 1970) is prepended to the
 *     file name as eight hexadecimal digits (PGP only supports 32bit timestamps
 *     so anything beyond 2106 cannot be expressed!).
 * (b) if a key pair gets generated in a PKCS#11 module, the key label identifies
 *     the key and the PKCS#11 key ID stores the key creation timestamp as a
 *     64bit value - again, only 32bits are usable with PGP.
 *
 * The next applet, 'onPGPSign' was especially written to support detached,
 * binary PGP signatures using a private key in a PKCS#11 module - there is
 * no need to set up complicated software stacks to enable e.g. GnuPG to
 * support cryptographic hardware (e.g. PKCS#11). Signatures can be computed
 * using the next applet, the signature verification can be performed by either
 * gpg, gpgv or the GRUB2 bootloader.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onPGPImport ( int argc, char *argv[] )
{
  (void)argc;
  (void)argv;
  int               rc = 1;
  bool              pkcs11_init_done = false;
  EVP_PKEY         *p_use_evp_key;
  EVP_PKEY         *p_pub_evp_key = NULL;
  EVP_PKEY         *p_priv_evp_key = NULL;
  EVP_PKEY         *p_pub_evp_key_cert = NULL;
  EVP_PKEY         *p_priv_evp_key_cert = NULL;
  x509parsed_ptr    p_x509 = NULL, p_x509_cert = NULL;
  struct tm        *ptm;
  gpg_binary_ptr    p_gpg = NULL;
  uint32_t          err, l_gpgbin, l_key_id = 0, l_key_id_cert = 0, l_input;
  uint8_t          *p_gpgbin = NULL, key_id[8], key_id_cert[8], *p_input;
  char              issuer_email[256], subject_user_name[256], subject_email[256];
  bool              is_self_signed = false, is_secret_key = false;
  time_t            creation_ts_cert = 0;
  time_t            pgp_creation_ts = 0, pgp_expiry_ts = 0;

  memset(key_id, 0, sizeof(key_id));
  memset(key_id_cert, 0, sizeof(key_id_cert));

  memcpy(issuer_email, email_addr_cert, sizeof(issuer_email)); // pre-fill with command line - if specified
  memcpy(subject_user_name, user_name, sizeof(subject_user_name)); // pre-fill with command line - if specified
  memcpy(subject_email, email_addr, sizeof(subject_email)); // pre-fill with command line - if specified

  if (0 == output_filename[0])
  {
    fprintf(stderr,"%sERROR%s: output file name is missing.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // we need any input key whether it is public or private or in a PKCS#11 module...

  if (0 == private_key_file[0] && 0 == pkcs11_label[0] && 0 == public_key_file[0])
  {
    fprintf(stderr,"%sERROR%s: need either a private or public key or a PKCS#11 label.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // if it is self-signed (no additional issuer), then a public key is insufficient...

  if (0 == private_key_cert_file[0] && 0 == pkcs11_label_cert[0])
  {
    if (0 == private_key_file[0] && 0 == pkcs11_label[0])
    {
      fprintf(stderr,"%sERROR%s: The positive certification signature requires a private key or PKCS#11 label.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // Initialize OpenSSL

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // Pull-in all required cryptographic assets (only for assets on disk)

  if (0 != public_key_file[0])
  {
    p_input = read_file(public_key_file, &l_input);
    if (NULL == p_input || 0 == l_input)
    {
      fprintf(stderr,"%sERROR%s: Unable to read: %s\n", ctrlRed, ctrlReset, public_key_file);
      goto Exit;
    }

    p_x509 = ossl_parse_x509(p_input,l_input,true);
    free(p_input);
    if (NULL == p_x509) // no, not an X.509v3
    {
      bool is_keypair = false;
      p_pub_evp_key = ossl_load_openssl_key(public_key_file, &is_keypair, NULL);
      if (NULL == p_pub_evp_key)
      {
        fprintf(stderr,"%sERROR%s: Unable to read public key from: %s\n", ctrlRed, ctrlReset, public_key_file);
        goto Exit;
      }

      if (0 == email_addr[0])
      {
        fprintf(stderr,"%sERROR%s: The subject E-mail address is required.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      if (0 == user_name[0])
      {
        fprintf(stderr,"%sERROR%s: The subject user name is required.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      memcpy(subject_email, email_addr, sizeof(subject_email));
      memcpy(subject_user_name, user_name, sizeof(subject_user_name));
    }
    else // X.509v3 is there
    {
      if (0 != email_addr[0]) // command line option overrides everything...
      {
        memcpy(subject_email, email_addr, sizeof(subject_email));
      }
      else
      if (0 != p_x509->emailaddr[0])
        memcpy(subject_email, p_x509->emailaddr, sizeof(subject_email));
      else
      {
        fprintf(stderr,"%sERROR%s: The subject E-mail address is required.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      if (0 != user_name[0]) // command line option overrides everything...
      {
        memcpy(subject_user_name, user_name, sizeof(subject_user_name));
      }
      else
      if (0 != p_x509->commonName[0])
        memcpy(subject_user_name, p_x509->commonName, sizeof(subject_user_name));
      else
      {
        fprintf(stderr,"%sERROR%s: The subject user name (user ID) is required.\n", ctrlRed, ctrlReset);
        goto Exit;
      }
    }
  }

  if (0 != public_key_cert_file[0])
  {
    p_input = read_file(public_key_cert_file, &l_input);
    if (NULL == p_input || 0 == l_input)
    {
      fprintf(stderr,"%sERROR%s: Unable to read: %s\n", ctrlRed, ctrlReset, public_key_cert_file);
      goto Exit;
    }

    p_x509_cert = ossl_parse_x509(p_input,l_input,true);
    free(p_input);
    if (NULL == p_x509_cert) // no, not an X.509v3
    {
      bool is_keypair = false;
      p_pub_evp_key_cert = ossl_load_openssl_key(public_key_cert_file, &is_keypair, NULL);
      if (NULL == p_pub_evp_key_cert)
      {
        fprintf(stderr,"%sERROR%s: Unable to read public key from: %s\n", ctrlRed, ctrlReset, public_key_cert_file);
        goto Exit;
      }
    }

    if (0 != email_addr_cert[0]) // command line option overrides everything...
    {
      memcpy(issuer_email, email_addr_cert, sizeof(issuer_email));
    }
    else
    if ((NULL != p_x509_cert) && (0 != p_x509_cert->emailaddr[0]))
      memcpy(issuer_email, p_x509_cert->emailaddr, sizeof(issuer_email));
    else
    {
      fprintf(stderr,"%sERROR%s: The issuer E-mail address is required.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  // check issuer stuff first

  if (0 != pkcs11_label_cert[0])
  {
    INIT_AND_LOGIN_PKCS11_LIBRARY;

    if (NULL != p_pub_evp_key_cert)
      EVP_PKEY_free(p_pub_evp_key_cert), p_pub_evp_key_cert = NULL;

    l_key_id_cert = sizeof(key_id_cert);
    if (!pkcs11_get_key_id_by_key_label((const uint8_t*)pkcs11_label_cert, (uint32_t)strlen(pkcs11_label_cert),
                                        key_id_cert, &l_key_id_cert))
    {
      fprintf(stderr,"%sERROR%s: Unable to retrieve key ID (=creation timestamp) from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label_cert);
      goto Exit;
    }

    if (unlikely(8 != l_key_id_cert))
    {
      fprintf(stderr, "%sERROR%s: Bad key ID (=creation timestamp) from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label_cert);
      goto Exit;
    }

    creation_ts_cert = (time_t)((((uint64_t)key_id_cert[0]) << 56) |
      (((uint64_t)key_id_cert[1]) << 48) |
      (((uint64_t)key_id_cert[2]) << 40) |
      (((uint64_t)key_id_cert[3]) << 32) |
      (((uint64_t)key_id_cert[4]) << 24) |
      (((uint64_t)key_id_cert[5]) << 16) |
      (((uint64_t)key_id_cert[6]) << 8) |
      ((uint64_t)key_id_cert[7]));

    p_pub_evp_key_cert = pkcs11_get_ossl_public_evp_key_from_pubkey(key_id_cert, l_key_id_cert, (const uint8_t*)pkcs11_label_cert, (uint32_t)strlen(pkcs11_label_cert));

    if (NULL == p_pub_evp_key_cert)
    {
      fprintf(stderr,"%sERROR%s: Unable to retrieve OpenSSL EVP_PKEY from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label_cert);
      goto Exit;
    }
  }
  else
  if (0 != private_key_cert_file[0])
  {
    bool is_keypair = false;
    p_priv_evp_key_cert = ossl_load_openssl_key(private_key_cert_file, &is_keypair, &creation_ts_cert);
    if (NULL == p_priv_evp_key_cert)
    {
      fprintf(stderr,"%sERROR%s: Unable to read private key (keypair) from: %s\n", ctrlRed, ctrlReset, private_key_cert_file);
      goto Exit;
    }
    if (!is_keypair)
    {
      fprintf(stderr,"%sERROR%s: Private key (keypair) '%s' is NOT a full key pair.\n", ctrlRed, ctrlReset, private_key_cert_file);
      goto Exit;
    }
    if (0 == creation_ts_cert)
    {
      fprintf(stderr,"%sERROR%s: All private key PEM files require the special verb 'KEY-CREATION-TIMESTAMP: YYYYMMDDHHMMSSZ' as part of the file: %s\n", ctrlRed, ctrlReset, private_key_cert_file);
      goto Exit;
    }
  }

  is_self_signed = (0 == pkcs11_label_cert[0] && 0 == private_key_cert_file[0]) ? true : false;

  // now the key itself...

  if (0 != pkcs11_label[0])
  {
    INIT_AND_LOGIN_PKCS11_LIBRARY;

    if (NULL != p_pub_evp_key)
      EVP_PKEY_free(p_pub_evp_key), p_pub_evp_key = NULL;

    l_key_id = sizeof(key_id);
    if (!pkcs11_get_key_id_by_key_label((const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label),key_id, &l_key_id))
    {
      fprintf(stderr,"%sERROR%s: Unable to retrieve key ID (=creation timestamp) from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label);
      goto Exit;
    }

    if (unlikely(8 != l_key_id))
    {
      fprintf(stderr, "%sERROR%s: Bad key ID (=creation timestamp) from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label);
      goto Exit;
    }

    pgp_creation_ts = (time_t)((((uint64_t)key_id[0]) << 56) |
      (((uint64_t)key_id[1]) << 48) |
      (((uint64_t)key_id[2]) << 40) |
      (((uint64_t)key_id[3]) << 32) |
      (((uint64_t)key_id[4]) << 24) |
      (((uint64_t)key_id[5]) << 16) |
      (((uint64_t)key_id[6]) << 8) |
      ((uint64_t)key_id[7]));

    p_pub_evp_key = pkcs11_get_ossl_public_evp_key_from_pubkey(key_id, l_key_id, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));

    if (NULL == p_pub_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Unable to retrieve OpenSSL EVP_PKEY from PKCS#11 module for label: %s\n", ctrlRed, ctrlReset, pkcs11_label);
      goto Exit;
    }
  }
  else
  {
    bool is_keypair = false;

    if (0 == private_key_file[0] && 0 == public_key_file[0] && NULL == p_x509)
    {
      fprintf(stderr,"%sERROR%s: No private/public key file (and no PKCS#11 label) and no X.509v3 input specified.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    if (0 == private_key_file[0])
    {
      fprintf(stderr,"%sERROR%s: Because of self-signed operation, a private key file has to be specified.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    p_priv_evp_key = ossl_load_openssl_key(private_key_file, &is_keypair, &pgp_creation_ts);
    if (NULL == p_priv_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Unable to read private key (keypair) from: %s\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }
    if (!is_keypair)
    {
      fprintf(stderr,"%sERROR%s: Private key (keypair) '%s' is NOT a full key pair.\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }
    if (0 == key_creation_ts)
    {
      if (0 == pgp_creation_ts)
      {
        fprintf(stderr, "%sERROR%s: All private key PEM files require the special verb 'KEY-CREATION-TIMESTAMP: YYYYMMDDHHMMSSZ' as part of the file: %s\n", ctrlRed, ctrlReset, private_key_file);
        goto Exit;
      }
    }
  }

  // global key_expiry_ts, if this is set, et.al. together with private key extracted ts or PKCS#11 key IDs and/or X.509 notBefore/notAfter
  // have to be evaluated here:

  if (0 != key_creation_ts)
    pgp_creation_ts = key_creation_ts;
  
  if ((0 == pgp_creation_ts) && (NULL != p_x509))
    pgp_creation_ts = (time_t)p_x509->notBefore;

  if (unlikely(0 == pgp_creation_ts))
  {
    fprintf(stderr,"%sERROR%s: Key creation timestamp is zero (0), which is not supported.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (expiry_days_set)
  {
    if (0 == expiry_days)
      pgp_expiry_ts = 0;
    else
      pgp_expiry_ts = pgp_creation_ts + expiry_days * 86400;
  }
  else
  {
    if (NULL != p_x509)
      pgp_expiry_ts = (time_t)p_x509->notAfter;
    else
      pgp_expiry_ts = 0; // no expiry
  }

  if (((uint64_t)pgp_creation_ts) > 0xFFFFFFFF)
  {
    fprintf(stderr,"%sERROR%s: key creation timestamp exceeds maximum 32bit range (beyond 2106-02-07 06:28:15 = 0xffffffff).\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (0 != pgp_expiry_ts && pgp_expiry_ts > 0xFFFFFFFF)
  {
    pgp_expiry_ts = 0xFFFFFFFF;
    if (!be_quiet)
      fprintf(stdout,"%sWARNING%s: key expiry timestamp limited to 2106-02-07 06:28:15 (0xffffffff).\n", ctrlYellow, ctrlReset);
  }

  if (0 != pgp_expiry_ts && (pgp_expiry_ts < pgp_creation_ts))
  {
    fprintf(stderr,"%sERROR%s: key expiry timestamp < creation timestamp.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if ((0 != creation_ts_cert) && (creation_ts_cert > 0xFFFFFFFF))
  {
    fprintf(stderr,"%sERROR%s: key creation timestamp (issuer) exceeds [0..0xffffffff].\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // output informational stuff if either not quiet or dryrun...

  if (unlikely(0 == subject_user_name[0] || 0 == subject_email[0]))
  {
    fprintf(stderr,"%sERROR%s: User name and/or E-mail address not available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (!is_self_signed && 0 == issuer_email[0])
  {
    fprintf(stderr,"%sERROR%s: Issuer E-mail address not available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  is_secret_key = (NULL != p_priv_evp_key) ? true : false;
  if (is_secret_key && convert_pubkey_only)
    is_secret_key = false;

  if (dryrun || !be_quiet)
  {
    if (dryrun)
      fprintf(stdout,"DRYRUN:\n-------\n\n");

    fprintf(stdout,"  ...going to create binary PGP %s KEY PACKET structure\n", is_secret_key ? "SECRET" : "PUBLIC");
    fprintf(stdout,"  ...writing output to: %s\n", output_filename);
    fprintf(stdout,"  ...using %s PGP packet format\n", pgp_new_packet_format ? "NEW" : "OLD");
    fprintf(stdout,"  ...creating a %sself signature\n", is_self_signed ? "" : "non-");
    fprintf(stdout,"  ...using the user name '%s'\n", subject_user_name);
    fprintf(stdout,"  ...and the E-mail address '%s'\n", subject_email);
    ptm = gmtime(&pgp_creation_ts);
    fprintf(stdout,"  ...key creation timestamp is: 0x%08x = %04u-%02u-%02u %02u:%02u:%02u\n",
        (uint32_t)pgp_creation_ts, ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
        ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    if (0 == pgp_expiry_ts)
      fprintf(stdout,"  ...no key expiry\n");
    else
    {
      ptm = gmtime(&pgp_expiry_ts);
      fprintf(stdout,"  ...key expiry timestamp is: 0x%08x = %04u-%02u-%02u %02u:%02u:%02u\n",
          (uint32_t)pgp_expiry_ts, ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    }
    if (!is_self_signed)
      fprintf(stdout,"  ...issuer E-mail address is '%s'\n", issuer_email);

    switch(gpg_enc_algo)
    {
      case SECRET_KEY_ENCR_NONE:
        fprintf(stdout,"  ...NO ENCRYPTION (key stored as plain text!)\n");
        break;
      case SECRET_KEY_ENCR_AES_CFB128:
        fprintf(stdout,"  ...AES-256bit enciphered (CFB128 mode)\n");
        break;
      case SECRET_KEY_ENCR_AES_GCM:
        fprintf(stdout,"  ...AES-256bit enciphered (Galois Counter Mode - EXPERIMENTAL)\n");
        break;
    }

    if (dryrun)
    {
      rc = 0;
      goto Exit;
    }
  }

  // and: action!

  p_gpg = GPGBIN_new(pgp_new_packet_format, 0/* use 64K */);
  if (unlikely(NULL == p_gpg))
  {
    fprintf(stderr,"%sERROR%s: Insufficient memory available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (NULL != p_x509)
    p_gpg->key_usage = p_x509->key_usage;

  p_use_evp_key = is_secret_key ? p_priv_evp_key : (NULL == p_pub_evp_key ? (NULL == p_x509 ? NULL : p_x509->p_pubkey) : p_pub_evp_key);
  if (NULL == p_use_evp_key && !is_secret_key && 0 == pkcs11_label[0])
    p_use_evp_key = p_priv_evp_key;

  if (unlikely(NULL == p_use_evp_key))
  {
    fprintf(stderr,"%sERROR (INTERNAL)%s: Do not have an EVP PKEY*\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  err = GPGBIN_addpacket_sign_key(p_gpg, p_use_evp_key, pgp_creation_ts, pgp_expiry_ts, is_secret_key);
  if (GPGBIN_ERROR_OK != err)
  {
    fprintf(stderr,"%sERROR%s: GPGBIN facility reports error 0x%08X (public/secret key packet)\n", ctrlRed, ctrlReset, err);
    goto Exit;
  }

  err = GPGBIN_addpacket_user_id(p_gpg, subject_user_name, (uint32_t)strlen(subject_user_name), subject_email, (uint32_t)strlen(subject_email));
  if (GPGBIN_ERROR_OK != err)
  {
    fprintf(stderr,"%sERROR%s: GPGBIN facility reports error 0x%08X (user id packet)\n", ctrlRed, ctrlReset, err);
    goto Exit;
  }

  p_gpg->creation_ts = is_self_signed ? ((uint32_t)pgp_creation_ts) : ((uint32_t)creation_ts_cert);

  if (unlikely(0 == p_gpg->creation_ts))
  {
    fprintf(stderr, "%sERROR%s: no PGP key creation timestamp available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (is_self_signed)
  {
    p_use_evp_key = NULL != p_priv_evp_key ? p_priv_evp_key : (NULL == p_pub_evp_key ? (NULL == p_x509 ? NULL : p_x509->p_pubkey) : p_pub_evp_key);
  }
  else
  {
    p_use_evp_key = NULL != p_priv_evp_key_cert ? p_priv_evp_key_cert : (NULL == p_pub_evp_key_cert ? (NULL == p_x509_cert ? NULL : p_x509_cert->p_pubkey) : p_pub_evp_key_cert);
  }

  if (NULL == p_use_evp_key)
  {
    fprintf(stderr, "%sERROR%s: do NOT have an OpenSSL EVP_PKEY*; unable to continue.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  if (0 != pkcs11_label_cert[0])
    err = GPGBIN_addpacket_signature(p_gpg, NULL, 0, pgp_digest_algo, p_use_evp_key, pkcs11_label_cert, NULL, 0, pgp_expiry_ts,
                                     issuer_email, (uint32_t)strlen(issuer_email),
                                     do_verify );
  else
  if (0 == pkcs11_label[0])
    err = GPGBIN_addpacket_signature(p_gpg, NULL, 0, pgp_digest_algo, p_use_evp_key, NULL, NULL, 0, pgp_expiry_ts,
                                     is_self_signed ? subject_email : issuer_email, is_self_signed ? ((uint32_t)strlen(subject_email)) :((uint32_t)strlen(issuer_email)),
                                     do_verify );
  else
    err = GPGBIN_addpacket_signature(p_gpg, NULL, 0, pgp_digest_algo, p_use_evp_key, pkcs11_label, NULL, 0, pgp_expiry_ts,
                                     is_self_signed ? subject_email : issuer_email, is_self_signed ? ((uint32_t)strlen(subject_email)) :((uint32_t)strlen(issuer_email)),
                                     do_verify );

  if (GPGBIN_ERROR_OK != err)
  {
    fprintf(stderr,"%sERROR%s: GPGBIN facility reports error 0x%08X (signature packet)\n", ctrlRed, ctrlReset, err);
    goto Exit;
  }

  // allocate memory for the full binary GPG structure

  p_gpgbin = (uint8_t*)malloc(p_gpg->workarea_idx);
  if (unlikely(NULL == p_gpgbin))
  {
    fprintf(stderr,"%sERROR%s: Insufficient memory available.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  memcpy(p_gpgbin, p_gpg->p_workarea, p_gpg->workarea_idx);

  l_gpgbin = p_gpg->workarea_idx;

  GPGBIN_free(p_gpg), p_gpg = NULL;

  if (!write_file(output_filename, p_gpgbin, l_gpgbin))
  {
    fprintf(stderr,"%sERROR%s: Unable to create/write output file: %s\n", ctrlRed, ctrlReset, output_filename);
    goto Exit;
  }

  free(p_gpgbin), p_gpgbin = NULL;

  rc = 0; // OK

  if (!be_quiet)
    fprintf(stdout,"%sGOOD%s: Overall operation status.\n", ctrlGreen, ctrlReset);

  // common exit

Exit:
  if (NULL != p_gpgbin)
    free(p_gpgbin);
  if (NULL != p_gpg)
    GPGBIN_free(p_gpg);
  if (NULL != p_x509_cert)
    ossl_free_x509(p_x509_cert);
  if (NULL != p_x509)
    ossl_free_x509(p_x509);
  if (NULL != p_priv_evp_key_cert)
    EVP_PKEY_free(p_priv_evp_key_cert);
  if (NULL != p_pub_evp_key_cert)
    EVP_PKEY_free(p_pub_evp_key_cert);
  if (NULL != p_priv_evp_key)
    EVP_PKEY_free(p_priv_evp_key);
  if (NULL != p_pub_evp_key)
    EVP_PKEY_free(p_pub_evp_key);

  if (pkcs11_init_done)
    pkcs11_fini();
  ossl_fini();

  return rc;
}

/**
 * @brief applet for creating a binary PGP detached signature for an opaque
 *        input file.
 *
 * You may of course just use the command line tool 'gpg -b' to produce this
 * kind of detached signatures. This applet was especially implemented to support
 * PGP signatures for private keys, which reside in a PKCS#11 module.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onPGPSign ( int argc, char *argv[] )
{
  (void)argc;
  (void)argv;
  int               i, rc = 1;
  EVP_PKEY         *p_priv_evp_key = NULL, *p_pub_evp_key = NULL;
  bool              pkcs11_init_done = false;
  uint8_t          *p_input = NULL;
  uint32_t          l_input;
  gpg_binary_ptr    p_gpg = NULL;
  uint32_t          err, l_gpgbin, l_key_id;
  uint8_t          *p_gpgbin = NULL, key_id[8];
  char              inputfile[256], outputfile[256];

  if (dryrun)
  {
    fprintf(stderr,"%sERROR%s: 'dry run' not supported by this applet.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == private_key_file[0] && 0 == pkcs11_label[0])
  {
    fprintf(stderr,"%sERROR%s: Signing requires either a private key (key pair) or a PKCS#11 label.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == email_addr[0])
  {
    fprintf(stderr,"%sERROR%s: please specify an E-mail address (the signer).\n", ctrlRed, ctrlReset);
    return 1;
  }

  // Initialize OpenSSL

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // read private key first (if PKCS#11 mode is off)

  if (0 == pkcs11_label[0])
  {
    bool is_keypair = false;
    time_t temp_time;
    p_priv_evp_key = ossl_load_openssl_key(private_key_file, &is_keypair, &temp_time);

    if (NULL == p_priv_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Running in non-PKCS#11 mode requires a private key pair (PEM): %s\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }

    if (!is_keypair)
    {
      fprintf(stderr,"%sERROR%s: Running in non-PKCS#11 mode requires a private key pair (PEM), not just a public key: %s\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }

    if (0 == key_creation_ts)
    {
      if (0 == temp_time)
      {
        fprintf(stderr, "%sERROR%s: All private key PEM files require the special verb 'KEY-CREATION-TIMESTAMP: YYYYMMDDHHMMSSZ' as part of the file (or use --keyts to specify it explicitly).\n", ctrlRed, ctrlReset);
        goto Exit;
      }
      key_creation_ts = temp_time;
    }
  }
  else
  {
    if (0 == pkcs11_library[0])
    {
      fprintf(stderr,"%sERROR%s: Please specify a PKCS#11 library.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    // initialize PKCS#11 and read public key as OpenSSL EVP_PKEY* (public) from PKCS#11 module

    if (!be_quiet)
    {
      fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot);
      if (0 != secret[0] || 0 != pkcs11_pin[0])
        fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
    }

    if (!pkcs11_init(pkcs11_library, pkcs11_slot))
    {
      fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
      goto Exit;
    }

    if (!pkcs11_login(NULL, 0))
    {
      pkcs11_fini();
      fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    pkcs11_init_done = true;

    p_pub_evp_key = pkcs11_get_ossl_public_evp_key_from_pubkey(NULL, 0, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
    if (NULL == p_pub_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Unable to derive OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module (primary)\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    l_key_id = sizeof(key_id);
    if (!pkcs11_get_key_id_by_key_label((const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label), key_id, &l_key_id))
    {
      fprintf(stderr,"%sERROR%s: Unable to retrieve key ID of PKCS#11 key.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
    if (sizeof(key_id) != l_key_id)
    {
      fprintf(stderr,"%sERROR%s: Size of PKCS#11 key id (used as creation timestamp) is not eight (8).\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    key_creation_ts = (time_t)((((uint64_t)key_id[0]) << 56) |
      (((uint64_t)key_id[1]) << 48) |
      (((uint64_t)key_id[2]) << 40) |
      (((uint64_t)key_id[3]) << 32) |
      (((uint64_t)key_id[4]) << 24) |
      (((uint64_t)key_id[5]) << 16) |
      (((uint64_t)key_id[6]) << 8) |
      ((uint64_t)key_id[7]));
  }

  // work on all input files in a batch //////////////////////////////////////////////////////

  for (i = 2; i < argc; i++)
  {
    if ((0 != argv[i][0]) && (('-' == argv[i][0] && 0 == argv[i][1]) || (('-' != argv[i][0]) && (0 != argv[i][0]))))
    {
      memset(inputfile, 0, sizeof(inputfile));
      memset(outputfile, 0, sizeof(outputfile));
      strncpy(inputfile, argv[i], sizeof(inputfile) - 1);
      snprintf(outputfile, sizeof(outputfile), "%s.sig", inputfile);

      if (!be_quiet)
        fprintf(stdout,"Working on input file: %s\n", inputfile);

      p_input = read_file(inputfile, &l_input);
      if (unlikely(NULL == p_input))
      {
        fprintf(stderr,"%sERROR%s: Unable to read input file into memory: %s\n", ctrlRed, ctrlReset, inputfile);
        goto Exit;
      }

      if (!be_quiet)
        fprintf(stdout,"input file '%s' successfully read: %u byte(s)\n", inputfile, l_input);

      p_gpg = GPGBIN_new(pgp_new_packet_format, 0/* use 64K */);
      if (unlikely(NULL == p_gpg))
      {
        fprintf(stderr,"%sERROR%s: Insufficient memory available.\n", ctrlRed, ctrlReset);
        goto Exit;
      }
      p_gpg->creation_ts = (uint32_t)key_creation_ts;

      if (unlikely(0 == p_gpg->creation_ts))
      {
        fprintf(stderr, "%sERROR%s: no PGP key creation timestamp available.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      err = GPGBIN_addpacket_signature(p_gpg, p_input, l_input,
                                       pgp_digest_algo,
                                       NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key,
                                       NULL != p_priv_evp_key ? NULL : pkcs11_label,
                                       NULL, 0, 0,
                                       email_addr,
                                       (uint32_t)strlen(email_addr),
                                       do_verify);
      if (GPGBIN_ERROR_OK != err)
      {
        fprintf(stderr,"%sERROR%s: GPGBIN facility reports error 0x%08X (signature packet)\n", ctrlRed, ctrlReset, err);
        goto Exit;
      }

      // allocate memory for the full binary GPG structure

      p_gpgbin = (uint8_t*)malloc(p_gpg->workarea_idx);
      if (unlikely(NULL == p_gpgbin))
      {
        fprintf(stderr,"%sERROR%s: Insufficient memory available.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      memcpy(p_gpgbin, p_gpg->p_workarea, p_gpg->workarea_idx);

      l_gpgbin = p_gpg->workarea_idx;

      if (!write_file(outputfile, p_gpgbin, l_gpgbin))
      {
        fprintf(stderr,"%sERROR%s: Unable to create/write output file: %s\n", ctrlRed, ctrlReset, outputfile);
        goto Exit;
      }

      if (!be_quiet)
        fprintf(stdout,"%sGOOD%s: Successfully wrote detached PGP signature to: %s\n", ctrlGreen, ctrlReset, outputfile);

      if (NULL != p_gpgbin)
        free(p_gpgbin), p_gpgbin = NULL;
      if (NULL != p_input)
        free(p_input), p_input = NULL;
      if (NULL != p_gpg)
        GPGBIN_free(p_gpg), p_gpg = NULL;
    }
  }

  rc = 0;

Exit:
  if (NULL != p_gpgbin)
    free(p_gpgbin);
  if (NULL != p_input)
    free(p_input);
  if (NULL != p_gpg)
    GPGBIN_free(p_gpg);
  if (NULL != p_priv_evp_key)
    EVP_PKEY_free(p_priv_evp_key);
  if (NULL != p_pub_evp_key)
    EVP_PKEY_free(p_pub_evp_key);

  if (pkcs11_init_done)
    pkcs11_fini();
  ossl_fini();

  return rc;
}

/**
 * @brief use an OpenSSL EVP_PKEY* as input and derive all algorithm parameters
 *        from this public key (may also be a privat key, though).
 *
 * @param [in]      p_key         the OpenSSL EVP_PKEY*
 * @param [out]     md_type       returns the message digest (uses the global
 *                                variable pgp_digest_algo for this)
 * @param [out]     sig_type      based on key type, the signature type is returned here
 * @param [out]     curve_idx     only ECC and Edwards: return curve index
 * @param [out]     comp_len      only ECC and Edwards: return component length here;
 *                                e.g. for a 256bit curve, this is 32 bytes, for NIST
 *                                521bit, this is 66 bytes, and so forth.
 *                                There are two 'exceptions' for Edwards: ED25519 is
 *                                round-up to 32 bytes (like a 256bit key); ED448
 *                                does not have a component length of 448/8 = 56 bytes
 *                                but one byte more, i.e. 57 bytes (see RFC 8032).
 *
 * @return true on success, false on error
 */
static bool deriveAlgorithmParameters ( const EVP_PKEY *p_key, uint32_t *md_type, uint32_t *sig_type, uint32_t *curve_idx, uint32_t *comp_len )
{
  const EC_KEY               *p_ec_key;
  const EC_GROUP             *p_ec_group;
  int                         ec_curve_nid;
  const char                 *digest_str = NULL;

  if (unlikely(NULL == p_key || NULL == md_type || NULL == sig_type || NULL == curve_idx || NULL == comp_len))
    return false;

  *md_type   = 0;
  *sig_type  = 0;
  *curve_idx = 0;
  *comp_len  = 0;

  switch(pgp_digest_algo) // we need md_type for our signature implementation...
  {
    case DIGEST_ALGO_SHA256:
      *md_type = MD_TYPE_SHA2_256;
      break;
    case DIGEST_ALGO_SHA384:
      *md_type = MD_TYPE_SHA2_384;
      break;
    case DIGEST_ALGO_SHA512:
      *md_type = MD_TYPE_SHA2_512;
      break;
    default: // case DIGEST_ALGO_SHA224:
      *md_type = MD_TYPE_SHA2_224;
      break;
  }

  switch(EVP_PKEY_id(p_key))
  {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2: // this is an RSA (public) key
      if (!use_rsa_pss)
      {
        if (!be_quiet)
          fprintf(stdout,"%sINFO%s: signature scheme is RSA PKCS#1 v1.5\n", ctrlYellow, ctrlReset);
        *sig_type = SIG_TYPE_RSA_PKCS1_V15;
      }
      else
      {
        switch(pgp_digest_algo) // we need md_type for our signature implementation...
        {
          case DIGEST_ALGO_SHA256:
            *sig_type = SIG_TYPE_RSA_PSS_SHA256;
            if (!be_quiet)
              fprintf(stdout,"%sINFO%s: signature scheme is RSA PSS, SHA-256, MGF-1(SHA-256), 32 bytes salt length, trailerField BC\n", ctrlYellow, ctrlReset);
            break;
          case DIGEST_ALGO_SHA384:
            *sig_type = SIG_TYPE_RSA_PSS_SHA384;
            if (!be_quiet)
              fprintf(stdout,"%sINFO%s: signature scheme is RSA PSS, SHA-384, MGF-1(SHA-384), 48 bytes salt length, trailerField BC\n", ctrlYellow, ctrlReset);
            break;
          case DIGEST_ALGO_SHA512:
            *sig_type = SIG_TYPE_RSA_PSS_SHA512;
            if (!be_quiet)
              fprintf(stdout,"%sINFO%s: signature scheme is RSA PSS, SHA-512, MGF-1(SHA-512), 64 bytes salt length, trailerField BC\n", ctrlYellow, ctrlReset);
            break;
          default:
            return false;
        }
      }
      break; // OK

    case EVP_PKEY_EC: // Elliptic Curve
      p_ec_key = EVP_PKEY_get0_EC_KEY(p_key);
      if (unlikely(NULL == p_ec_key))
        return false;

      p_ec_group = EC_KEY_get0_group(p_ec_key);
      if (unlikely(NULL == p_ec_group))
        return false;

      ec_curve_nid = EC_GROUP_get_curve_name(p_ec_group);

      switch(pgp_digest_algo) // we need md_type for our signature implementation...
      {
        case DIGEST_ALGO_SHA256:
          digest_str = "SHA2-256";
          break;
        case DIGEST_ALGO_SHA384:
          digest_str = "SHA2-384";
          break;
        case DIGEST_ALGO_SHA512:
          digest_str = "SHA2-512";
          break;
        default:
          return false; // also SHA2-224 yields false here!
      }

      switch(ec_curve_nid)
      {
        case NID_X9_62_prime256v1:
          *curve_idx = CURVE_NIST_256;
          *sig_type = SIG_TYPE_ECDSA_SECP256R1;
          *comp_len = 32;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'prime256v1' (256 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        case NID_secp384r1:
          *curve_idx = CURVE_NIST_384;
          *sig_type = SIG_TYPE_ECDSA_SECP384R1;
          *comp_len = 48;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'secp384r1' (384 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        case NID_secp521r1:
          *curve_idx = CURVE_NIST_521;
          *sig_type = SIG_TYPE_ECDSA_SECP521R1;
          *comp_len = 66;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'secp521r1' (521 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        case NID_brainpoolP256r1:
          *curve_idx = CURVE_BRAINPOOL_256;
          *sig_type = SIG_TYPE_ECDSA_BRAINPOOLP256R1;
          *comp_len = 32;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'brainpoolP256R1' (256 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        case NID_brainpoolP384r1:
          *curve_idx = CURVE_BRAINPOOL_384;
          *sig_type = SIG_TYPE_ECDSA_BRAINPOOLP384R1;
          *comp_len = 48;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'brainpoolP384R1' (384 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        case NID_brainpoolP512r1:
          *curve_idx = CURVE_BRAINPOOL_512;
          *sig_type = SIG_TYPE_ECDSA_BRAINPOOLP512R1;
          *comp_len = 64;
          if (!be_quiet)
            fprintf(stdout,"%sINFO%s: signature scheme is ECDSA, curve 'brainpoolP512R1' (512 bit), digest: %s\n", ctrlYellow, ctrlReset, digest_str);
          break;
        default:
          return false;
      }
      break;

    case EVP_PKEY_ED25519:
      *curve_idx = CURVE_ED25519;
      *sig_type = SIG_TYPE_EDDSA_25519;
      *comp_len = 32;
      if (!be_quiet)
        fprintf(stdout,"%sINFO%s: signature scheme is EdDSA, curve 'ED25519' (255 bit), digest: SHA2-512\n", ctrlYellow, ctrlReset);
      break;

    case EVP_PKEY_ED448: // as with ED25519, this is non-standard (signing a hash with pure ED448)
      *curve_idx = CURVE_ED25519;
      *sig_type = SIG_TYPE_EDDSA_448;
      *comp_len = 57; // not 56 = 448 / 8 but: 57 = ((448 / 8) + 1)
      if (!be_quiet)
        fprintf(stdout,"%sINFO%s: signature scheme is EdDSA, curve 'ED448' (448 bit), digest: SHAKE-256(64)\n", ctrlYellow, ctrlReset);
      break;
  }

  return true;
}

/**
 * @brief applet for creating a binary RAW detached signature for an opaque
 *        input file.
 *
 * This creates and stores the raw binary signature, which is for RSA just
 * one big integer (size matches RSA modulus size).
 * For ECDSA and EdDSA, this is 2 x component length, i.e. the two integers
 * R and S. THIS IS NOT THE ASN.1-STORAGE TYPE!!!
 * In ASN.1, this would be a SEQUENCE { INTEGER R, INTEGER S } and, because
 * ASN.1 integers are stored in the two's complement, an additional leading
 * zero may be added if the most significant bit of R,S is set. Also, if
 * the first octets of R,S equal 0x00 AND the most significant bit in the
 * next octet is also (0), then leading zeros are removed.
 * This is sometimes called the 'canonicalization' of integers.
 *
 * This function DOES NOT do this kind of things, R||S are just stored (e.g.
 * for a 256bit curve) as 32 bytes||32 bytes (64 bytes total).
 *
 * NEVER use this raw representation in software libraries such as OpenSSL
 * or BouncyCastle directly or the verification of a digital signature will FAIL.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onSign ( int argc, char *argv[] )
{
  int               i, rc = 1;
  char              inputfile[256];
  char              outputfile[256];
  EVP_PKEY         *p_priv_evp_key = NULL, *p_pub_evp_key = NULL;
  bool              pkcs11_init_done = false;
  uint8_t          *p_input = NULL, *p_sig = NULL;
  uint32_t          md_type, sig_type, curve_idx, comp_len, l_input, l_sig;

  if (dryrun)
  {
    fprintf(stderr,"%sERROR%s: 'dry run' not supported by this applet.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // Initialize OpenSSL

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // read private key first (if PKCS#11 mode is off)

  if (0 == pkcs11_library[0])
  {
    bool is_keypair = false;

    if (0 == private_key_file[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a private key file.\n", ctrlRed, ctrlReset);
      ossl_fini();
      return 1;
    }

    p_priv_evp_key = ossl_load_openssl_key(private_key_file, &is_keypair, NULL);

    if (NULL == p_priv_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Running in non-PKCS#11 mode requires a private key pair (PEM): %s\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }

    if (!is_keypair)
    {
      fprintf(stderr,"%sERROR%s: Running in non-PKCS#11 mode requires a private key pair (PEM), not a public key: %s\n", ctrlRed, ctrlReset, private_key_file);
      goto Exit;
    }
  }
  else
  {
    if (0 == pkcs11_label[0])
    {
      fprintf(stderr,"%sERROR%s: You have to specify a PKCS#11 label.\n", ctrlRed, ctrlReset);
      ossl_fini();
      return 1;
    }

    // initialize PKCS#11 and read public key as OpenSSL EVP_PKEY* (public) from PKCS#11 module

    if (!be_quiet)
    {
      fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot);
      if (0 != secret[0] || 0 != pkcs11_pin[0])
        fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
    }

    if (!pkcs11_init(pkcs11_library, pkcs11_slot))
    {
      fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
      goto Exit;
    }

    if (!pkcs11_login(NULL, 0))
    {
      pkcs11_fini();
      fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
      goto Exit;
    }

    pkcs11_init_done = true;

    p_pub_evp_key = pkcs11_get_ossl_public_evp_key_from_pubkey(NULL, 0, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
    if (NULL == p_pub_evp_key)
    {
      fprintf(stderr,"%sERROR%s: Unable to derive OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module (primary)\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }

  if (!deriveAlgorithmParameters(NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key,
                                 &md_type, &sig_type, &curve_idx, &comp_len))
  {
    fprintf(stderr,"%sERROR%s: Unable to derive cryptographic parameters from key.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  // work on all input files in a batch //////////////////////////////////////////////////////

  for (i = 2; i < argc; i++)
  {
    if ((0 != argv[i][0]) && (('-' == argv[i][0] && 0 == argv[i][1]) || (('-' != argv[i][0]) && (0 != argv[i][0]))))
    {
      memset(inputfile, 0, sizeof(inputfile));
      memset(outputfile, 0, sizeof(outputfile));
      strncpy(inputfile, argv[i], sizeof(inputfile) - 1);
      snprintf(outputfile, sizeof(outputfile), "%s.sig", inputfile);

      if (!be_quiet)
        fprintf(stdout,"Working on input file: %s\n", inputfile);

      p_input = read_file(inputfile, &l_input);
      if (unlikely(NULL == p_input))
      {
        fprintf(stderr,"%sERROR%s: Unable to read input file into memory: %s\n", ctrlRed, ctrlReset, inputfile);
        goto Exit;
      }

      if (!be_quiet)
        fprintf(stdout,"input file '%s' successfully read: %u byte(s)\n", inputfile, l_input);

      if (0 == pkcs11_label[0]) // use OpenSSL
      {
        if (!ossl_create_digital_signature(p_priv_evp_key, sig_type, md_type, p_input, l_input, &p_sig, &l_sig, false/*raw ECDSA signature*/, false))
        {
          fprintf(stderr,"%sERROR%s: Unable to create digital signature using OpenSSL.\n", ctrlRed, ctrlReset);
          goto Exit;
        }
      }
      else // use PKCS#11
      {
        if (!pkcs11_create_signature(pkcs11_label, sig_type, md_type, p_input, l_input, &p_sig, &l_sig, false/*raw ECDSA signature*/, false))
        {
          fprintf(stderr,"%sERROR%s: Unable to create digital signature using PKCS#11.\n", ctrlRed, ctrlReset);
          goto Exit;
        }
      }

      // if loop-back verification desired, do it

      if (do_verify)
      {
        if (!ossl_verify_digital_signature(NULL != p_priv_evp_key ? p_priv_evp_key : p_pub_evp_key, sig_type, md_type, p_input, l_input, p_sig, l_sig, false))
        {
          fprintf(stderr,"%sERROR%s: Unable to perform loopback verification of just created digital signature using OpenSSL.\n", ctrlRed, ctrlReset);
          goto Exit;
        }
      }

      if (!write_file(outputfile, p_sig, l_sig))
      {
        fprintf(stderr,"%sERROR%s: Unable to write raw digital signature to: %s\n", ctrlRed, ctrlReset, outputfile);
        goto Exit;
      }

      if (!be_quiet)
        fprintf(stdout,"%sGOOD%s: Successfully wrote detached raw signature to: %s\n", ctrlGreen, ctrlReset, outputfile);

      free(p_sig), p_sig = NULL;
      free(p_input), p_input = NULL;
    }
  }

  rc = 0;

Exit:
  if (NULL != p_sig)
    free(p_sig);
  if (NULL != p_input)
    free(p_input);
  if (NULL != p_priv_evp_key)
    EVP_PKEY_free(p_priv_evp_key);
  if (NULL != p_pub_evp_key)
    EVP_PKEY_free(p_pub_evp_key);

  if (pkcs11_init_done)
    pkcs11_fini();
  ossl_fini();

  return rc;
}

/**
 * @brief applet for verifying a binary RAW detached signature for an opaque
 *        input file.
 *
 * Verifies digital signatures (RAW, binary) created by some other software
 * or with the "sign" applet. Verification is always performed in software
 * using OpenSSL.
 *
 * If the required public key is not available (for any resasons) using the
 * PKCS#11 module for private key storage, then you may specify all PKCS#11
 * input data (at least: library and key label) and this tool extracts /
 * recovers the OpenSSL EVP_PKEY* from the PKCS#11 module - also in this case,
 * no verification is performed IN the PKCS#11 module because verifications
 * are always operations using the public, not the private key.
 *
 * @param [in] argc       total number of arguments
 * @param [in] argv       arguments, some of them may have been removed
 *                        (eaten) by the main function, though.
 *
 * @return program exit code (0 = OK, 1 on error)
 */
static int onVerify ( int argc, char *argv[] )
{
  int               i, rc = 1;
  bool              have_inputfile = false;
  bool              have_sigfile = false;
  bool              have_pubkeyfile = false;
  bool              pkcs11_init_done = false;
  char              inputfile[256];
  char              sigfile[256];
  char              pubkeyfile[256];
  bool              inp_is_keypair;
  EVP_PKEY         *p_evp_key = NULL;
  x509parsed_ptr    p_input_x509 = NULL;
  uint32_t          md_type, sig_type, curve_idx, comp_len, l_input, l_sig;
  uint8_t          *p_input = NULL, *p_sig = NULL;

  if (dryrun)
  {
    fprintf(stderr,"%sERROR%s: 'dry run' not supported by this applet.\n", ctrlRed, ctrlReset);
    return 1;
  }

  memset(inputfile, 0, sizeof(inputfile));
  memset(sigfile, 0, sizeof(sigfile));
  memset(pubkeyfile, 0, sizeof(pubkeyfile));

  for (i = 2; i < argc; i++)
  {
    if ((0 != argv[i][0]) && (('-' == argv[i][0] && 0 == argv[i][1]) || (('-' != argv[i][0]) && (0 != argv[i][0]))))
    {
      if (!have_inputfile)
      {
        strncpy(inputfile, argv[i], sizeof(inputfile) - 1);
        have_inputfile = true;
      }
      else
      if (!have_sigfile)
      {
        strncpy(sigfile, argv[i], sizeof(sigfile) - 1);
        have_sigfile = true;
      }
      else
      if (!have_pubkeyfile)
      {
        strncpy(pubkeyfile, argv[i], sizeof(pubkeyfile) - 1);
        have_pubkeyfile = true;
      }
    }
  }

  if (0 == inputfile[0] || 0 == sigfile[0])
  {
    fprintf(stderr,"%sERROR%s: please specify input and signature file.\n", ctrlRed, ctrlReset);
    return 1;
  }

  // Initialize OpenSSL

  if (!ossl_init())
  {
    fprintf(stderr,"%sERROR%s: Unable to initialize OpenSSL.\n", ctrlRed, ctrlReset);
    return 1;
  }

  if (0 == pubkeyfile[0])
  {
    if (0 != pkcs11_label[0])
    {
      if (0 == pkcs11_library[0])
      {
        fprintf(stderr,"%sERROR%s: PKCS#11 library missing.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      // initialize PKCS#11 and read public key as OpenSSL EVP_PKEY* (public) from PKCS#11 module

      if (!be_quiet)
      {
        fprintf(stdout,"PKCS#11 mode, library = '%s', slot = %u\n", pkcs11_library, pkcs11_slot);
        if (0 != secret[0] || 0 != pkcs11_pin[0])
          fprintf(stdout,"PKCS#11 PIN will NOT be acquired but taken from environment.\n");
      }

      if (!pkcs11_init(pkcs11_library, pkcs11_slot))
      {
        fprintf(stderr,"%sERROR%s: Unable to initialize PKCS#11 library: %s\n", ctrlRed, ctrlReset, pkcs11_library);
        goto Exit;
      }

      if (!pkcs11_login(NULL, 0))
      {
        pkcs11_fini();
        fprintf(stderr,"%sERROR%s: Unable to perform PKCS#11 login.\n", ctrlRed, ctrlReset);
        goto Exit;
      }

      pkcs11_init_done = true;

      p_evp_key = pkcs11_get_ossl_public_evp_key_from_pubkey(NULL, 0, (const uint8_t*)pkcs11_label, (uint32_t)strlen(pkcs11_label));
      if (NULL == p_evp_key)
      {
        fprintf(stderr,"%sERROR%s: Unable to derive OpenSSL EVP_PKEY* from PKCS#11 public key in PKCS#11 module (primary), label: %s\n", ctrlRed, ctrlReset, pkcs11_label);
        goto Exit;
      }
    }
    else
    {
      fprintf(stderr,"%sERROR%s: public key file or X.509v3 certificate for signature verification is missing.\n", ctrlRed, ctrlReset);
      goto Exit;
    }
  }
  else
  {
    // read public key or X.509v3 file

    p_evp_key = ossl_load_openssl_key(pubkeyfile, &inp_is_keypair, NULL);
    if (NULL == p_evp_key)
    {
      uint32_t l_x509;
      uint8_t *p_x509 = read_file(pubkeyfile, &l_x509);

      p_input_x509 = ossl_parse_x509(p_x509, l_x509, true);
      free(p_x509);
      if (NULL == p_input_x509)
      {
        fprintf(stderr,"%sERROR%s: pubkey file '%s' is neither a public/private key nor an X.509v3 certificate (only PEM format supported).\n", ctrlRed, ctrlReset, pubkeyfile);
        goto Exit;
      }
    }
  }

  if (!deriveAlgorithmParameters(NULL != p_evp_key ? p_evp_key : p_input_x509->p_pubkey,
                                 &md_type, &sig_type, &curve_idx, &comp_len))
  {
    fprintf(stderr,"%sERROR%s: Unable to derive cryptographic parameters from public key or X.509v3, respectively.\n", ctrlRed, ctrlReset);
    goto Exit;
  }

  p_input = read_file(inputfile, &l_input);
  if (unlikely(NULL == p_input))
  {
    fprintf(stderr,"%sERROR%s: Unable to read input file into memory: %s\n", ctrlRed, ctrlReset, inputfile);
    goto Exit;
  }

  if (!be_quiet)
    fprintf(stdout,"input file '%s' successfully read: %u byte(s)\n", inputfile, l_input);

  p_sig = read_file(sigfile, &l_sig);
  if (unlikely(NULL == p_input))
  {
    fprintf(stderr,"%sERROR%s: Unable to read detached binary signature from file into memory: %s\n", ctrlRed, ctrlReset, sigfile);
    goto Exit;
  }

  if (ossl_verify_digital_signature(NULL != p_evp_key ? p_evp_key : p_input_x509->p_pubkey, sig_type, md_type, p_input, l_input, p_sig, l_sig, false))
  {
    if (!be_quiet)
      fprintf(stdout,"%sGOOD%s: Successfully verified the detached signature for %s\n", ctrlGreen, ctrlReset, inputfile);
    rc = 0;
  }
  else
  {
    if (!be_quiet)
      fprintf(stdout,"%sFAIL%s: FAILED to verify the detached signature for %s\n", ctrlRed, ctrlReset, inputfile);
  }

Exit:

  if (NULL != p_sig)
    free(p_sig);
  if (NULL != p_input)
    free(p_input);
  if (NULL != p_evp_key)
    EVP_PKEY_free(p_evp_key);
  if (NULL != p_input_x509)
    ossl_free_x509(p_input_x509);

  if (pkcs11_init_done)
    pkcs11_fini();
  ossl_fini();

  return rc;
}

/**
 * @brief the application's main function
 *
 * Parses all globally available command line arguments, removing them
 * from the argv array. Subsequently, calls one of the applets.
 *
 * Implements the help page and provides more help if an applet name
 * is specified together with the -h or --help, respectively.
 *
 * @param [in] argc       number of arguments
 * @param [in] argv       arguments, argv[0] is the process name
 *
 * @return program exit code (0 = OK, 1 on error)
 */
int main ( int argc, char *argv[] )
{
  int                 i, rc = 1;
  char               *p;
  bool                show_version = false, show_help = false;

  memset(pkcs11_library, 0, sizeof(pkcs11_library));
  memset(secret, 0, sizeof(secret));
  memset(serial, 0, sizeof(serial));
  memset(user_name, 0, sizeof(user_name));
  memset(email_addr, 0, sizeof(email_addr));
  memset(pkcs11_label, 0, sizeof(pkcs11_label));
  memset(pkcs11_label_cert, 0, sizeof(pkcs11_label_cert));
  memset(pkcs11_pin, 0, sizeof(pkcs11_pin));
  memset(pgp_secret, 0, sizeof(pgp_secret));
  memset(input_filename, 0, sizeof(input_filename));
  memset(output_filename, 0, sizeof(output_filename));
  memset(private_key_file, 0, sizeof(private_key_file));
  memset(public_key_file, 0, sizeof(public_key_file));
  memset(private_key_cert_file, 0, sizeof(private_key_cert_file));
  memset(public_key_cert_file, 0, sizeof(public_key_cert_file));
  memset(email_addr_cert, 0, sizeof(email_addr_cert));

  // get all kinds of environment variables

  p = getenv("PKCS11_LIBRARY");
  if ((NULL != p) && (0 != p[0]))
    strncpy(pkcs11_library, p, sizeof(pkcs11_library) - 1);
  p = getenv("PKCS11_SLOT");
  if ((NULL != p) && (0 != p[0]))
    pkcs11_slot = (uint32_t)strtoul(p, NULL, 10);
  p = getenv("PKCS11_LABEL");
  if ((NULL != p) && (0 != p[0]))
    strncpy(pkcs11_label, p, sizeof(pkcs11_label) - 1);
  p = getenv("PKCS11_LABEL_CERT");
  if ((NULL != p) && (0 != p[0]))
    strncpy(pkcs11_label_cert, p, sizeof(pkcs11_label_cert) - 1);
  p = getenv("SECRET");
  if (NULL != p)
  {
    secret_set = true;
    if (('"' == p[0] && '"' == p[1]) || ('\'' == p[0] && '\'' == p[1]))
    {
    }
    else
    if (0 != p[0])
    {
      strncpy(secret, p, sizeof(secret) - 1);
    }
  }
  p = getenv("PKCS11_PIN");
  if ((NULL != p) && (0 != p[0]))
    strncpy(pkcs11_pin, p, sizeof(pkcs11_pin) - 1);
  p = getenv("PGP_SECRET");
  if (NULL != p)
  {
    if (('"' == p[0] && '"' == p[1]) || ('\'' == p[0] && '\'' == p[1]))
    {
    }
    else
    if (0 != p[0])
    {
      strncpy(pgp_secret, p, sizeof(pgp_secret) - 1);
    }
  }

  // check a lot of generic options now:

  for (i=1;i<argc;i++)
  {
    if (!strcmp(argv[i],"--colored"))
    {
      colored_output = true;
      init_colored_console(false);
      argv[i] = "";
    }
  }

  for (i=1;i<argc;i++)
  {
    if ((!strcmp(argv[i],"--quiet")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'q')))
    {
      be_quiet = true;
      argv[i] = "";
    }
    else
    if ((!strcmp(argv[i],"--version")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'v')))
    {
      show_version = true;
      argv[i] = "";
    }
    else
    if ((!strcmp(argv[i],"--help")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'h')))
    {
      show_help = true;
      argv[i] = "";
    }
    else
    if ((!strcmp(argv[i],"--dryrun")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'d')))
    {
      dryrun = true;
      argv[i] = "";
    }
    else
    if ((!strcmp(argv[i],"--out")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'o')))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: output file name missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(output_filename, argv[i], sizeof(output_filename) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if ((!strcmp(argv[i],"--in")) || ('-' == argv[i][0] && '-' != argv[i][1] && strchr(argv[i],'i')))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: Input file name missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(input_filename, argv[i], sizeof(input_filename) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--p11lib"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: PKCS#11 library name missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(pkcs11_library, 0, sizeof(pkcs11_library));
      strncpy(pkcs11_library, argv[i], sizeof(pkcs11_library) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--p11slot"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: PKCS#11 slot number missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      pkcs11_slot = (uint32_t)strtoul(argv[i],NULL,10);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--serial"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: serial number missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(serial, argv[i], sizeof(serial) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--pkonly"))
    {
      convert_pubkey_only = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--user"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: user name missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(user_name, 0, sizeof(user_name));
      strncpy(user_name, argv[i], sizeof(user_name) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--email"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: E-mail address missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(email_addr, 0, sizeof(email_addr));
      strncpy(email_addr, argv[i], sizeof(email_addr) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--p11label"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: PKCS#11 label missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(pkcs11_label, 0, sizeof(pkcs11_label));
      strncpy(pkcs11_label, argv[i], sizeof(pkcs11_label) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--p11labelcert"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: PKCS#11 label (cert) missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(pkcs11_label_cert, 0, sizeof(pkcs11_label_cert));
      strncpy(pkcs11_label_cert, argv[i], sizeof(pkcs11_label_cert) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--prv"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: private key file missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(private_key_file, argv[i], sizeof(private_key_file) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--pub"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: public key file / X.509v3 file missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(public_key_file, argv[i], sizeof(public_key_file) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }

    else
    if (!strcmp(argv[i], "--prvcert"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: private key file (for certification) missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(private_key_cert_file, argv[i], sizeof(private_key_cert_file) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--pubcert"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: public key file / X.509v3 file (for certification) missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      strncpy(public_key_cert_file, argv[i], sizeof(public_key_cert_file) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--emailcert"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: E-mail address (certification) missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      memset(email_addr_cert, 0, sizeof(email_addr_cert));
      strncpy(email_addr_cert, argv[i], sizeof(email_addr_cert) - 1);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--expiry"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: expiry days missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      expiry_days = (uint32_t)strtoul(argv[i],NULL,10);
      expiry_days_set = true;
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--keyts"))
    {
      uint64_t systime = 0;
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: key creation timestamp missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }

      // can be YYYY-MM-DD-HH-MM-SS or <decimal seconds since 1970> or 0x<hexadecimal seconds since 1970>

      if ((IS_DDIGIT(argv[i][0])) && (IS_DDIGIT(argv[i][1])) &&
          (IS_DDIGIT(argv[i][2])) && (IS_DDIGIT(argv[i][3])) &&
          ('-' == argv[i][4]) &&
          (IS_DDIGIT(argv[i][5])) && (IS_DDIGIT(argv[i][6])) &&
          ('-' == argv[i][7]) &&
          (IS_DDIGIT(argv[i][8])) && (IS_DDIGIT(argv[i][9])) &&
          ('-' == argv[i][10]) &&
          (IS_DDIGIT(argv[i][11])) && (IS_DDIGIT(argv[i][12])) &&
          ('-' == argv[i][13]) &&
          (IS_DDIGIT(argv[i][14])) && (IS_DDIGIT(argv[i][15])) &&
          ('-' == argv[i][16]) &&
          (IS_DDIGIT(argv[i][17])) && (IS_DDIGIT(argv[i][18])))
      {
        uint32_t  year, month, mday, hour, minute, second;

        year   = (uint32_t)strtoul(&argv[i][0], NULL, 10);
        month  = (uint32_t)strtoul(&argv[i][5], NULL, 10);
        mday   = (uint32_t)strtoul(&argv[i][8], NULL, 10);
        hour   = (uint32_t)strtoul(&argv[i][11], NULL, 10);
        minute = (uint32_t)strtoul(&argv[i][14], NULL, 10);
        second = (uint32_t)strtoul(&argv[i][17], NULL, 10);

        if (!time_date2systime(&systime, year, month, mday, hour, minute, second))
        {
          fprintf(stderr,"%sERROR%s: unable to convert key creation timestamp to seconds: %s\n", ctrlRed, ctrlReset, argv[i]);
          goto Return;
        }
      }
      else
        systime = (uint64_t)strtoul(argv[i], NULL, 0);

      if (systime > 0xFFFFFFFF)
      {
        fprintf(stderr,"%sERROR%s: key creation timestamp exceeds maximum 32bit range (beyond 2106-02-07 06:28:15 = 0xffffffff).\n", ctrlRed, ctrlReset);
        goto Return;
      }

      key_creation_ts = (time_t)systime;
    }
    else
    if (!strcmp(argv[i], "--digest"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: digest missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      if (!strcasecmp(argv[i],"sha224"))
      {
        md_type = MD_TYPE_SHA2_224;
        pgp_digest_algo = DIGEST_ALGO_SHA224;
      }
      else
      if (!strcasecmp(argv[i],"sha256"))
      {
        md_type = MD_TYPE_SHA2_256;
        pgp_digest_algo = DIGEST_ALGO_SHA256;
      }
      else
      if (!strcasecmp(argv[i],"sha384"))
      {
        md_type = MD_TYPE_SHA2_384;
        pgp_digest_algo = DIGEST_ALGO_SHA384;
      }
      else
      if (!strcasecmp(argv[i],"sha512"))
      {
        md_type = MD_TYPE_SHA2_512;
        pgp_digest_algo = DIGEST_ALGO_SHA512;
      }
      else
      {
        fprintf(stderr,"%sERROR%s: digest '%s' unsupported.\n", ctrlRed, ctrlReset, argv[i]);
        goto Return;
      }
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i], "--rsaexp"))
    {
      i++;
      if (argc==i)
      {
        fprintf(stderr,"%sERROR%s: RSA exponent missing.\n", ctrlRed, ctrlReset);
        goto Return;
      }
      rsa_pubexp = (uint64_t)strtoul(argv[i],NULL,0);
      argv[i-1] = "";
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--iknowwhatiamdoing"))
    {
      force = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--pgp-new-packet-format"))
    {
      pgp_new_packet_format = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--use-pss"))
    {
      use_rsa_pss = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--use-edph"))
    {
      use_ed_ph = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--do-verify"))
    {
      do_verify = true;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--new-edwards")) // currently DOES NOT work!!!
    {
      edwards_legacy = false;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--enc-aescfb")) // currently DOES NOT work!!!
    {
      gpg_enc_algo = SECRET_KEY_ENCR_AES_CFB128;
      argv[i] = "";
    }
    else
    if (!strcmp(argv[i],"--enc-aesgcm")) // currently NOT TESTABLE because no GnuPG available that fully implements RFC 9580
    {
      gpg_enc_algo = SECRET_KEY_ENCR_AES_GCM;
      argv[i] = "";
    }
  }

  if (!be_quiet)
    fprintf(stdout,"x509-to-pgp v%u.%u - Copyright 2025 Ingo A. Kubbilun (ingo.kubbilun@gmail.com)\n", VERSION_MAJOR, VERSION_MINOR);

  if (show_version)
    fprintf(stdout,"  build date: %s %s\n", __DATE__, __TIME__);

  if (show_help || 1 == argc)
  {
    fprintf(stdout,"\nusage: %s <command> [<option>...]\n", argv[0]);
    fprintf(stdout,"------\n\n");

    fprintf(stdout,"  Available commands:\n\n");
    fprintf(stdout,"  genkeypair      generate key pair either in software or using PKCS#11\n");
    fprintf(stdout,"  patchx509       takes an X.509v3 certificate, patches a public key\n");
    fprintf(stdout,"                  into the certificate, re-computes self-signature\n");
    fprintf(stdout,"                  (First issue fake certificate with software key, then\n");
    fprintf(stdout,"                   use this applet to convert it into PKCS#11-enabled)\n");
    fprintf(stdout,"  pgpimport       imports a public/private key providing a binary\n");
    fprintf(stdout,"                  PGP file, which can be used for subsequent import\n");
    fprintf(stdout,"  pgpsign         creates one or more detached, binary PGP signature(s)\n");
    fprintf(stdout,"  sign            OpenSSL/PKCS#11 sign data (one or more files); raw\n");
    fprintf(stdout,"                  binary signatures\n");
    fprintf(stdout,"  verify          OpenSSL verify data (only in software)\n");
    fprintf(stdout,"  deletepkcs11key delete PKCS#11 key by label\n\n");

    fprintf(stdout,"  Available options:\n\n");
    fprintf(stdout,"  -q | --quiet            be quiet\n");
    fprintf(stdout,"  -v | --version          display version and build date, then exit\n");
    fprintf(stdout,"  -h | --help             display this help, then exit\n");
    fprintf(stdout,"                          specify -h with a command to get help for it\n");
    fprintf(stdout,"  -o | --out <file>       specify output file\n");
    fprintf(stdout,"  -i | --in <file>        specify input file (only for patchx509) \n");
    fprintf(stdout,"  -d | --dryrun           do nothing, output what would be done, then exit\n\n");
    fprintf(stdout,"  DO USE THE GREAT DRYRUN FEATURE TO CHECK TOOL PARAMETERS!\n\n");
    fprintf(stdout,"  --p11lib <lib>          use PKCS#11 library, alternatively define\n");
    fprintf(stdout,"                          env. variable PKCS11_LIBRARY\n");
    fprintf(stdout,"  --p11label <label>      explicitly specify PKCS#11 label or via PKCS11_LABEL\n");
    fprintf(stdout,"  --p11labelcert <label>  explicitly specify PKCS#11 label for certification\n");
    fprintf(stdout,"  --p11slot <slot>        define PKCS#11 slot, alternatively define\n");
    fprintf(stdout,"                          env. variable PKCS11_SLOT; default: 0\n");
    fprintf(stdout,"                          env. variable SECRET may be defined as\n");
    fprintf(stdout,"                          a password or the PKCS#11 user PIN\n\n");
    fprintf(stdout,"  --pkonly                only for pgpimport: convert public key only;\n");
    fprintf(stdout,"                          no matter what input is specified\n");
    fprintf(stdout,"  --prv <file>            specify private key file\n");
    fprintf(stdout,"  --pub <file>            specify public key file or X.509v3 certificate (PEM)\n");
    fprintf(stdout,"  --prvcert <file>        specify private key file for certification\n");
    fprintf(stdout,"  --pubcert <file>        specify public key file or X.509v3 certificate (PEM)\n");
    fprintf(stdout,"                          for certification\n");
    fprintf(stdout,"  --user <name>           specify user name (if not part of X.509v3)\n");
    fprintf(stdout,"  --email <E-mail addr>   specify E-mail address (if not part of X.509v3)\n");
    fprintf(stdout,"  --emailcert <E-mail>    E-mail address of issuer (certification)\n");
    fprintf(stdout,"  --expiry <days>         number of expiry days;\n");
    fprintf(stdout,"                          YOU HAVE TO specify <days>=0 if you do not want\n");
    fprintf(stdout,"                          a key expiry also in the X.509v3 public key case!\n");
    fprintf(stdout,"  --digest <digest>       SHA-256 is default; <digest> can be (case-insensitive)\n");
    fprintf(stdout,"                          sha224, sha256, sha384 or sha512 (all from SHA-2)\n");
    fprintf(stdout,"  --rsaexp <number>       specify RSA public exponent, defaults to 65.537\n");
    fprintf(stdout,"  --keyts <timestamp>     key creation timestamp either as YYYY-MM-DD-HH-MM-SS\n");
    fprintf(stdout,"                          or as number of seconds since 1970-01-01 (decimal or\n");
    fprintf(stdout,"                          hexadecimal)\n");
    fprintf(stdout,"  --serial <number>       only for patchx509: use this serial no.\n");
    fprintf(stdout,"  --iknowwhatiamdoing     only for deletion of PKCS#11 keys: force mode, do not ask\n");
    fprintf(stdout,"  --pgp-new-packet-format use PGP new packet format (default: old format)\n");
    fprintf(stdout,"  --use-pss               use RSA PSS instead of PKCS#1 v1.5\n");
    fprintf(stdout,"  --use-edph              use pre-hashed versions of Edwards Curve algorithm (rarely used)\n");
    fprintf(stdout,"  --new-edwards           for PGP, use new ED25519/448 algorithm scheme\n");
    fprintf(stdout,"  --do-verify             verify digital signature in software after having\n");
    fprintf(stdout,"                          computed it.\n");
    fprintf(stdout,"  --enc-aescfb            use AES/256bit in CFB128 mode for PGP secret key enc.\n");
    fprintf(stdout,"  --enc-aesgcm            use AES/256bit in Galois Counter Mode for PGP secret key enc.\n");
    fprintf(stdout,"                          (EXPERIMENTAL, not yet tested)\n");
    fprintf(stdout,"  --colored               enable colored console output\n\n");

    if (argc > 1)
    {
      if (!strcmp(argv[1], "genkeypair"))
      {
        fprintf(stdout,"help for command 'genkeypair':\n");
        fprintf(stdout,"------------------------------\n\n");
        fprintf(stdout,"  genkeypair <type>\n");
        fprintf(stdout,"  <type> is one of rsa2048, rsa3072, rsa4096, ecnist256, ecnist384\n");
        fprintf(stdout,"         ecnist521, ecbpool256, ecbpool384, ecbpool512, ed25519 or ed448\n");
        fprintf(stdout,"  <output> is output file name without extension. '.pub.pem' is added\n");
        fprintf(stdout,"           for the public key, '.prv.pem' for the private key.\n");
        fprintf(stdout,"           If PKCS11 is used, no private key is created.\n\n");
        fprintf(stdout,"           A private key encryption password is queried on the\n");
        fprintf(stdout,"           console or taken from SECRET env. variable.\n\n");
        fprintf(stdout,"           Declare either empty SECRET variable or press <ENTER>\n");
        fprintf(stdout,"           to store the private key file in plain text.\n\n");
        fprintf(stdout,"  Hint: PKCS#11 key pairs are generated using the current time as\n");
        fprintf(stdout,"  ----- their PKCS#11 key ID. This key ID is automatically fetched\n");
        fprintf(stdout,"        from the PKCS#11 module when a digital signature is computed.\n");
        fprintf(stdout,"        It is necessary to create the PGP key fingerprint.\n");
        fprintf(stdout,"        For soft keys (OpenSSL), you have to record the printed key\n");
        fprintf(stdout,"        creation timestamp, which has to be specified if this tool\n");
        fprintf(stdout,"        is used to generate a PGP signature (you could also use e.g. gpg\n");
        fprintf(stdout,"        instead (with soft keys).\n");
        fprintf(stdout,"        If a private (OpenSSL) key file is specified, then the tool\n");
        fprintf(stdout,"        checks the first eight characters for hexadecimal digits and\n");
        fprintf(stdout,"        automatically uses this information as the creation ts.\n\n");
      }
      else
      if (!strcmp(argv[1], "patchx509"))
      {
        fprintf(stdout,"help for command 'patchx509':\n");
        fprintf(stdout,"-----------------------------\n\n");
        fprintf(stdout,"  patchx509 -i <input X.509> --pub <input> -o <output> --prv <private key>\n");
        fprintf(stdout,"            [--pubcert <file> --prvcert <file>]\n");
        fprintf(stdout,"            Alternatively, specify PKCS#11 label for private\n");
        fprintf(stdout,"            key file(s).\n");
        fprintf(stdout,"            If --pubcert/--prvcert missing, then self issuance.\n");
        fprintf(stdout,"            Use --expiry to patch validity period.\n\n");
      }
      else
      if (!strcmp(argv[1], "pgpimport"))
      {
        fprintf(stdout,"help for command 'pgpimport':\n");
        fprintf(stdout,"-----------------------------\n\n");
        fprintf(stdout,"  pgpimport create binary PGP packet structure suitable for importing\n");
        fprintf(stdout,"            a public key or a full key pair into a PGP keyring.\n");
        fprintf(stdout,"            Use the switches --p11lib, --p11label, --p11labelcert,\n");
        fprintf(stdout,"            --pkonly, --out, --prv, --pub, --prvcert, and --pubcert\n");
        fprintf(stdout,"            The user ID (name) and E-mail address have to be specified\n");
        fprintf(stdout,"            using --user and --email or --useriss and --emailiss, respectively.\n");
        fprintf(stdout,"            If X.509v3 are specified as public keys, then the two information\n");
        fprintf(stdout,"            items user ID and E-mail may be extracted from there.\n");
        fprintf(stdout,"            Use --expiry to define a PGP key expiration. If the input contains\n");
        fprintf(stdout,"            an X.509v3 certificate, then notBefore and notAfter are used for PGP.\n");
        fprintf(stdout,"            In this case, if you do not want to have a PGP key expiry, specify\n");
        fprintf(stdout,"            '--expiry 0' EXPLICITLY.\n\n");
      }
      else
      if (!strcmp(argv[1], "pgpsign"))
      {
        fprintf(stdout,"help for command 'pgpsign':\n");
        fprintf(stdout,"---------------------------\n\n");
        fprintf(stdout,"  pgpsign <private key file or PKCS#11 label: --prv or P11 label>\n");
        fprintf(stdout,"          <input file> [<input file>...]\n");
        fprintf(stdout,"          Private key file or PKCS#11 label required for\n");
        fprintf(stdout,"          digital signature.\n");
        fprintf(stdout,"          The 32bit (decimal/hexadecimal with 0x prefix)\n");
        fprintf(stdout,"          key creation timestamp (seconds from 1970-01-01)\n");
        fprintf(stdout,"          is required to compute the key fingerprint.\n");
        fprintf(stdout,"          One or more <input file> has/have to be specified.\n");
        fprintf(stdout,"          The detached digital signatures are stored as\n");
        fprintf(stdout,"          '<input file>.sig'.\n");
        fprintf(stdout,"          PGP signature version is 4. Version 5 is solely\n");
        fprintf(stdout,"          used for ED448 signatures.\n\n");
      }
      else
      if (!strcmp(argv[1], "sign"))
      {
        fprintf(stdout,"help for command 'sign':\n");
        fprintf(stdout,"------------------------\n\n");
        fprintf(stdout,"  sign <private key file or PKCS#11 label: --prv or P11 label>\n");
        fprintf(stdout,"       <input file> [<input file>...]\n");
        fprintf(stdout,"       Private key file or PKCS#11 label required for\n");
        fprintf(stdout,"       digital signature.\n");
        fprintf(stdout,"       <input file> contains data to be signed - \n");
        fprintf(stdout,"       The raw, detached digital signature is stored as\n");
        fprintf(stdout,"       '<input file>.sig'.\n");
        fprintf(stdout,"       For RSA, the raw signature bytes (number equals the\n");
        fprintf(stdout,"       RSA key size) are stored. For ECDSA/EdDSA, R||S\n");
        fprintf(stdout,"       are stored as raw bytes, i.e. the total size is twice\n");
        fprintf(stdout,"       the curve bit size / 8.\n");
        fprintf(stdout,"       Exception: ED448 signatures store 57 instead of 56\n");
        fprintf(stdout,"       ---------- bytes per R, S (total: 114 bytes).\n\n");
      }
      else
      if (!strcmp(argv[1], "verify"))
      {
        fprintf(stdout,"help for command 'verify':\n");
        fprintf(stdout,"--------------------------\n\n");
        fprintf(stdout,"  verify <input file> <signature file> <--pub public key file\n");
        fprintf(stdout,"        or X.509v3 certificate>\n");
        fprintf(stdout,"        <input file> contains data used to create signature\n");
        fprintf(stdout,"        <signature file> is detached binary signature\n");
        fprintf(stdout,"        Public key file or X.509v3 certificate required for\n");
        fprintf(stdout,"        digital signature verification.\n\n");
      }
    }
    goto Return;
  }

  // Check, which command has to be executed...

  if (!strcmp(argv[1], "genkeypair"))
  {
    rc = onGenKeyPair(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "patchx509"))
  {
    rc = onPatchX509(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "pgpimport"))
  {
    rc = onPGPImport(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "pgpsign"))
  {
    rc = onPGPSign(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "sign"))
  {
    rc = onSign(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "verify"))
  {
    rc = onVerify(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "deletepkcs11key"))
  {
    rc = OnDeletePKCS11Key(argc,argv);
    goto Return;
  }

  if (!strcmp(argv[1], "testsuite"))
  {
    rc = run_tests();
    goto Return;
  }

  if (!show_version && !show_help)
  {
    fprintf(stderr,"%sERROR%s: command '%s' unknown.\n", ctrlRed, ctrlReset, argv[1]);
    fprintf(stdout,"Please execute with -h|--help to display help.\n");
    fprintf(stdout,"Alternatively, execute with <applet> -h to display help for this command.\n");
  }
  else
    rc = 0;

Return:

  fini_colored_console();

  return rc;
}
