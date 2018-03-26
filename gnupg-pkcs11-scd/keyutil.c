/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#if defined(ENABLE_GNUTLS)
#include <gnutls/x509.h>
#endif
#if defined(ENABLE_OPENSSL)
#include <openssl/x509.h>
#include <openssl/gost.h>
#endif
#include "encoding.h"
#include "keyutil.h"

#if defined(ENABLE_OPENSSL)
#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *my_openssl_d2i_t;
#else
typedef const unsigned char *my_openssl_d2i_t;
#endif
#endif

gpg_err_code_t
keyutil_get_cert_params (
	unsigned char *der,
	size_t len,
	cert_params_t *params
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
#if defined(ENABLE_GNUTLS)
	gnutls_x509_crt_t cert = NULL;
	gnutls_datum_t datum = {der, len};
	gnutls_datum_t m = {NULL, 0}, e = {NULL, 0};
#elif defined(ENABLE_OPENSSL)
	X509 *x509 = NULL;
	EVP_PKEY *pubkey = NULL;
	char *a_hex = NULL, *b_hex = NULL;
#endif

	keyutil_params_cleanup (params);

#if defined(ENABLE_GNUTLS)
	if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS) {
		cert = NULL;
		error = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	if (gnutls_x509_crt_get_pk_rsa_raw (cert, &m, &e) != GNUTLS_E_SUCCESS) {
		error = GPG_ERR_BAD_KEY;
		m.data = NULL;
		e.data = NULL;
		goto cleanup;
	}

	params->key_type = KEY_RSA;

	if (
		gcry_mpi_scan(&params->a, GCRYMPI_FMT_USG, m.data, m.size, NULL) ||
		gcry_mpi_scan(&params->b, GCRYMPI_FMT_USG, e.data, e.size, NULL)
	) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
#elif defined(ENABLE_OPENSSL)
	if (!d2i_X509 (&x509, (my_openssl_d2i_t *)&der, len)) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}
 
	if ((pubkey = X509_get_pubkey (x509)) == NULL) {
		error = GPG_ERR_BAD_CERT;
		goto cleanup;
	}

	switch (pubkey->type) {
	case EVP_PKEY_RSA:
		params->key_type = KEY_RSA;
		a_hex = BN_bn2hex (pubkey->pkey.rsa->n);
		b_hex = BN_bn2hex (pubkey->pkey.rsa->e);
		break;
	case EVP_PKEY_GOSTR01:
		params->key_type = KEY_GOSTR01;
		const EC_GROUP *group = GOST_KEY_get0_group(pubkey->pkey.gost);
		const EC_POINT *pub_key = GOST_KEY_get0_public_key(pubkey->pkey.gost);
		BIGNUM *X = BN_new(), *Y = BN_new();
		params->nid = EC_GROUP_get_curve_name(group);
		int ret = EC_POINT_get_affine_coordinates_GFp(group,
													  pub_key, X, Y, NULL);
		if (ret) {
			a_hex = BN_bn2hex (X);
			b_hex = BN_bn2hex (Y);
		}
		BN_free(X); BN_free(Y);
		if (!ret) {
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
		}
	default:
		error = GPG_ERR_WRONG_PUBKEY_ALGO;
		goto cleanup;
	}

	if (a_hex == NULL || b_hex == NULL) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
 
	if (
		gcry_mpi_scan (&params->a, GCRYMPI_FMT_HEX, a_hex, 0, NULL) ||
		gcry_mpi_scan (&params->b, GCRYMPI_FMT_HEX, b_hex, 0, NULL)
	) {
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
#else
#error Invalid configuration.
#endif

	error = GPG_ERR_NO_ERROR;

cleanup:
	
	keyutil_params_cleanup (params);

#if defined(ENABLE_GNUTLS)

	if (m.data != NULL) {
		gnutls_free (m.data);
		m.data = NULL;
	}

	if (e.data != NULL) {
		gnutls_free (e.data);
		e.data = NULL;
	}

	if (cert != NULL) {
		gnutls_x509_crt_deinit (cert);
		cert = NULL;
	}

#elif defined(ENABLE_OPENSSL)

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	if (pubkey != NULL) {
		EVP_PKEY_free(pubkey);
		pubkey = NULL;
	}

	if (a_hex != NULL) {
		OPENSSL_free (a_hex);
		a_hex = NULL;
	}
	
	if (b_hex != NULL) {
		OPENSSL_free (b_hex);
		b_hex = NULL;
	}

#else
#error Invalid configuration.
#endif

	return error;
}

void
keyutil_params_cleanup (cert_params_t *params) {
	if (params->a) {
		gcry_mpi_release (params->a);
		params->a = NULL;
	}
	if (params->b) {
		gcry_mpi_release (params->b);
		params->b = NULL;
	}
}

/**
   Convert X.509 RSA public key into gcrypt internal sexp form. Only RSA
   public keys are accepted at the moment. The resul is stored in *sexp,
   which must be freed (using ) when not needed anymore. *sexp must be
   NULL on entry, since it is overwritten.
*/
gpg_err_code_t
keyutil_get_cert_sexp (
	unsigned char *der,
	size_t len,
	gcry_sexp_t *p_sexp
) {
	gpg_err_code_t error = GPG_ERR_GENERAL;
	cert_params_t params;
	const char *curve_name = NULL;
	gcry_sexp_t sexp = NULL;

	if (
		(error = keyutil_get_cert_params (der, len, &params))
		!= GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	switch (params.key_type) {
	case KEY_RSA:
		if (
			gcry_sexp_build (
			    &sexp,
				NULL,
				"(public-key (rsa (n %m) (e %m)))",
				params.a,
				params.b
			)
		) {
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
		}
		break;
	case KEY_GOSTR01:
		curve_name = "GOST2001-test"; //FIXME
		if (
			gcry_sexp_build (
			    &sexp,
				NULL,
				"(public-key\n"
				" (ecc\n"
				"  (curve %s)\n"
				"  (q %m%m)))\n",
				curve_name,
				params.a,
				params.b
			)
		) {
			error = GPG_ERR_BAD_KEY;
			goto cleanup;
		}
		break;
	default:
		error = GPG_ERR_BAD_KEY;
		goto cleanup;
	}
	
	*p_sexp = sexp;
	sexp = NULL;
	error = GPG_ERR_NO_ERROR;

cleanup:

	keyutil_params_cleanup (&params);

	if (sexp != NULL) {
		gcry_sexp_release (sexp);
		sexp = NULL;
	}

	return error;
}

#if 0
/**
   Calculate certid for the certificate. The certid is stored as hex-encoded,
   null-terminated string into certid which must be at least 41 bytes long.
   This is very primitive ID, just using the SHA1 of the whole certificate DER
   encoding. Currently not used.
*/
void cert_get_hexgrip(unsigned char *der, size_t len, char *certid)
{
	int ret;
	char grip[20];

	SHA1(der, len, grip);
	ret = bin2hex(hexgrip, 41, grip, 20);
	g_assert(ret == 20);
}
#endif

/** Calculate hex-encoded keygrip of public key in sexp. */
char *keyutil_get_cert_hexgrip (gcry_sexp_t sexp)
{
	char *ret = NULL;
	unsigned char grip[20];

	if (gcry_pk_get_keygrip (sexp, grip)) {
		ret = encoding_bin2hex (grip, sizeof (grip));
	}

	return ret;
}
