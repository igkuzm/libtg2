/* Two-factor authentication
 *
 * Telegram uses the Secure Remote Password protocol version 6a 
 * to implement 2FA.
 *
 * Example implementation: tdlib.
 *
 * Checking the password with SRP 
 * To login to an account protected by a 2FA password or to 
 * perform some other actions (like changing channel owner), 
 * you will need to verify the user's knowledge of the current 
 * 2FA account password.
 * To do this, first the client needs to obtain SRP parameters 
 * and the KDF algorithm to use to check the validity of the 
 * password via account.getPassword method. For now, only 
 * the passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
 * algorithm is supported, so we'll only explain that.
 *
 * Then, after the user provides a password, the client should 
 * generate an InputCheckPasswordSRP object using SRP and a 
 * specific KDF algorithm as shown below and pass it to 
 * appropriate method (e.g. auth.checkPassword in case of authorization).
 * 
 * This extension of the SRP protocol uses the password-based PBKDF2 
 * with 100000 iterations using sha512 (PBKDF2HMACSHA512iter100000).
 *  PBKDF2 is used to additionally rehash the x parameter, 
 *  obtained using a method similar to the one described in 
 *  RFC 2945 (H(s | H ( I | password | I) | s) 
 *  instead of H(s | H ( I | ":" | password)) (see below).
 *
 *  Here, | denotes concatenation and + denotes the arithmetical
 *  operator +. In all cases where concatenation of numbers 
 *  passed to hashing functions is done, the numbers must be 
 *  used in big-endian form, padded to 2048 bits; all math 
 *  is modulo p. Instead of I, salt1 will be used (see SRP protocol).
 *  Instead of s, salt2 will be used (see SRP protocol).
 *
 *  The main hashing function H is sha256:
 *  H(data) := sha256(data)
 *
 *  The salting hashing function SH is defined as follows:
 *  SH(data, salt) := H(salt | data | salt)
 *
 *  The primary password hashing function is defined as follows:
 *  PH1(password, salt1, salt2) := SH(SH(password, salt1), salt2)
 *
 *  The secondary password hashing function is defined as follows:
 *  PH2(password, salt1, salt2) := SH(pbkdf2(sha512, PH1(password, salt1, salt2), salt1, 100000), salt2) */

#include "tg.h"
#include "send_query.h"
#include <assert.h>
#include <endian.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/cryptoerr_legacy.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include <string.h>
#include "crypto/hsh.h"
#include "tg_log.h"

static buf_t tg_pbkdf2_sha512(
		tg_t *tg, buf_t password, buf_t salt, unsigned int iter)
{
	ON_LOG(tg, "%s", __func__);

	buf_t ret = buf_new();

	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *kctx = NULL;
	OSSL_PARAM params[5];

	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();

	// fetch PBKDF2 KDF algorithm
	kdf = EVP_KDF_fetch(NULL, "PBKDF2",
		 	NULL);
	if (!kdf){
		ON_ERR(tg, "Error fetching PBKDF2 KDF");
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// create kdf context
	kctx = EVP_KDF_CTX_new(kdf);
	if (!kctx){
		ON_ERR(tg, "Error creating KDF context");
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// set KDF params
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
		 	"SHA512", 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
		 	(char *)password.data, password.size);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
		 	(char *)salt.data, salt.size);
	params[3] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
	params[4] = OSSL_PARAM_construct_end();

	// derive
	if (EVP_KDF_derive(kctx, ret.data, 64, params) <= 0)
	{
		ON_ERR(tg, "Error deriving key with PBKDF2");
		ERR_print_errors_fp(stderr);
		goto end;
	}
	ret.size = 64;

end:
	// clean up
	EVP_KDF_CTX_free(kctx);
	EVP_KDF_free(kdf);
	EVP_cleanup();
	ERR_free_strings();

	return ret;
}

static buf_t tg_calc_password_hash(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2)
{
	ON_LOG(tg, "Begin password hash calculation");
	
	buf_t password_buf = buf_add((unsigned char *)password,
		 	strlen(password));

	buf_t SH = tg_hsh_sha256_free(
			buf_add_bufs(3, salt1, password_buf, salt1));
	buf_free(password_buf);

	buf_t PH1 = tg_hsh_sha256_free(
			buf_add_bufs(3, salt2, SH, salt2));
	buf_free(SH);

	buf_t PBKDF2 = tg_pbkdf2_sha512(tg,PH1, salt1, 100000);
	buf_free(PH1);
	
	buf_t PH2 = tg_hsh_sha256_free(
			buf_add_bufs(3, salt2, PBKDF2, salt2));
	buf_free(PBKDF2);

	ON_LOG(tg, "End password hash calculation");
	return PH2;
}	


static buf_t tg_calc_password_srp_hash(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2, 
		uint32_t g, buf_t p)
{
	ON_LOG(tg, "%s", __func__);
	
	buf_t hash = tg_calc_password_hash(tg, password, salt1, salt2);
	
	BIGNUM *p_bn = BN_new();
	BN_bin2bn(p.data, p.size, p_bn); 

	BIGNUM *g_bn = BN_new();
	BN_set_word(g_bn, g);
	
	BIGNUM *x_bn = BN_new();
	BN_bin2bn(hash.data, hash.size, x_bn); 

	BN_CTX *ctx = BN_CTX_new();	

	BIGNUM *v_bn = BN_new();
  assert(BN_mod_exp(v_bn, g_bn, x_bn, p_bn, ctx)); 

	buf_t result = buf_new();
	BN_bn2bin(v_bn, result.data);
	result.size = 256;
	
	return result;
}

static InputCheckPasswordSRP tg_get_inputCheckPasswordSRP(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2, 
		uint32_t g, buf_t p, buf_t B, uint64_t id)
{
	InputCheckPasswordSRP srp = buf_new();

	BIGNUM *p_bn = BN_new();
	BN_bin2bn(p.data, p.size, p_bn); 

	BIGNUM *B_bn = BN_new();
	BN_bin2bn(B.data, B.size, B_bn); 
	
	BIGNUM *zero = NULL;
	BN_dec2bn(&zero, "0");

	if (BN_cmp(zero, B_bn) != -1 ||
	    BN_cmp(B_bn, p_bn) != -1 ||
			B.size != 256)
	{
		ON_ERR(tg, "Receive invalid value of B: (%d): %s: %s", 
				B.size,
				BN_bn2dec(B_bn), BN_bn2dec(p_bn));
		return srp;
	}

	ON_LOG(tg, "Begin input password SRP hash calculation");

	BIGNUM *g_bn = BN_new();
	BN_set_word(g_bn, g);
	buf_t g_padded = buf_new();
	BN_bn2bin(g_bn, g_padded.data);
	g_padded.size = 256;

	buf_t x = tg_calc_password_hash(tg, password, salt1, salt2);
	BIGNUM *x_bn = BN_new();
	BN_bin2bn(x.data, x.size, x_bn);

	buf_t a = buf_rand(2048/8);
	BIGNUM *a_bn = BN_new();
	BN_bin2bn(a.data, a.size, a_bn);

	BN_CTX *ctx = BN_CTX_new();	

	BIGNUM *A_bn = BN_new();
  assert(BN_mod_exp(A_bn, g_bn, a_bn, p_bn, ctx)); 
	
	buf_t A = buf_new();
	BN_bn2bin(A_bn, A.data);
	A.size = 256;

	buf_t u = tg_hsh_sha256_free(buf_add_bufs(2, A, B));
	BIGNUM *u_bn = BN_new();
	BN_bin2bn(u.data, u.size, u_bn);

	buf_t k = tg_hsh_sha256_free(buf_add_bufs(2, p, g_padded));
	BIGNUM *k_bn = BN_new();
	BN_bin2bn(k.data, k.size, k_bn);

	BIGNUM *v_bn = BN_new();
  assert(BN_mod_exp(v_bn, g_bn, x_bn, p_bn, ctx)); 
	
	BIGNUM *kv_bn = BN_new();
  assert(BN_mod_exp(kv_bn, k_bn, v_bn, p_bn, ctx)); 
	
	BIGNUM *t_bn = BN_new();
  assert(BN_sub(t_bn, B_bn, kv_bn)); 
	if (BN_cmp(t_bn, zero) == -1)
		assert(BN_add(t_bn, t_bn, p_bn)); 
	
	BIGNUM *ex_bn = BN_new();
  assert(BN_mul(ex_bn, u_bn, x_bn, ctx)); 
	assert(BN_add(ex_bn, ex_bn, a_bn)); 
	
	BIGNUM *S_bn = BN_new();
  assert(BN_mod_exp(S_bn, t_bn, ex_bn, p_bn, ctx)); 
	buf_t S = buf_new();
	BN_bn2bin(S_bn, S.data);
	S.size = 256;
	buf_t K = tg_hsh_sha256(S);

	buf_t h1 = tg_hsh_sha256(p);
	buf_t h2 = tg_hsh_sha256(g_padded);

	buf_t salt1_hash = tg_hsh_sha256(salt1);
	buf_t salt2_hash = tg_hsh_sha256(salt2);

	buf_t M1 = tg_hsh_sha256_free(
			buf_add_bufs(6, h1, salt1_hash, salt2_hash, 
				A, B, K));

	buf_free(h1);
	buf_free(salt1_hash);
	buf_free(salt2_hash);

	buf_free(g_padded);
	
	ON_LOG(tg, "End input password SRP hash calculation");

	buf_free(srp);
	srp = tl_inputCheckPasswordSRP(id, &A, &M1);

	return srp;
}

int tg_2fa(tg_t *tg, const char *password){
	
	tl_t *tl = NULL; 
/* Client-side, the following parameters are extracted from 
 * the passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
 * object, contained in the account.password object. */

	// get account.password
	buf_t account_getPassword = 
		tl_account_getPassword();
	tl = tg_send_query_sync(tg, &account_getPassword, true);
	buf_free(account_getPassword);
	
	if (tl == NULL){
		ON_ERR(tg, "%s: TL is NULL", __func__);
		return 1;
	}

	if (tl->_id != id_account_password){
		ON_ERR(tg, "%s: expected: account_password, but got: %s",
			 	__func__, TL_NAME_FROM_ID(tl->_id));
		return 1;
	}
	
	tl_account_password_t *account_password = 
		(tl_account_password_t *)tl;

	tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t 
		*algo = 
		(tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t *)account_password->current_algo_;


	InputCheckPasswordSRP srp = tg_get_inputCheckPasswordSRP(
			tg, password, algo->salt1_, algo->salt2_, 
			algo->g_, algo->p_, 
			account_password->srp_B_, account_password->srp_id_);	
	if (srp.size == 0)
		return 1;

	buf_t auth_check_password = 
		tl_auth_checkPassword(&srp);
	buf_free(srp);

	tl = tg_send_query_sync(tg, &auth_check_password, true);
	buf_free(auth_check_password);

	if (!tl){
		ON_ERR(tg, "%s: TL is NULL", __func__);
		return 1;
	}

	if (tl->_id == id_rpc_error){
		tl_rpc_error_t *error  = 
			(tl_rpc_error_t *)tl;
		ON_ERR(tg, "%s: %s", __func__, error->error_message_.data);
		return 1;
	}

	if (tl->_id != id_auth_authorization){
		ON_ERR(tg, "%s: expected auth_authorization but got: %s",
				__func__, TL_NAME_FROM_ID(tl->_id));
		return 1;
	}

	printf("GOOD PASSWORD!!!!\n");

	return 0;
}
