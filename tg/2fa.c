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
 * PBKDF2 is used to additionally rehash the x parameter, 
 * obtained using a method similar to the one described in 
 * RFC 2945 (H(s | H ( I | password | I) | s) 
 * instead of H(s | H ( I | ":" | password)) (see below).
 *
 * Here, | denotes concatenation and + denotes the arithmetical
 * operator +. In all cases where concatenation of numbers 
 * passed to hashing functions is done, the numbers must be 
 * used in big-endian form, padded to 2048 bits; all math 
 * is modulo p. Instead of I, salt1 will be used (see SRP protocol).
 * Instead of s, salt2 will be used (see SRP protocol).
 *
 * The main hashing function H is sha256:
 * H(data) := sha256(data)
 *
 * The salting hashing function SH is defined as follows:
 * SH(data, salt) := H(salt | data | salt)
 *
 * The primary password hashing function is defined as follows:
 * PH1(password, salt1, salt2) := SH(SH(password, salt1), salt2)
 *
 * The secondary password hashing function is defined as follows:
 * PH2(password, salt1, salt2) := SH(pbkdf2(sha512, PH1(password, salt1, salt2), salt1, 100000), salt2) */

#include "errors.h"
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
#include <stdio.h>
#include <string.h>
#include "crypto/hsh.h"
#include "crypto/pbkdf2.h"
#include "tg_log.h"

// H(data) := sha256(data)
#define H(data) tg_hsh_sha256(data)
 
// SH(data, salt) := H(salt | data | salt)
#define SH(data, salt) \
	({buf_t _buf = buf_new(); \
	  _buf = buf_cat(_buf, salt); \
	  _buf = buf_cat(_buf, data); \
	  _buf = buf_cat(_buf, salt); \
		buf_t _ret = H(_buf); \
		buf_free(_buf); \
		_ret;})
 
// PH1(password, salt1, salt2) := SH(SH(password, salt1), salt2)
#define PH1(password, salt1, salt2) \
	({buf_t _buf = SH(password, salt1); \
		buf_t _ret = SH(_buf, salt2); \
		buf_free(_buf); \
		_ret;})
 
// PH2(password, salt1, salt2) := 
// SH(pbkdf2(sha512, PH1(password, salt1, salt2), salt1, 100000), salt2)
#define PH2(password, salt1, salt2) \
	({buf_t _psw = buf_add((unsigned char*)password,strlen(password));\
		buf_t _ph1 = PH1(_psw, salt1, salt2); \
	  buf_t _buf = tg_pbkdf2_sha512(_ph1, salt1, 100000); \
		buf_t _ret = SH(_buf, salt2); \
		buf_free(_psw); \
		buf_free(_ph1); \
		buf_free(_buf); \
		_ret;})


static buf_t BN_bn2bin_size(BIGNUM *a, int exact_size){
	assert(exact_size <= BUFSIZ);
	// int num_size = get_num_bytes();
  int num_size = BN_num_bytes(a);
  if (exact_size == -1) {
    exact_size = num_size;
  } else {
		//CHECK(exact_size >= num_size);
		assert(exact_size >= num_size);
  }
  // string res(exact_size, '\0');
	buf_t res = buf_new();
  // BN_bn2bin(impl_->big_num, MutableSlice(res).ubegin() + (exact_size - num_size));
  BN_bn2bin(a, res.data + (exact_size - num_size));
	res.size = exact_size;
  return res;
}

#define buf_concat_sha256(__b1, __b2) \
	({buf_t __b = buf_concat(__b1, __b2); \
	  buf_t __sh = tg_hsh_sha256(__b); \
		buf_free(__b); \
	  __sh; })
 
/*
static buf_t tg_calc_password_hash(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2)
{
	ON_LOG(tg, "Begin password hash calculation");
	
	buf_t password_buf = buf_add((unsigned char *)password,
		 	strlen(password));

	buf_t SH = buf_new();
	//buf_add_bufs(3, salt1, password_buf, salt1);
	SH = buf_cat(SH, salt1);
	SH = buf_cat(SH, password_buf);
	SH = buf_cat(SH, salt1);
	buf_free(password_buf);
	ON_LOG_BUF(tg, SH, "%s: SH: ", __func__);

	buf_t SH_HSH = tg_hsh_sha256(SH);
	buf_free(SH);
	ON_LOG_BUF(tg, SH_HSH, "%s: SH_HSH: ", __func__);

	//buf_t PH1 = buf_add_bufs(3, salt2, SH_HSH, salt2);
	buf_t PH1 = buf_new();
	PH1 = buf_cat(PH1, salt2);
	PH1 = buf_cat(PH1, SH_HSH);
	PH1 = buf_cat(PH1, salt2);
	buf_free(SH_HSH);
	ON_LOG_BUF(tg, PH1, "%s: PH1: ", __func__);

	buf_t PH1_HSH = tg_hsh_sha256(PH1);
	buf_free(PH1);
	ON_LOG_BUF(tg, PH1_HSH, "%s: PH1_HSH: ", __func__);

	buf_t PBKDF2 = tg_pbkdf2_sha512(
			PH1_HSH, salt1, 100000);
	buf_free(PH1_HSH);
	ON_LOG_BUF(tg, PBKDF2, "%s: PBKDF2: ", __func__);
	
	//buf_t PH2 = buf_add_bufs(3, salt2, PBKDF2, salt2);
	buf_t PH2 = buf_new();
	PH2 = buf_cat(PH2, salt2);
	PH2 = buf_cat(PH2, PBKDF2);
	PH2 = buf_cat(PH2, salt2);
	buf_free(PBKDF2);
	ON_LOG_BUF(tg, PH2, "%s: PH2: ", __func__);

	buf_t PH2_HSH = tg_hsh_sha256(PH2);
	buf_free(PH2);
	ON_LOG_BUF(tg, PH2_HSH, "%s: PH2_HSH: ", __func__);

	ON_LOG(tg, "End password hash calculation");
	return PH2_HSH;
}	
*/

static buf_t tg_calc_password_hash(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2)
{
	ON_LOG(tg, "Begin password hash calculation");
	buf_t pas = buf_add((unsigned char*)password,
		 	strlen(password));
	//BufferSlice buf(32);
  //hash_sha256(password, client_salt, buf.as_mutable_slice());
  buf_t buf1 = SH(pas, salt1);
	buf_free(pas);

  // hash_sha256(buf.as_slice(), server_salt, buf.as_mutable_slice());
	buf_t buf2 = SH(buf1, salt2);
	buf_free(buf1);

	//BufferSlice hash(64);
  //pbkdf2_sha512(buf.as_slice(), client_salt, 100000, hash.as_mutable_slice());
	buf_t buf3 = tg_pbkdf2_sha512(buf2,
		 	salt1, 100000);
	buf_free(buf2);

  //hash_sha256(hash.as_slice(), server_salt, buf.as_mutable_slice());
	buf_t buf4 = SH(buf3, salt2);
	buf_free(buf3);

  ON_LOG(tg, "End password hash calculation");
  return buf4;
}

/*
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
*/

/*
static InputCheckPasswordSRP tg_get_inputCheckPasswordSRP(
		tg_t *tg, const char *password_str, buf_t salt1, buf_t salt2, 
		uint32_t g_int, buf_t p, buf_t B, uint64_t id)
{
	InputCheckPasswordSRP srp = buf_new();

// If the client has an inadequate random number generator, 
// it makes sense to use the secure_random of 
// account.password as additional seed.

// password := (user-provided password)
// salt1 := algo.salt1
// salt2 := algo.salt2
	
	BIGNUM *gBN = BN_new();
	assert(BN_set_word(gBN, g_int));

	BIGNUM *pBN = BN_new();
	assert(BN_bin2bn(p.data, p.size, pBN));
	
	// init context
	BN_CTX *ctx = BN_CTX_new();	
	if (!ctx){
		ON_ERR(tg, "%s: can't init BigNumContext", __func__);
		return srp;
	}
	
// The client computes a 2048-bit number a (using sufficient 
// entropy or the server's random; see above) and generates:
// g_a := pow(g, a) mod p.
	BIGNUM *aBN = BN_new();
	assert(BN_rand(aBN, 2048, 0, 0));
	BIGNUM *g_aBN = BN_new();
  assert(BN_mod_exp(g_aBN, gBN, aBN, pBN, ctx)); 

// g_b := srp_b srp_b and srp_id are extracted from the 
// account.password object.
// The server computes a 2048-bit number b using sufficient 
// entropy and generates the g_b parameter that was sent 
// to us (see above).
	BIGNUM *g_bBN = BN_new();
	assert(BN_bin2bn(B.data, B.size, g_bBN));

// The k parameter is generated, both on client and server:
// k := H(p | g)
	buf_t g = buf_add_ui32(g_int);
	buf_t p_g = buf_new();
	p_g = buf_cat(p_g, p);
	p_g = buf_cat(p_g, g);
	// buf_free(g_); - need to compile M1
	buf_t k = H(p_g);
	buf_free(p_g);
	BIGNUM *kBN = BN_new();
	assert(BN_bin2bn(k.data, k.size, kBN));

// The shared param u is generated: the client does this, 
// and the server does the same with the g_a we will send 
// him later (see below)
// u := H(g_a | g_b)
	buf_t g_a = buf_new();
	g_a.size = BN_bn2bin(g_aBN, g_a.data);
	assert(g_a.size);
	buf_t g_b = buf_new();
	g_b.size = BN_bn2bin(g_bBN, g_b.data);
	assert(g_b.size);
	buf_t g_a_g_b = buf_new();
	g_a_g_b = buf_cat(g_a_g_b, g_a);
	g_a_g_b = buf_cat(g_a_g_b, g_b);
	// buf_free(g_a_); - need to compile M1
	// buf_free(g_b_); - need to compile M1
	buf_t u = H(g_a_g_b);
	buf_free(g_a_g_b);
	BIGNUM *uBN = BN_new();
	assert(BN_bin2bn(u.data, u.size, uBN));

// The final parameters are generated client-side only:
// x := PH2(password, salt1, salt2)
	buf_t password = buf_add((unsigned char *)password_str,
		 	strlen(password_str));
	buf_t x = PH2(password, salt1, salt2);
	//buf_t x = tg_calc_password_hash(
	//		tg, password_str, salt1, salt2);
	buf_free(password);
	BIGNUM *xBN = BN_new();
	assert(BN_bin2bn(x.data, x.size, xBN));

// v := pow(g, x) mod p
// The server already has v, from when we set the password.
	BIGNUM *vBN = BN_new();
  assert(BN_mod_exp(vBN, gBN, xBN, pBN, ctx)); 

// A final shared param is generated, for commodity:
// k_v := (k * v) mod p
	BIGNUM *k_vBN = BN_new();
  assert(BN_mod_exp(k_vBN, kBN, vBN, pBN, ctx)); 

// Finally, the SRP session keys are generated:
// Client side:
// t := (g_b - k_v) mod p (positive modulo, if the result 
// is negative increment by p)
	BIGNUM *zeroBN = BN_new();
	BN_zero(zeroBN);
	//BN_dec2bn(&zeroBN, "0");
	BIGNUM *tBN = BN_new();
  assert(BN_sub(tBN, g_bBN, k_vBN)); 
	if (BN_cmp(tBN, zeroBN) == -1)
		assert(BN_add(tBN, tBN, pBN)); 
	
// s_a := pow(t, a + u * x) mod p
	BIGNUM *expBN = BN_new();
  assert(BN_mul(expBN, uBN, xBN, ctx)); 
	assert(BN_add(expBN, expBN, aBN)); 
	BIGNUM *s_aBN = BN_new();
  assert(BN_mod_exp(s_aBN, tBN, expBN, pBN, ctx)); 
	
// k_a := H(s_a)
	buf_t s_a = buf_new();
	s_a.size = BN_bn2bin(s_aBN, s_a.data);
	assert(s_a.size);
	buf_t k_a = H(s_a);
	buf_free(s_a);
	
// Finally, as per SRP:
// M1 := H(H(p) xor H(g) | H(salt1) | H(salt2) | g_a | g_b | k_a)
	buf_t H_p = H(p);
	buf_t H_g = H(g);
	buf_t xor = buf_xor(H_p, H_g);
	buf_t H_salt1 = H(salt1);
	buf_t H_salt2 = H(salt2);
	buf_t M  = buf_new();
	M = buf_cat(M, xor);
	M = buf_cat(M, H_salt1);
	M = buf_cat(M, H_salt2);
	M = buf_cat(M, g_a);
	M = buf_cat(M, g_b);
	M = buf_cat(M, k_a);
	buf_t M1 = H(M);	
	buf_free(p);
	buf_free(g);
	buf_free(H_p);
	buf_free(H_g);
	buf_free(xor);
	buf_free(H_salt1);
	buf_free(H_salt2);
	// buf_free(g_a); - need to compile CheckPasswordSRP
	buf_free(g_b);
	buf_free(k_a);
	buf_free(M);
	
	srp = tl_inputCheckPasswordSRP(id, &g_a, &M1);
	
	buf_free(g_a);
	buf_free(M1);

	return srp;
}
*/

static InputCheckPasswordSRP tg_get_inputCheckPasswordSRP(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2, 
		uint32_t g, buf_t p, buf_t B, uint64_t id)
{
	ON_LOG_BUF(tg, B, "%s: B: ", __func__);
	ON_LOG(tg, "%s: g: %d", __func__, g);
	InputCheckPasswordSRP srp = buf_new();

	// auto p_bn = BigNum::from_binary(p);
	BIGNUM *p_bn = BN_bin2bn(p.data, p.size, NULL); 

	// auto B_bn = BigNum::from_binary(B);
	BIGNUM *B_bn = BN_bin2bn(B.data, B.size, NULL); 
	
	// auto zero = BigNum::from_decimal("0").move_as_ok();
	BIGNUM *zero = BN_new();
	BN_zero(zero);

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

	// BigNum g_bn;
	// g_bn.set_value(g);
	// auto g_padded = g_bn.to_binary(256);
	BIGNUM *g_bn = BN_new();
	BN_set_word(g_bn, g);
	buf_t g_padded = BN_bn2bin_size(g_bn, 256);
	ON_LOG_BUF(tg, g_padded, "%s: g_padded: ", __func__);

	// auto x = calc_password_hash(password, client_salt, server_salt);
	// auto x_bn = BigNum::from_binary(x.as_slice());
	buf_t x = tg_calc_password_hash(tg, password, salt1, salt2);
	//buf_t x = PH2(password, salt1, salt2);
	BIGNUM *x_bn = BN_bin2bn(x.data, x.size, NULL);

	// BufferSlice a(2048 / 8);
  // Random::secure_bytes(a.as_mutable_slice());
  // auto a_bn = BigNum::from_binary(a.as_slice());
	buf_t a = buf_rand(2048/8);
	BIGNUM *a_bn = BN_bin2bn(a.data, a.size, NULL);
	//ON_LOG_BUF(tg, a, "%s: a: ", __func__);
	
	// BigNumContext ctx;
	BN_CTX *ctx = BN_CTX_new();	
  
	// BigNum A_bn;
  // BigNum::mod_exp(A_bn, g_bn, a_bn, p_bn, ctx);
  // string A = A_bn.to_binary(256);
	BIGNUM *A_bn = BN_new();
  assert(BN_mod_exp(A_bn, g_bn, a_bn, p_bn, ctx)); 
	buf_t A = BN_bn2bin_size(A_bn, 256);
	//ON_LOG_BUF(tg, A, "%s: A: ", __func__);
	
	// string u = sha256(PSLICE() << A << B);
	buf_t u  = buf_concat_sha256(A, B);
	//ON_LOG_BUF(tg, u, "%s: u: ", __func__);
  
	// auto u_bn = BigNum::from_binary(u);
	BIGNUM *u_bn = BN_bin2bn(u.data, u.size, NULL);
  
	// string k = sha256(PSLICE() << p << g_padded);
  // auto k_bn = BigNum::from_binary(k);
	buf_t k  = buf_concat_sha256(p, g_padded);
	BIGNUM *k_bn = BN_bin2bn(k.data, k.size, NULL);
	//ON_LOG_BUF(tg, k, "%s: k: ", __func__);
	
  // BigNum v_bn;
  // BigNum::mod_exp(v_bn, g_bn, x_bn, p_bn, ctx);
	BIGNUM *v_bn = BN_new();
  assert(BN_mod_exp(v_bn, g_bn, x_bn, p_bn, ctx)); 
	
	// BigNum kv_bn;
  // BigNum::mod_mul(kv_bn, k_bn, v_bn, p_bn, ctx);
	BIGNUM *kv_bn = BN_new();
	assert(BN_mod_mul(kv_bn, k_bn, v_bn, p_bn, ctx));
	
	// BigNum t_bn;
  // BigNum::sub(t_bn, B_bn, kv_bn);
  // if (BigNum::compare(t_bn, zero) == -1) {
  //  BigNum::add(t_bn, t_bn, p_bn);
  // }
	BIGNUM *t_bn = BN_new();
  assert(BN_sub(t_bn, B_bn, kv_bn)); 
	if (BN_cmp(t_bn, zero) == -1){
		assert(BN_add(t_bn, t_bn, p_bn)); 
	}
	
  // BigNum exp_bn;
  // BigNum::mul(exp_bn, u_bn, x_bn, ctx);
  // BigNum::add(exp_bn, exp_bn, a_bn);
	BIGNUM *exp_bn = BN_new();
  assert(BN_mul(exp_bn, u_bn, x_bn, ctx)); 
	assert(BN_add(exp_bn, exp_bn, a_bn)); 
	
  // BigNum S_bn;
  // BigNum::mod_exp(S_bn, t_bn, exp_bn, p_bn, ctx);
  // string S = S_bn.to_binary(256);
	BIGNUM *S_bn = BN_new();
  assert(BN_mod_exp(S_bn, t_bn, exp_bn, p_bn, ctx)); 
	buf_t S = BN_bn2bin_size(S_bn, 256);
	//ON_LOG_BUF(tg, S, "%s: S: ", __func__);
  
	// auto K = sha256(S);
	buf_t K = tg_hsh_sha256(S);
	ON_LOG_BUF(tg, K, "%s: K: ", __func__);

	// auto h1 = sha256(p);
  // auto h2 = sha256(g_padded);
	buf_t h1 = tg_hsh_sha256(p);
	buf_t h2 = tg_hsh_sha256(g_padded);
	
	// for (size_t i = 0; i < h1.size(); i++) {
  // h1[i] = static_cast<char>(static_cast<unsigned char>(h1[i]) ^ static_cast<unsigned char>(h2[i]));
  // }
	buf_t xor = buf_xor(h1, h2);

	buf_t salt1_hash = tg_hsh_sha256(salt1);
	buf_t salt2_hash = tg_hsh_sha256(salt2);

  // auto M = sha256(PSLICE() << h1 << sha256(client_salt) << sha256(server_salt) << A << B << K);
	buf_t M1_ = buf_new(); 
	M1_ = buf_cat(M1_, xor);
	M1_ = buf_cat(M1_, salt1_hash);
	M1_ = buf_cat(M1_, salt2_hash);
	M1_ = buf_cat(M1_, A);
	M1_ = buf_cat(M1_, B);
	M1_ = buf_cat(M1_, K);
	buf_t M1  = tg_hsh_sha256(M1_);
	buf_free(M1_);

	buf_free(h1);
	buf_free(h2);
	buf_free(xor);
	buf_free(salt1_hash);
	buf_free(salt2_hash);
	buf_free(K);
	buf_free(S);
	buf_free(g_padded);
	buf_free(u);
	buf_free(k);
	buf_free(x);

	BN_free(g_bn);
	BN_free(x_bn);
	BN_free(a_bn);
	BN_free(A_bn);
	BN_free(u_bn);
	BN_free(k_bn);
	BN_free(v_bn);
	BN_free(kv_bn);
	BN_free(t_bn);
	BN_free(exp_bn);
	BN_free(S_bn);

	BN_CTX_free(ctx);
	
	ON_LOG(tg, "End input password SRP hash calculation");

	buf_free(srp);
	srp = tl_inputCheckPasswordSRP(id, &A, &M1);

	buf_free(A);
	buf_free(M1);
	
	return srp;
}

static tl_account_password_t *tg_account_getPassword(tg_t *tg)
{
	tl_t *tl = NULL; 
	
	// get account.password
	buf_t account_getPassword = 
		tl_account_getPassword();
	tl = tg_send_query_sync(tg, &account_getPassword);
	buf_free(account_getPassword);
	
	if (tl == NULL){
		ON_ERR(tg, "%s: TL is NULL", __func__);
		return NULL;
	}

	if (tl->_id == id_rpc_error){
		// throw error
		ON_ERR(tg, "%s: %s", __func__, RPC_ERROR(tl));
		tl_free(tl);
		return NULL;
	}

	if (tl->_id != id_account_password){
		ON_ERR(tg, "%s: expected: account_password, but got: %s",
			 	__func__, TL_NAME_FROM_ID(tl->_id));
		tl_free(tl);
		return NULL;
	}

	return (tl_account_password_t *)tl;
}

tl_auth_authorization_t *
tg_auth_check_password(tg_t *tg, const char *password){
	
	tl_t *tl = NULL; 

/* Client-side, the following parameters are extracted from 
 * the passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
 * object, contained in the account.password object. */

	tl_account_password_t *account_password = 
		tg_account_getPassword(tg);
	if (!account_password)
		return NULL;

	// check algo
	if (account_password->current_algo_->_id !=
			id_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
			)
	{
		ON_ERR(tg, "not supported password algo");
		return NULL;
	}

	tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t 
		*algo = 
		(tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t *)
		account_password->current_algo_;

	InputCheckPasswordSRP srp = tg_get_inputCheckPasswordSRP(
			tg, password, algo->salt1_, algo->salt2_, 
			algo->g_, algo->p_, 
			account_password->srp_B_, account_password->srp_id_);	

	if (srp.size == 0){
		return NULL;
	}

	buf_t auth_check_password = 
		tl_auth_checkPassword(&srp);
	buf_free(srp);

	tl = tg_send_query_sync(tg, &auth_check_password);
	buf_free(auth_check_password);

	if (!tl){
		ON_ERR(tg, "%s: TL is NULL", __func__);
		return NULL;
	}

	if (tl->_id == id_rpc_error){
		ON_ERR(tg, "%s: %s", __func__, RPC_ERROR(tl));
		tl_free(tl);
		return NULL;
	}

	if (tl->_id != id_auth_authorization){
		ON_ERR(tg, "%s: expected auth_authorization but got: %s",
				__func__, TL_NAME_FROM_ID(tl->_id));
		tl_free(tl);
		return NULL;
	}

	printf("GOOD PASSWORD!!!!\n");

	return (tl_auth_authorization_t *)tl;
}
