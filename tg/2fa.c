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
#include <string.h>
#include "crypto/hsh.h"
#include "crypto/pbkdf2.h"
#include "tg_log.h"

// H(data) := sha256(data)
#define H(data) tg_hsh_sha256(data)
 
// SH(data, salt) := H(salt | data | salt)
#define SH(data, salt) \
	({buf_t _buf = buf_add_bufs(salt, data, salt); \
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
	({buf_t _ph1 = PH1(password, salt1, salt2); \
	  buf_t _buf = tg_pbkdf2_sha512(_ph1, salt1, 100000); \
		buf_t _ret = SH(_buf, salt2); \
		buf_free(_ph1); \
		buf_free(_buf); \
		_ret;})
 
static buf_t tg_calc_password_hash(
		tg_t *tg, const char *password, buf_t salt1, buf_t salt2)
{
	ON_LOG(tg, "Begin password hash calculation");
	
	buf_t password_buf = buf_add((unsigned char *)password,
		 	strlen(password));

	buf_t SH = buf_add_bufs(3, salt1, password_buf, salt1);
	buf_free(password_buf);
	ON_LOG_BUF(tg, SH, "%s: SH: ", __func__);
	buf_t SH_HSH = tg_hsh_sha256(SH);
	buf_free(SH);
	ON_LOG_BUF(tg, SH_HSH, "%s: SH_HSH: ", __func__);

	buf_t PH1 = buf_add_bufs(3, salt2, SH_HSH, salt2);
	buf_free(SH);
	ON_LOG_BUF(tg, PH1, "%s: PH1: ", __func__);
	buf_t PH1_HSH = tg_hsh_sha256(PH1);
	buf_free(PH1);
	ON_LOG_BUF(tg, PH1_HSH, "%s: PH1_HSH: ", __func__);

	buf_t PBKDF2 = tg_pbkdf2_sha512(
			PH1_HSH, salt1, 100000);
	buf_free(PH1_HSH);
	ON_LOG_BUF(tg, PBKDF2, "%s: PBKDF2: ", __func__);
	
	buf_t PH2 = buf_add_bufs(3, salt2, PBKDF2, salt2);
	buf_free(PBKDF2);
	ON_LOG_BUF(tg, PH2, "%s: PH2: ", __func__);
	buf_t PH2_HSH = tg_hsh_sha256(PH2);
	buf_free(PH2);
	ON_LOG_BUF(tg, PH2_HSH, "%s: PH2_HSH: ", __func__);

	ON_LOG(tg, "End password hash calculation");
	return PH2_HSH;
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

	// auto p_bn = BigNum::from_binary(p);
	BIGNUM *p_bn = BN_new();
	BN_bin2bn(p.data, p.size, p_bn); 

	// auto B_bn = BigNum::from_binary(B);
	BIGNUM *B_bn = BN_new();
	BN_bin2bn(B.data, B.size, B_bn); 
	
	// auto zero = BigNum::from_decimal("0").move_as_ok();
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

	// BigNum g_bn;
	// g_bn.set_value(g);
	// auto g_padded = g_bn.to_binary(256);
	BIGNUM *g_bn = BN_new();
	BN_set_word(g_bn, g);
	buf_t g_padded = buf_new();
	BN_bn2bin(g_bn, g_padded.data);
	g_padded.size = 256;
	ON_LOG_BUF(tg, g_padded, "%s: g_padded: ", __func__);

	// auto x = calc_password_hash(password, client_salt, server_salt);
	// auto x_bn = BigNum::from_binary(x.as_slice());
	buf_t x = tg_calc_password_hash(tg, password, salt1, salt2);
	BIGNUM *x_bn = BN_new();
	BN_bin2bn(x.data, x.size, x_bn);

	// BufferSlice a(2048 / 8);
  // Random::secure_bytes(a.as_mutable_slice());
  // auto a_bn = BigNum::from_binary(a.as_slice());
	buf_t a = buf_rand(2048/8);
	BIGNUM *a_bn = BN_new();
	BN_bin2bn(a.data, a.size, a_bn);
	ON_LOG_BUF(tg, a, "%s: a: ", __func__);
	
	// BigNumContext ctx;
  // BigNum A_bn;
  // BigNum::mod_exp(A_bn, g_bn, a_bn, p_bn, ctx);
  // string A = A_bn.to_binary(256);
	BN_CTX *ctx = BN_CTX_new();	
	BIGNUM *A_bn = BN_new();
  assert(BN_mod_exp(A_bn, g_bn, a_bn, p_bn, ctx)); 
	buf_t A = buf_new();
	BN_bn2bin(A_bn, A.data);
	A.size = 256;
	ON_LOG_BUF(tg, A, "%s: A: ", __func__);
	
	// string B_pad(256 - B.size(), '\0');
	buf_t B_pad = buf_new();
	B_pad.size = 256 - B.size;
	ON_LOG_BUF(tg, B_pad, "%s: B_pad: ", __func__);
  
	// string u = sha256(PSLICE() << A << B_pad << B);
	buf_t u_ = buf_add_bufs(3, A, B_pad, B);
	buf_t u  = tg_hsh_sha256(u);
	buf_free(u_);
	ON_LOG_BUF(tg, u, "%s: u: ", __func__);
  
	// auto u_bn = BigNum::from_binary(u);
	BIGNUM *u_bn = BN_new();
	BN_bin2bn(u.data, u.size, u_bn);
  
	// string k = sha256(PSLICE() << p << g_padded);
  // auto k_bn = BigNum::from_binary(k);
	buf_t k_ = buf_add_bufs(2, p, g_padded);
	buf_t k  = tg_hsh_sha256(k_);
	buf_free(k_);
	BIGNUM *k_bn = BN_new();
	BN_bin2bn(k.data, k.size, k_bn);
	ON_LOG_BUF(tg, k, "%s: k: ", __func__);
	
  // BigNum v_bn;
  // BigNum::mod_exp(v_bn, g_bn, x_bn, p_bn, ctx);
	BIGNUM *v_bn = BN_new();
  assert(BN_mod_exp(v_bn, g_bn, x_bn, p_bn, ctx)); 
	
	// BigNum kv_bn;
  // BigNum::mod_mul(kv_bn, k_bn, v_bn, p_bn, ctx);
	BIGNUM *kv_bn = BN_new();
  assert(BN_mod_exp(kv_bn, k_bn, v_bn, p_bn, ctx)); 
	
	// BigNum t_bn;
  // BigNum::sub(t_bn, B_bn, kv_bn);
  // if (BigNum::compare(t_bn, zero) == -1) {
  //  BigNum::add(t_bn, t_bn, p_bn);
  // }
	BIGNUM *t_bn = BN_new();
  assert(BN_sub(t_bn, B_bn, kv_bn)); 
	if (BN_cmp(t_bn, zero) == -1)
		assert(BN_add(t_bn, t_bn, p_bn)); 
	
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
	buf_t S = buf_new();
	BN_bn2bin(S_bn, S.data);
	S.size = 256;
	ON_LOG_BUF(tg, S, "%s: S: ", __func__);
  
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

  // auto M = sha256(PSLICE() << h1 << sha256(client_salt) << sha256(server_salt) << A << B_pad << B << K);
	buf_t M1_ = buf_add_bufs(7, 
			xor, salt1_hash, salt2_hash, A, B_pad, B, K);
	buf_t M1  = tg_hsh_sha256(M1_);
	buf_free(M1_);

	buf_free(h1);
	buf_free(h2);
	buf_free(xor);
	buf_free(salt1_hash);
	buf_free(salt2_hash);
	buf_free(B_pad);
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

	tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t 
		*algo = 
		(tl_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow_t *)account_password->current_algo_;


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


/*
Result<BufferSlice> PasswordManager::calc_password_srp_hash(Slice password, Slice client_salt, Slice server_salt,
                                                            int32 g, Slice p) {
  LOG(INFO) << "Begin password SRP hash calculation";
  TRY_STATUS(mtproto::DhHandshake::check_config(g, p, DhCache::instance()));

  auto hash = calc_password_hash(password, client_salt, server_salt);
  auto p_bn = BigNum::from_binary(p);
  BigNum g_bn;
  g_bn.set_value(g);
  auto x_bn = BigNum::from_binary(hash.as_slice());

  BigNumContext ctx;
  BigNum v_bn;
  BigNum::mod_exp(v_bn, g_bn, x_bn, p_bn, ctx);

  BufferSlice result(v_bn.to_binary(256));
  LOG(INFO) << "End password SRP hash calculation";
  return std::move(result);
}

tl_object_ptr<telegram_api::InputCheckPasswordSRP> PasswordManager::get_input_check_password(
    Slice password, Slice client_salt, Slice server_salt, int32 g, Slice p, Slice B, int64 id) {
  if (password.empty()) {
    return make_tl_object<telegram_api::inputCheckPasswordEmpty>();
  }

  if (mtproto::DhHandshake::check_config(g, p, DhCache::instance()).is_error()) {
    LOG(ERROR) << "Receive invalid config " << g << " " << format::escaped(p);
    return make_tl_object<telegram_api::inputCheckPasswordEmpty>();
  }

  auto p_bn = BigNum::from_binary(p);
  auto B_bn = BigNum::from_binary(B);
  auto zero = BigNum::from_decimal("0").move_as_ok();
  if (BigNum::compare(zero, B_bn) != -1 || BigNum::compare(B_bn, p_bn) != -1 || B.size() < 248 || B.size() > 256) {
    LOG(ERROR) << "Receive invalid value of B(" << B.size() << "): " << B_bn << " " << p_bn;
    return make_tl_object<telegram_api::inputCheckPasswordEmpty>();
  }

  LOG(INFO) << "Begin input password SRP hash calculation";
  BigNum g_bn;
  g_bn.set_value(g);
  auto g_padded = g_bn.to_binary(256);

  auto x = calc_password_hash(password, client_salt, server_salt);
  auto x_bn = BigNum::from_binary(x.as_slice());

  BufferSlice a(2048 / 8);
  Random::secure_bytes(a.as_mutable_slice());
  auto a_bn = BigNum::from_binary(a.as_slice());

  BigNumContext ctx;
  BigNum A_bn;
  BigNum::mod_exp(A_bn, g_bn, a_bn, p_bn, ctx);
  string A = A_bn.to_binary(256);

  string B_pad(256 - B.size(), '\0');
  string u = sha256(PSLICE() << A << B_pad << B);
  auto u_bn = BigNum::from_binary(u);
  string k = sha256(PSLICE() << p << g_padded);
  auto k_bn = BigNum::from_binary(k);

  BigNum v_bn;
  BigNum::mod_exp(v_bn, g_bn, x_bn, p_bn, ctx);
  BigNum kv_bn;
  BigNum::mod_mul(kv_bn, k_bn, v_bn, p_bn, ctx);
  BigNum t_bn;
  BigNum::sub(t_bn, B_bn, kv_bn);
  if (BigNum::compare(t_bn, zero) == -1) {
    BigNum::add(t_bn, t_bn, p_bn);
  }
  BigNum exp_bn;
  BigNum::mul(exp_bn, u_bn, x_bn, ctx);
  BigNum::add(exp_bn, exp_bn, a_bn);

  BigNum S_bn;
  BigNum::mod_exp(S_bn, t_bn, exp_bn, p_bn, ctx);
  string S = S_bn.to_binary(256);
  auto K = sha256(S);

  auto h1 = sha256(p);
  auto h2 = sha256(g_padded);
  for (size_t i = 0; i < h1.size(); i++) {
    h1[i] = static_cast<char>(static_cast<unsigned char>(h1[i]) ^ static_cast<unsigned char>(h2[i]));
  }
  auto M = sha256(PSLICE() << h1 << sha256(client_salt) << sha256(server_salt) << A << B_pad << B << K);

  LOG(INFO) << "End input password SRP hash calculation";
  return make_tl_object<telegram_api::inputCheckPasswordSRP>(id, BufferSlice(A), BufferSlice(M));
}


*/
