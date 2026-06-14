/*
 * air-crypto — C23 cryptographic core: PBKDF2-HMAC-SHA1.
 *
 * Clean-room implementation (SHA-1 -> HMAC-SHA1 -> PBKDF2), no external
 * crypto dependencies. Built with clang -std=c23.
 */
#include "pbkdf2_sha1.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-1 (FIPS 180-1)                                                  */
/* ------------------------------------------------------------------ */

constexpr size_t SHA1_DIGEST_LEN = 20;
constexpr size_t SHA1_BLOCK_LEN = 64;

typedef struct
{
	uint32_t state[5];
	uint64_t bitcount;
	uint8_t buffer[SHA1_BLOCK_LEN];
} sha1_ctx;

static inline uint32_t rol32(uint32_t value, unsigned bits)
{
	return (value << bits) | (value >> (32 - bits));
}

static void sha1_transform(uint32_t state[static 5],
                           const uint8_t block[static 64])
{
	uint32_t w[80];

	for (int i = 0; i < 16; ++i)
		w[i] = ((uint32_t) block[i * 4] << 24)
			   | ((uint32_t) block[i * 4 + 1] << 16)
			   | ((uint32_t) block[i * 4 + 2] << 8)
			   | ((uint32_t) block[i * 4 + 3]);

	for (int i = 16; i < 80; ++i)
		w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3],
			 e = state[4];

	for (int i = 0; i < 80; ++i)
	{
		uint32_t f, k;
		if (i < 20)
		{
			f = (b & c) | ((~b) & d);
			k = 0x5A827999u;
		}
		else if (i < 40)
		{
			f = b ^ c ^ d;
			k = 0x6ED9EBA1u;
		}
		else if (i < 60)
		{
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDCu;
		}
		else
		{
			f = b ^ c ^ d;
			k = 0xCA62C1D6u;
		}

		uint32_t tmp = rol32(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rol32(b, 30);
		b = a;
		a = tmp;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

static void sha1_init(sha1_ctx *ctx)
{
	ctx->state[0] = 0x67452301u;
	ctx->state[1] = 0xEFCDAB89u;
	ctx->state[2] = 0x98BADCFEu;
	ctx->state[3] = 0x10325476u;
	ctx->state[4] = 0xC3D2E1F0u;
	ctx->bitcount = 0;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
{
	size_t index = (size_t) ((ctx->bitcount >> 3) & (SHA1_BLOCK_LEN - 1));
	ctx->bitcount += (uint64_t) len << 3;

	size_t part = SHA1_BLOCK_LEN - index;
	size_t i = 0;

	if (len >= part)
	{
		memcpy(&ctx->buffer[index], data, part);
		sha1_transform(ctx->state, ctx->buffer);
		for (i = part; i + SHA1_BLOCK_LEN - 1 < len; i += SHA1_BLOCK_LEN)
			sha1_transform(ctx->state, &data[i]);
		index = 0;
	}

	memcpy(&ctx->buffer[index], &data[i], len - i);
}

static void sha1_final(sha1_ctx *ctx, uint8_t digest[static 20])
{
	uint8_t length[8];
	for (int i = 0; i < 8; ++i)
		length[i] = (uint8_t) (ctx->bitcount >> ((7 - i) * 8));

	uint8_t pad = 0x80;
	sha1_update(ctx, &pad, 1);

	pad = 0x00;
	while (((ctx->bitcount >> 3) & (SHA1_BLOCK_LEN - 1)) != 56)
		sha1_update(ctx, &pad, 1);

	sha1_update(ctx, length, 8);

	for (int i = 0; i < 20; ++i)
		digest[i]
			= (uint8_t) (ctx->state[i >> 2] >> ((3 - (i & 3)) * 8));
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA1 (RFC 2104)                                                */
/* ------------------------------------------------------------------ */

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[static 20])
{
	uint8_t block_key[SHA1_BLOCK_LEN];
	uint8_t ipad[SHA1_BLOCK_LEN];
	uint8_t opad[SHA1_BLOCK_LEN];
	uint8_t inner[SHA1_DIGEST_LEN];
	uint8_t shortened[SHA1_DIGEST_LEN];
	sha1_ctx ctx;

	if (key_len > SHA1_BLOCK_LEN)
	{
		sha1_init(&ctx);
		sha1_update(&ctx, key, key_len);
		sha1_final(&ctx, shortened);
		key = shortened;
		key_len = SHA1_DIGEST_LEN;
	}

	memset(block_key, 0, SHA1_BLOCK_LEN);
	memcpy(block_key, key, key_len);

	for (size_t i = 0; i < SHA1_BLOCK_LEN; ++i)
	{
		ipad[i] = block_key[i] ^ 0x36;
		opad[i] = block_key[i] ^ 0x5C;
	}

	sha1_init(&ctx);
	sha1_update(&ctx, ipad, SHA1_BLOCK_LEN);
	sha1_update(&ctx, msg, msg_len);
	sha1_final(&ctx, inner);

	sha1_init(&ctx);
	sha1_update(&ctx, opad, SHA1_BLOCK_LEN);
	sha1_update(&ctx, inner, SHA1_DIGEST_LEN);
	sha1_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA1 (RFC 2898)                                         */
/* ------------------------------------------------------------------ */

int air_pbkdf2_sha1(const uint8_t *passphrase, size_t passphrase_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t iterations,
                    uint8_t *out, size_t out_len)
{
	if (passphrase == nullptr || salt == nullptr || out == nullptr)
		return 1;
	if (iterations == 0 || out_len == 0)
		return 2;

	constexpr size_t HLEN = SHA1_DIGEST_LEN;

	/* salt || INT_BE32(block_index) */
	uint8_t *salted = malloc(salt_len + 4);
	if (salted == nullptr)
		return 3;
	memcpy(salted, salt, salt_len);

	uint8_t u[HLEN];
	uint8_t t[HLEN];
	size_t offset = 0;

	const uint32_t blocks = (uint32_t) ((out_len + HLEN - 1) / HLEN);

	for (uint32_t block = 1; block <= blocks; ++block)
	{
		salted[salt_len + 0] = (uint8_t) (block >> 24);
		salted[salt_len + 1] = (uint8_t) (block >> 16);
		salted[salt_len + 2] = (uint8_t) (block >> 8);
		salted[salt_len + 3] = (uint8_t) (block);

		hmac_sha1(passphrase, passphrase_len, salted, salt_len + 4, u);
		memcpy(t, u, HLEN);

		for (uint32_t iter = 1; iter < iterations; ++iter)
		{
			hmac_sha1(passphrase, passphrase_len, u, HLEN, u);
			for (size_t i = 0; i < HLEN; ++i)
				t[i] ^= u[i];
		}

		size_t to_copy = (out_len - offset < HLEN) ? (out_len - offset) : HLEN;
		memcpy(out + offset, t, to_copy);
		offset += to_copy;
	}

	free(salted);
	return 0;
}

int air_calc_pmk(const char *passphrase, const char *essid,
                 uint8_t out[static AIR_PMK_LEN])
{
	if (passphrase == nullptr || essid == nullptr)
		return 1;

	return air_pbkdf2_sha1((const uint8_t *) passphrase, strlen(passphrase),
	                       (const uint8_t *) essid, strlen(essid), 4096, out,
	                       AIR_PMK_LEN);
}
