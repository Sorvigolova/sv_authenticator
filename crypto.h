/**
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "common.h"

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

enum {
	AES_DECRYPT = 0,
	AES_ENCRYPT = 1,

	AES_BLOCK_SIZE = 16,
};

enum {
	// Invalid mode
	ERROR_INVALID_MODE = -1,

	// Invalid key length
	ERROR_INVALID_KEY_SIZE = -2,

	// Invalid data size
	ERROR_INVALID_DATA_SIZE = -3,
};

// 
// \brief AES context structure
// 
// \note  buf is able to hold 32 extra bytes, which can be used:
//        to simplify key expansion in the 256-bit case by generating an extra round key
// 
struct aes_context_t {
	uint32_t buf[68]; // unaligned data
	uint32_t* rk; // round keys
	int nr; // number of rounds
	int mode; // AES_ENCRYPT or AES_DECRYPT
};

// 
// \brief AES-XTS context structure
// 
struct aes_xts_context_t {
	struct aes_context_t tweak_ctx;
	struct aes_context_t data_ctx;
	int mode;
};

// 
// \brief          AES key schedule
// 
// \param ctx      AES context to be initialized
// \param mode     AES_ENCRYPT or AES_DECRYPT
// \param key      decryption key
// \param key_size must be 128, 192 or 256
// 
// \return         0 if successful, or ERROR_INVALID_KEY_SIZE
// 
int aes_init(struct aes_context_t* const ctx, const int mode, const uint8_t* const key, const unsigned int key_size);

// 
// \brief        AES-ECB block encryption/decryption
// 
// \param ctx    AES context
// \param input  16-byte input block
// \param output 16-byte output block
// 
// \return       0 if successful
// 
int aes_crypt_ecb(struct aes_context_t* const ctx, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE]);
int aes_encrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length);
int aes_decrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length);

// 
// \brief        AES-CBC buffer encryption/decryption
//               Length should be a multiple of the block size (16 bytes)
// 
// \param ctx    AES context
// \param mode   AES_ENCRYPT or AES_DECRYPT
// \param length length of the input data
// \param iv     initialization vector (updated after use)
// \param input  buffer holding the input data
// \param output buffer holding the output data
// 
// \return       0 if successful, or ERROR_INVALID_DATA_SIZE
// 
int aes_crypt_cbc(struct aes_context_t* const ctx, uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_encrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_decrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);

// 
// \brief         AES-CTR buffer encryption/decryption
// 
// \param ctx     AES context
// \param nonce   The 128-bit nonce
// \param length  The length of the data
// \param input   buffer holding the input data
// \param output  buffer holding the output data
// 
// \return        0 if successful
// 
int aes_crypt_ctr(struct aes_context_t* const ctx, uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);
int aes_ctr(const uint8_t* const key, const int key_size, const uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length);

// 
// \brief AES-XTS key schedule
// 
int aes_xts_init(struct aes_xts_context_t* const ctx, const int mode, const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size);

// 
// \brief AES-XTS sector encryption/decryption
// 
int aes_crypt_xts(struct aes_xts_context_t* const ctx, const uint8_t* const input, uint8_t* const output, const uint64_t sector_index, const uint32_t sector_size);
int aes_encrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size);
int aes_decrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size);

// 
// \brief AES-CMAC
// 
int aes_cmac(const uint8_t* const key, const int key_size, const uint8_t* const input, uint8_t* const output, const uint32_t length);

//-----------------------------------------------------------------------------
// SHA-1
//-----------------------------------------------------------------------------

enum {
	SHA1_HASH_SIZE = 20,
	SHA1_BLOCK_SIZE = 64,
};

//
// \brief SHA-1 context structure
//
struct sha1_context_t {
	uint32_t total[2]; // number of bytes processed
	uint32_t state[5]; // intermediate digest state
	uint8_t buffer[64]; // data block being processed
	uint8_t ipad[64]; // HMAC: inner padding
	uint8_t opad[64]; // HMAC: outer padding
};

// 
// \brief     SHA-1 context setup
// 
// \param ctx context to be initialized
// 
void sha1_starts(struct sha1_context_t* const ctx);

// For internal use
void sha1_transform(struct sha1_context_t* const ctx, const uint8_t data[SHA1_BLOCK_SIZE]);

// 
// \brief        SHA-1 process buffer
// 
// \param ctx    SHA-1 context
// \param input  buffer holding the data
// \param length length of the input data
// 
void sha1_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length);

// 
// \brief        SHA-1 final digest
// 
// \param ctx    SHA-1 context
// \param output SHA-1 checksum result
// 
void sha1_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]);

// 
// \brief        Output = SHA-1(input buffer)
// 
// \param input  buffer holding the data
// \param output SHA-1 checksum result
// \param length length of the input data
// 
void sha1(const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length);

// 
// \brief          SHA-1 HMAC context setup
// 
// \param ctx      HMAC context to be initialized
// \param key      HMAC secret key
// \param key_size length of the HMAC key
// 
void sha1_hmac_starts(struct sha1_context_t* const ctx, const uint8_t* const key, const uint32_t key_size);

// 
// \brief        SHA-1 HMAC process buffer
// 
// \param ctx    HMAC context
// \param input  buffer holding the  data
// \param length length of the input data
// 
void sha1_hmac_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length);

// 
// \brief        SHA-1 HMAC final digest
// 
// \param ctx    HMAC context
// \param output SHA-1 HMAC checksum result
// 
void sha1_hmac_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]);

// 
// \brief     SHA-1 HMAC context reset
// 
// \param ctx HMAC context to be reset
// 
void sha1_hmac_reset(struct sha1_context_t* const ctx);

// 
// \brief          Output = HMAC-SHA-1(hmac key, input buffer)
// 
// \param key      HMAC secret key
// \param key_size length of the HMAC key
// \param input    buffer holding the  data
// \param output   HMAC-SHA-1 result
// \param length   length of the input data
// 
void sha1_hmac(const uint8_t* const key, const uint32_t key_size, const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length);

//-----------------------------------------------------------------------------
// Random numbers generation
//-----------------------------------------------------------------------------

int generate_random_bytes(uint8_t* const data, const uint32_t length);

//-----------------------------------------------------------------------------
// DES
//-----------------------------------------------------------------------------
#define DES_ENCRYPT     1
#define DES_DECRYPT     0

#define POLARSSL_ERR_DES_INVALID_INPUT_LENGTH              -0x0032  /**< The data input has an invalid length. */

#define DES_KEY_SIZE    8

/**
 * \brief          DES context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    uint32_t sk[32];            /*!<  DES subkeys       */
}
des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    uint32_t sk[96];            /*!<  3DES subkeys      */
}
des3_context;

/**
 * \brief          Set key parity on the given key to odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 */
void des_key_set_parity(unsigned char key[DES_KEY_SIZE]);

/**
 * \brief          Check that key parity on the given key is odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \return         0 is parity was ok, 1 if parity was not correct.
 */
int des_key_check_key_parity(const unsigned char key[DES_KEY_SIZE]);

/**
 * \brief          Check that key is not a weak or semi-weak DES key
 *
 * \param key      8-byte secret key
 *
 * \return         0 if no weak key was found, 1 if a weak key was identified.
 */
int des_key_check_weak(const unsigned char key[DES_KEY_SIZE]);

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 */
int des_setkey_enc(des_context *ctx, const unsigned char key[DES_KEY_SIZE]);

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 */
int des_setkey_dec(des_context *ctx, const unsigned char key[DES_KEY_SIZE]);

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
int des3_set2key_enc(des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 2]);

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
int des3_set2key_dec(des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 2]);

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
int des3_set3key_enc(des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 3]);

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
int des3_set3key_dec(des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 3]);

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
int des_crypt_ecb (des_context *ctx, const unsigned char input[8], unsigned char output[8]);

/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \param ctx      DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
int des_crypt_cbc (des_context *ctx, int mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
int des3_crypt_ecb(des3_context *ctx, const unsigned char input[8], unsigned char output[8]);

/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \param ctx      3DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or POLARSSL_ERR_DES_INVALID_INPUT_LENGTH
 */
int des3_crypt_cbc (des3_context *ctx, int mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output);
					 
int des3_encrypt_cbc (const unsigned char key[DES_KEY_SIZE * 2], unsigned char iv[8], const unsigned char *input, unsigned char *output, size_t length);

int des3_decrypt_cbc (const unsigned char key[DES_KEY_SIZE * 2], unsigned char iv[8], const unsigned char *input, unsigned char *output, size_t length);

#endif
