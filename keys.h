#ifndef __KEYS_H__
#define __KEYS_H__

#include "common.h"

#define EID_ROOT_KEY_SIZE 0x20
#define EID_ROOT_IV_SIZE 0x10
#define EID4_KEY_SIZE 0x20
#define EID4_IV_SIZE 0x10
#define EID4_SIZE 0x30

#define INDIVIDUAL_SEED_SIZE 0x40
#define INDIVIDUAL_KEY_SIZE 0x20
#define INDIVIDUAL_IV_SIZE 0x10
#define ZERO_IV_SIZE 0x10
#define USER_PARAM_SIZE 0x40
#define TDES_IV_SIZE 8
#define IVS_AES_SIZE 0x10
#define GIV_SIZE 0x10

const uint8_t sv_iso_module_individual_seed[INDIVIDUAL_SEED_SIZE];
const uint8_t zero_iv[ZERO_IV_SIZE];
const uint8_t user_param_u0[USER_PARAM_SIZE];
const uint8_t user_param_u1[USER_PARAM_SIZE];
const uint8_t user_param_u2[USER_PARAM_SIZE];
const uint8_t user_param_u3[USER_PARAM_SIZE];
const uint8_t user_param_u4[USER_PARAM_SIZE];
unsigned char ivs_3des[TDES_IV_SIZE];
const uint8_t ivs_aes[IVS_AES_SIZE];
const uint8_t fix1_it[0x10];
const uint8_t fix2_it[0x10];
const uint8_t fix1_pn[0x10];
const uint8_t fix2_pn[0x10];
const uint8_t Kf1_u0[0x10];
const uint8_t Kf2_u0[0x10];
const uint8_t Kf1_u1[0x10];
const uint8_t Kf2_u1[0x10];
const uint8_t Kf1_u2[0x10];
const uint8_t Kf2_u2[0x10];
const uint8_t Kf1_u3[0x10];
const uint8_t Kf2_u3[0x10];
const uint8_t Kf1_u4[0x10];
const uint8_t Kf2_u4[0x10];
const uint8_t giv[GIV_SIZE];
const uint8_t kms1[0x10];
const uint8_t kms2[0x10];
const uint8_t PS3_L_DEBUG_DISC[0x10];
const uint8_t intikey[0x10];
const uint8_t Kh[0x10];
const uint8_t IVh[0x10];
const uint8_t Kwm[0x10];
const uint8_t Kdid[0x10];

uint8_t eid_root_key[EID_ROOT_KEY_SIZE];
uint8_t eid_root_iv[EID_ROOT_IV_SIZE];

void set_eid_root_key();
int decrypt_eid4();

#endif
