#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_udata_command.h"

int sv_udata_command_set()
{
	
	unsigned char udata_cmd_buf[0x90] = {0};
	
	//header
	unsigned int payload_size = 0x70;
	memcpy(udata_cmd_buf, &payload_size, 4);
	memcpy(udata_cmd_buf + 4, &payload_size, 4);
	
	unsigned short spu_cmd_id = 0xA0;
	unsigned short spu_cmd_size = 0x64;
	memcpy(udata_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(udata_cmd_buf + 0x12, &spu_cmd_size, 2);
	
	
	unsigned char plain_cdb[4] = {0};
	plain_cdb[0] = 0xE1; //opcode
	plain_cdb[2] = 0x54; //arglen
	memcpy(udata_cmd_buf + 0x14, plain_cdb, 4);
	
	unsigned char encrypted_cdb[8] = {0};
	encrypted_cdb[0] = ENC_CMD_USERDATA;
	generate_rnd (encrypted_cdb + 6, 1);
	encrypted_cdb[7] = generate_check_code (encrypted_cdb, 7);
	if (des3_encrypt_cbc(sv_auth.ks1, ivs_3des, encrypted_cdb, udata_cmd_buf + 0x18, 8) != 0)
		return -15;
	
	unsigned char encrypted_arg[0x50] = {0};  //must be encrypted with session key (ks1)
	
	fprintf(stdout, "sv_udata_command: mode: 0x%08X\n", sv_auth.m_mode);
	
	switch (sv_auth.m_mode)
	{
		case 0:
			memcpy(encrypted_arg + 4, user_param_u0, USER_PARAM_SIZE);
			break;
		case 1:
			memcpy(encrypted_arg + 4, user_param_u1, USER_PARAM_SIZE);
			break;
		case 2:
		case 12:
			memcpy(encrypted_arg + 4, user_param_u2, USER_PARAM_SIZE);
			break;
		case 3:
		case 13:
		case 14:
			memcpy(encrypted_arg + 4, user_param_u3, USER_PARAM_SIZE);
			break;
		case 4:
		case 20:
			memcpy(encrypted_arg + 4, user_param_u4, USER_PARAM_SIZE);
			break;
		default:
			return -10;
			break;
	}

	generate_rnd(encrypted_arg + 1, 1);
	encrypted_arg[0] = generate_check_code(encrypted_arg + 1, 0x4F);

	if (aes_encrypt_cbc(sv_auth.ks1, 128, ivs_aes, encrypted_arg, udata_cmd_buf + 0x28, 0x50) != 0)
		return -11;

	unsigned char plain_arg[4] = {0};
	plain_arg[0] = 0;      //encrypted arglen MSB
	plain_arg[1] = 0x50;   //encrypted arglen LSB
	memcpy (udata_cmd_buf + 0x24, plain_arg, 4);

	//dump_data(udata_cmd_buf, 0x90);
	
	//copy command buffer to "shared LS"
	memcpy(packet_buffer, udata_cmd_buf, 0x90);
	return 0;
}

