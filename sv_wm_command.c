#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_wm_command.h"


int sv_wm_command_set()
{
	unsigned char wm_cmd_buf[0x70] = {0};

	//header
	unsigned int payload_size = 0x60;
	memcpy(wm_cmd_buf, &payload_size, 4);
	memcpy(wm_cmd_buf + 4, &payload_size, 4);

	unsigned short spu_cmd_id = 0xB0;
	unsigned short spu_cmd_size = 0x44;
	memcpy(wm_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(wm_cmd_buf + 0x12, &spu_cmd_size, 2);

	//init cdb
	void *cdb_offset = wm_cmd_buf + 0x14;	
	memset(cdb_offset, 0, 0x10);

	unsigned char plain_cdb[4] = {0};
	plain_cdb[0] = 0xE0; //opcode SECURE REPORT
	plain_cdb[2] = 0x34; //arglen
	memcpy(cdb_offset, plain_cdb, 4);

	unsigned char encrypted_cdb[8] = {0};
	encrypted_cdb[0] = ENC_CMD_PS3DISC;
	generate_rnd (encrypted_cdb + 6, 1);
	encrypted_cdb[7] = generate_check_code (encrypted_cdb, 7);
	if (des3_encrypt_cbc(sv_auth.ks1, ivs_3des, encrypted_cdb, wm_cmd_buf + 0x18, 8) != 0)
		return -3;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, wm_cmd_buf, 0x70);
	return 0;
}


int sv_wm_command_check_recved_data(unsigned char *wm)
{
	unsigned char wm_buf[0x30] = {0};
	memcpy(wm_buf, packet_buffer + 0x28, 0x30);

	//remove session key1 encryption layer
	if (aes_decrypt_cbc(sv_auth.ks1, 128, ivs_aes, wm_buf, wm_buf, 0x30) != 0)
		return -3;

	//verify check code
	unsigned char checkcode = generate_check_code(wm_buf + 1, 0x2F);
	if(wm_buf[0] != checkcode)
		return -1;

	//remove session key2 encryption layer
	if (aes_decrypt_cbc(sv_auth.ks2, 128, ivs_aes, wm_buf + 3, wm_buf + 3, 0x10) != 0)
		return -3;

	if (aes_decrypt_cbc(sv_auth.ks2, 128, ivs_aes, wm_buf + 0x13, wm_buf + 0x13, 0x10) != 0)
		return -3;

	memcpy(wm, wm_buf, 0x30);
	return 0;
}
