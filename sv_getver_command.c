#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_getver_command.h"

int sv_getver_command_set()
{
	unsigned char getver_cmd_buf[0x90] = {0};

	//header
	unsigned int payload_size = 0x80;
	memcpy(getver_cmd_buf, &payload_size, 4);
	memcpy(getver_cmd_buf + 4, &payload_size, 4);

	unsigned short spu_cmd_id = 0xC0;
	unsigned short spu_cmd_size = 0x64;
	memcpy(getver_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(getver_cmd_buf + 0x12, &spu_cmd_size, 2);

	//plain cdb
	unsigned char plain_cdb[4] = {0};
	plain_cdb[0] = 0xE0; //opcode
	plain_cdb[2] = 0x54; //arglen
	memcpy(getver_cmd_buf + 0x14, plain_cdb, 4);

	//encrypted cdb
	unsigned char encrypted_cdb[8] = {0};
	encrypted_cdb[0] = ENC_CMD_GETVER;
	generate_rnd (encrypted_cdb + 6, 1);
	encrypted_cdb[7] = generate_check_code (encrypted_cdb, 7);
	if (des3_encrypt_cbc(sv_auth.ks1, ivs_3des, encrypted_cdb, getver_cmd_buf + 0x18, 8) != 0)
		return -3;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, getver_cmd_buf, 0x90);
	return 0;
}

int sv_getver_check_recved_data(unsigned char *version)
{
	unsigned char version_buf[0x50] = {0};
	memcpy(version_buf, packet_buffer + 0x28, 0x50);

	if (aes_decrypt_cbc(sv_auth.ks1, 128, ivs_aes, version_buf, version_buf, 0x50) != 0)
		return -15;

	//verify check code
	unsigned char checkcode = generate_check_code(version_buf + 1, 0x4F);
	if(version_buf[0] != checkcode)
		return -10;

	//copy 0x40 bytes from decrypted data at offset 2 to the destination
	memcpy(version, version_buf + 2, 0x40);
	return 0;
}