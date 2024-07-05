#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_wm2_command.h"

int sv_wm2_command_set(unsigned char layer, unsigned char area, unsigned int lba)
{
	unsigned char wm2_cmd_buf[0x80] = {0};
	
	//header
	unsigned int payload_size = 0x70;
	memcpy(wm2_cmd_buf, &payload_size, 4);
	memcpy(wm2_cmd_buf + 4, &payload_size, 4);
	
	
	unsigned short spu_cmd_id = 0xB1;
	unsigned short spu_cmd_size = 0x54;
	memcpy(wm2_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(wm2_cmd_buf + 0x12, &spu_cmd_size, 2);
	
	//init cdb
	void *cdb_offset = wm2_cmd_buf + 0x14;	
	memset(cdb_offset, 0, 0x10);

	unsigned char plain_cdb[4] = {0};
	plain_cdb[0] = 0xE0; //opcode SECURE REPORT
	plain_cdb[2] = 0x44; //arglen
	memcpy(cdb_offset, plain_cdb, 4);
	
	
	unsigned char encrypted_cdb[8] = {0};
	encrypted_cdb[0] = ENC_CMD_PS2DISC;
	encrypted_cdb[1] = (lba & 0xFF000000)>>0x18;   //MSB lba
	encrypted_cdb[2] = (lba & 0xFF0000)>>0x10;     // lba
	encrypted_cdb[3] = (lba & 0xFF00)>>8;          // lba
	encrypted_cdb[4] = (lba & 0xFF);               //lba LSB
	encrypted_cdb[5] = (area & 0xF)|(layer << 4);  //MSB 4bits layer, 4bits area LSB
	generate_rnd (encrypted_cdb + 6, 1);
	encrypted_cdb[7] = generate_check_code (encrypted_cdb, 7);
	if (des3_encrypt_cbc(sv_auth.ks1, ivs_3des, encrypted_cdb, wm2_cmd_buf + 0x18, 8) != 0)
		return -3;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, wm2_cmd_buf, 0x80);
	return 0;
}


int sv_wm2_command_check_recved_data(unsigned char *buf1, unsigned char *buf2)
{
	unsigned char wm2_buf[0x40] = {0};
	memcpy(wm2_buf, packet_buffer + 0x28, 0x40);
	
	//remove session key1 encryption layer
	if (aes_decrypt_cbc(sv_auth.ks1, 128, ivs_aes, wm2_buf, wm2_buf, 0x40) != 0)
		return -15;
	
	//verify check code
	unsigned char checkcode = generate_check_code(wm2_buf + 1, 0x3F);
	if(wm2_buf[0] != checkcode)
		return -16;

	//remove session key2 encryption layer
	if (aes_decrypt_cbc(sv_auth.ks2, 128, ivs_aes, wm2_buf + 3, wm2_buf + 3, 0x10) != 0)
		return -17;

	if (aes_decrypt_cbc(sv_auth.ks2, 128, ivs_aes, wm2_buf + 0x13, wm2_buf + 0x13, 0x10) != 0)
		return -18;
	
	if (aes_decrypt_cbc(sv_auth.ks2, 128, ivs_aes, wm2_buf + 0x23, wm2_buf + 0x23, 0x10) != 0)
		return -19;

	if (aes_decrypt_cbc(Kwm, 128, giv, wm2_buf + 3, wm2_buf + 3, 0x10) != 0)
		return -17;
	
	if (aes_decrypt_cbc(Kwm, 128, giv, wm2_buf + 0x13, wm2_buf + 0x13, 0x10) != 0)
		return -18;

	if (aes_decrypt_cbc(Kwm, 128, giv, wm2_buf + 0x23, wm2_buf + 0x23, 0x10) != 0)
		return -19;
	
	
	fprintf(stdout, "WM2 BUF:\n");
	dump_data(wm2_buf, 0x40);
	
	memcpy(buf1, wm2_buf + 2, 1);
	memcpy(buf2, wm2_buf + 3, 0x30);
	return 0;
}