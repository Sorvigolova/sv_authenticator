#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_report0_command.h"

int sv_report0_command_set()
{
	unsigned char report0_cmd_buf[0x50] = {0};

	//header
	unsigned int payload_size = 0x40;
	memcpy(report0_cmd_buf, &payload_size, 4);
	memcpy(report0_cmd_buf + 4, &payload_size, 4);

	unsigned short spu_cmd_id = 0x90;
	unsigned short spu_cmd_size = 0x34;
	memcpy(report0_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(report0_cmd_buf + 0x12, &spu_cmd_size, 2);

	//init cdb
	void *cdb_offset = report0_cmd_buf + 0x14;	
	struct sce_report_key_cdb_t* cdb = cdb_offset;
	memset(cdb_offset, 0, 0x10);

	//fill cdb
	cdb->operation_code = 0xA4; // REPORT KEY
	cdb->key_class = 0xE0;
	cdb->allocation_len[0] = 0;
	cdb->allocation_len[1] = 0x24;
	int auth_mode = sv_auth.m_auth_mode;
	if (auth_mode == AUTH_MODE_SUPER)
	{
		cdb->bd_sce_function = BD_SCE_FUNC_AUTH_SUPER_MODE;
	}
	else
	{
		if(auth_mode == AUTH_MODE_USER)
		{
			cdb->bd_sce_function = BD_SCE_FUNC_AUTH_USER_MODE;
		}
		else
		{
			return -1;
		}
	}

	//init returned data
	void *returned_data_offset = report0_cmd_buf + 0x24;
	struct sce_report_key_returned_data_t* returned_data = returned_data_offset;

	//fill returned data
	returned_data->data_len[0] = 0;
	returned_data->data_len[1] = 0x20;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, report0_cmd_buf, 0x50);
	return 0;
}

int sv_report0_command_check_recved_data()
{
	unsigned char enc_rand1[0x10] = {0};
	unsigned char dec_rand1[0x10] = {0};
	memcpy(enc_rand1, packet_buffer + 0x28, 0x10);

	//Decrypt sv_auth::m_rand1 from the drive
	aes_decrypt_cbc(sv_auth.fix2, 128, giv, enc_rand1, dec_rand1, 0x10);

	//Check sv_auth::m_rand1
	if (memcmp(dec_rand1, sv_auth.m_rand1, 0x10) != 0)
		return -2;

	unsigned char enc_rand2[0x10] = {0};
	memcpy(enc_rand2, packet_buffer + 0x38, 0x10);

	//Decrypt and set sv_auth::m_rand2 from the drive to host
	aes_decrypt_cbc(sv_auth.fix2, 128, giv, enc_rand2, sv_auth.m_rand2, 0x10);

	//Check rands, they must not be same
	if  (memcmp(sv_auth.m_rand1, sv_auth.m_rand2, 0x10) == 0)
		return -3;

	return 0;
}