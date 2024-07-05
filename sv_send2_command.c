#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_send2_command.h"

int sv_send2_command_set()
{
	unsigned char send2_cmd_buf[0x40] = {0};
	memset(send2_cmd_buf, 0, 0x38);

	//header
	unsigned int payload_size = 0x30;
	memcpy(send2_cmd_buf, &payload_size, 4);
	memcpy(send2_cmd_buf + 4, &payload_size, 4);

	unsigned short spu_cmd_id = 0x82;
	unsigned short spu_cmd_size = 0x24;
	memcpy(send2_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(send2_cmd_buf + 0x12, &spu_cmd_size, 2);

	//init cdb
	void *cdb_offset = send2_cmd_buf + 0x14;	
	struct sce_send_key_cdb_t* cdb = cdb_offset;
	memset(cdb_offset, 0, 0x10);

	//fill cdb
	cdb->operation_code = 0xA3; // SEND KEY
	cdb->key_class = 0xE0;
	cdb->param_list_len[0] = 0;
	cdb->param_list_len[1] = 0x14;
	int auth_mode = sv_auth.m_auth_mode;
	if (auth_mode == AUTH_MODE_SUPER)
	{
		cdb->bd_sce_function = BD_SCE_FUNC_HOST_CHALLENGE;
	}
	else
	{
		if(auth_mode == AUTH_MODE_USER)
		{
			cdb->bd_sce_function = BD_SCE_FUNC_DRIVE_CHALLENGE;
		}
		else
		{
			return -1;
		}
	}

	//init param list
	void *args_offset = send2_cmd_buf + 0x24;
	struct sce_send_key_param_list_t* args = args_offset;

	//fill param list
	args->data_len[0] = 0;
	args->data_len[1] = 0x10;

	//encrypt m_rand2 using fix1 as aes key and set the result into the param list
	if(aes_encrypt_cbc(sv_auth.fix1, 128, giv, sv_auth.m_rand2, args->data, 0x10) != 0)
		return -3;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, send2_cmd_buf, 0x40);
	return 0;
}

int sv_send2_command_check_recved_data()
{
	//copy first 8 bytes of rand1 and second 8 bytes of rand2 to session key1
	unsigned char session_key1_buf[0x10] = {0};
	memcpy(session_key1_buf, sv_auth.m_rand1, 8);
	memcpy(session_key1_buf + 8, sv_auth.m_rand2 + 8, 8);

	//copy second 8 bytes of rand1 and first 8 bytes of rand2 to session key2
	unsigned char session_key2_buf[0x10] = {0};
	memcpy(session_key2_buf, sv_auth.m_rand1 + 8, 8);
	memcpy(session_key2_buf + 8, sv_auth.m_rand2, 8);

	//encrypt session key1 using kms1 key
	if (aes_encrypt_cbc(kms1, 128, giv, session_key1_buf, sv_auth.ks1, 0x10) != 0)
		return -3;

	//encrypt session key2 using kms2 key
	if (aes_encrypt_cbc(kms2, 128, giv, session_key2_buf, sv_auth.ks2, 0x10) != 0)
		return -3;

	return 0;
}