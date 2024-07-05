#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_send0_command.h"

int sv_send0_command_set()
{
	unsigned char send0_cmd_buf[0x40] = {0};
	
	memset(send0_cmd_buf, 0, 0x38);
	generate_rnd(sv_auth.m_rand1, 0x10);

	//header
	unsigned int payload_size = 0x30;
	memcpy(send0_cmd_buf, &payload_size, 4);
	memcpy(send0_cmd_buf + 4, &payload_size, 4);
	
	unsigned short spu_cmd_id = 0x80;
	unsigned short spu_cmd_size = 0x24;
	memcpy(send0_cmd_buf + 0x10, &spu_cmd_id, 2);
	memcpy(send0_cmd_buf + 0x12, &spu_cmd_size, 2);
	
	//init cdb
	void *cdb_offset = send0_cmd_buf + 0x14;	
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

	//init param list
	void *args_offset = send0_cmd_buf + 0x24;
	struct sce_send_key_param_list_t* args = args_offset;
	
	//fill param list
	args->data_len[0] = 0;
	args->data_len[1] = 0x10;

	//encrypt m_rand1 using fix1 as aes key and set the result into the param list
	if(aes_encrypt_cbc(sv_auth.fix1, 128, giv, sv_auth.m_rand1, args->data, 0x10) != 0)
		return -3;

	//copy command buffer to "shared LS"
	memcpy(packet_buffer, send0_cmd_buf, 0x40);
	return 0;
}