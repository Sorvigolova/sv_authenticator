#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_command.h"
#include "sv_send0_command.h"
#include "sv_send2_command.h"
#include "sv_report0_command.h"
#include "sv_udata_command.h"
#include "sv_wm_command.h"
#include "sv_wm2_command.h"
#include "sv_getver_command.h"
#include "sv_auth.h"


int authenticate_common(unsigned int auth_mode, unsigned int allow_retry)
{
	sv_auth.m_auth_mode = auth_mode;
	//check fix values
	unsigned char zeroes[0x10] = {0};
	if (memcmp(sv_auth.fix1, zeroes, 0x10) == 0)
		return -1;

	if (memcmp(sv_auth.fix2, zeroes, 0x10) == 0)
		return -1;

	//send0
	sv_send0_command_set();

	if (sendrecv() != 0)
		return -1;

	//report0
	sv_report0_command_set();

	if (sendrecv() != 0)
		return -1;

	//check reported data
	int result = sv_report0_command_check_recved_data();

	if (result !=0)
	{
		fprintf(stderr, "authenticate_common :: allow_retry: %d\n", allow_retry);

		if(allow_retry == ALLOW_RETRY_YES)
		{
			return -8;
		}
		else
		{
			return -1;
		}
	}

	//send2
	sv_send2_command_set();

	if (sendrecv() != 0)
		return -1;

	//set session keys at this step
	result = sv_send2_command_check_recved_data();
	return result;
}

int auth_drive_super()
{
	unsigned int auth_mode, allow_retry;
	memcpy(sv_auth.fix1, sv_auth.kf1_eid, 0x10);
	memcpy(sv_auth.fix2, sv_auth.kf2_eid, 0x10);

	if(sv_auth.m_retry_flag == RETRY_FLAG_ALLOW)
	{
		auth_mode = AUTH_MODE_SUPER;
		allow_retry = ALLOW_RETRY_YES;
	}
	else
	{
		auth_mode = AUTH_MODE_SUPER;
		allow_retry = ALLOW_RETRY_NO;
	}

	int result = authenticate_common(auth_mode, allow_retry);
	if (result == -8)
	{
		memcpy(sv_auth.fix1, fix1_it, 0x10);
		memcpy(sv_auth.fix2, fix2_it, 0x10);
		auth_mode = AUTH_MODE_SUPER;
		allow_retry = ALLOW_RETRY_YES;
		result = authenticate_common(auth_mode, allow_retry);
		if (result == -8)
		{
			memcpy(sv_auth.fix1, fix1_pn, 0x10);
			memcpy(sv_auth.fix2, fix2_pn, 0x10);
			auth_mode = AUTH_MODE_SUPER;
			allow_retry = ALLOW_RETRY_NO;
			result = authenticate_common(auth_mode, allow_retry);
		}
	}

	return result;
}

int auth_drive_user()
{
	switch (sv_auth.m_mode)
	{
		case 0:
			memcpy(sv_auth.fix1, Kf1_u0, 0x10);
			memcpy(sv_auth.fix2, Kf2_u0, 0x10);
			break;
		case 1:
			memcpy(sv_auth.fix1, Kf1_u1, 0x10);
			memcpy(sv_auth.fix2, Kf2_u1, 0x10);
			break;
		case 2:
		case 12:
			memcpy(sv_auth.fix1, Kf1_u2, 0x10);
			memcpy(sv_auth.fix2, Kf2_u2, 0x10);
			break;
		case 3:
		case 13:
		case 14:
			memcpy(sv_auth.fix1, Kf1_u3, 0x10);
			memcpy(sv_auth.fix2, Kf2_u3, 0x10);
			break;
		case 4:
		case 20:
			memcpy(sv_auth.fix1, Kf1_u4, 0x10);
			memcpy(sv_auth.fix2, Kf2_u4, 0x10);
			break;
		default:
			return -15;
			break;
	}

	unsigned int auth_mode, allow_retry;
	auth_mode = AUTH_MODE_USER;
	allow_retry = ALLOW_RETRY_NO;

	int result = authenticate_common(auth_mode, allow_retry);

	return result;
}

int set_user_parameter()
{
	sv_udata_command_set();
	
	if (sendrecv() != 0)
		return -1;

	return 0;
}

int get_version(unsigned char *version)
{
	sv_getver_command_set();

	if (sendrecv() != 0)
		return -1;
	
	if (sv_getver_check_recved_data(version) != 0)
		return -1;

	return 0;
}

int set_contents_key(unsigned char *wm3_data1, unsigned char *contents_key, unsigned long long *disc_mode)
{
	unsigned long long dm;

	if (memcmp(wm3_data1, PS3_L_DEBUG_DISC, 0x10) == 0)
	{
		memcpy(contents_key, intikey, 0x10);
		dm = PS3_DISC_DEBUG_MODE;
	}
	else
	{
		if (aes_encrypt_cbc(Kh, 128, IVh, wm3_data1, contents_key, 0x10) != 0)		
			return -3;

		dm = PS3_DISC_RELEASE_MODE;
	}

	memcpy(disc_mode, &dm, sizeof(unsigned long long));
	return 0;
}

int  set_misc_wm(unsigned char *wm3_data2, unsigned char *misc_wm)
{
	if (aes_decrypt_cbc(Kwm, 128, giv, wm3_data2, misc_wm, 0x10) != 0)
		return -3;

	return 0;
}

int get_wm3(unsigned char *contents_key, unsigned char *misc_wm, unsigned long long *disc_mode)
{
	sv_wm_command_set();

	if (sendrecv() != 0)
		return -1;

	unsigned char wm_buf[0x30] = {0};

	if (sv_wm_command_check_recved_data(wm_buf) != 0)
		return -1;

	fprintf(stdout, "WM3 buf:\n");
	dump_data(wm_buf, 0x30);

	int result = set_contents_key(wm_buf + 3, contents_key, disc_mode);
	if (result != 0)
		return result;

	result = set_misc_wm(wm_buf + 0x13, misc_wm);
	if (result != 0)
		return result;

	return 0;
}

int get_disc_id(unsigned char *misc_wm, unsigned char *disc_id)
{
	unsigned char buf[0x10] = {0};
	memcpy(buf + 0xB, misc_wm + 0xB, 5);

	if (aes_encrypt_cbc(Kdid, 128, zero_iv, buf, disc_id, 0x10) != 0)		
		return -3;

	return 0;
}

int get_wm2(unsigned char layer, unsigned char area, unsigned int lba, unsigned char *buf1, unsigned char *buf2)
{
	sv_wm2_command_set(layer, area, lba);
	
	if (sendrecv() != 0)
		return -1;
	
	sv_wm2_command_check_recved_data(buf1, buf2);
	
	
	
	return 0;
}