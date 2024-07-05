#include "common.h"
#include "keys.h"
#include "crypto.h"
#include "sv_auth.h"
#include "sv_command.h"
#include "sv_udata_command.h"


int main(int argc, char* argv[])
{
	int result, stopcode;
	result = 0;

	// init RNG
	srand((unsigned int)time(0));

	set_eid_root_key();

	result = decrypt_eid4();
	if (result != 0)
	{
		fprintf(stderr, "decrypt_eid4() failed: %d\n", result);
		goto fail;
	}

	//setup mode
	sv_auth.m_mode = 0xD;  //PS3 Disc AUTH
	sv_auth.m_retry_flag = RETRY_FLAG_ALLOW;

	//authenticate supervisor
	result = auth_drive_super();

	//mode 0x46 (Drive Auth)
	if (sv_auth.m_mode == 0x46)
	{
		if (result != 0)
		{
			fprintf(stderr, "auth_drive_super() failed: %d\n", result);
			stopcode = 0x10B;
			goto fail;
		}

		sv_auth.m_mode = 0x4;
		result = set_user_parameter();
		if (result != 0)
		{
			fprintf(stderr, "set_user_parameter() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		result = auth_drive_user();
		if (result != 0)
		{
			fprintf(stderr, "auth_drive_user() failed: %d\n", result);
			goto fail;
		}

		fprintf(stdout, "sv_auth.ks1:\n");
		dump_data(sv_auth.ks1, 0x10);
		fprintf(stdout, "sv_auth.ks2:\n");
		dump_data(sv_auth.ks2, 0x10);
		goto done;
	}

	if (result != 0)
	{
		fprintf(stderr, "auth_drive_super() failed: %d\n", result);
		stopcode = 0x103;
		goto fail;
	}

	if (sv_auth.m_mode <= 0x4)
	{
		result = set_user_parameter();
		if (result != 0)
		{
			fprintf(stderr, "set_user_parameter() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		result = auth_drive_user();
		if (result != 0)
		{
			fprintf(stderr, "auth_drive_user() failed: %d\n", result);
			goto fail;
		}

		//Auth Data:
		fprintf(stdout, "sv_auth.ks1:\n");
		dump_data(sv_auth.ks1, 0x10);
		fprintf(stdout, "sv_auth.ks2:\n");
		dump_data(sv_auth.ks2, 0x10);
		goto done;
	}

	//mode 0xD (PS3 Disc Auth)
	if (sv_auth.m_mode == 0xD)
	{
		result = set_user_parameter();
		if (result != 0)
		{
			fprintf(stderr, "set_user_parameter() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		unsigned char *contents_key = malloc(0x10);
		unsigned char *misc_wm = malloc(0x10);
		unsigned long long *disc_mode = malloc(sizeof(unsigned long long));
		memset(contents_key, 0, 0x10);
		memset(misc_wm, 0, 0x10);
		memset(disc_mode, 0, sizeof(unsigned long long));

		result = get_wm3(contents_key, misc_wm, disc_mode);
		if (result == -2)
		{
			fprintf(stderr, "get_wm3() failed: %d\n", result);
			stopcode = 0x104;
			goto fail;
		}
		else if (result != 0)
		{
			fprintf(stderr, "get_wm3() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		fprintf(stdout, "Contents Key:\n");
		dump_data(contents_key, 0x10);
		fprintf(stdout, "Misc WM:\n");
		dump_data(misc_wm, 0x10);

		//TODO:
		//sb_set_key(entry_no = 0, sb_rev, ...., contents_key)

		unsigned char *disc_id = malloc(0x10);
		memset(disc_id, 0, 0x10);
		result = get_disc_id(misc_wm, disc_id);
		if (result != 0)
		{
			fprintf(stderr, "get_disc_id() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		//Auth Data:
		fprintf(stdout, "Disc ID:\n");
		dump_data(disc_id, 0x10);
		fprintf(stdout, "Disc Mode: %llx %s\n", (unsigned long long)*disc_mode, (*disc_mode == 2) ? "(DEBUG)" : (*disc_mode == 1) ? "(RELEASE)" : "(UNKNOWN)");
		fprintf(stdout, "sv_auth.ks1:\n");
		dump_data(sv_auth.ks1, 0x10);
		
		unsigned char auth_data[0x30] = {0};
		memcpy(auth_data, disc_id, 0x10);
		memcpy(auth_data + 0x10, disc_mode, sizeof(unsigned long long));
		memcpy(auth_data + 0x20, sv_auth.ks1, 0x10);
		
		fprintf(stdout, "Auth Data:\n");
		dump_data(auth_data, 0x30);
		goto done;
	}

	//mode 0xC (PS2 Disc Auth)
	if (sv_auth.m_mode == 0xC)
	{
		result = set_user_parameter();
		if (result != 0)
		{
			fprintf(stderr, "set_user_parameter() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}
		unsigned char layer = 0; //passed from ppu, chosen by fair dice roll ;)
		unsigned char area = 0;  //passed from ppu, chosen by fair dice roll ;)
		unsigned int lba = 1;    //passed from ppu, chosen by fair dice roll ;)
		unsigned char *buf1 = malloc(1);
		unsigned char *buf2 = malloc(0x30);
		memset(buf1, 0, 1);
		memset(buf2, 0, 0x30);

		result = get_wm2(layer, area, lba, buf1, buf2);
		if (result == -2)
		{
			fprintf(stderr, "get_wm2() failed: %d\n", result);
			stopcode = 0x104;
			goto fail;
		}
		else if (result != 0)
		{
			fprintf(stderr, "get_wm2() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		//Auth Data:
		unsigned char auth_data[0x40] = {0};
		memcpy(auth_data, buf1, 1);
		memcpy(auth_data + 8, buf2, 0x30);

		fprintf(stdout, "Auth Data:\n");
		dump_data(auth_data, 0x40);
		goto done;
	}

	
	

	//mode 0x14 (Get Version)
	if (sv_auth.m_mode == 0x14)
	{
		result = set_user_parameter();
		if (result != 0)
		{
			fprintf(stderr, "set_user_parameter() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		unsigned char *version_buf = malloc(0x40);
		memset(version_buf, 0, 0x40);

		result = get_version(version_buf);
		if (result != 0)
		{
			fprintf(stderr, "get_version() failed: %d\n", result);
			stopcode = 0x103;
			goto fail;
		}

		fprintf(stdout, "Version:\n");
		dump_data(version_buf, 0x40);
		goto done;
	}

	goto done;

fail:
	fprintf(stderr, "Stopcode: %#4x\n", stopcode);
	return result;

done:
	fprintf(stdout, "Success!\n");
	return 0;
}
