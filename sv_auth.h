#ifndef __SV_AUTH_H__
#define __SV_AUTH_H__

struct __attribute__ ((packed)) sv_auth_t
{
	unsigned int m_mode;
	unsigned int m_auth_mode;
	unsigned short m_retry_flag;
	unsigned char kf1_eid[0x10];
	unsigned char kf2_eid[0x10];
	unsigned char fix1[0x10];
	unsigned char fix2[0x10];
	unsigned char m_rand1[0x10];
	unsigned char m_rand2[0x10];
	unsigned char ks1[0x10];
	unsigned char ks2[0x10];
};

struct sv_auth_t sv_auth;

#endif


enum {
	MODE_BD_VOUCHER = 0xE,
	MODE_NP_PASSPHRASE = 0xF,
	MODE_GET_VERSION = 0x14,
};

enum {
	RETRY_FLAG_ALLOW = 0,
	RETRY_FLAG_DENY = 1,
};

enum {
	ALLOW_RETRY_NO = 0,
	ALLOW_RETRY_YES = 1,
};

enum {
	AUTH_MODE_SUPER = 0,
	AUTH_MODE_USER = 1,
};

enum {
	BD_SCE_FUNC_AUTH_SUPER_MODE = 0,
	BD_SCE_FUNC_AUTH_USER_MODE = 1,
	BD_SCE_FUNC_HOST_CHALLENGE = 2,
	BD_SCE_FUNC_DRIVE_CHALLENGE = 3,
};

enum {
	PS3_DISC_RELEASE_MODE = 1,
	PS3_DISC_DEBUG_MODE = 2,
};

int auth_drive_super();

int auth_drive_user();

int set_user_parameter();

int get_wm2(unsigned char layer, unsigned char area, unsigned int lba, unsigned char *buf1, unsigned char *buf2);

int get_wm3(unsigned char *contents_key, unsigned char *misc_wm, unsigned long long *disc_mode);

int get_disc_id(unsigned char *misc_wm, unsigned char *disc_id);

int get_version(unsigned char *version);
