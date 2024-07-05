
enum {
	ENC_CMD_USERDATA = 0,
	ENC_CMD_PS2DISC = 2,
	ENC_CMD_PS3DISC = 3,
	ENC_CMD_GETVER = 4,
};

struct  __attribute__ ((packed)) atp_io_params_t {
	unsigned char pkt_len;
	unsigned char atp_proto;
	unsigned char direction;
};

struct __attribute__ ((packed)) sce_send_key_cdb_t
{
	unsigned char operation_code;
	unsigned char reserved[6];
	unsigned char key_class;
	unsigned char param_list_len[2];
	unsigned char bd_sce_function;
	unsigned char control;
};

struct __attribute__ ((packed)) sce_send_key_param_list_t {
	unsigned char data_len[2];
	unsigned char reserved[2];
	unsigned char data[0];
};

struct __attribute__ ((packed)) sce_report_key_cdb_t
{
	unsigned char operation_code;
	unsigned char reserved[6];
	unsigned char key_class;
	unsigned char allocation_len[2];
	unsigned char bd_sce_function;
	unsigned char control;
};

struct __attribute__ ((packed)) sce_report_key_returned_data_t {
	unsigned char data_len[2];
	unsigned char reserved[2];
	unsigned char data[0];
};


unsigned char generate_check_code(const unsigned char *data, int len);

void generate_rnd(unsigned char *dest, int size);

int sendrecv();
