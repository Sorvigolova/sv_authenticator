#include "common.h"
#include "sv_command.h"
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <scsi/scsi_ioctl.h>

unsigned char generate_check_code(const unsigned char *data, int len)
{
	unsigned short check_code = 0;

	while (len--)
		check_code += *data++;

	return (~check_code);
}

void generate_rnd(unsigned char *dest, int size)
{
    unsigned char *buffer = (uint8_t*)malloc(size);
//	srand((unsigned int)time(0));  // random fail fix, srand must be initialized at main function

	int i;
	for(i = 0; i < size; i++)
      buffer[i] = (unsigned char)(rand() & 0xFF);

	memcpy(dest, buffer, size);

	free (buffer);
}

int get_atp_io_params_by_opcode(struct atp_io_params_t *params, unsigned char opcode)
{
	unsigned char atp_io_params[62][4] = {
		{0xA1, 0xC, 0, 0},  // BLANK
		{0x5B, 0xC, 0, 0},  // CLOSE TRACK/SESSION
		{0x35, 0xC, 0, 0},  // SYNCHRONIZE CACHE
		{0x04, 0xC, 1, 1},  // FORMAT UNIT
		{0x46, 0xC, 1, 1},  // GET CONFIGURATION
		{0x4A, 0xC, 1, 1},  // GET EVENT STATUS NOTIFICATION
		{0xAC, 0xC, 1, 1},  // GET PERFORMANCE
		{0x12, 0xC, 1, 1},  // INQUIRY
		{0xA6, 0xC, 0, 0},  // LOAD/UNLOAD MEDIUM
		{0xBD, 0xC, 1, 1},  // MECHANISM STATUS
		{0x55, 0xC, 2, 0},  // MODE SELECT (10)
		{0x5A, 0xC, 1, 1},  // MODE SENSE (10)
		{0x4B, 0xC, 0, 0},  // PAUSE/RESUME
		{0x45, 0xC, 0, 0},  // PLAY AUDIO(10)
		{0x47, 0xC, 0, 0},  // PLAY AUDIO MSF
		{0x48, 0xC, 0, 0},  //
		{0xBC, 0xC, 0, 0},  //
		{0x1E, 0xC, 0, 0},  // PREVENT ALLOW MEDIUM REMOVAL
		{0x28, 0xC, 3, 1},  // READ (10)
		{0xA8, 0xC, 3, 1},  // READ (12)
		{0x25, 0xC, 1, 1},  // READ CAPACITY
		{0xBE, 0xC, 3, 1},  // READ CD
		{0xB9, 0xC, 3, 1},  // READ CD MSF
		{0x51, 0xC, 1, 1},  // READ DISC INFORMATION
		{0xAD, 0xC, 1, 1},  // READ DISC STRUCTURE
		{0x23, 0xC, 1, 1},  // READ FORMAT CAPACITIES
		{0x44, 0xC, 0, 0},  // READ HEADER
		{0x52, 0xC, 1, 1},  // READ TRACK INFORMATION
		{0x42, 0xC, 1, 1},  // READ SUBCHANNEL
		{0x43, 0xC, 1, 1},  // READ TOC/PMA/ATIP
		{0x58, 0xC, 0, 0},  // REPAIR TRACK
		{0xA4, 0xC, 1, 1},  // REPORT KEY
		{0x03, 0xC, 1, 1},  // REQUEST SENSE
		{0x53, 0xC, 0, 0},  // RESERVE TRACK
		{0xBA, 0xC, 0, 0},  // SCAN
		{0x2B, 0xC, 0, 0},  // SEEK (10)
		{0xBF, 0xC, 2, 0},  // SEND DISC STRUCTURE
		{0xA2, 0xC, 0, 0},  // SECURITY PROTOCOL IN
		{0xA3, 0xC, 2, 0},  // SEND KEY
		{0x54, 0xC, 2, 0},  // SEND OPC INFORMATION
		{0xA7, 0xC, 0, 0},  // SET READ AHEAD
		{0xB6, 0xC, 2, 0},  // SET STREAMING
		{0x1B, 0xC, 0, 0},  // START STOP UNIT
		{0x4E, 0xC, 0, 0},  // STOP PLAY/SCAN
		{0x00, 0xC, 0, 0},  // TEST UNIT READY
		{0x2F, 0xC, 0, 0},  // VERIFY (10)
		{0x2A, 0xC, 2, 0},  // WRITE (10)
		{0xAA, 0xC, 2, 0},  // WRITE (12)
		{0x2E, 0xC, 2, 0},  // WRITE AND VERIFY (10)
		{0xBB, 0xC, 0, 0},  // SET CD SPEED
		{0x48, 0xC, 0, 0},  // 
		{0xDA, 0xC, 0, 0},  // 
		{0xF6, 0xC, 0, 0},  // 
		{0xF9, 0xC, 0, 0},  // 
		{0x3B, 0xC, 2, 0},  // WRITE BUFFER
		{0x3C, 0xC, 1, 1},  // READ BUFFER
		{0xD7, 0xC, 1, 1},  // d7_cmd_sacd
		{0xA5, 0xC, 0, 0},  // 
		{0x4C, 0xC, 2, 0},  // LOG SELECT
		{0x4D, 0xC, 1, 1},  // LOG SENSE
		{0xE0, 0xC, 1, 1},  // SECURE REPORT
		{0xE1, 0xC, 2, 0},  // SECURE SEND
	};
	
	//find entry
	int f;
	for (f = 0; f < 62; f++)
	{
		if ((unsigned char)(atp_io_params[f][0]) == opcode)
		{
			params->pkt_len = atp_io_params[f][1];
			params->atp_proto = atp_io_params[f][2];
			params->direction = atp_io_params[f][3];
			return 0;
		}
	}
	return -1;
}


int sendrecv()
{
	//print input packet
//	int *command_size = (int*)(packet_buffer);
//	fprintf(stdout, "Data put:\n");
//	dump_data(packet_buffer, *command_size + 0x10);
	
	
	int rbd = open("/dev/sr0", O_RDWR | O_NONBLOCK);
	struct sg_io_hdr io_hdr;
	if (rbd < 0)
		return -1;

	memset(&io_hdr, 0, sizeof(io_hdr));
	struct atp_io_params_t *atp_io_params = malloc(sizeof(struct atp_io_params_t));
	unsigned char opcode = packet_buffer[0x14];
	unsigned short spu_cmd_size = (packet_buffer[0x12] * 0x100) + (packet_buffer[0x13]);
	unsigned char sense[32];

	//geting packet len, atp protocol and direction by operation code
	if (get_atp_io_params_by_opcode(atp_io_params, opcode) != 0)
		return -1;

	//fprintf(stdout, "opcode: 0x%02X pkt_len: 0x%02X , atp_proto: 0x%02X , direction: 0x%02X , spu_cmd_size: 0x%02X\n", opcode, atp_io_params->pkt_len, atp_io_params->atp_proto, atp_io_params->direction, spu_cmd_size);

	io_hdr.interface_id = 'S';
	if (atp_io_params->direction == 0)
		io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
	
	if (atp_io_params->direction == 1)
		io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;

	io_hdr.timeout = 20000;
	io_hdr.cmdp = (void*)(packet_buffer + 0x14);
	io_hdr.cmd_len = atp_io_params->pkt_len;
	io_hdr.dxferp = (void*)(packet_buffer + 0x24);
	io_hdr.dxfer_len = spu_cmd_size - 0x10;
	io_hdr.sbp = sense;
	io_hdr.mx_sb_len = sizeof(sense);
	
	if (ioctl(rbd, SG_IO, &io_hdr) != 0)
	{
		close(rbd);
		return (-1);
	}

	close(rbd);

	if (io_hdr.status) {
		fprintf(stderr, "status %d host status %d driver status %d\n", io_hdr.status, io_hdr.host_status, io_hdr.driver_status);
		return (-1);
	}

	// print command
//	fprintf(stdout, "Data get:\n");
//	dump_data(packet_buffer, *command_size + 0x10);

//	dump_data(io_hdr.cmdp, io_hdr.cmd_len);
//	dump_data(io_hdr.dxferp, io_hdr.dxfer_len);
	return 0;
}