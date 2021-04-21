//*********************************************************************
// File: trueport.h
//
// Description: trueport Dameon Definitions for trueport
//
// Copyright (c) 1999-2009 Perle Systems Limited. All rights reserved.
//
//*********************************************************************

/****************************************************************************
 *	Type definitions    						    *
 ****************************************************************************/

typedef struct 
{
	unsigned char   data [DS_BUF_SIZE];
	int offset;     /* position of start of data */
	int     len;        /* length of data in buffer */
} buf_t;

typedef struct 
{
	unsigned char   data [DS_BUF_SIZE];
	int 	woffset;     /* position of start of data */
	int     len;        /* length of data in buffer */
	int		roffset;		// position of data to read
} bufqueue_t;


typedef enum 
{
   tl_none, tl_error, tl_status, tl_info, tl_debug, tl_data
} trace_level_t;

typedef struct
{
	unsigned char command;
	unsigned char sequence_no;
} udp_response_t;

typedef enum
{
    s_initial, s_sent_packet_req, s_wait_port_number, s_data_transfer
} state_t;

typedef int dserver_packet_t;


extern buf_t	dserver_in_buf;         // data read from device server
extern buf_t	dserver_out_buf;
extern bufqueue_t	qbuf;
extern int		dserver_fd;
extern int		keepalive_time;			// Time in seconds for keepalive
extern int		delay_close_tcp_time;	// Time in seconds to delay tpc close
extern char	*client_tcp_host;
extern int 	delay_close_tcp_flag;
extern int		retry_time;
extern unsigned short retry_num_left;
extern unsigned int ptyx_ctrl_status;		//  ctrl_status from ptyx driver
extern protocol_mode_t mode;


//******************************************************************************
// trueport daemon proto-types
void close_connection(void);
void drop_modem_signals(void);
int is_tp_conn_avail(void);
void initialise_connection_state(void);
void catch_signal(int sig_num);
void close_tty_common(int rmdev);
void	trace(trace_level_t level, char *msg, ...);
int buf_append(buf_t *buf, char *data, int len);
void buf_init(buf_t *buf);
void qbuf_init(bufqueue_t *buf);
int buf_insert(buf_t *buf, char *data, int len);
void cleanup(void);
void close_connection();
void close_tty(void);
int convert_hex_str(char *dest_str, char *src_str);
void handle_signal(int signum);
void initialise_connection_state();
int make_path(char *path);
void make_restore_script(char *filename);
int open_tty();
int read_dserver(int fd, dserver_packet_t *type, buf_t * buf, int tty_write_blocked, int read_queue);
int	process_dserver_queue( int fd, dserver_packet_t *type, buf_t * buf, short *count, short *header, int tty_write_blocked  );
int read_dserver_udp_message(udp_response_t *udp_response);
void set_dserver_modes(int set_all);
int setup_udp_socket(void);

void timer_handler( int sig );
void update_input_window(int n);
int wait_for_dserver_connection(void);
int write_buf_raw( int fd, unsigned char *buf, int size );
int write_dserver_ctrl(int fd, int cmd);
int write_dserver_udp_ctrl(int cmd);
int write_dserver_udp_ctrl_wait(int command);

int write_tty_ctrl(int fd, int cmd, unsigned char *data, unsigned int len);
int pbytes(int bytesps);
void set_hangup(void);
int tp_read( int fd, unsigned char *buf, int size );
int wait_for_tty_open_close(struct timeval *ptim);
int wait_for_tcp_connect(void);
int wait_for_tcp_listen(void);
int wait_for_ssl_connect(int nsfd);
int read_dserver_iodata_wait(int fd, dserver_packet_t *type, buf_t * buf);
void do_open(char open_mode);
int dserver_out_available(forwarding_info_t *pInfo);
void drop_modem_signals(void);
BOOL is_tp_conn_avail(void);
uint32_t get_tps_feat(unsigned char *data,int datalen);
void set_RTS_DTR(int rts, int dtr);
int write_dserver_imm_ctrl(int fd, int cmd,  unsigned char data);
BOOL IsNoUDP(void);
int process_tty_ctrl();
void dump_buf(FILE *fd, unsigned char * buf, int len);





