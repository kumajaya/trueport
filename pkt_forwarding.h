//*****************************************************************************
//
//	pkg_fowarding.h
//
//	This file provides access to the packet forwarding initialization, 
//	configuration, and running routines and structures.
//
//******************************************************************************


//#define SERIAL_DEBUG_FORWARDING		

#if defined(SERIAL_DEBUG_FORWARDING)
  #define 	DEBUG_FORWARDING( trace )  (trace)
#else
  #define	DEBUG_FORWARDING(trace)
#endif


// forwarding field
#define PKT_FORWARD_ON_COUNT        0x0001
#define PKT_FORWARD_ON_IDLE         0x0002
#define PKT_FORWARD_ON_TIME         0x0004
#define PKT_FORWARD_ON_CHAR1        0x0010
#define PKT_FORWARD_ON_CHAR2        0x0020
#define PKT_FORWARD_START_CHAR1     0x0100
#define PKT_FORWARD_START_CHAR2     0x0200
#define PKT_FORWARD_END_CHAR1       0x1000
#define PKT_FORWARD_END_CHAR2       0x2000

// transmit rules
#define PKT_FORWARD_TRANS_TRIG      0
#define PKT_FORWARD_TRANS_TRIG_1    1
#define PKT_FORWARD_TRANS_TRIG_2    2
#define PKT_FORWARD_TRANS_STRIP     3


// forwarding options

#define PKT_FORWARD_ON_CHAR		(PKT_FORWARD_ON_CHAR1|PKT_FORWARD_ON_CHAR2)
#define PKT_FORWARD_ON_FRAME		(PKT_FORWARD_START_CHAR1|PKT_FORWARD_START_CHAR2|PKT_FORWARD_END_CHAR1|PKT_FORWARD_END_CHAR2)

#define FORWARD_STATE_START_1OF1        0
#define FORWARD_STATE_START_1OF2        1
#define FORWARD_STATE_START_2OF2        2
#define FORWARD_STATE_END_1OF1          3
#define FORWARD_STATE_END_1OF2          4
#define FORWARD_STATE_END_2OF2          5
#define FORWARD_STATE_WAITING_1OF1      6
#define FORWARD_STATE_WAITING_1OF2      7
#define FORWARD_STATE_WAITING_2OF2      8

// Packet Forwarding parameter defines 
#define MAX_PKT_FWD_BUF_SIZE 	 	 DEFAULT_OUT_WINDOW_SIZE
#define MAX_DATA_PKT_FWD_COUNT 	 	 1024
#define DEFAULT_PKT_FWD_BUF_SIZE   0


#define DEFAULT_PKT_FWD_CFG_FILE		"/etc/trueport/pktfwdcfg.tp"


typedef struct {
	unsigned char	data[ MAX_PKT_FWD_BUF_SIZE ];
	unsigned char 	*data_ptr;     /* position of start of data */
	int     		len;        /* length of data in buffer */
} buf_t2;

// as of version 6.2.0 the packet forwarding buffer contain data packets
// and some TruePort commands
typedef struct forwarding_info {
	// forwarding config
	unsigned short		forwarding;        	// options for packet forwarding
    unsigned short    start_transmit_rule;
    unsigned short    end_transmit_rule;
	unsigned short		packet_size;       	// maximum packet size
	unsigned short		idle_time;         	// idle time in msec
	unsigned short		force_time;        	// time to force transmit in msec
	unsigned char		trigger_char1;     	// transmit if char is encountered
	unsigned char		trigger_char2;     	// transmit if char is encountered
	unsigned char		start_frame1;      	// start of frame marker
	unsigned char		start_frame2;      	// start of frame marker
	unsigned char		end_frame1;        	// end of frame marker
	unsigned char		end_frame2;        	// end of frame marker
	// forwarding state info
	unsigned int		forward_state; 		// state of forwarding
    unsigned int  		base_state;   		// starting state
    unsigned int   	stored_char;  			// was the char saved in the flip buf
    unsigned char     saved_ch;     		// save char for later
    struct timeval		idle_time_start;	// start time for idle forwarding
	struct timeval		force_time_start;	// start time for forced forwarding.
	struct timeval		keepalive_start;	// start time for keepalive timer.
	struct timeval		delay_close_tcp_start; // start time for delay close of tcp on tty close
	unsigned char			dscmd;				// indicate in-line commands that need to put in pkt fwd buffer

	// forwarding buffer
	unsigned char		*char_buf_ptr;
	int		        	count;
	unsigned short		data_count;							// count of only the data
	unsigned short		curr_data_count;					// current data pkt data count when using new pkt fwd logic
	unsigned char		*pCurrDataPkt;						// this a pointer to the current data pkt
	unsigned char		char_buf[MAX_PKT_FWD_BUF_SIZE];
	int					write_blocked;
} forwarding_info_t;

void process_packet_forwarding( forwarding_info_t *info, buf_t2 *buf );
void forward_frame( forwarding_info_t *info );
struct timeval *set_time_out( forwarding_info_t *info, struct timeval *time_out);
int check_time_out( struct timeval *start_time, unsigned short time_out );
int get_pkt_fwd_config( forwarding_info_t *pInfo, char *tcp_host, int net_port_num );
int read_and_verify_input(	char *input, long lower_limit, long upper_limit, int  format, void *retValue );
							 
int UseNewPktFwdLogic(forwarding_info_t *pInfo);
int ChkPutDsCmdPktFwdBuf(forwarding_info_t *pInfo, char *dscmd_ptr, int dscmd_size);

extern int		pkt_fwd_enabled;


