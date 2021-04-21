/*******************************************************************************
 Module: trueportd.c
 
 Description: TruePort server daemon for Linux
 
 Copyright (c) Perle Systems Limited 1999-2016
 All rights reserved
 
*******************************************************************************/

/* Linux stdlib pro ttypes two functions (grantpt, unlockpt) only when
this symbol is defined. I don't know a "neater" way to do this, andma
they don't have a manual :-( -- REW */
#define _GNU_SOURCE


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <term.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <termios.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <termio.h>
#include <asm/ioctls.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <linux/version.h>

#include <netdb.h>
#include <sys/wait.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include "ssl_tp.h"
#endif /* USE_SSL */

#include "clparse.h"
#include "tp.h"
#include "pkt_forwarding.h"
#include "trueport.h"

//****************************************************************************
// Local constant definitions					    *
//****************************************************************************
//

#define MAX_TRACE_LEN 16
#define SMSIZEOF(_STRUCT, _MEMBER) sizeof((((_STRUCT *)0)->_MEMBER))



/****************************************************************************
 *	Global data definitions						    *
 ****************************************************************************/
forwarding_info_t	info;		// structure for packet forwarding.

const char IOMBASCIIarg[] = { "mb_ascii" };
const char IOMBRTUarg[] =   { "mb_rtu" };
const char IOAPIarg[] =     { "io_api" };

#define OPMODE_NAME_OPTIMIZELAN			"optimize_lan"
#define OPMODE_NAME_LOWLATENCY			"low_latency"
#define OPMODE_NAME_PACKETIDLETIMEOUT	"packet_idle_timeout"
#define OPMODE_NAME_CUSTOM				"custom"

opmode_type_t opmode_type=OPMODE_TYPE_NONE;
/* bit definitions for DServerFeatures */
#define TPSFEAT_IOLANDS				 0x80000000		// The server is an IOLANDS that supports feature identification at session startup (ie. version >= 3.2)
#define TPSFEAT_TCPBREAKCTL		 0x40000000		// break supported on the TCP channel
#define TPSFEAT_SYNCDRAIN			 0x20000000		// synchronous drain
#define TPSFEAT_TCPXREPORT			 0x10000000		// extended report mode command (MSR & LSR info) on the TCP channel
#define TPSFEAT_NO_UDP				 0x08000000		// No UDP support
#define TPSFEAT_SYNCFLUSHENDRESET 0x04000000		// DS_TCP_SYNC_FLUSH_END reset window logic support


// TruePort feature/logic support/configured mask
#define TPSFEAT_MASK	  (TPSFEAT_IOLANDS		| \
								TPSFEAT_TCPBREAKCTL	| \
								TPSFEAT_SYNCDRAIN 	| \
								TPSFEAT_TCPXREPORT	| \
								TPSFEAT_NO_UDP			| \
								TpFeatureSupport 		| \
								TPSFEAT_SYNCFLUSHENDRESET)	

uint32_t DServerFeatures = 0;


#define MAXTTYNAMESIZE	20				// size of at least "/dev/ptyx[cm]nnnnn"
char slave_ttyname[MAXTTYNAMESIZE];
char ctrl_ttyname[MAXTTYNAMESIZE]; 
char master_ttyname[MAXTTYNAMESIZE]; 

/* Command line options */
char	*fixed_ttyname  = NULL;    // Ptr to link file name

//  Setting to 1 prevents an unlink from occuring if error occures.
char	*terminal_name	= NULL;		// Ptr to terminal name
int			tcp_port 		= -1;		/* TCP port to receive on */
int			keepalive_time 	= DEFAULT_KEEPALIVE_TIME; /* Time in seconds for keepalive */
trace_level_t	trace_level     = tl_none;	// Tracing level
protocol_mode_t mode = pm_lite; 	// Operating mode


BOOL		close_tty_flag	= FALSE;	/* Hangup - close tty ports if tcp connection is lost */
int		pkt_fwd_enabled = 0;

char	*server_tcp_host = NULL;			// server mode host IP address/name
char	*client_tcp_host = NULL;			// client mode host IP address/name
int	retry_time = DEFAULT_RETRY_TIME;
int	retry_num = DEFAULT_RETRY_NUM;
int	nodisc_tcp = 0;
int	no_tcp_nagle = 0;
char  *opmode_name;				// name of operational mode ("optimize_lan","low_latency","idle_time_packet","custom")
int idle_time_packet_timeout=DEFAULT_IDLE_TIME_PACKET_TIMEOUT;
int connect_on_init=0;  // for client initiated, if set then try to establish the TCP session immediately when loaded
int open_wait_time=DEFAULT_OPEN_WAIT_TIME;
int	delay_close_tcp_time = DEFAULT_DELAY_CLOSE_TCP_TIME;		// delay (in seconds) TCP close on slave close
int restorenet=1;		// restore failed network connection.  default is yes
int use_legacy_UDP=1;	// Use legacy UDP protocol for full mode, default is yes
char  *io_type_name;						// name of client I/O types
/******* end of command line opentions ****/

/* DEVICE_SERVER connection variables */
BOOL		dserver_connected;				/* State of DEVICE_SERVER connection */
BOOL		tty_connected = 0;					/* State of main TTY connection */
unsigned char	tp_connected = 0;	// State of TruePort connection, which include TCP, SSL and fullmode 
state_t	state;              		// State of Device Server protocol
int		dserver_fd;					// DEVICE_SERVER TCP socket
int		ipv6_not_running = 0;
int flushing_net_read=0;			// <>0 means we're discarding any data read from the network (not commands)

struct	sockaddr_in6		dserver_addr6;    	/* Address details of Device Server (remote end) */
struct	sockaddr_in6		udp_addr6;          /* address for UDP messages */
struct	sockaddr_in		dserver_addr; 	    /* Address details of Device Server (remote end) */

int		udp_sock = -1;

struct sockaddr_in		udp_addr;           /* address for UDP messages */
unsigned char   udp_sequence_no;        /* Sequence number for UDP messages */
udp_response_t  udp_response;

int 	dserver_port_no;
int current_state = 0;
int	out_window_size;   			// amount allowed to write to Device Server
int	in_window_used;				// amount read from Device Server

const int			send_bufsize	= LM_MAX_SEND_BUF_SIZE;	/* send window for DEVICE_SERVER socket(lite mode only) */

buf_t       dserver_in_buf;           /* data read from device server */
buf_t       dserver_out_buf;
bufqueue_t	qbuf = 
{
	{0}, 0, 0, 0
};


unsigned int    max_udp_retries = 20;
int 		udp_ack_timeout = 250000;	/* Timeout for UDP commands(uS) */
int 		drainpoll_period  = 500000;	/* Delay for doing drain polls(uS) */
int		keepalive_sent = 0;			// keep-alive sent flag
int slave_is_open = FALSE;

/* we use dserver_termio_modes as the master set of flags */
struct termios  dserver_termios_modes;

/* other globals */
FILE 	*trace_file;					// trace file
int		ptyxm_fd = -1;
int		ptyxc_fd = -1;

int		pty_mode = -1;  /* The permissions on the pty device */
int   pty_uid  = -1;
int   pty_gid  = -1;
unsigned int ptyx_ctrl_status=0;		// ptyx ctrl_status from ptyx driver
int end2end_ctrl=1;					// end to end control active? (for drain)
int dev_type=0;
int tty_write_blocked=0;
const char	trueport_dir[] 		= "/etc/trueport";

#define DEV_TYPE_UNKNOWN 0
#define DEV_TYPE_PTY     1
#define DEV_TYPE_PTMX    2

char *tcp_host = NULL;	
int	delay_close_tcp_flag = FALSE;
io_type_t client_io_type = NOTDEF;
int netfailed=0;		// indicates if the network connection failed.  This is used to control how we bring up the network connection

static struct sigaction sigact;

// These next 2 variables are used to optimize LAN traffic.
// We will only update the Device Server if we need to...
// if we have never sent the signal state or the signal state has
// changed
int signal_state_sent=0;
unsigned int prev_signal_state=0;

int pending_drain=0;



#ifdef	USE_SSL

static	SSL_CTX		*ssl_ctx;
static	SSL     	*ssl;
BIO 		*bio_err=NULL;		//used for debug for SSL
SSL_CFG		sslcfg;
int			read_ssl, write_ssl;

static int  tp_pem_passwd_cb(char *buf, int size, int rwflag, void *password);
static RSA  *tp_tmp_rsa_cb(SSL *s, int is_export, int keylength);

#endif /* USE_SSL */


struct  clparse_st  ptab[] =    /* Cmd argument parse table */
{
/*  Flags       Value 		Variable				Token			Sub-opt
	-----       --------   	--------            	-----  			------- */
	{CLF_NAMES,   		0,     	&fixed_ttyname,			"-tty",         	NULL },
	{CLF_NAMES,   		0,     	&terminal_name,			"-term",        	NULL },
	{CLF_WVAL,    		0,     	&tcp_port,				"-port",        	NULL },
	{CLF_WVAL,    		0,     	&keepalive_time,		"-ka",          	NULL },
	{CLF_WVAL,    		0,     	&pty_mode,				"-mode",        	NULL },
	{CLF_WVAL,    		0,     	&pty_uid,				"-uid",         	NULL },
	{CLF_WVAL,    		0,     	&pty_gid,				"-gid",         	NULL },
	{CLF_WVAL,    		0,     	&trace_level,			"-trace",       	NULL },
	{CLF_WINIT,   		4,     	&trace_level,			"-debug",       	NULL },
	{CLF_WINIT,   		5,  	&trace_level,			"-data",        	NULL },
	{CLF_WOR,     		pm_lite, &mode,					"-standard",    	NULL },
	{CLF_WOR,     		pm_full, &mode,          		"-trueport",	NULL },
	{CLF_WOR,     		1,   	&close_tty_flag, 		"-hub",         	NULL },
	{CLF_WOR,     		1,  	&close_tty_flag, 		"-hup",         	NULL },
	#ifdef USE_SSL	
	{CLF_WOR,     		1,     	&sslcfg.enabled,		"-ssl",         	NULL },
	#endif /* USE_SSL */
	{CLF_WOR,	  		1,		&pkt_fwd_enabled,		"-pf",				NULL },
	{CLF_NAMES,	  		0,		&server_tcp_host,		"-server",			NULL },
	{CLF_NAMES,	  		0,		&client_tcp_host,		"-client",			NULL },
	{CLF_WVAL,	  		0,		&retry_time,			"-retrytime",		NULL },
	{CLF_WVAL,	  		0,		&retry_num,				"-retrynum",		NULL },
	{CLF_WOR,	  		1,		&nodisc_tcp,    		"-nodisc",			NULL },
	{CLF_WOR,	  		1,		&no_tcp_nagle,		 	"-nagleoff",		NULL },
	{CLF_NAMES,			0,		&opmode_name,			"-opmode",			NULL },
	{CLF_WVAL,			0,		&idle_time_packet_timeout,"-pktidletime",	NULL },
	{CLF_WINIT,	  		1,		&connect_on_init, 		"-initconnect",		NULL },
	{CLF_WVAL,	  		0,		&delay_close_tcp_time,"-closedelaytime",	NULL },
	{CLF_WVAL,			0,		&open_wait_time,		"-openwaittime",	NULL },
	{CLF_WINIT,			0,		&restorenet,			"-norestorenet",	NULL },
	{CLF_WINIT,			0,		&use_legacy_UDP,		"-noudp",			NULL },
	{CLF_WINIT,			1,		&use_legacy_UDP,		"-useudp",			NULL },
	{CLF_NAMES,	  		0,		&io_type_name,    		"-io",				NULL },

	{CLF_EOT,     		0,          NULL,               NULL,         		NULL }
};

/****************************************************************************
 *	Definitions used for tracing					    *
 ****************************************************************************/
char    *trace_level_str[] =
    {
        "tl_none  ",
        "tl_error ",
        "tl_status",
        "tl_info  ",
        "tl_debug ",
        "tl_data  ",
    };

/* Disable special character functions */
#ifdef _POSIX_VDISABLE
# define VDISABLE   _POSIX_VDISABLE
#else
# define VDISABLE   255
#endif


typedef struct msg_name
{
	int  msg;
	char *name;
} msg_name_t;


/* Device Server UDP messages */
msg_name_t dserver_udp_msg_list[] =
    {
        {DS_UDP_RESET, 				"DS_UDP_RESET"					},
        {DS_UDP_TCXON,                   "DS_UDP_TCXON"   },
        {DS_UDP_TCXOFF,                  "DS_UDP_TCXOFF"  },
        {DS_UDP_WFLUSH,                  "DS_UDP_WFLUSH"  },
        {DS_UDP_RFLUSH,                  "DS_UDP_RFLUSH"  },
        {DS_UDP_WR_FLUSH,                "DS_UDP_WR_FLUSH"    },
        {DS_UDP_ACK,                     "DS_UDP_ACK" },
        {DS_UDP_DRAIN_POLL,              "DS_UDP_DRAIN_POLL"  },
        {DS_UDP_DRAIN_CLEAR,             "DS_UDP_DRAIN_CLEAR" },
        {DS_UDP_KEEP_ALIVE,              "DS_UDP_KEEP_ALIVE"  },
        {DS_UDP_NAK,                     "DS_UDP_NAK" },
        {DS_UDP_SYN,                     "DS_UDP_SYN" },
        {DS_UDP_WAK,                     "DS_UDP_WAK" },
        {	DS_UDP_GET_MODEM_STATUS,"DS_UDP_GET_MODEM_STATUS"	},
        {	DS_UDP_GET_COMM_STATUS,	"DS_UDP_GET_COMM_STATUS"	},
        {	DS_UDP_LSRMST_INSERT,	"DS_UDP_LSRMST_INSERT"		},
        {	DS_UDP_SET_BREAK_ON,		"DS_UDP_SET_BREAK_ON"		},
        {	DS_UDP_SET_BREAK_OFF,	"DS_UDP_SET_BREAK_OFF"		},
        {	DS_UDP_IMMEDIATE_CHAR,	"DS_UDP_IMMEDIATE_CHAR"		},
        {	DS_UDP_SET_DTR,       	"DS_UDP_SET_DTR"				},
        {	DS_UDP_CLR_DTR,       	"DS_UDP_CLR_DTR"				},
        {	DS_UDP_SET_RTS,       	"DS_UDP_SET_RTS"				},
        {	DS_UDP_CLR_RTS,       	"DS_UDP_CLR_RTS"				},
        {	DS_UDP_GET_DTRRTS,      "DS_UDP_GET_DTRRTS"			},
        {	-1, 							"Unknown"						}
    };

/* DEVICE_SERVER TCP Messages(in-band) */
msg_name_t dserver_tcp_msg_list[] =
    {
        {DS_TCP_SEND_BREAK,      		"DS_TCP_SEND_BREAK"  },
        {DS_TCP_STTY_SET,        		"DS_TCP_STTY_SET/DS_TCP_CD1400_STATE" },
        {DS_TCP_STTY_REPORT_ON,  		"DS_TCP_STTY_REPORT_ON"  },
        {DS_TCP_STTY_REPORT_OFF, 		"DS_TCP_STTY_REPORT_OFF" },
        {DS_TCP_SYNC_FLUSH_END,  		"DS_TCP_SYNC_FLUSH_END"  },
        {DS_TCP_PORT_NUMBER,     		"DS_TCP_PORT_NUMBER" },
        {DS_TCP_DRAIN_PORT,      		"DS_TCP_DRAIN_PORT"  },
        {DS_TCP_DRAIN_ACK,       		"DS_TCP_DRAIN_ACK"   },
        {DS_TCP_LSR_NODATA,      		"DS_TCP_LSR_NODATA" },
        {DS_TCP_MST,             		"DS_TCP_MST" },
        {DS_TCP_SEND_BREAKON,    		"DS_TCP_SEND_BREAKON"},
        {DS_TCP_SEND_BREAKOFF,   		"DS_TCP_SEND_BREAKOFF"},
        {DS_TCP_SEND_SYNCDRAIN,			"DS_TCP_SEND_SYNCDRAIN"	},
        {DS_TCP_STTY_XREPORT_ON,		"DS_TCP_STTY_XREPORT_ON"	},
        {DS_TCP_FEATURE_ACK,			"DS_TCP_FEATURE_ACK"	},
        {DS_TCP_SET_DTR,				"DS_TCP_SET_DTR"	},
        {DS_TCP_CLR_DTR,				"DS_TCP_CLR_DTR"	},
        {DS_TCP_SET_RTS,				"DS_TCP_SET_RTS"	},
        {DS_TCP_CLR_RTS,				"DS_TCP_CLR_RTS"	},
        {DEVICE_SERVER_DATA,     		"DEVICE_SERVER_DATA"    },
        {DEVICE_SERVER_DATA_INCOMPLETE, "DEVICE_SERVER_DATA_INCOMPLETE"    },
        {DEVICE_SERVER_UPDATE_WINDOW, 	"DEVICE_SERVER_UPDATE_WINDOW"    },
        {DEVICE_SERVER_DATA_QUEUED, 	"DEVICE_SERVER_DATA_QUEUED"    },
		{DEVICE_SERVER_QUEUE_EMPTY,     "DEVICE_SERVER_QUEUE_EMPTY"    },
		{DEVICE_SERVER_NONE,     		"DEVICE_SERVER_NONE"    },
        {-1,                        	"Unknown"   },
    };







/****************************************************************************
 *	Main program							    *
 ****************************************************************************/
/*
	Arguments	: - See documentation
	Return values	: - Exit code
*/

int main(int argc, char **argv)
{
	struct timeval timeout;
	fd_set			read_fds;	/* Arrays for select call */
	fd_set			write_fds;	/* Arrays for select call */
	fd_set			exception_fds;	/* Array for select on error */
	int				ret;
	buf_t2			buffer;
	int				len;
	int				read_flag;
	struct timeval 	*ptimeout = NULL;
	time_t			cur_time;
	int				force_ptyx_write=0;
	char 			*tmpptr, *tmp_tcp_host;
	char			tcp_host_str[MAX_HOST_NAMELEN +1] = {0};
	int				read_queue = FALSE;
#ifdef USE_SSL
	int         	ssl_pending = 0;
#endif	//USE_SSL

	// Must be root - this is somewhat redundant as the tpadm will normally
	//	be used to start the daemon and it has this check as well. However I
	//	will keep it here for completness.
	if (getuid() != 0)
	{
		fprintf( stderr, "Not root !\n" );
		exit(FAILURE);
	}


	ret = clparse(argc, argv, ptab);


	if (trace_level > tl_none)
	{
		char file_name[80];
		char *master_tty_name=NULL;
		// strip off dev
		master_tty_name = strrchr(fixed_ttyname, '/'); 
		if (master_tty_name == NULL)
		{
			// just use give name
			master_tty_name = fixed_ttyname;
		}
		else
		{
			 master_tty_name++;
		}	 
		sprintf(file_name, "%s/trace.%s", trueport_dir, master_tty_name );

		trace_file = fopen(file_name, "a");
		if (trace_file == NULL)
		{
			perror("trueport error: opening trace file");
			exit(EXIT_FAILURE);
		}
		cur_time = time( &cur_time );
		trace( tl_info, "\n******************:    %s", ctime( &cur_time ));
	}

	if ( ret	!= 0 )
	{
		trace(tl_error, "invalid option: %s\n", argv[ret]);
		exit(EXIT_FAILURE);
	}

	if (tcp_port == -1)
	{
		trace(tl_error, "TCP port not specified\n");
		exit(-1);
	}

	trace(tl_status, "TruePort starting Version %s on port %d", TP_VERSION, tcp_port);
	trace(tl_status, " - (c) 1999-2017, Perle Systems Limited\n" );

	// if client I/O type name defined then set enumeration value
	if (io_type_name)
	{
		if (!strcmp(io_type_name, IOMBASCIIarg))
		{
			client_io_type = MB_ASCII;
		}
		else if (!strcmp(io_type_name, IOMBRTUarg))
		{
			client_io_type = MB_RTU;
		}
		else if (!strcmp(io_type_name, IOAPIarg))
		{
			client_io_type = IO_API;
		}
		else
		{
		   trace(tl_error, "Invalid Client I/O type\n");
		   exit(-1);
		}

		// force lite mode for client I/O
		mode = pm_lite;
		if (client_tcp_host == NULL)
		{
			trace(tl_error, "Client I/O Access option requires -client host option to be set \n");
			exit(EXIT_FAILURE);
		}
	}
	if (opmode_name)
	{
		if (!strcmp(opmode_name, OPMODE_NAME_OPTIMIZELAN))
		{
			opmode_type = OPMODE_TYPE_OPTIMIZELAN;
			pkt_fwd_enabled=0;
			no_tcp_nagle=0;
		}
		else if (!strcmp(opmode_name, OPMODE_NAME_LOWLATENCY))
		{
			opmode_type = OPMODE_TYPE_LOWLATENCY;
			pkt_fwd_enabled=0;
            no_tcp_nagle=1;
		}
		else if (!strcmp(opmode_name, OPMODE_NAME_PACKETIDLETIMEOUT))
		{
			opmode_type = OPMODE_TYPE_PACKETIDLETIMEOUT;
			pkt_fwd_enabled=0;
			no_tcp_nagle=1;
		}
		else if (!strcmp(opmode_name, OPMODE_NAME_CUSTOM))
		{
			opmode_type = OPMODE_TYPE_CUSTOM;
		}
		else
		{
		   trace(tl_error, "Invalid operational mode: %s\n",opmode_name);
		   exit(-1);
		}
	}

	tcp_host = server_tcp_host;
	// if client initiated then init some variables
	if (client_tcp_host)
	{
		tcp_host = client_tcp_host;
		trace(tl_status, " - running Client Initiated mode \n");
		trace(tl_status, "   - number of reconnect retries are %d", retry_num);
		trace(tl_status, "   - reconnect interval of %d seconds \n",retry_time);
	}
	else
	{
		trace(tl_status, " - running Server mode \n");
	}

	if (tcp_host != NULL)
	{
		// copy configured IP address
		strncpy(&tcp_host_str[0], tcp_host, MAX_HOST_NAMELEN);
 		tmp_tcp_host = &tcp_host_str[0];

		// strip of IPv6 brackets if required
		tmpptr = strchr(tmp_tcp_host, '[');
		// we have a literal IPv6 address
		if (tmpptr != NULL)
		{
			*tmpptr = 0;						// null out startin "[" 
			tmp_tcp_host = tmpptr + 1;			// increment pass "["
	 
			// now search for ending "]"
			tmpptr = strchr(tmp_tcp_host, ']');
			if (tmpptr == NULL)
			{
				trace (tl_error,"Specified IPv6 address must be inclosed in square brackets]\n");
				exit(-1);
			}
			*tmpptr = 0;		// zero out ending ] bracket
			// set client or server host back
			if (client_tcp_host)
				client_tcp_host = tmp_tcp_host;
			if (server_tcp_host)
				server_tcp_host = tmp_tcp_host;
		}
	}
	
	if (io_type_name)
	{
		trace(tl_status, " - running I/O Access mode via %s \n",io_type_name );
	}
	else
	{
		trace(tl_status, " - running %s mode\n", mode == pm_lite ? "lite " : "full" );
	}

	if (mode == pm_full)
	{
		if (use_legacy_UDP)
		{
			trace(tl_status, " - Use legacy UDP protcol for Full mode \n");
		}
		else
		{
			trace(tl_status, " - Don't use UDP procotol if device server supports it \n");
		}
}

#ifdef	USE_SSL

	trace(tl_status, " - running %s(%x)\n", OPENSSL_VERSION_TEXT, SSLeay() );

	if (bio_err == NULL)
		bio_err = BIO_new_fp( trace_file, BIO_NOCLOSE );
#endif	//USE_SSL

	/* Parameters OK, initialise ttys */
	ptyxm_fd = -1;
	ptyxc_fd = -1;
	tty_connected = FALSE;
	buffer.len = 0;

	/* Install signal handler */
	sigact.sa_handler = handle_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGTERM,&sigact,0);
	sigaction(SIGINT,&sigact,0);
	signal(SIGPIPE, SIG_IGN);

	dserver_connected = FALSE;
	buf_init(&dserver_out_buf);
	buf_init(&dserver_in_buf);
	qbuf_init(&qbuf);
	
	while( 1 )
	{
		if (!tty_connected)
		{
			// Open main tty and also the control status tty
			ptyxm_fd = open_tty();
			if (ptyxm_fd < 0)
			{
				trace(tl_error, "Error opening master or control device\n");
				sleep(1);   // try again later
				continue;
			}
			else
			{
				tty_connected = TRUE;
	 			// inform driver of open wait time configuration and trueport connection state
				trace(tl_debug, "Open wait time is %d. \n", open_wait_time );
				write_tty_ctrl(ptyxm_fd, TP_PROTO_SET_OPEN_WAIT, (unsigned char *)&open_wait_time, sizeof(int));
				is_tp_conn_avail();		// update tp_connected
				write_tty_ctrl(ptyxm_fd, TP_PROTO_TP_CONNECTION, &tp_connected, 1);
			}
		}
		if ( !dserver_connected )
		{
			initialise_connection_state ();
			dserver_fd = wait_for_dserver_connection();

			if(dserver_fd == FAILURE)
			{
				trace(tl_debug, "Connecting or Accepting dserver connection failed \n");
				sleep(3);		// just so log files won't fill up to quickly
				continue;
			}
			if (mode == pm_full)
			{
				char ch;

				// Delay a bit before sending packet mode request to make sure
				// other side has finished initializing socket or SSL
				usleep( 100 * 1000);	

				trace(tl_info, "send packet mode req\n");
				ch = DS_URG_TCP_PACKETMODE_REQ;

				// Do not send this in SSL stream if configured. The OOB data
				//  must NOT be encrypted or put in line with other data or the
				//  device server will not be able to detect it. There is such a
				//  a small amount of OOB data that encryption is not justified.
				ret = send (dserver_fd, &ch, 1, MSG_OOB);

				if (ret != 1)
				{
					trace(tl_error, "Error sending packet\n");
				}
				fflush(stdout);
				state = s_sent_packet_req;
			}
			else
			{
				// send out initial keep-alive cmd for client I/O mode if required
				// This first keep-alive cmd will configure the device server for keep-alive
				if ( client_io_type && keepalive_time)
				{
					ret = write_dserver_ctrl(dserver_fd, IOCMD_KEEP_ALIVE);
					if (ret < 0)
					{
						trace(tl_error, "Error sending I/O Keep-alive cmd, closing connection\n");
						close_connection();
					}
					else
					{
						 keepalive_sent = 1;
					}
				}
				state = s_data_transfer;
			}
		}

		while (dserver_connected && tty_connected)
		{
			process_tty_ctrl();	// get and process any ctrl statuses

			/* Initialise FD sets for select */
			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);
			FD_ZERO(&exception_fds);

			// Test SSL enabled and pending flag. If there is SSL data pending then
			//	do not call select, fall through to the read section to get SSL
			//	pending data.
			read_flag = FALSE;
#ifdef  USE_SSL

			if( sslcfg.enabled )
			{
				if ( (ssl_pending = SSL_pending( ssl )) )
				{
					read_flag = TRUE;						// data is pending, skip select.
				}
			}
#endif  //USE_SSL
			// If there is no read data pending, then prepare file descriptors for select
			//	Else, skip down and read pending data.
			if( read_flag == FALSE )
			{
				// only poll for writes on ptyxm when writing is blocked.
				// Otherwise when data is ready for ptyxm we will set force_ptyx_write
				if (tty_write_blocked)
					FD_SET(ptyxm_fd,&write_fds);
				if (dserver_fd != -1)
				{
				    FD_SET(dserver_fd, &read_fds);
				}
				else
				{
				    dserver_connected = FALSE;
				    continue;
				}
				if (udp_sock != -1)
					FD_SET(udp_sock, &read_fds);

				if (dserver_out_buf.len != 0 || buffer.len > 0 )
				{
				    if (dserver_fd != -1)
				    {
				        FD_SET(dserver_fd, &write_fds);
				    }
				    else
				    {
				        dserver_connected = FALSE;
				        continue;
				    }
				}
				else 
				{
					if ((dserver_out_available(&info) > 2) && state == s_data_transfer)
					{
						FD_SET(ptyxm_fd, &read_fds);
					}
				}

				/* exceptions(TCP urgent data or ctrl messages) */
				if (udp_sock != -1)
					FD_SET(udp_sock, &exception_fds);

				if (dserver_fd != -1)
				{
				    FD_SET(dserver_fd, &exception_fds);
				}
				else
				{
				    dserver_connected = FALSE;
				    continue;
				}
				    
				FD_SET(ptyxm_fd, &exception_fds);
				// look for any control status changes
				FD_SET(ptyxc_fd, &exception_fds);
				FD_SET(ptyxc_fd, &read_fds);

				// set_time_out() will return address of timeval structure if
				// timers are to be set. Otherwise, a NULL pointer is returned
				//	for no timeout.
				ptimeout = set_time_out( &info, &timeout );
				process_tty_ctrl();			// make sure there's no out signals
				ret = select( FD_SETSIZE, &read_fds, &write_fds, &exception_fds, ptimeout );

				// timeout occured
				if (ret == 0)
				{
					// check keep-alive timers
					if ( keepalive_time )
					{
						// restart keep-alive timer if expired.
						if (check_time_out( &info.keepalive_start, keepalive_time * 1000)) 
						{
							// only do keep alive logic if in data transfer state
							// send out Client I/O Access keep-alive
							if ( client_io_type && (state == s_data_transfer) )
							{
								// if we've already sent one without a response then close connection
								if (keepalive_sent && !tty_write_blocked)
								{
									trace(tl_info, "No Client I/O keep-alive response, Closing connection\n");
									close_connection();
									keepalive_sent = 0;
								}
								else
								{
									ret = write_dserver_ctrl(dserver_fd, IOCMD_KEEP_ALIVE);
									if (ret < 0)
									{
										trace(tl_error, "Error sending I/O Keep-alive cmd, closing connection\n");
										close_connection();
									}
									else
									{
										 keepalive_sent = 1;
									}
								}
							}
							else
							// if not using UDP then send keep-alive immediate command
							// only do keep alive logic if in data transfer state
							if ( IsNoUDP() && (state == s_data_transfer) )
							{
								// if we've already sent one without a response then close connection
								// we will ignore keep-alive expiring if we are blocked on tty writes
//								if (keepalive_sent && !tty_write_blocked)
								if (keepalive_sent)
								{
									if (!tty_write_blocked)
									{
										trace(tl_info, "No keep-alive response, Closing connection\n");
										close_connection();
									}
									keepalive_sent = 0;
								}
								else
								{
									ret = write_dserver_imm_ctrl(dserver_fd, DS_UDP_KEEP_ALIVE, 0);
									if (ret < 0)
									{
										trace(tl_error, "Error sending Keep-alive immediate cmd, closing connection\n");
										close_connection();
									}
									else
									{
										if (!tty_write_blocked)
										{
											keepalive_sent = 1;
										}
									}
								}
							}
							// otherwise send UDP keep-alive
							// only do keep alive logic if in data transfer satae
							else if (state == s_data_transfer)
							{
								ret = write_dserver_udp_ctrl_wait(DS_UDP_KEEP_ALIVE);
								if (ret == -1 || udp_response.command == DS_UDP_SYN)
								{
								  trace(tl_error, "No UDP keep-alive response, Closing connection\n");
								  close_connection();
								}
							}
							gettimeofday( &info.keepalive_start, NULL );
						} // end of keep-alive expired

					} // end of keep-alive logic
					// check pkt forwarding timers
					if ( info.forwarding & PKT_FORWARD_ON_IDLE && info.data_count != 0 )
					{
						if ( check_time_out( &info.idle_time_start, info.idle_time ) )
						{
							trace(tl_data, "Forwarding frame on PKT_FORWARD_ON_IDLE\n");
							forward_frame(&info );
						}
					}

					if ( info.forwarding & PKT_FORWARD_ON_TIME && info.data_count != 0 )
					{
						if ( check_time_out( &info.force_time_start, info.force_time ) )
						{
 							trace(tl_data, "Forwarding frame on PKT_FORWARD_ON_TIME\n");
							forward_frame(&info );
						}
					}
					// check client-initiated delay closed timer
					if (client_tcp_host)
					{
						 if ( check_time_out( &info.delay_close_tcp_start, delay_close_tcp_time * 1000 ) )
						 {
							  if ( delay_close_tcp_flag && !(dserver_out_buf.len != 0 || buffer.len > 0 ) )
							  {
									delay_close_tcp_flag = FALSE;
									trace(tl_info, "Delayed closing of TCP connection\n");
									close_connection();
									netfailed=0;
							  }
						 }
					}
					continue;
				} // end of if time-out occured
				else if (ret < 0 )		// select error
				{
					trace(tl_error, "Error in select: %d\n", ret);
					close_connection();
					continue;
				}
			}
			// if we've lost either network or TTY then exit while connected loop now
			if (dserver_connected == 0 || tty_connected == 0)
			{
				continue;
			}

			if(FD_ISSET(ptyxc_fd, &exception_fds))
			{
				/* Error but make tl_debug because no action taken */
				trace(tl_debug, "ptyxc_fd exception\n");
				usleep(100000);
			}

			// process any control status if there was any
			if(FD_ISSET(ptyxc_fd, &read_fds))
			{
				process_tty_ctrl();
			}
			//****************************************************************
			// Read from application through master tty (and write to network)
			//****************************************************************
			if(ptyxm_fd >= 0 && FD_ISSET(ptyxm_fd, &exception_fds))
			{
				/* Error but make tl_debug because no action taken */
				trace(tl_debug, "ptyxm_fd exception\n");
				usleep(100000);
			}

			if ( ptyxm_fd >= 0 && FD_ISSET(ptyxm_fd, &read_fds) )
			{
				len = dserver_out_available(&info)-2+1;
				buffer.data_ptr = &buffer.data[0];
				buffer.len = read( ptyxm_fd, buffer.data_ptr, len );		// read from master TTY

				/* If we get a read error, the most likely reason is that other
				   side has closed /dev/tx? . In any case, close the master
				   side and let the main loop re-open it to prevent continually
				   getting the error.
				*/
				if (buffer.len == -1)
				{
					int closeit=0;

					if (errno == EIO)
					{
						trace(tl_info, "Port closed from other side - close our side");
						closeit=1;
					}
					else
					{
						if (errno != EAGAIN)
						{
							trace(tl_error, "Error reading from master tty. errno: %d", errno);
							closeit=1;
						}
					}
					if (closeit)
					{
						 close_tty();
					}
					continue;
				}

				if (!buffer.len)
				{
					trace(tl_data, "EOF in master tty\n");
					exit(-1);
				}

				if(trace_level >= tl_data)
				{
					 trace(tl_data, "main(): read from master tty returned %d bytes", buffer.len );
					 dump_buf(trace_file, buffer.data_ptr, buffer.len );
				}

				process_packet_forwarding( &info, &buffer);
			}

			
			//****************************************************************
			// Write to device server through network
			//	(only used if TCP resources not available after tty read)
			//****************************************************************
			if ( (dserver_fd != -1) && FD_ISSET(dserver_fd, &write_fds))
			{
				if (dserver_out_buf.len > 0)
				{

					ret = write_buf_raw(  dserver_fd,
					                        &dserver_out_buf.data[dserver_out_buf.offset],
					                        dserver_out_buf.len);
					if(ret >= 0)
					{
						dserver_out_buf.len -= ret;
						dserver_out_buf.offset += ret;
					}
					else
					{
						close_connection();
					}
				}
				// If dserver_out_buf has been fully sent, then check if there
				//	is any other data that needs to be forwarded.
				if ( dserver_out_buf.len == 0 && buffer.len > 0 )
				{
					process_packet_forwarding( &info, &buffer);
				}
			}

			//***********************************************************
			//	Exception from Device Server
			//****************************************************************
			if ( (dserver_fd != -1) && (FD_ISSET(dserver_fd, &exception_fds)) )
			{
				trace(tl_error, "device server exception, %d: %s\n", errno, strerror(errno));
				close_connection();
				continue;
			}

			if(udp_sock != -1)
			{
				if (FD_ISSET(udp_sock, &exception_fds))
				{
					trace(tl_debug, "UDP exception\n");
				}
				
				if (FD_ISSET(udp_sock, &read_fds))
				{
					/* we don't really expect to get any unsolicited responses */
					ret = read_dserver_udp_message(&udp_response);
					if (ret == FAILURE || udp_response.command == DS_UDP_SYN)
					{
						close_connection();
						continue;
					}
				}
			}

			//****************************************************************
			//  Read from device server through network (and write to tty)
			//****************************************************************
			read_flag = FALSE;
#ifdef USE_SSL
			if ( sslcfg.enabled )
			{
				if ( ssl_pending )
					read_flag = TRUE;		// SSL data is pending so read it.
				else if ((dserver_fd != -1) && FD_ISSET(dserver_fd, &read_fds) )
					read_flag = TRUE;
			}
			else
#endif  //USE_SSL
			{
				if ((dserver_fd != -1) && FD_ISSET(dserver_fd, &read_fds) )
					read_flag = TRUE;
			}
			
			// loop on reading from dserver in case there is mulitple packets
			// in the dserver queue.
			read_queue = FALSE;
			do					
			{
				if ( read_flag )
				{
					int bytes_read;
					dserver_packet_t  packet_type=DEVICE_SERVER_NONE;
					
					bytes_read = read_dserver(dserver_fd, &packet_type, &dserver_in_buf, tty_write_blocked, read_queue  );
					if( packet_type == DEVICE_SERVER_QUEUE_EMPTY )
					{
						read_queue = FALSE;
						break;
					}
					else if( packet_type == DEVICE_SERVER_UPDATE_WINDOW )
						continue;		// do nothing, output window is updated but there may still be data in dserver_in_buf
					
					if(bytes_read <= 0)
					{
						/* dserver socket close or socket error */
						if(bytes_read < 0)
						{
							if(errno == EAGAIN)
							{
								trace(tl_debug, "read_device_server returned %d: %s\n", errno, strerror(errno));
								break;
							}
							else
								trace(tl_error, "read_device_server returned %d: %s\n", errno, strerror(errno));
						}
						else
							trace(tl_info, "read_device_server returned %d: %s\n", errno, strerror(errno));
				
						close_connection();
						break;
					}
					else if (packet_type == DEVICE_SERVER_DATA)
					{
						if (flushing_net_read || slave_is_open==FALSE)
						{
							buf_init(&dserver_in_buf);
							qbuf_init(&qbuf);
						}
						else
						{
							force_ptyx_write=1;
						}
					}
					
					else if( packet_type == DEVICE_SERVER_DATA_QUEUED )
						;		// Data was queued, do nothing and wait for next read of data from dserver.
					else if( packet_type == DEVICE_SERVER_DATA_INCOMPLETE )
						;		// Do nothing and wait for next read of data from dserver.
					else
					{						
						buf_init(&dserver_in_buf);
						tty_write_blocked=0;
					}
					
					// This was added to detect a tty close caused by loss of CD from the Device Server
					if ( !tty_connected )
					{
						ptyxm_fd = -1;
						continue;
					}
					process_tty_ctrl();
				}
				
				// try to write data to the tty
				if (ptyxm_fd != -1 && (force_ptyx_write || FD_ISSET(ptyxm_fd, &write_fds)))
				{	
					trace(tl_debug, "ptyx write force_ptyx_write %d, tty_write_blocked %d", 
								force_ptyx_write, tty_write_blocked );
					force_ptyx_write=0;
					if (flushing_net_read || slave_is_open==FALSE)
					{
						trace(tl_data, "TTY is closing, or doing net flush, discarding network data\n");
						buf_init(&dserver_in_buf);
						qbuf_init(&qbuf);
						tty_write_blocked = 0;
					}
					else
					{
						ret=write(ptyxm_fd, &dserver_in_buf.data[dserver_in_buf.offset], dserver_in_buf.len);
						if (ret < 0)
						{
							if (errno != EAGAIN)
							{
								trace(tl_error, "Error writing to ptyx: %d\n", errno);
								buf_init(&dserver_in_buf);
								qbuf_init(&qbuf);
								close_connection();
								break ;
							}
							else
							{
								tty_write_blocked = 1;
								if (pending_drain)
								{
									write_tty_ctrl(ptyxm_fd, TP_PROTO_DRAIN_ACK, NULL, 0);
									pending_drain = 0;
								}
							}
						}
						else
						{
							trace(tl_debug, "%s ptyx write len=%d written=%d remaining=%d\n", (ret < dserver_in_buf.len)?"Incomplete":"Completed",dserver_in_buf.len,ret,dserver_in_buf.len-ret);
							dserver_in_buf.len-=ret;
							dserver_in_buf.offset+=ret;
							if (dserver_in_buf.len == 0)
							{
								buf_init(&dserver_in_buf);
								if( tty_write_blocked )		// if tty was write blocked, then set read_queue to check for any queued data
								{
									read_queue = TRUE;
									read_flag = TRUE;
								}
								tty_write_blocked=0;
								keepalive_sent=0;	// allow another keep alive time period after tty becomes unblocked
							}
							else
							{
								tty_write_blocked=1;
								if (pending_drain)
								{
									write_tty_ctrl(ptyxm_fd, TP_PROTO_DRAIN_ACK, NULL, 0);
									pending_drain=0;
								}
							}
						}
					}
				}
			}while( read_queue );
			
		}	// while( dserver_connect && tty_connect )
	}	// while( 1 )
	close_tty();
	return 0;
}

/****************************************************************************
 *	Initialise all state information used for DEVICE_SERVER connection	    *
 ****************************************************************************/
/*
	Arguments	: none
	Return values	: none
*/
void initialise_connection_state(void)
{
	state = s_initial;
	dserver_connected = FALSE;
	tp_connected = FALSE;
	dserver_fd = -1;
	udp_sock = -1;
	dserver_port_no = 0xff;
	udp_sequence_no = 0;
	out_window_size = DEFAULT_OUT_WINDOW_SIZE;
	in_window_used = 0;
	buf_init(&dserver_in_buf);
	qbuf_init(&qbuf);
}

//******************************************************************************
//*	Initialise a buffer   						    *
//****************************************************************************/
//
//	Arguments	: buf : a buffer
//	Return values	: None
//
void    buf_init(buf_t *buf)
{
	buf->offset = 0;
	buf->len = 0;
}

void qbuf_init( bufqueue_t *queuebuf )
{
	queuebuf->woffset = 0;
	queuebuf->len = 0;
	queuebuf->roffset = 0;
}


int buf_append(buf_t *buf, char *data, int len)
{
	if ((buf->offset+buf->len+len > (int)sizeof (buf->data)) || (len<0) )
	{
		trace(tl_error, "buf_append: invalid length: %d", len);
		return FAILURE;
	}

	memcpy(&buf->data [buf->offset+buf->len], data, len);
	buf->len += len;

	return OK;
}



// open master tty and also the new ctrl status tty
int open_tty()
{
	int ptyxm_fd = -1;
//	int len;
	char *p;
	static int succeeded = 0;
	char buf[1024];
	struct stat stat_buf;
	int tries=0;
	int minor_number;

#define MAX_TRIES 100

	// setup master, control & slave tty names
	// fixed_ttyname legacy format is "/dev/pxnnnn"
	if ( (p = strstr( fixed_ttyname,"px" )) != NULL )
	{
		sscanf( p+2, "%d", &minor_number );
	}
	// new format is simply tty number
	else
	{
		p = fixed_ttyname;
		sscanf( p, "%d", &minor_number );
	}
	sprintf( master_ttyname, "/dev/%s%d",PTYX_MASTER_NAME, minor_number );
	sprintf( ctrl_ttyname, "/dev/%s%d",PTYX_CTRL_NAME, minor_number );
	sprintf( slave_ttyname, "/dev/%s%04d","tx", minor_number );
	
	/* First try to open 'our' pty device */
	if ( fixed_ttyname )
	{
		// if the device nodes do not exist, then create them
		if( lstat( slave_ttyname, &stat_buf ) < 0 )
		{
			trace( tl_status, "Creating slave device node: %s \n", slave_ttyname );
			sprintf( buf, "mknod %s c %d %d", slave_ttyname, PTYX_SLAVE_MAJOR, minor_number );
			if( system( buf ) == -1 ) 
			{
				trace( tl_error, "Could not create slave device node: %s\n", slave_ttyname  );
				trace( tl_error, "  - %s\n", strerror( errno ) );
				exit(-1);
			}
		}

		if( lstat( master_ttyname, &stat_buf ) < 0 )
		{
			trace( tl_status, "Creating master device node: %s \n", master_ttyname );
			sprintf( buf, "mknod %s c %d %d", master_ttyname, PTYX_MASTER_MAJOR, minor_number );
			if( system( buf ) == -1 ) 
			{
				trace( tl_error, "Could not create master device node: %s\n", master_ttyname  );
				trace( tl_error, "  - %s\n", strerror( errno ) );
				exit(-1);
			}
		}

		if( lstat( ctrl_ttyname, &stat_buf ) < 0 )
		{
			trace( tl_status, "Creating control device node: %s \n", ctrl_ttyname );
			sprintf( buf, "mknod %s c %d %d", ctrl_ttyname, PTYX_CTRL_MAJOR, minor_number );
			if( system( buf ) == -1 ) 
			{
				trace( tl_error, "Could not create control device node: %s\n", ctrl_ttyname  );
				trace( tl_error, "  - %s\n", strerror( errno ) );
				exit(-1);
			}
		}

		ptyxm_fd = open( master_ttyname, O_RDWR | O_NONBLOCK);
		ptyxc_fd = open( ctrl_ttyname, O_RDWR | O_NONBLOCK);


		while( !succeeded && ((ptyxm_fd < 0) || (ptyxc_fd < 0)) && (++tries < MAX_TRIES) )
		{
			usleep( 1000*tries );
			if (ptyxm_fd < 0)
			{
				 ptyxm_fd = open( master_ttyname, O_RDWR | O_NONBLOCK);
			}
			if (ptyxc_fd < 0)
			{
				 ptyxc_fd = open( ctrl_ttyname, O_RDWR | O_NONBLOCK);
			}
		}
		if ( (ptyxm_fd >= 0) && (ptyxc_fd >= 0) )
		{
			succeeded=1;
//			len = 1;
			trace( tl_debug, "Opened port %s and %s\n", master_ttyname, ctrl_ttyname );
			return ptyxm_fd;
		}
		else
		{
			if (ptyxm_fd < 0)
			{
				 trace( tl_error, "Error in opening master tty %s errno=%d\n", master_ttyname, errno  );
				 trace( tl_error, "   - %s\n", strerror( errno ) );
			}
			else
			{
				 trace( tl_error, "Error in opening control %s errno=%d\n", ctrl_ttyname, errno  );
				 trace( tl_error, "   - %s\n", strerror( errno ) );
	
			}
			if (succeeded)
			{
				return -1;
			}
			else
			{
				exit(-1);
			}
		}
	}
	else
	{
			trace( tl_error, "We only support fixed tty name.\n"  );
			exit(-1);	
	}
}


void close_tty(void)
{
	trace( tl_debug, "close_tty(): Closeing ptyxm_fd=%d\n", ptyxm_fd );

	close_tty_common(1);
}


void close_tty_common(int rmdev)
{
	if (ptyxm_fd != -1)
	{
	        trace( tl_debug, "close_tty_common(): Closeing ptyxm_fd=%d\n", ptyxm_fd );
		close(ptyxm_fd);
	        trace( tl_debug, "close_tty_common(): Closeing ptyxc_fd=%d\n", ptyxc_fd );
		close(ptyxc_fd);
		tty_connected = 0;
		ptyxm_fd = -1;
		ptyxc_fd = -1;
		slave_is_open = FALSE;
		tty_write_blocked=0;
		pending_drain=0;
		trace( tl_debug, "close_tty_common(): complete\n" );
	}
}

void close_tty_no_rm(void)
{
	close_tty_common(0);
}


/****************************************************************************
 *	Get a message name from a message list		    		    *
 ****************************************************************************/
/*
	Arguments	: msg_val  : value of message to look up
			  msg_list : list of value/name
	Return value	: pointer to name
*/
char *get_msg(int msg_val, msg_name_t *msg_list)
{
	int j;

	for (j=0; msg_list [j].msg != msg_val && msg_list [j].msg != -1; j++)
		;
	return msg_list [j].name;
}


/****************************************************************************
 *	Close connections						 				    		    *
 ****************************************************************************/
/*
	Arguments	: - None
	Return value	: - None
*/
void close_connection()
{
	/* close */
	trace(tl_debug, "closing device server connection");

	/* tidy up */
	if (dserver_fd != -1)
	{
		// try to forward any held frames
		forward_frame(&info );
		if ( close(dserver_fd) < 0 )
		{
			 trace(tl_debug, "close_connection(): Error closing dserver_fd=%d, errno: %d",dserver_fd, errno);
		}
		if (ptyxm_fd != -1)
		{
			if (open_wait_time == OPENWAIT_ALWAYS_SUCCESSFUL)
			{
				drop_modem_signals();
			}
			tp_connected = FALSE;
			write_tty_ctrl(ptyxm_fd, TP_PROTO_TP_CONNECTION, &tp_connected, 1);
		}
		keepalive_sent = 0;
	}
	dserver_fd = -1;
	if (udp_sock != -1)
	{
		close(udp_sock);
	}
	udp_sock = -1;
	dserver_connected = FALSE;
	tp_connected = FALSE;
	signal_state_sent = 0;
	flushing_net_read = 0;	// clean up in case we didn't get the DS_TCP_SYNC_FLUSH_END from the server yet
	DServerFeatures = 0;
	// as long as we are not blocked on writting to the tty then clear out read data
	// from network
	if (!tty_write_blocked)
	{
		trace(tl_debug, "close_connection(): tty write not blocked so throwing away %d bytes rx", dserver_in_buf.len );
		buf_init(&dserver_in_buf);
		qbuf_init(&qbuf);
	}
	if ( close_tty_flag && (ptyxm_fd != -1) )
	{
		trace(tl_info, "Closing tty connections\n");
		close_tty();
	}


#ifdef	USE_SSL
	if ( ssl )
	{
		SSL_free( ssl );
		ssl = NULL;
	}
#endif	//USE_SSL
}


//******************************************************************************
static	void	close_connection_2( int fd )
{
	dserver_fd = fd;
	close_connection();
}


static void my_hd (void *ad, int len)
{
	unsigned char *addr = ad;
	int i, j, ch;
	char			buf[256];

	buf[0] = 0;
	for (i=0;i<len;i+=16)
	{
		sprintf ( &buf[strlen(buf)], "%p ", (void *)addr+i);
		for (j=0;j<16;j++)
		{
			sprintf (&buf[strlen(buf)], "%02x %s", addr[j+i], (j==7)?" ":"");
		}
		for (j=0;j<16;j++)
		{
			ch = addr[j+i];
			sprintf (&buf[strlen(buf)], "%c", (ch < 0x20)?'.':((ch > 0x7f)?'.':ch));
		}
		sprintf (&buf[strlen(buf)], "\n");
	}
}


//******************************************************************************

void    trace(trace_level_t level, char *msg, ...)
{
	va_list ap;
	char    *arg [7];
	char    buf [2049];
	time_t  now;
	struct tm *tim;

	/* provide fast exit if we're not going to do anything */

	if (level > trace_level)
		return;

	va_start(ap, msg);

	arg [0] = va_arg(ap, char *);
	arg [1] = va_arg(ap, char *);
	arg [2] = va_arg(ap, char *);
	arg [3] = va_arg(ap, char *);
	arg [4] = va_arg(ap, char *);
	arg [5] = va_arg(ap, char *);
	arg [6] = va_arg(ap, char *);

	va_end(ap);

	sprintf(buf, msg, arg [0], arg [1], arg [2], arg [3], arg [4], arg [5], arg [6]);

	if (buf[strlen(buf)-1] != '\n')
		strcat(buf, "\n");

	time(&now);
	tim = localtime(&now);

	if (trace_file)
	{
		fprintf(trace_file, "%02d:%02d:%02d %s: %s",
		         tim->tm_hour, tim->tm_min, tim->tm_sec,
		         trace_level_str [level], buf);
		fflush(trace_file);
		fprintf( trace_file, " \b" );
	}
	else
	{
		/* Useful when debuging only !*/
		fprintf(stderr, "trueport: %s", buf);
	}
}



//******************************************************************************
// returns:	network socket fd for connection
//				< 0 on error
//
int wait_for_dserver_connection(void)
{
	int 	nsfd = -1;
	int 	on = 1;
	int     tries;
	int	ret;
	int	force_try=0;
    int doretry=0;
	
	// Configured to initiate TCP connection
	if (client_tcp_host)
	{
		 // if necessary wait until the appliction has opened or reopened the slave tty
		 // if connect_on_init is enabled, don't bother waiting for the app to open
		 // the serial port before attempting to make the TCP connection for 1 time
		 // only
		if (connect_on_init)
		{
			connect_on_init=0;
			force_try=1;
			doretry=1;
		}
		else if (netfailed)
		{
			netfailed = 0;
			if (restorenet)
			{
				force_try=1;
				doretry=1;
			}
		}
		else if (tty_connected && !slave_is_open)
		{
			trace(tl_debug, "Client Initiated needs slave tty open to start connection");
			ret = wait_for_tty_open_close(NULL);
			if( (ret == -1) || !tty_connected)
				return(FAILURE);

			force_try=1;
			doretry=1;
		}
		trace(tl_debug, "%s: About try to connect, retry_num=%d",__FUNCTION__,retry_num);
		// try to connect for configured retry number and time
		for (tries=0; force_try || (doretry && (retry_num == -1 || tries < retry_num)) ;)
		{
			// Try to connect to device server
			if ( (nsfd = wait_for_tcp_connect()) >= 0 )
			{
#ifdef USE_SSL
				if ( sslcfg.enabled )
				{
					if ( wait_for_ssl_connect(nsfd) >= 0)
					{
						break;		// connected, break out of retries
					}
				}
				else
#endif //USE_SSL
				{
					break; // connected, break out of retries
				}
			}
			nsfd = -1;			// nsfd is invalid now
			trace(tl_status, "wait_for_tcp_connect() failed tries=%d", tries);

			if (!force_try)
			{
				 tries++;
			}
			force_try=0;
			if (retry_num==-1 || tries < retry_num)
			{
				 // wait for retry time before trying again 
				 sleep(retry_time);
			}
		}  // end for ()

		// if restore network connection is disabled or retry has expired, return connection failed
		if (nsfd < 0 && (!doretry || retry_num >= 0))
		{
			// main line will reopen the tty
			trace(tl_status, "wait_for_dserver_connection(): Connect retry expired or no restore connection , closing tty");
			drop_modem_signals();
			close_tty();
			return(-1);
		}
		netfailed=1;	// default to network failed.  this is set to 0 at specific code locations, when we close the network connection
	}
	// Configured to listen for TCP connection
	else
	{
		nsfd = wait_for_tcp_listen();
		if ( nsfd < 0 )
		{
			return(-1);
		}
#ifdef USE_SSL
		if ( sslcfg.enabled )
		{
			if ( wait_for_ssl_connect(nsfd) < 0)
			{
				 return(-1);
			}
		}
#endif //USE_SSL
	}

	// ********** Common already TCP Connected logic *****************
	trace(tl_status, "Connected to Device Server(fd=%d)", nsfd);
	dserver_connected = TRUE;


	setsockopt(nsfd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof(on));

	if (mode == pm_lite)
	{
		setsockopt(nsfd, SOL_SOCKET, SO_SNDBUF,
					 (const char *) &send_bufsize, sizeof(send_bufsize));
	}
	if (no_tcp_nagle)
	{
		 setsockopt(nsfd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
	}

	fcntl(nsfd, F_SETFL, fcntl( nsfd, F_GETFL ) | O_NONBLOCK );

	memset( &info, 0, sizeof( forwarding_info_t )  );
	if (keepalive_time)
	{
		gettimeofday( &info.keepalive_start, NULL );
	}
	if ( pkt_fwd_enabled || opmode_type == OPMODE_TYPE_CUSTOM )
	{
		if ( get_pkt_fwd_config( &info, tcp_host, tcp_port ) < 0  )
		{
			trace( tl_error, "Packet forwarding setup failed.\n" );
			close_connection_2(nsfd);
			return -1;
		}
	}
	else
	{
/* now let's try to fix up the config taking into account the operation mode
*/
		if (opmode_type == OPMODE_TYPE_PACKETIDLETIMEOUT)
		{
			info.idle_time = idle_time_packet_timeout;
			trace( tl_debug, "Operation mode: %s, idle timeout=%d.\n",opmode_name, idle_time_packet_timeout);
			if (info.idle_time)
			{
				info.forwarding |= PKT_FORWARD_ON_IDLE;
                info.char_buf_ptr = &info.char_buf[0];
			}
		}
	}
	if (is_tp_conn_avail()) 
	{
		// update driver that connection is up
		write_tty_ctrl(ptyxm_fd, TP_PROTO_TP_CONNECTION, &tp_connected, 1);

		// if in Lite mode then fake out modem signals and send TP_PROTO_DCD_UP message
		// to unblock any waiting opens since TCP connection is now up
		if (mode == pm_lite)
		{
			ret = ioctl(ptyxm_fd, TIOCMGET, &current_state);	// get modem status
			if (ret)
			{
				trace(tl_error, "%s(): TIOCMGET error %d %d\n", __FUNCTION__, ret, errno);
				close_connection_2(nsfd);
				return(-1);
			}
			current_state|=(TIOCM_DSR|TIOCM_CD|TIOCM_CTS);
			ret = ioctl(ptyxm_fd, PTX_IOCMSET, &current_state);	// set modem status
			if (ret)
			{
				trace(tl_error, "%s(): PTX_IOCMSET error %d %d\n", __FUNCTION__, ret, errno);
				close_connection_2(nsfd);
				return(-1);
			}
		}
	}
	return nsfd;                /* Return new socket */
}


//******************************************************************************
// wait_for_tcp_connect
// returns:	network socket fd for connection
//				< 0 on error
//
int wait_for_tcp_connect(void)
{
	struct addrinfo hints; 
	struct addrinfo *res = NULL;
	int nsfd = -1;
	int rc;
	char portstr[7];
	struct	sockaddr_in6 saddr6;
	struct sockaddr_in saddr;
	struct linger linger;
	int syn_count = 3;

	ipv6_not_running = 0;  // clear ipv6 flag
   memset((char *) &hints, 0, sizeof(struct addrinfo));    // Clear out hints

	trace(tl_debug, "wait_for_tcp_connect() Enter ");
	
	do
	{
		hints.ai_flags    = 0;
		hints.ai_family   = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		// Convert the text form of the address to binary
		// form. If it is numeric then we want to prevent getaddrinfo()
		// from doing any name resolution.
		memset((char *) &saddr, 0, sizeof(saddr));    // Clear address structure
		rc = inet_pton(AF_INET, client_tcp_host, &saddr);
		if (rc == 1)				// valid IPv4 text address ?
		{
			hints.ai_family = AF_INET;
			hints.ai_flags |= AI_NUMERICHOST;
			ipv6_not_running = 1;
		}
		else
		{
   		memset((char *) &saddr6, 0, sizeof(saddr6));    // Clear address structure
			rc = inet_pton(AF_INET6, client_tcp_host, &saddr6);
			if (errno == EAFNOSUPPORT)
			{
				ipv6_not_running = 1;
			}
			else if (rc == 1) /* valid IPv6 text address? */
			{
				hints.ai_family = AF_INET6;
				hints.ai_flags |= AI_NUMERICHOST;
			}
		}
		// Get the address information for the device server
		snprintf(portstr, 6, "%d", tcp_port);			// convert tcp_port to string
		rc = getaddrinfo(client_tcp_host, portstr, &hints, &res);
		if (rc != 0)
		{
			trace(tl_error, "Host name %s could not be found:  %s ", 
							client_tcp_host, gai_strerror(errno));
			if (rc == EAI_SYSTEM)
			{
				trace(tl_error, "getaddrinfo() failed"); 
			}
			break;
		}
		
		nsfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (nsfd < 0) 
		{
			trace(tl_error, "can't open socket: %s", strerror(errno));
			break;
		}
		setsockopt(nsfd, SOL_TCP, TCP_SYNCNT, &syn_count, sizeof(syn_count));
		// use host address information to try to connect

		trace (tl_debug, "calling connect() - fd=%d\n", nsfd);

		rc = connect(nsfd, res->ai_addr, res->ai_addrlen);

		if (rc < 0)
		{
		  	close(nsfd);
			nsfd = -1;
			trace(tl_error, "connect() failed: %s\n", strerror(errno));
			break;
		}
		// make sure all data is sent out on TCP close
		linger.l_onoff = 1; 
		linger.l_linger = 5;
		setsockopt(nsfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
		
		// now we are connected fill in dserver address info
		if (res->ai_family == AF_INET6)
		{
	 		memset(&dserver_addr6.sin6_addr, 0, sizeof (struct in6_addr));
			dserver_addr6.sin6_family = AF_INET6;
			memcpy(&dserver_addr6, (struct sockaddr_in *)res->ai_addr, res->ai_addrlen);
			
		}
		else if (res->ai_family == AF_INET)
		{
			ipv6_not_running = 1;
 	 		memset(&dserver_addr.sin_addr, 0, sizeof (struct in_addr));
			dserver_addr.sin_family = AF_INET;
			memcpy(&dserver_addr, (struct sockaddr_in *)res->ai_addr, res->ai_addrlen);

		}
		else
		{
			// should never get here
			trace(tl_error, "wait_for_tcp_connect() failed: Invalid Address Family \n", res->ai_family);
			break;
		}
	} while(FALSE);

	// common clean-up
	if (res != NULL)
		freeaddrinfo(res);
	return(nsfd);
}


//******************************************************************************
// returns:	network socket fd for connection
//				< 0 on error
//
int wait_for_tcp_listen(void)
{
	int 		on = 1;
	struct 	sockaddr_in 	saddr;
	socklen_t				saddrlen = sizeof(struct sockaddr_in);		// Temp for addr length
	int 					listenfd = -1;
	int i, rc, rc2;
	struct addrinfo hints; 
	struct addrinfo *res = NULL;
	int nsfd = -1;
	int closensfd = 0;
	struct sockaddr *sa;
//	int	salen;
	char ipstr[INET6_ADDRSTRLEN];
	struct	sockaddr_in6	saddr6;
	socklen_t saddr6len = sizeof(struct sockaddr_in6);	// Temp for addr length

	ipv6_not_running = 0;  // clear ipv6 flag
   memset((char *) &hints, 0, sizeof(struct addrinfo));    // Clear out hints
	
	do
	{
		// Resolve server host name/IP address if specified 
		if (server_tcp_host)
		{
	
			hints.ai_flags    = 0;
			hints.ai_family   = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			// Convert the text form of the address to binary
			// form. If it is numeric then we want to prevent getaddrinfo()
			// from doing any name resolution.  
			memset((char *) &saddr, 0, sizeof(saddr));    // Clear address structure
			rc = inet_pton(AF_INET, server_tcp_host, &saddr);
			if (rc == 1)				// valid IPv4 text address ?
			{
				hints.ai_family = AF_INET;
				hints.ai_flags |= AI_NUMERICHOST;
				ipv6_not_running = 1;
			}
			else
			{
	 			memset((char *) &saddr6, 0, sizeof(saddr6));     /* Clear address structure */
				rc = inet_pton(AF_INET6, server_tcp_host, &saddr6);
				if (errno == EAFNOSUPPORT)
				{
					 ipv6_not_running = 1;
				}
				else if (rc == 1) /* valid IPv6 text address? */
				{
					 hints.ai_family = AF_INET6;
					 hints.ai_flags |= AI_NUMERICHOST;
				}
			}
			// Get the address information for the configured host
			rc = getaddrinfo(server_tcp_host, NULL, &hints, &res);
			if (rc != 0)
			{
				trace(tl_error, "Host name %s could not be found:  %s ", 
								server_tcp_host, gai_strerror(errno));
				if (rc == EAI_SYSTEM)
				{
					trace(tl_error, "getaddrinfo() failed"); 
				}
				break;
			}
			sa = res->ai_addr;
//			salen = res->ai_addrlen;
			if (res->ai_family == AF_INET6)
			{
				if ( inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, ipstr, sizeof(ipstr)) )
				{
					trace(tl_info, "Configured host name %s resolved to IP address %s ", server_tcp_host, ipstr);
				}
			}
			else if (res->ai_family == AF_INET)
			{
				ipv6_not_running = 1;
				if ( inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, ipstr, sizeof(ipstr)) )
				{
				   trace(tl_info, "Configured host name %s resolved to IP address %s ", server_tcp_host, ipstr);
				}
			}
			else
			{
				trace(tl_info, "getaddrinfo() failed: Unsupported INET family ");
				break;
			}
		}
		
		listenfd = socket(PF_INET6, SOCK_STREAM, 0);  /* Go open socket */
		
		// if IPv6 protocol not running/available then use IPv4
		if (ipv6_not_running || (listenfd == -1 && errno == EAFNOSUPPORT) )
		{
			if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) /* Go open socket */
			{
				trace(tl_error, "can't open socket: %s", strerror(errno));
				break;
			}
			ipv6_not_running = 1;
			memset((char *) &saddr, 0, sizeof(saddr));    // Clear address structure
			saddr.sin_family = AF_INET;         			// Set family
			saddr.sin_addr.s_addr = INADDR_ANY;
			saddr.sin_port = htons((u_short) tcp_port);  	// .. and listener port
			setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
			if (bind(listenfd,(struct sockaddr *)&saddr, sizeof(saddr)) < 0)  // Go bind address to socket
			{
				trace(tl_error, "can't bind on listen address: %s", strerror(errno));
				break;
			}
	
			trace (tl_debug, "calling listen() - fd=%d\n", listenfd);
			while ((i = listen(listenfd, 1)) < 0)       /* Wait for a connection */
			{
				trace(tl_error, "listen failed: %s\n", strerror(errno));
				sleep(5);
			}
	
			trace (tl_debug, "calling accept\n");
			if ((nsfd = accept(listenfd,(struct sockaddr *) &dserver_addr, &saddrlen)) < 0) /* Accept caller */
			{
				trace(tl_error, "can't accept connection: %s", strerror(errno));  // Failed, clean-up below
				break;
			}
		}
		else if ( listenfd == -1 )
		{
			trace(tl_error, "can't open socket(6): %s (%d)", strerror(errno), errno );
			break;
		}
		else
		{
			memset((char *) &saddr6, 0, sizeof(saddr6));	/* Clear address structure */
			saddr6.sin6_family = AF_INET6;        			 	/* Set family */
			saddr6.sin6_port = htons((u_short) tcp_port);  /* .. and listener port */
			setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
			if (bind(listenfd,(struct sockaddr *)&saddr6, sizeof(saddr6)) < 0) /* Go bind address to socket */
			{
				trace(tl_error, "can't bind on listen address(6): %s", strerror(errno));
				break;
			}
	
			trace (tl_debug, "calling listen() - fd=%d\n", listenfd);
			while ((i = listen(listenfd, 1)) < 0)       /* Wait for a connection */
			{
				trace(tl_error, "listen failed(6): %s\n", strerror(errno));
				sleep(5);
			}
	
			trace (tl_debug, "calling accept\n");
			if ((nsfd = accept(listenfd,(struct sockaddr *) &dserver_addr6, &saddr6len)) < 0) /* Accept caller */
			{
				trace(tl_error, "can't accept connection(6): %s", strerror(errno)); /* Failed */
				break;
			}
		}
		// Validate remote host if required
		if (server_tcp_host)
		{
			// get address of peer and compare to configured host
			if (ipv6_not_running)
			{
				rc = getpeername(nsfd, (struct sockaddr *)&dserver_addr, &saddrlen);
				if (rc == 0)
				{
					rc2 = memcmp( &((struct sockaddr_in *)sa)->sin_addr, &dserver_addr.sin_addr, 4);
					if ( inet_ntop(AF_INET, (struct sockaddr_in *)&dserver_addr.sin_addr, ipstr, sizeof(ipstr)) )
					{
						trace(tl_info, "Peer host IP4 address is %s ", ipstr);
					}
				}
			}
			else
			{
				rc = getpeername(nsfd, (struct sockaddr *)&dserver_addr6, &saddr6len);
				if (rc == 0)
				{
					 rc2 = memcmp(&((struct sockaddr_in6 *)sa)->sin6_addr, &dserver_addr6.sin6_addr, 16);
					if ( inet_ntop(AF_INET6, (struct sockaddr_in6 *)&dserver_addr6.sin6_addr, ipstr, sizeof(ipstr)) ) 
					{
						trace(tl_info, "Peer host IP address is %s ", ipstr);
					}
				}
			}
			if (rc < 0)
			{
				trace(tl_error, "getpeername() failed: %s (%d)", strerror(errno), errno);
				closensfd = 1;
				break;
			}
			if (rc2 != 0)
			{
				trace(tl_error, "Peer host does not match configured server host %s ", server_tcp_host);
				closensfd = 1;
				break;
			}
		} // end validate server_tcp_host
		
	} while(FALSE);

	// common clean-up
	if (listenfd != -1)
		close(listenfd);
	if (closensfd)
	{
		 close(nsfd);
		 nsfd = -1;
	}
	if (res != NULL)
		freeaddrinfo(res);
	return(nsfd);
}


//******************************************************************************
// returns:	< 0 on error, including timeout
//
#ifdef USE_SSL
int wait_for_ssl_connect(int nsfd)
{
	int rc, ret;
	fd_set read_set;
	fd_set write_set;
	struct timeval	tim;
	int ssl_error;
	const char *err_string;

	if ( get_ssl_config(tcp_host, tcp_port) != 0 )
	{
		trace( tl_error, "get_ssl_config failed\n" );
		close_connection_2(nsfd);
		return FAILURE;          /* Return failure */
	}

	trace( tl_info, "initializing SSL...\n" );
	if ( ssl_init( &ssl_ctx, tp_pem_passwd_cb, tp_tmp_rsa_cb ) < 0 )
	{
		close_connection_2(nsfd);
		return FAILURE;          /* Return failure */
	}
	ssl = SSL_new( ssl_ctx );
	SSL_set_fd( ssl, nsfd );

#if	0	//debug only
	{
		int 	i = 0;
		char	*cipher;
		char	cipherList[2048];
		memset( cipherList, 0, 2048 );
		while ( (cipher = SSL_get_cipher_list( ssl, i )) != NULL )
		{
			trace( tl_info, "%d: %s\n", i, cipher );
			i++;
		}
	}
#endif
	// If device server is configured as an SSL server then accept incoming
	//  SSL connections
	if ( sslcfg.ssl_type == SSL_SERVER )
	{

		trace( tl_info, "waiting for SSL accept\n" );
		while(1)
		{
			if ( (rc = SSL_accept( ssl )) > 0 )
				break;		//successful

			switch( ssl_error = SSL_get_error( ssl, rc ) )
			{

				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				FD_ZERO( &read_set );
				FD_ZERO( &write_set );
				if ( ssl_error == SSL_ERROR_WANT_READ )
					FD_SET( nsfd, &read_set );
				else
					FD_SET( nsfd, &write_set );

				tim.tv_sec  = SSL_ACCEPT_OR_CONNECT_TIMEOUT_SECS;
				tim.tv_usec = 0;
				ret = select(FD_SETSIZE, &read_set, &write_set, NULL, &tim );

				if ( ret == 0)
				{
					tim.tv_sec  = 0;
					tim.tv_usec = 0;
					
					ret = select(FD_SETSIZE, &read_set, &write_set, NULL, &tim);

					if ( ret <= 0 )
					{
						trace( tl_error, "SSL_accept failed - timeout\n" );
						close_connection_2(nsfd);
						return FAILURE;          /* Return failure */
					}
					break;		//
				}
				else if ( ret < 0 )
				{
					if((err_string = strerror(errno)) == NULL )
						err_string = "...";
					trace( tl_error, "SSL_accept failed - %s", err_string );
					close_connection_2(nsfd);
					return FAILURE;          /* Return failure */
				}
				else
					trace( tl_debug, "%s event occured.", "SSL_accept" );
				// keep trying while getting events from select
				break;

				default:
				if((err_string = ERR_reason_error_string( ERR_get_error() )) == NULL )
				{
					err_string = "...";
				}
				trace( tl_status, "%s", err_string );
				trace( tl_error, "SSL_accept failed - error = %x", ssl_error );
				close_connection_2( nsfd );
				return FAILURE;          /* Return failure */
				break;
			}
		}
	}

	// device server is configured as an SSL client. Make an SSL connection.
	else
	{
		trace( tl_info, "waiting for SSL connect\n" );
		while(1)
		{
			if ( (rc = SSL_connect( ssl )) > 0 )
				break;		//successful

			switch( ssl_error = SSL_get_error( ssl, rc ) )
			{

				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				FD_ZERO( &read_set );
				FD_ZERO( &write_set );
				if ( ssl_error == SSL_ERROR_WANT_READ )
					FD_SET( nsfd, &read_set );
				else
					FD_SET( nsfd, &write_set );

				tim.tv_sec  = SSL_ACCEPT_OR_CONNECT_TIMEOUT_SECS;
				tim.tv_usec = 0;

				ret = select(FD_SETSIZE, &read_set, &write_set, NULL, &tim );
				
				if ( ret == 0)
				{
					tim.tv_sec  = 0;
					tim.tv_usec = 0;
					ret = select(FD_SETSIZE, &read_set, &write_set, NULL, &tim);
					
					if ( ret <= 0 )
					{
						trace( tl_error, "SSL_connect failed - timeout\n" );
						close_connection_2(nsfd);
						return FAILURE;          /* Return failure */
					}
					trace( tl_debug, "%s event occured after timeout.",  "SSL_connect" );
					break;		//
				}
				else if ( ret < 0 )
				{
					if((err_string = strerror(errno)) == NULL )
						err_string = "..";
					trace( tl_error, "SSL_connect failed - %s\n", err_string );
					close_connection_2(nsfd);
					return FAILURE;          /* Return failure */
				}
				else
					trace( tl_debug, "%s event occured.",  "SSL_connect" );
				// keep trying while getting events from select
				break;

				default:
				//					ERR_print_errors( bio_err );		//Debug
				if((err_string = ERR_reason_error_string( ERR_get_error() )) == NULL )
					err_string = "...";
				trace( tl_status, "%s\n", err_string );
				trace( tl_error, "SSL_connect failed - error = %x\n", ssl_error );
				close_connection_2(nsfd);
				return FAILURE;          /* Return failure */
				break;
			}
		}
	}

	// authenticate the peer.
	if ( sslcfg.do_authentication )
	{
		trace( tl_info, "Authenticating peer(%s)\n",
			   (sslcfg.ssl_type == SSL_SERVER ? "client" : "server") );
		if ( !check_cert( ssl ) )
		{
			trace( tl_error, "Peer authentication failed\n" );
			close_connection_2(nsfd);
			return FAILURE;          /* Return failure */
		}
	}
	trace( tl_info, "SSL connection complete!\n" );
	trace( tl_info, "Protocol = %s, Cipher = %s\n",
		   SSL_get_cipher_version( ssl ),
		   SSL_get_cipher_name( ssl ) );
	return(1);
}
#endif // USE_SSL




void dump_buf(FILE *fd, unsigned char * buf, int len)
{
	int j, k;
	if(len > MAX_TRACE_LEN)
		len = MAX_TRACE_LEN;
	for(j=0; j<len; j+=16)
	{
		fprintf(fd, "%04x ", j);
		for(k=0; k<16; k++)
			if(j+k < len)
				fprintf(fd, "%02x ",(unsigned char)buf [j+k]);
			else
				fprintf(fd, "   ");
		fprintf(fd, "  ");
		for(k=0; k<16 && j+k<len; k++)
			if(isprint(buf [j+k]))
				fprintf(fd, "%c", buf[j+k]);
			else
				fprintf(fd, ".");
		fprintf(fd, "\n");
	}
}


/****************************************************************************
 *	Write data to a file descriptor
 ****************************************************************************/
/*
	Arguments	: fd   : descriptor of file
			  buf  : pointer to data buffer
			  size : number of bytes
	Return values	: -1 if error(errno is set), 
					or 0/+Ve number of bytes(errno EAGAIN),
					otherwise no of bytes written
*/
int write_buf_raw( int fd, unsigned char *buf, int size )
{
	int  len;
	unsigned char *cp;
	int  ret;
	
#ifdef USE_SSL
	int	 err;
#endif

	cp = buf;
	len = size;

	// if dserver not connected, and this includes SSL if configured
	// then return error
	if( (dserver_connected == FALSE) || (fd == -1) )
		return FAILURE;
  
#ifdef USE_SSL
	if( sslcfg.enabled )
	{
		do
		{
			ret = SSL_write( ssl, cp, len );

			switch((err = SSL_get_error( ssl, ret )) )
			{

				case SSL_ERROR_NONE:
				cp += ret;
				len -= ret;
				if( len <= 0 )
				{
					write_ssl = 0;
				}
				else /* if (len > 0) */
					write_ssl=1;

				break;

				case SSL_ERROR_WANT_WRITE:
				trace (tl_data, "SSL_write returns %d: %s\n", ret, strerror (errno) );
				write_ssl=1;
//				return( size - len);
				ret = size - len;
				goto write_buf_raw_done;

			default:
				trace(tl_error, "SSL_write error %d: %s\n", ret, strerror(errno) );
				if( err == SSL_ERROR_ZERO_RETURN && ret == 0 )
				{
//					return ret;
					goto write_buf_raw_done;
				}
				else
				{
//					return -1;
					ret = -1;
					goto write_buf_raw_done;
				}
			}
			if( len > 0 )
				trace(tl_debug, "partial SSL_writer - looping" );
		}
		while ( len > 0 );
	}
	else
#endif  // USE_SSL
	{
		do
		{
			ret = write(fd, cp, len );
			if ( ret < 0 )
			{
				if (errno == EAGAIN)
				{
					trace (tl_data, "write_buf_raw(): write(fd=%d) returned %d: %s, bytes written=%d\n", 
									fd, ret, strerror (errno), size-len );
					/* Return count of bytes written */
//					return (size-len);
					ret = size - len;
					goto write_buf_raw_done;
				}
				else
				{
					trace(tl_error, "write_buf_raw(): write_dserver error %d: %s\n", ret, strerror(errno) );
					/* Error condition so return the error */
//					return ret;
					goto write_buf_raw_done;
				}
			}
			else if(ret < len)
			{
				trace(tl_debug, "write_buf_raw(): partial write_dserver - looping" );
			}
			
			if(trace_level >= tl_data)
			{
				trace(tl_data, "write_buf_raw(): write_device_server %d bytes",ret);
				dump_buf(trace_file, cp, ret);
			}
			
			len -= ret;
			cp += ret;
		}
		while ( len > 0 );
	}
	/* Wrote everything ! */
	ret = size;
	
write_buf_raw_done:
	 
	// restart keep-alive timer if in Lite mode
	// resolves issue with tcp zero-window probe response being lost when
	// urgent data message is sent
	if ( (keepalive_time) && (ret > 0) && (mode == pm_lite) )
	{
		gettimeofday( &info.keepalive_start, NULL );
	}
	return( ret );
}

/****************************************************************************
 *	Read from an DEVICE_SERVER connection
 ****************************************************************************/
/*
	Arguments	: fd   : descriptor of socket
			  type : type of packet read
			  buf  : pointer to data buffer
	Return values	: >0   : ok, number of bytes read
			   0   : connection closed
			  -1   : if error(errno may be set)
*/
int read_dserver(int fd, dserver_packet_t *type, buf_t * buf, int tty_write_blocked, int read_queue )
{
	int  ret;
	unsigned short temp;
	static  short header, count = 0;
	unsigned char new_state;
	unsigned char temp_state;
	
	//****************************
	//   Lite Mode
	if (mode == pm_lite)
	{
		// process client I/O data from Device Server
		if (client_io_type)
		{
			ret = read_dserver_iodata_wait(fd, type, buf);
			trace(tl_data, "read_dserver(): mode = Client I/O; read returned %d\n", ret);
			return(ret);
		}
		else
		{
			*type = DEVICE_SERVER_DATA;
			ret = tp_read(fd, (unsigned char *)buf->data, sizeof(buf->data));
			if (ret > 0)
				buf->len = ret;
			if(trace_level >= tl_data)
			{
				trace(tl_data, "read_dserver(): Lite mode tp_read returned %d", ret);
				dump_buf(trace_file, buf->data, buf->len);
			}
			return ret;
		}
	}

	//***************************
	//   Packet Mode(Full)
	else
	{
		if(state == s_sent_packet_req)
		{
			ret = tp_read(fd, (unsigned char *)buf->data, 1);
			if (ret==1 && (buf->data[0] == DS_URG_TCP_PACKETMODE_ACK))
			{
				trace(tl_info, "received packet mode ack\n");
				*type = DS_URG_TCP_PACKETMODE_ACK;
				state = s_wait_port_number;
				return 1;
			}
			else
			{
				// Do not cause error if data not correct for packet mode ack.
				// There is now a window where data can be received from the device
				//	server when SSL has been configured. Throw out data until packet
				//	mode ack is received.
				trace(tl_data, "packet mode ack not received yet - ret = %d, data = %x\n", ret, buf->data[0] );
				*type = DEVICE_SERVER_NONE;  // This will cause the data to be ignored at the upper level.(i.e. throw out the data)
				return ret;
			}
		}
		else
		{
			// get new packet header if
			//		1. Previous packet is complete.
			//		2. tty is blocked so get new packet to put on queue
			//		3. If there is data on the queue, then get header from queue, not here.
			if( (buf->len == 0 || tty_write_blocked) && !read_queue )
			{
				ret = tp_read( fd,(unsigned char *)&temp, 2 );
				if(ret <= 0 ) {
					trace(tl_debug, "read_dserver(): no data from tp" );
					return ret;
				}
				
				// If we can't read two bytes here we are obviously messed up
//				assert(ret==2);
				if (ret !=2)
				{
					trace(tl_data, "read_dserver(): Expecting tp_read to return 2 bytes but read %d, fake out and return 0 bytes read",	ret);
					return 0;
				}

				header = ntohs(temp);
				count = header & DEVICE_SERVER_COUNT_MASK;
				if ((count < 0) || (count > (int)sizeof(buf->data)))
				{
					trace(tl_error, "count invalid :%d, return 0 bytes read indicating fake connection closed", count);
					return 0;
				}
				if(header & DEVICE_SERVER_WINDOW)
				{
					out_window_size += 512;
					trace(tl_data, "read_dserver(): window update - %d", out_window_size );
					*type = DEVICE_SERVER_UPDATE_WINDOW;
					return( 0 );
				}
			}
			
			// read dserver data if:
			//		1. There is still data to be read for current packet
			//		2. tty is blocked so put data on queue
			//		3. get data from queue
			if(count - buf->len > 0  || tty_write_blocked || read_queue )
			{
				*type = DEVICE_SERVER_NONE;
				ret = process_dserver_queue( fd, type, buf, &count, &header, tty_write_blocked  );	
				/* possibly we could get ret==0 buf connection is not closed ? */
				if(ret <= 0 )
				{
					return ret;
				}

				// dserver_in_buf not updated, but data put on queue.
				if( *type == DEVICE_SERVER_DATA_QUEUED )
				{
					return ret;
				}

				buf->len += ret;
				if(buf->len < count)
				{
					/* incomplete */
					*type = DEVICE_SERVER_DATA_INCOMPLETE;	
					trace(tl_data, "read_dserver(): Incomplete packet, count=%d, returning %d bytes read\n", count, ret);
					return ret;
				}
			}

			/* we have a complete packet */
			if(trace_level >= tl_data)
			{
				trace(tl_data, "read_dserver(): count=%d, header=%04x, %d bytes", count, header, buf->len);
				dump_buf(trace_file, buf->data, buf->len);
			}

			if(header & DEVICE_SERVER_COMMAND)
			{
				trace(tl_data, "read_dserver(): Received dserver command with count=%d\n", count);
				if( count != 0 )	// Is there any instance where count would be negative? Zero value handled above.
				{
					*type = buf->data [0];

					// if not an immediate command then update window size
					if ( (count > 0) && !(*type & DS_IMM_CMD_MASK))
					{
						trace(tl_data, "read_dserver(): In-line command - count = %d, cmd = %s", count, get_msg(*type, dserver_tcp_msg_list));
						update_input_window(count + 2);
						// if we were disconnected then return 0 bytes read indicating connection closed
						if (dserver_connected == FALSE)
						{
							return 0;
						}
					}

					switch(*type)
					{
						case DS_TCP_SEND_BREAK:
						{	
							write_tty_ctrl(ptyxm_fd, TP_PROTO_GOT_BREAK, NULL, 0);
							break;
						}
						case DS_TCP_CD1400_STATE:
						{
							new_state = buf->data [1];
							trace(tl_debug, "CD1400_STATE new modem state : %02x = %cDTR %cRTS %cRI %cDCD %cDSR %cCTS\n",
						       new_state,
						       new_state & CD_CTS ? '+' : '-',
						       new_state & CD_DSR ? '+' : '-',
						       new_state & CD_RI  ? '+' : '-',
						       new_state & CD_CD  ? '+' : '-',
						       new_state & CD_DTR ? '+' : '-',
						       new_state & CD_RTS ? '+' : '-');

							/* always report state */
							write_tty_ctrl(ptyxm_fd, TP_PROTO_DCD_UP, &new_state, 1);
							break;
						}
						case DS_TCP_MST:
						{
							// for historical reasons, the bit definition for this
							// command is not the same as for DS_TCP_CD1400_STATE,
							// but the information is the same
							temp_state=buf->data[1];
							
							// let's convert the bits to the DS_TCP_CD1400_STATE format
							// so we can call the write_tty_ctrl routine the same way
		
							new_state=0;
				
							if (temp_state & MST_CTS)
								new_state |= CD_CTS;
							if (temp_state & MST_DSR)
								new_state |= CD_DSR;
						  	if (temp_state & MST_RI)
								new_state |= CD_RI;
						  	if (temp_state & MST_DCD)
								new_state |= CD_CD;
						  	if (temp_state & MST_DTR)
								new_state |= CD_DTR;
						  	if (temp_state & MST_RTS)
								new_state |= CD_RTS;

						  	trace(tl_debug, "MST new modem state : 0x%02x = %cCTS %cDSR %cRI %cDCD %cDTR %cRTS\n",
								new_state,
								new_state & CD_CTS ? '+' : '-',
								new_state & CD_DSR ? '+' : '-',
								new_state & CD_RI  ? '+' : '-',
								new_state & CD_CD  ? '+' : '-',
								new_state & CD_DTR ? '+' : '-',
								new_state & CD_RTS ? '+' : '-');
						  
							/* always report state */
							write_tty_ctrl(ptyxm_fd, TP_PROTO_DCD_UP, &new_state, 1);
							break;
						}
						case DS_TCP_LSR_NODATA:
						{
							new_state = buf->data [1];
							trace(tl_debug, "new line state : %02x = %cOE %cPE %cFE %cBI\n",
								new_state,
								new_state & LSRNODATA_OE ? '+' : '-',
								new_state & LSRNODATA_PE ? '+' : '-',
								new_state & LSRNODATA_FE  ? '+' : '-',
								new_state & LSRNODATA_BI  ? '+' : '-');

							/* always report state */
							write_tty_ctrl(ptyxm_fd, TP_PROTO_LSRUPDATE, &new_state, 1);
							break;
						}	
						case DS_TCP_SYNC_FLUSH_END:
						{
							write_tty_ctrl(ptyxm_fd, TP_PROTO_SYNC_FLUSH_END, NULL, 0);
							flushing_net_read = 0;
							// reset out ack count if DS supports it since we just flushed read data
							if (DServerFeatures & TPSFEAT_SYNCFLUSHENDRESET)
							{
								 in_window_used = 0;		// also DS doesn't require ack for DS_TCP_SYNC_FLUSH_END
							}
							// inform driver tp connection is now up if it was waiting on
							// a pending read flush
							if (!tp_connected && is_tp_conn_avail())
							{
								// update driver that tp connection is up
								write_tty_ctrl(ptyxm_fd, TP_PROTO_TP_CONNECTION, &tp_connected, 1);
							}
							trace( tl_debug, "sync_flush_end" );
							break;
						}
						case DS_TCP_PORT_NUMBER:
						{
							dserver_port_no = buf->data[1];
							trace(tl_debug, "device server port number is %d", dserver_port_no);
							DServerFeatures=ntohl(get_tps_feat(&buf->data[0], buf->len));
							trace( tl_debug, "server features 0x%x\n",DServerFeatures );
	 
							if (state == s_wait_port_number)
							{
								// This was put back in to turn on reporting if Device Server process was
								//	restarted without closing and opening the tty port.
								if ( (DServerFeatures & TPSFEAT_IOLANDS) == 0 )
								{
									 ret = write_dserver_ctrl(dserver_fd, DS_TCP_STTY_REPORT_ON);
								}
								else
								{
									ret = write_dserver_ctrl(dserver_fd, DS_TCP_STTY_XREPORT_ON);
								}
								// if DS supports no UDP then don't setup UDP socket
								// A bit kludgy but we will use the TPSFEAT_NO_UDP bit to determine if we want to send 
								// the DS_TCP_FEATURE_ACK cmd back to the DS.
								if ( (ret >= 0) && (DServerFeatures & TPSFEAT_NO_UDP) )
								{
									ret = write_dserver_ctrl(dserver_fd, DS_TCP_FEATURE_ACK);
								}
								if ( ret >= 0)
								{ 
									// if we are not useing UDP then we are now in data transfer state 
									if ( IsNoUDP() )
									{
										state = s_data_transfer;
									}
									else
									{
										setup_udp_socket();
										// only set state to data transfer state if we
										// get a UDP response
										ret = write_dserver_udp_ctrl_wait(DS_UDP_RESET );
										if (!ret)
										{
											state = s_data_transfer;
										}
									}
								}
	
								if ( ret < 0 )
								{
									close_connection();
								}
								else
								{
									// inform driver tp connection is now up if it was waiting on
									// a pending read flush
									if (!tp_connected && is_tp_conn_avail() )
									{
										// update driver that tp connection is up
										write_tty_ctrl(ptyxm_fd, TP_PROTO_TP_CONNECTION, &tp_connected, 1);
	 
									}
                                    sleep(1);
									tcgetattr(ptyxm_fd, &dserver_termios_modes);
									set_dserver_modes(TRUE);
								}
							}
							break;
						}
						case DS_TCP_DRAIN_ACK:
						{
							write_tty_ctrl(ptyxm_fd, TP_PROTO_DRAIN_ACK, NULL, 0);
							pending_drain = 0;
							break;
						}
 				 		case (DS_UDP_KEEP_ALIVE | DS_IMM_CMD_MASK):
						{
							trace(tl_debug, "read_dserver(): Immediate DS_UDP_KEEP_ALIVE command, count = %d", count);

							// acknowledge we received keep-alive response
							keepalive_sent = 0;
							break;
						}
						default:
						{
							trace(tl_debug, "read_dserver(): unexpected message");
					}
					} // end of switch
				}
				buf->len = 0;
				return (2+count);
			}
			else if (state == s_data_transfer)
			{
				if (count > 0)
				{
					update_input_window(count + 2);
				}
				if (dserver_connected == FALSE)
				{
					return 0;
				}
				*type = DEVICE_SERVER_DATA;
				trace(tl_data, "read_dserver(): DATA count=%d bytes", count);
				buf->data[buf->len+1] = '\0';
				return count;
			}
			else
			{
				trace(tl_data, "read_dserver(): not in data transfer state, and not a command, throu data away\n");
				*type = DEVICE_SERVER_NONE;
				return count;
			}
		}
	}
}


/****************************************************************************
 *	Provides a circular queue to  buffer the data between dserver and the dserver_in_buf.
 ****************************************************************************/
 
/*
	Arguments	: fd   : descriptor of socket
			  buf  : pointer to data buffer
	Return values	: >0   : ok, number of bytes read
			   0   : connection closed
			  -1   : if error(errno may be set)
*/

int	process_dserver_queue( int fd, dserver_packet_t *type, buf_t * buf, short *count, short *header, int tty_write_blocked  )
{
	int		ret;
	int		len, len2;
	
	//**************************************************************************
	// if tty not write blocked or there is no data in que then read from TP
	// directly into dserver_in_buf;
	
	if( !tty_write_blocked && (qbuf.roffset == qbuf.woffset) )
	{
		trace(tl_debug, "process_dserver_queue(): direct read: w=%d, l=%d, r=%d; c=%d, bl=%d",
					qbuf.woffset, qbuf.len, qbuf.roffset, *count, buf->len);
		return( tp_read(fd, (unsigned char *)&buf->data[buf->len], *count - buf->len) );
	}
	
	//**************************************************************************
	// if tty write is blocked then read from TP and place in queue
	
	if( tty_write_blocked )
	{
		trace(tl_debug, "process_dserver_queue(): put: w=%d, l=%d, r=%d; c=%d, bl=%d", 
					qbuf.woffset, qbuf.len, qbuf.roffset, *count, buf->len);
		// put header on queue
		if( qbuf.woffset >= qbuf.roffset )
		{
			if( 2 <= DS_BUF_SIZE - qbuf.woffset ) {
				*(short *)&qbuf.data[qbuf.woffset] = *header;
				qbuf.woffset += 2;
			}
			else
				qbuf.woffset = 0;		
		}
		if( qbuf.woffset <= qbuf.roffset ) 
		{	
			if( qbuf.woffset + 2 <= qbuf.roffset )
			{
				*(short *)&qbuf.data[qbuf.woffset] = *header;
				qbuf.woffset += 2;
			}
			else
			{
				trace(tl_error, "process_dserver_queue(): not enough room in queue for data");
				return 0;
			}
		}
		// Now store data.
		if( qbuf.woffset >= qbuf.roffset )
		{
			// add data to end of queue buffer
			len = *count - qbuf.len; 
			if( len < DS_BUF_SIZE - qbuf.woffset )
			{	
				ret =  tp_read( fd, (unsigned char *)&qbuf.data[qbuf.woffset], len );
				if( ret <= 0 ){			
					trace(tl_debug, "process_dserver_queue(): (1)no data to read from tp; ret %d", ret);
					return ret;
				}
				qbuf.woffset += ret;
				qbuf.len += ret;
				
			}
			
			// data will wrap from end to beginning of queue buffer.
			else 
			{	
				len = DS_BUF_SIZE - qbuf.woffset;
				ret =  tp_read( fd, (unsigned char *)&qbuf.data[qbuf.woffset], len );
				if( ret <= 0 ){			
					trace(tl_debug, "process_dserver_queue(): (2)no data to read from tp; ret %d", ret);
					return ret;
				}
				qbuf.woffset = 0;
				qbuf.len += ret;
				len2 = *count - qbuf.len;
				if( len2 > qbuf.roffset )		// this should not happen if window pacing is working
				{
					trace(tl_error, "process_dserver_queue(): not enough room in queue for data");
					return 0;
				}
		
				ret =  tp_read( fd, (unsigned char *)&qbuf.data[qbuf.woffset], len2 );
				if( ret <= 0 ){			
					trace(tl_debug, "process_dserver_queue(): (3)no data to read from tp; ret %d", ret);
					return ret;
				}
				qbuf.woffset += ret;
				qbuf.len += ret;
			}
		}
		// put in front of read queue data.
		else
		{
			len = *count - qbuf.len;
			// if not enough room for header and data in queue, then window pacing is not working
			if( len > qbuf.roffset - qbuf.woffset )
			{
				trace(tl_error, "process_dserver_queue(): not enough room in queue for data");
				return 0;
			}
			ret =  tp_read( fd, (unsigned char *)&qbuf.data[qbuf.woffset], len );
			if( ret <= 0 )
				return ret;
			qbuf.woffset += ret;
			qbuf.len += ret;
		}
		if( qbuf.len == *count )
			qbuf.len = 0;
		*type = DEVICE_SERVER_DATA_QUEUED; 
		return ret;
	}
	
	//************************************************************************
	// take data off queue.

	if( qbuf.roffset != qbuf.woffset )	// queue is not empty
	{
		trace(tl_debug, "process_dserver_queue(): get: w=%d, l=%d, r=%d; c=%d, bl=%d", 
				qbuf.woffset, qbuf.len, qbuf.roffset, *count, buf->len);
		// If this is a new buffer, get header information.
		if( buf->len == 0 )
		{
			if( qbuf.roffset > qbuf.woffset )	// get from end of queue
			{
				if( 2 <= DS_BUF_SIZE - qbuf.roffset ) {
					*header = *(short *)&qbuf.data[qbuf.roffset];
					qbuf.roffset += 2;
				}
				else
					qbuf.roffset = 0;		// never split header, go to start of queue		
			}
			if( qbuf.roffset < qbuf.woffset )	// get from beginning of queue
			{
				if( qbuf.woffset - qbuf.roffset > 2 ) {
					*header = *(short *)&qbuf.data[qbuf.roffset];
					qbuf.roffset += 2;
				}
				else 	 
				{	// not enough room for header, consider queue empty
					trace(tl_debug, "process_dserver_queue(): queue buffer is empty");
					*type = DEVICE_SERVER_QUEUE_EMPTY;
					return 0;			
				}	
			}
			*count = *header & DEVICE_SERVER_COUNT_MASK;
			trace(tl_debug, "process_dserver_queue(): count=%d, header=%04x", *count, *header);
			if( *count <= 0 || *count > DS_BUF_SIZE )
			{
				trace(tl_debug, "process_dserver_queue(): packet byte count is invalid");
				return 0;
			}
		}
		
		if( *count - buf->len <= 0 )
		{
			trace(tl_debug, "process_dserver_queue(): no data length specified");
			return 0;
		}
		// now get data.
		if( qbuf.roffset > qbuf.woffset )
		{
			len = *count - buf->len;
			if( len < DS_BUF_SIZE - qbuf.roffset )
			{
				memcpy( &buf->data[buf->len], &qbuf.data[qbuf.roffset], len );
				qbuf.roffset += len;
			}
			else
			{
				len = DS_BUF_SIZE - qbuf.roffset;
				memcpy( &buf->data[buf->len], &qbuf.data[qbuf.roffset], len );
				qbuf.roffset = 0;
				len2 = *count - (buf->len + len);
				if( len2 > qbuf.woffset - qbuf.roffset )
				{
					trace(tl_debug, "process_dserver_queue() - get: not full packet: count %d, len2 %d, avail %d",
									*count, len2, qbuf.woffset-qbuf.roffset );
					len2 = qbuf.woffset - qbuf.roffset;
				}
				memcpy( &buf->data[buf->len+len], &qbuf.data[qbuf.roffset], len2 );
				qbuf.roffset += len2;
				len += len2;
			}
		}
		else
		{
			len = *count - buf->len; 
			if( len > qbuf.woffset - qbuf.roffset )
			{
				trace(tl_debug, "process_dserver_queue() - get: not full packet: count %d, len %d, avail %d",
								*count, len, qbuf.woffset-qbuf.roffset );
				len = qbuf.woffset - qbuf.roffset;
			}
			memcpy( &buf->data[buf->len], &qbuf.data[qbuf.roffset], len );
			qbuf.roffset += len;
		}
		*type = DEVICE_SERVER_DATA; 
		return len;
	}	
			
	trace(tl_debug, "process_dserver_queue(): no valid conditions to process queue");
	return 0;		// should not reach here.	
}


/****************************************************************************
 *	Read an DEVICE_SERVER UDP message
 ****************************************************************************/
/*
	Arguments	: udp_response : pointer to response structure
	Return values	: OK or FAILURE
*/
int read_dserver_udp_message(udp_response_t *udp_response)
{
	int     		ret;
	socklen_t      	addr_size;
	unsigned char   buf [16];

	if ( ipv6_not_running )
	{
		addr_size = sizeof (dserver_addr);
		ret = recvfrom(udp_sock, (char *) buf, sizeof (buf), 0,
		                (struct sockaddr *) &dserver_addr, &addr_size );
	}
	else
	{
		addr_size = sizeof (dserver_addr6);
		ret = recvfrom(udp_sock, (char *) buf, sizeof (buf), 0,
		                (struct sockaddr *) &dserver_addr6, &addr_size );
	}

	if (ret <= 0)
	{
		trace(tl_error, "receiving UDP message: %s", strerror(errno) );
		return FAILURE;
	}
	else
	{
		/* cmd, seq */
		udp_response->command = buf[0];
		udp_response->sequence_no = buf[1];

		if(trace_level >= tl_data)
		{
			trace(tl_data, "read UDP data: %d bytes", ret);
			dump_buf(trace_file, buf, ret);
		}
		trace(tl_data, "read_dserver_udp_message(): %s, seq = %02x",
		      get_msg(udp_response->command, dserver_udp_msg_list), udp_response->sequence_no);

	}

	return OK;
}
/****************************************************************************
 *	Set up a UDP socket for out of band communication with DEVICE_SERVER
 ****************************************************************************/
/*
	Arguments	: None
	Return values	: OK or FAILURE
 
 	dserver_addr must be set before calling(in wait_for_connect).
	On successful exit udp_sock and udp_addr are set.
*/
int setup_udp_socket(void)
{
	int on = 1;

	if ( udp_sock != -1 )
		return OK;
	
	// If IPv6 is not running then try IPv4.
	if ( ipv6_not_running )
	{
		udp_sock = socket( AF_INET, SOCK_DGRAM, 0 );

		if (udp_sock == -1)
		{
			trace(tl_error, "UDP socket create failed: %s\n", strerror(errno) );
			return FAILURE;
		}

		memset( &udp_addr, 0, sizeof(udp_addr) );

		udp_addr.sin_family = AF_INET;
		memset(&udp_addr.sin_addr, 0, sizeof (struct in_addr));
		udp_addr.sin_port = htons(tcp_port);

		setsockopt( udp_sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));

		if ( bind( udp_sock, (struct sockaddr *) & udp_addr, sizeof(udp_addr) ) < 0 )
		{
			trace(tl_error, "udp bind failed: %d\n", errno );
			return FAILURE;
		}

		memset( &udp_addr, 0, sizeof(udp_addr) );
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_port = htons(DEVICE_SERVER_UDP_PORT);
		memcpy(&udp_addr.sin_addr, &dserver_addr.sin_addr, sizeof (struct in_addr));
	}
	else
	{
		udp_sock = socket( AF_INET6, SOCK_DGRAM, 0 );
		if (udp_sock == -1)
		{
			trace(tl_error, "UDP socket create failed(6): %s\n", strerror(errno) );
			return FAILURE;
		}

		memset( &udp_addr6, 0, sizeof(udp_addr6) );

		udp_addr6.sin6_family = AF_INET6;
		memset(&udp_addr6.sin6_addr, 0, sizeof (struct in6_addr));
		udp_addr6.sin6_port = htons(tcp_port);

		setsockopt( udp_sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));

		if ( bind( udp_sock, (struct sockaddr *) & udp_addr6, sizeof(udp_addr6) ) < 0 )
		{
			trace(tl_error, "udp bind failed(6): %d\n", errno );
			return FAILURE;
		}

		memset( &udp_addr6, 0, sizeof(udp_addr6) );
		udp_addr6.sin6_family = AF_INET6;
		udp_addr6.sin6_port = htons(DEVICE_SERVER_UDP_PORT);
		memcpy (&udp_addr6.sin6_addr, &dserver_addr6.sin6_addr, sizeof (struct in6_addr));
	}
	trace(tl_debug, "created udp socket");
	return OK;
}


/****************************************************************************
 *	Write control command to an DEVICE_SERVER connection(in-band TCP messages)
 ****************************************************************************/
/*
	Arguments	: fd   : descriptor of socket
			  cmd  : command
		Return values	: -1 if error(errno is set), 
					or 0/+Ve number of bytes(errno EAGAIN),
					otherwise no of bytes written
*/
int 	write_dserver_ctrl(int fd, int cmd)
{
	int ret= -1;
	dserver_cmd_t dserver_cmd;
	feature_ack_cmd_t feat_ack_cmd;

	io_packet_t io_cmd;

	if (mode == pm_lite)
	{
		if (client_io_type)
		{
			if (cmd == IOCMD_KEEP_ALIVE)
			{
				io_cmd.iotype = cmd;
				io_cmd.datalength = htons((sizeof(keep_alive_t)));
				io_cmd.io_u.keep_alive.interval = htons(keepalive_time);
				ret = write_buf_raw( fd, (unsigned char *)&io_cmd, 
									(IO_HEADER_SIZE + sizeof(keep_alive_t)) );
				return(ret);
			}
			return(FAILURE);
		}
		else
		{
			return(FAILURE);
		}
	}

	if (cmd == DS_TCP_FEATURE_ACK)
	{
		uint32_t TpFeatureSupport;

		feat_ack_cmd.count = htons(DEVICE_SERVER_COMMAND | (sizeof(feature_ack_cmd_t) - 2));
		feat_ack_cmd.cmd = cmd;
		dserver_cmd.command = cmd;
		TpFeatureSupport = DServerFeatures;
		if (use_legacy_UDP)
		{
			TpFeatureSupport &= (TPSFEAT_MASK & ~TPSFEAT_NO_UDP);
		}
		else
		{  
			TpFeatureSupport &= TPSFEAT_MASK;
		}

		feat_ack_cmd.tpfeatures = htonl(TpFeatureSupport);
		ret = write_buf_raw(fd, (unsigned char *)&feat_ack_cmd, sizeof(feature_ack_cmd_t));
		out_window_size -= sizeof(feature_ack_cmd_t);
		trace(tl_debug, "write_dserver_ctrl(): Sent DS_TCP_FEATURE_ACK Cmd=0x%X, TpFeatureSupport= 0x%04X\n", DS_TCP_FEATURE_ACK, TpFeatureSupport );
	}
	else
	{
		dserver_cmd.count = htons(DEVICE_SERVER_COMMAND | 1);
		dserver_cmd.command = cmd;
		// check if this command is to be put int the packet forwarding buffer and if so try
		// else just send command to dserver
		if ( !( (info.dscmd == cmd) && ChkPutDsCmdPktFwdBuf(&info, (char *)&dserver_cmd, 3) ) )
		{
			// if the command was to go in the pkt fwd buf then forward now before sending cmd
			if (info.dscmd)
				forward_frame(&info);
			ret = write_buf_raw(fd, (unsigned char *)&dserver_cmd, 3);
			out_window_size -= 3;
		}
	}
	trace(tl_debug, "write_dserver_ctrl(): Sending device server inline command %s", get_msg(dserver_cmd.command,dserver_tcp_msg_list) );
	return ret;
}


// This function will send any TCP Immediate commands, These are the old UDP
// OOB commands plus a few new ones.
// Note, these commands do not use up any of the window count
//	Return values	: -1 if error(errno is set), 
//					or 0/+Ve number of bytes(errno EAGAIN),
//					otherwise no of bytes written
int write_dserver_imm_ctrl(int fd, int cmd,  unsigned char data)
{
	int      			ret = -1;
	dserver_cmd_t		dserver_cmd;
	keepalive_cmd_t keepalive_cmd;
	unsigned char 	null_ch = 0;

	if (mode == pm_lite)
	{
		if ((cmd == DS_UDP_KEEP_ALIVE)
		   && !client_io_type
		)
		{
			null_ch = DS_URG_TCP_PACKETMODE_ACK;
			ret = send(dserver_fd,(const char *) &null_ch, 1, MSG_OOB);
			if( ret != 1 )
				return FAILURE;
			else
				return OK;
		}
		else
			/* no other controls supported */
			return FAILURE;
	}	

	// if currently using UDP protocol then return error
	if (!IsNoUDP())
	{
		trace(tl_debug, "write_dserver_imm_ctrl() called and device server does not support these commands" );
		return(FAILURE);
	}

	trace(tl_debug, "write_dserver_imm_ctrl(): Sending device server IMMediate command %s", get_msg( (cmd & ~DS_IMM_CMD_MASK), dserver_udp_msg_list) );
	
	// if keep-alive command and non-zero keep-alive value then send immediate keep-alive command
	if ( (cmd == DS_UDP_KEEP_ALIVE) && keepalive_time )
	{
		keepalive_cmd.count = htons(DEVICE_SERVER_COMMAND  | (sizeof(keepalive_cmd_t) - 2));
		keepalive_cmd.cmd = cmd | DS_IMM_CMD_MASK;		// set immediate command
	
		keepalive_cmd.keepalive_data.interval = htons(keepalive_time);
		ret = write_buf_raw( fd, (unsigned char *)&keepalive_cmd, sizeof(keepalive_cmd_t) );
	}
	// else the rest of the commands are all one byte
	else
	{
		dserver_cmd.count = htons(DEVICE_SERVER_COMMAND  | 1);
		dserver_cmd.command = cmd | DS_IMM_CMD_MASK;		// set immediate command
		ret = write_buf_raw(fd, (unsigned char *)&dserver_cmd, 3 );
	}

	return(ret);
}


/****************************************************************************
 *	Write UDP control command to a DEVICE_SERVER connection
 ****************************************************************************/
/*
	Arguments	: command  : UDP command
	Return values	: error code
*/
int 	write_dserver_udp_ctrl(int command)
{
	unsigned char 	null_ch = 0;
	unsigned char 	message [3];
	int 		ret;

	if (mode == pm_lite)
	{
		if ((command == DS_UDP_KEEP_ALIVE)
		   && !client_io_type
		)
		{
			/* synchronous write? */
			/* ret = write_buf_raw(dserver_fd, &null_ch, 1);
						We used a null byte in-band before - however this appears in
						data. If we send a UDP DS_URG_TCP_PACKETMODE_ACK,
						this is ignored by JS  */

			null_ch = DS_URG_TCP_PACKETMODE_ACK;
			ret = send(dserver_fd,(const char *) &null_ch, 1, MSG_OOB);
			if( ret != 1 )
				return FAILURE;
			else
				return OK;
		}
		else
			/* no other controls supported */
			return FAILURE;
	}
	else    /* full mode */
	{
		if(udp_sock == -1)
		{
			trace(tl_error, "Current udp_sock is invalid");
			return FAILURE;
		}

		if(command == DS_UDP_RESET)
		{
			udp_sequence_no = 0;
		}

		message[0] = dserver_port_no;
		message[1] = udp_sequence_no;
		message[2] = command;

		trace(tl_data, "sending UDP message %s, seq = %02x",
		      get_msg(command, dserver_udp_msg_list), udp_sequence_no);

		// The udp control channel is not encrypted, as SSL does not support
		//  udp connections.
		if( ipv6_not_running )
		{
			if( sendto( udp_sock,(const char *) message,
			            sizeof(message), 0,(const struct sockaddr *) &udp_addr,
			            sizeof(udp_addr) ) < 0 )
			{
				trace(tl_error, "UDP sendto failed: %d", errno );
				return FAILURE;
			}
		}
		else
		{
			if( sendto( udp_sock,(const char *) message,
			            sizeof(message), 0,(const struct sockaddr *) &udp_addr6,
			            sizeof(udp_addr6) ) < 0 )
			{
				trace(tl_error, "UDP sendto failed: %d\n", errno );
				return -1;
			}
		}

	}
	return OK;
}


/****************************************************************************
 *	Write UDP control command to an DEVICE_SERVER connection and wait for response
 ****************************************************************************/
/*
	Arguments	: command      : UDP command to send
	Return values	: error code
*/
int 	write_dserver_udp_ctrl_wait(int command)
{
	int  ret;
	fd_set		read_set;
	struct timeval	tim;
	unsigned int 	tries;

	if ( (mode == pm_full) && (udp_sock == -1) )
	{
		 // if currently not using UDP then send immediate command
		 if ( IsNoUDP() && (dserver_fd != -1) )
		 {
			  return(write_dserver_imm_ctrl(dserver_fd, command, 0));
		 }
		 else
			  return FAILURE;
	}
	
	for(tries=0; tries < max_udp_retries; tries++)
	{
		ret = write_dserver_udp_ctrl(command);
		if (mode == pm_lite)
		{
			return ret;
		}

		if (ret == FAILURE)
		{
			/* socket not open or sendto failed */
//			close_connection();
//			return FAILURE;
			goto write_udp_fail;
		}

		/* wait for reply */

		FD_ZERO( &read_set );
		FD_SET( udp_sock, &read_set );

		tim.tv_sec  = udp_ack_timeout / 1000000;
		tim.tv_usec = udp_ack_timeout % 1000000;

		ret = select(FD_SETSIZE, &read_set, NULL, NULL, &tim );

		if (ret == 0)
		{
			trace(tl_debug, "timed out waiting for UDP response(%d) - %x",
			      udp_sequence_no, command );
		}
		else if (ret == -1)
		{
			trace (tl_error, "error on select for UDP receive: %s", strerror (errno));
//			return FAILURE;
			goto write_udp_fail_noclose;
		}

		if((udp_sock != -1) && FD_ISSET( udp_sock, &read_set) )
		{
			ret = read_dserver_udp_message(&udp_response);

			/* process the response */

			switch (udp_response.command)
			{
				case DS_UDP_SYN:
				{
					 /* This is really very bad */
					/* *** abort connection */
//					close_connection();
//					return FAILURE;
					goto write_udp_fail;
					break;
				}
				case DS_UDP_ACK:
				{
					if (udp_response.sequence_no == udp_sequence_no)
					{
						trace(tl_debug, "UDP ACK sequence ok(%d) - %x", udp_sequence_no, command );
						udp_sequence_no++;
						return OK;
					}
					else
					{
						trace(tl_error, "error in UDP ACK sequence no(%d : %d) - %x ",
								udp_sequence_no, udp_response.sequence_no, command );
					}
					break;
				}
				case DS_UDP_WAK:
				{
					if (udp_response.sequence_no == udp_sequence_no)
					{
						trace (tl_debug, "UDP WAK sequence ok");
						udp_sequence_no++;
						return OK;
					}
					else
					{
						trace (tl_error, "error in UDP WAK sequence no");
					}
					break;
				}
				case DS_UDP_NAK:
				{
					 trace (tl_error, "received NAK");
					 /* fairly bad too */
//					close_connection();
//					return FAILURE;
					goto write_udp_fail;
					break;
				}
			default:
			{
				trace (tl_error, "unexpected UDP message: %d", udp_response.command);
			}
			} // end switch
		}
	}

write_udp_fail:
	close_connection();

write_udp_fail_noclose:
	return FAILURE;
}

//*********************************************************************
//  write_dserver_data - write application data to dserver
//****************************************************************************/
//
//	Arguments	: fd   : descriptor of socket
//			  buf  : pointer to buffer
//	Return values	: 0,+Ve number of bytes( errno maybe EAGAIN),
//					otherwise -1( errno set )
//
int write_dserver_data(int fd, buf_t *dstbuf, unsigned char *srcbuf, int srcbuf_len)
{
	int ret;
	int count;
	
	unsigned short header;

	if (mode == pm_lite)
	{
		// process client I/O data from Application
		if (client_io_type)
		{
			io_packet_t *pio_header;

			count = srcbuf_len;
			// fill in I/O Access header
			pio_header = (io_packet_t *)&dstbuf->data;
			pio_header->iotype = client_io_type;
			pio_header->datalength = htons(count);
			dstbuf->len = IO_HEADER_SIZE;
			// copy in the rest of I/O Access application data
			memcpy(&pio_header->io_u.data, srcbuf, srcbuf_len);
			dstbuf->len += srcbuf_len;
			ret = write_buf_raw(fd, &dstbuf->data[dstbuf->offset], dstbuf->len);
		}
		else
		{
			memcpy(&dstbuf->data, srcbuf, srcbuf_len);
			dstbuf->len = srcbuf_len;
			ret = write_buf_raw(fd, &dstbuf->data[ dstbuf->offset ], dstbuf->len);
		}
	}
	else
	{
		// if using new pkt fwd logic then srcbuf is already packetized
		if (UseNewPktFwdLogic(&info))
		{
			memcpy(&dstbuf->data, srcbuf, srcbuf_len);
			dstbuf->len = srcbuf_len;
			out_window_size -= srcbuf_len;
			ret = write_buf_raw(fd, &dstbuf->data[ dstbuf->offset ], dstbuf->len);
		}
		else
		{
			 header = srcbuf_len;
			 // insert header into dstbuf
			 dstbuf->len += 2;
			 dstbuf->data[0] = (header >> 8) & 0xff;
			 dstbuf->data[1] = (header) & 0xff;
	 
			 // copy data into dstbuf
			 memcpy(&dstbuf->data[2], srcbuf, srcbuf_len);
			 dstbuf->len = srcbuf_len + 2;
	 
			 out_window_size -= dstbuf->len;
			 ret = write_buf_raw(fd, &dstbuf->data[dstbuf->offset], dstbuf->len);
		}
	}

	/* handle incomplete writes */
	if (ret > 0)
	{
		if (ret != dstbuf->len)
		{
			trace(tl_error, "incomplete write on device server, req %d written %d\n",dstbuf->len, ret);
		}
		dstbuf->len -= ret;
		dstbuf->offset += ret;
	}

	return ret;
}


/****************************************************************************
 *	Write control command to a TTY connection(trueport mode)
 ****************************************************************************/
/*
	Arguments: 
				fd   : descriptor of socket
				cmd  : command
				data : optional parameter data
				len  : length of parameter data
	Return values	: error code
*/
int write_tty_ctrl(int fd, int cmd, unsigned char *data, unsigned int len)
{
	unsigned int new_state;
	unsigned int old_state;
	int open_wait, temp_iparm;
	int ret;

	trace(tl_debug, "write_tty_ctrl(): cmd=0x%x\n", cmd);

	switch ( cmd )
	{
		case TP_PROTO_GOT_BREAK:
		{
			ret = ioctl(fd, TCSBRK, NULL);
			if (ret)
			{
				trace(tl_error, "Error in ioctl TCSBRK %d %d\n", ret, errno);
//				exit(-1);
				return FAILURE;
			}
			break;
		}
		case TP_PROTO_LSRUPDATE:
		{
			if (data)
			{
				new_state = *data;
				trace(tl_debug, "write_tty_ctrl TP_PROTO_LSRUPDATE : %02x = %cOE %cPE %cFE %cBI\n",
				   new_state,
				   new_state & LSRNODATA_OE ? '+' : '-',
				   new_state & LSRNODATA_PE ? '+' : '-',
				   new_state & LSRNODATA_FE  ? '+' : '-',
				   new_state & LSRNODATA_BI  ? '+' : '-');
				ret = ioctl(fd, PTX_IOCLSET, &new_state);	// set line status info
				if (ret)
				{
					trace(tl_error, "Error in ioctl %d %d\n", ret, errno);
//					exit(-1);
					return FAILURE;
				}
			}
			break;
		}
		case TP_PROTO_DCD_UP:
		case TP_PROTO_DCD_DOWN:
		{
			if (data)
			{
				new_state = *data;
				ret = ioctl(fd, TIOCMGET, &current_state);	// get modem status
				old_state = current_state;
				if (ret)
				{
					trace(tl_error, "Error in tiocmget: %d %d\n", ret, errno);
//					exit(-1);
					return FAILURE;
				}

				trace( tl_debug, "write_tty_ctrl(): new=0x%02x, old=0x%08x\n", new_state, old_state );
				//		  if (new_state & CD_DSR) current_state |= TIOCM_RTS; else current_state &= ~TIOCM_RTS;
				if (new_state & CD_RI)
					current_state |= TIOCM_RI;
			  	else
					 current_state &= ~TIOCM_RI;

				if (new_state & CD_CD)
					 current_state |= TIOCM_CD;
				else
					 current_state &= ~TIOCM_CD;
            
				if (DServerFeatures & TPSFEAT_IOLANDS)
				{
					if (new_state & CD_DTR)
						current_state |= TIOCM_DTR;
				  else
						current_state &= ~TIOCM_DTR;
				
				  if (new_state & CD_RTS)
						current_state |= TIOCM_RTS;
				  else
						current_state &= ~TIOCM_RTS;
				
				  if (new_state & CD_DSR)
						current_state |= TIOCM_DSR;
				  else
						current_state &= ~TIOCM_DSR;
				
				  if (new_state & CD_CTS)
						current_state |= TIOCM_CTS;
				  else
						current_state &= ~TIOCM_CTS;
				}
				else
				{
					if (new_state & CD_DTR)
						current_state |= TIOCM_DSR;
				  else
						current_state &= ~TIOCM_DSR;
				
				  if (new_state & CD_RTS)
						current_state |= TIOCM_CTS;
				  else
						current_state &= ~TIOCM_CTS;
				}
				trace( tl_debug, "write_tty_ctrl(): curr=0x%08x\n", current_state );

				ret = ioctl(fd, PTX_IOCMSET, &current_state);	// set modem status
				if (ret)
				{
					trace(tl_debug, "Error in ioctl-4: %d %d\n", ret, errno);
					return FAILURE;
				}

				if (!(current_state & TIOCM_CD) && (old_state & TIOCM_CD) &&
			        !(dserver_termios_modes.c_cflag & CLOCAL))
				{
					trace( tl_info, "Lost CD - close tty port" );
					close_tty_no_rm();
				}
			}
			break;
		}
		case TP_PROTO_DRAIN_ACK:
		{
			ret = ioctl(fd, PTX_IOCDRAINEND, 0);	// drain complete
			if (ret)
			{
				trace(tl_error, "Error in ioctl-PTX_IOCDRAINEND: %d %d %d\n", __LINE__,ret, errno);
				return FAILURE;
			}
		
			break;
		}
		case TP_PROTO_SET_OPEN_WAIT:
		{
			// data points to open wait time 
			if (data)
			{
				open_wait = *(int *)data;
				if (open_wait >= 0)
				{
					temp_iparm =  open_wait*1000;
				}
				else
				{
					temp_iparm = open_wait;
				}
				ret = ioctl(ptyxm_fd,PTX_IOCOWTSET,&temp_iparm);	// give ptyx, the open wait time in msec
				if (ret)
				{
					trace(tl_error, "Error in ioctl-PTX_IOCOWTSET: %d %d %d\n", __LINE__,ret, errno);
//					exit(-1);
					return FAILURE;
				}
			}
			break;
		}
		case TP_PROTO_TP_CONNECTION:
		{
			// data points to network connect state
			if (data)
			{
				ret = ioctl(ptyxm_fd,PTX_IOCNETSTAT, data);		// give ptyx, the connection status
				if (ret)
				{
					trace(tl_error, "Error in ioctl-PTX_IOCNETSTAT: %d %d %d\n", __LINE__,ret, errno);
//					exit(-1);
					return FAILURE;
				}
			}
			break;
		}
		default:
		{
			 break;
		}
	}
	return OK;
}



// Check if there is any master tty control status by polling the 
// control tty.  If there is any then read it process. Returns when 
// no new control statuses are available
// Returns 0 if succesfull
// 			<0 on failure
//
int process_tty_ctrl()
{
	int ret = 0;
	int len = 0;
	fd_set read_set;
	unsigned int new_state;
	typeof(ptyx_ctrl_status) temp_ctrl_status;
	/* termios */
	struct termios  new_dserver_termios_modes;
	struct timeval zerotimeout={0};

	// we should only get new tty control status if:
	//   * there's a valid control status tty file handle
	//   * there is a TruePort connection
//	while ((ptyxc_fd > 0) && is_tp_conn_avail() )
	while ( ptyxc_fd > 0 )
	{
		// We only need to read from the control status tty
		
		FD_ZERO( &read_set );
		FD_SET(ptyxc_fd, &read_set);
		ret = select(FD_SETSIZE, &read_set, NULL, NULL, &zerotimeout );
	
		// Return no error if no control status
		if (ret == 0)
		{
			break;
		}
		
		// ret error
		if (ret < 0) 
		{
			trace(tl_error, "process_tty_ctrl(): Error in select: ret=%d, errno=%d \n", ret, errno);
			break;
		}
		
		if (!FD_ISSET(ptyxc_fd, &read_set))
		{
 			trace(tl_error, "process_tty_ctrl(): read_fds should be set \n");
			ret = -1;
			break;
		}
		
		len = read( ptyxc_fd, &temp_ctrl_status, sizeof(ptyx_ctrl_status));
		
		if (len <= 0 )
		{
			// temporarly busy, try again
			if (errno == EAGAIN)
			{
	 			trace(tl_debug, "process_tty_ctrl():  ptyxc_fd=%d temporarly busy... try again \n", ptyxc_fd);
				continue;
			}
			trace(tl_error, "process_tty_ctrl(): Error in read from control status tty: ret=%d, errno=%d \n", len, errno);
			ret = -1;
			break;		// return error
		}
		
		if ( len != sizeof(ptyx_ctrl_status) )
		{
			trace(tl_error, "process_tty_ctrl(): read length=%d from control status tty invalid !!! \n", len);
			ret = -1;
			break;
		}

		// we have a valid tty fd and an outstading ctlr status
		trace(tl_debug, "process_tty_ctrl(): Have new control status, current=0x%08x new=0x%08x, combined=0x%08x\n", 
			 								ptyx_ctrl_status, temp_ctrl_status, (ptyx_ctrl_status|temp_ctrl_status));
		ptyx_ctrl_status |= temp_ctrl_status;

		if (ptyx_ctrl_status & CTRLSTATUS_CLOSE)
		{
			ptyx_ctrl_status &= (~CTRLSTATUS_CLOSE);
			trace(tl_info, "CTRLSTATUS_CLOSE recieved\n");
			forward_frame(&info );	// push any queued up data
			slave_is_open = FALSE;
			if (client_tcp_host)
			{
				// setup to close TCP connection on slave tty being closed
				//  as long as -nodisc not set
				if ( !nodisc_tcp && dserver_connected)
				{
					delay_close_tcp_flag = TRUE;
					gettimeofday( &info.delay_close_tcp_start, NULL );
				}
			}
		}
		if (ptyx_ctrl_status & CTRLSTATUS_OPEN)
		{
			trace(tl_debug, "CTRLSTATUS_OPEN recieved\n");
			ptyx_ctrl_status &= (~CTRLSTATUS_OPEN);
			slave_is_open = TRUE;
			if (client_tcp_host)
			{
				// clear delay_close_tcp_flag since we will eventually
				// get another close after this open
				delay_close_tcp_flag = FALSE;
			}
		}

		if (ptyx_ctrl_status & CTRLSTATUS_STOP)
		{
			ptyx_ctrl_status &= (~CTRLSTATUS_STOP);
			trace(tl_info, "CTRLSTATUS_STOP recieved\n");
	 
			if (mode == pm_full)
			{	
				ret = write_dserver_udp_ctrl_wait( DS_UDP_TCXOFF );
				if (ret < 0)
				{
					trace(tl_error, "CTRLSTATUS_STOP: Error sending DS_UDP_RFLUSH, closing connection\n");
					close_connection();
				}
			}
		}
		if (ptyx_ctrl_status & CTRLSTATUS_START)
		{
			ptyx_ctrl_status &= (~CTRLSTATUS_START);
			trace(tl_info, "CTRLSTATUS_START recieved\n");
	 
			if (mode == pm_full)
			{	
				ret = write_dserver_udp_ctrl_wait( DS_UDP_TCXON );
				if (ret < 0)
				{
					trace(tl_error, "CTRLSTATUS_START: Error sending DS_UDP_RFLUSH, closing connection\n");
					close_connection();
				}
			}
		}
		if (ptyx_ctrl_status & CTRLSTATUS_FLUSHREAD)
		{
			ptyx_ctrl_status &= (~CTRLSTATUS_FLUSHREAD);
			trace(tl_info, "CTRLSTATUS_FLUSHREAD recieved\n");
	 
			if (mode == pm_full)
			{
				/*
					put the daemon in read flush mode.  When in this mode
					any received data is discarded
					send a UDP DS_UDP_RFLUSH command to the server
					- when the daemon receives a TCP DS_TCP_SYNC_FLUSH_END
					command from the server, exit read flush mode.
				*/
				trace(tl_debug, "FLUSHREAD from app\n");
				flushing_net_read=1;
				ret = write_dserver_udp_ctrl_wait(DS_UDP_RFLUSH);
				if (ret < 0)
				{
					trace(tl_error, "CTRLSTATUS_FLUSHREAD: Error sending DS_UDP_RFLUSH, closing connection\n");
					close_connection();
				}
			}
		}
		if (ptyx_ctrl_status & CTRLSTATUS_FLUSHWRITE)
		{
			ptyx_ctrl_status &= (~CTRLSTATUS_FLUSHWRITE);
			trace(tl_info, "CTRLSTATUS_FLUSHWRITE recieved\n");
	 
			if (mode == pm_full)
			{
				/*
				- send a UDP DS_UDP_WFLUSH command to the server
				- send a TCP DS_TCP_SYNC_FLUSH_END command/marker to the
					server.
				*/
				trace(tl_debug, "FLUSHWRITE from app\n");
				ret = write_dserver_udp_ctrl_wait(DS_UDP_WFLUSH);
				forward_frame(&info );	// push any queued up data
				if (ret >= 0)
					ret = write_dserver_ctrl(dserver_fd, DS_TCP_SYNC_FLUSH_END);
				if (ret < 0)
				{
					trace(tl_error, "CTRLSTATUS_FLUSHWRITE: Error sending DS_TCP_SYNC_FLUSH_END, closing connection\n");
					close_connection();
				}
			}
		}
		// make sure we are in data transfer state if full mode or 
		// we can't process some of these
		if (mode == pm_lite  || ( state == s_data_transfer) )    
		{
			if (ptyx_ctrl_status & CTRLSTATUS_TERMIOS)
			{
				trace(tl_debug, "CTRLSTATUS_TERMIOS recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_TERMIOS);
				if (mode == pm_full)
				{
					tcgetattr(ptyxm_fd, &new_dserver_termios_modes);
					if (memcmp(&new_dserver_termios_modes, &dserver_termios_modes, sizeof (struct termios)))
					{
						trace(tl_debug, "setting termios\n");
						memcpy(&dserver_termios_modes, &new_dserver_termios_modes, sizeof (struct termios));
						if (UseNewPktFwdLogic(&info))
						{
							 // indicate that set tty command should be put into pkt fwd buf
							 info.dscmd = DS_TCP_STTY_SET;
						}
						set_dserver_modes(TRUE);
					}
				}
			}
			if (ptyx_ctrl_status & CTRLSTATUS_SIGNALS)
			{
				trace(tl_debug, "CTRLSTATUS_SIGNALS recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_SIGNALS);
				if (mode == pm_full)
				{
					/* Siganals */
					new_state = 0;
					ret = -1;
					ret = ioctl(ptyxm_fd, TIOCMGET, &new_state);	// get modem status
					if (ret)
					{
						trace(tl_error, "Error in ioctl-5: %d %d\n", ret, errno);
					}
					else
					{
						if (!signal_state_sent || 
							 ((prev_signal_state & (TIOCM_RTS|TIOCM_DTR))!=(new_state & (TIOCM_RTS|TIOCM_DTR))))
						{
							signal_state_sent=1;
							prev_signal_state=new_state;
							trace( tl_debug, "CTRLSTATUS_SIGNALS: new_state=%08x\n", new_state );
							if (UseNewPktFwdLogic(&info))
							{
								 // indicate that signals command should be put into pkt fwd buf
								 // don't know which one here
								 info.dscmd = DS_TCP_SET_DTR + DS_TCP_CLR_DTR + DS_TCP_SET_RTS + DS_TCP_CLR_RTS;
							}
							set_RTS_DTR(new_state & TIOCM_RTS, new_state & TIOCM_DTR);
							if ( dserver_connected && ((DServerFeatures & TPSFEAT_IOLANDS) == 0) )
							{
								write_dserver_ctrl(dserver_fd, DS_TCP_STTY_REPORT_ON);
							}
						}
					}
				}
			}
			if (ptyx_ctrl_status & CTRLSTATUS_BREAK )
			{
				trace(tl_debug, "CTRLSTATUS_BREAK recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_BREAK);
				forward_frame(&info );	// push any queued up data
				if (mode == pm_full)
				{
					ret = write_dserver_ctrl(dserver_fd, DS_TCP_SEND_BREAK);
					if (ret < 0)
					{
						trace(tl_error, "CTRLSTATUS_BREAK: Error sending DS_TCP_SEND_BREAK, closing connection\n");
						close_connection();
					}
				}
			}
			if (ptyx_ctrl_status & CTRLSTATUS_BREAKON)
			{
				trace(tl_debug, "CTRLSTATUS_BREAKON recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_BREAKON);
				forward_frame(&info );	// push any queued up data
				if (mode == pm_full)
				{
					if (DServerFeatures & TPSFEAT_TCPBREAKCTL)
					{
						ret = write_dserver_ctrl(dserver_fd, DS_TCP_SEND_BREAKON);
					}
					else
					{
						ret = write_dserver_udp_ctrl_wait(DS_UDP_SET_BREAK_ON);
					}
					if (ret < 0)
					{
						trace(tl_error, "CTRLSTATUS_BREAKON: Error sending commands, closing connection\n");
						close_connection();
					}
				}
			}
			if (ptyx_ctrl_status & CTRLSTATUS_BREAKOFF)
			{
				trace(tl_debug, "CTRLSTATUS_BREAKOFF recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_BREAKOFF);
				forward_frame(&info );	// push any queued up data
				if (mode == pm_full)
				{
					if (DServerFeatures & TPSFEAT_TCPBREAKCTL)
					{
						ret = write_dserver_ctrl(dserver_fd, DS_TCP_SEND_BREAKOFF);
					}
					else
					{
						ret = write_dserver_udp_ctrl_wait(DS_UDP_SET_BREAK_OFF);
					}
					if (ret < 0)
					{
						trace(tl_error, "CTRLSTATUS_BREAKOFF: Error sending commands, closing connection\n");
						close_connection();
					}
				}
			}
			if (ptyx_ctrl_status & CTRLSTATUS_DRAIN)
			{
				trace(tl_debug, "CTRLSTATUS_DRAIN recieved\n");
				ptyx_ctrl_status &= (~CTRLSTATUS_DRAIN);
				forward_frame(&info );	// push any queued up data
				if (DServerFeatures & TPSFEAT_SYNCDRAIN)			// note lite mode won't have this set
				{
					if (end2end_ctrl && tty_write_blocked==0)
					{
						ret = write_dserver_ctrl(dserver_fd, DS_TCP_SEND_SYNCDRAIN);
						pending_drain=1;
						if (ret < 0)
						{
							trace(tl_error, "CTRLSTATUS_DRAIN: Error sending DS_TCP_SEND_SYNCDRAIN, closing connection\n");
							close_connection();
						}	
					}
					else	// local control; so fake out an ack to the pty driver
					{
						ret = write_tty_ctrl(ptyxm_fd, TP_PROTO_DRAIN_ACK, NULL, 0); // drain complete
						if (ret < 0)
						{
							trace(tl_error, "Error in TP_PROTO_DRAIN_ACK: %d %d %d\n", __LINE__,ret, errno);
							break;
						}
					}
				}
				else	// lite mode or syncdrain not supported by server
				{		// fake ack to the pty driver
					ret = write_tty_ctrl(ptyxm_fd, TP_PROTO_DRAIN_ACK, NULL, 0); // drain complete
					if (ret < 0)
					{
						trace(tl_error, "Error in TP_PROTO_DRAIN_ACK: %d %d %d\n", __LINE__,ret, errno);
						break;
					}
				}
			}
		}
	} // end while (1)
	
	return ret;
}

/****************************************************************************
 *	Update input window
 ****************************************************************************/
/*
	Arguments	: n	: amount used up
	Return values	: none
*/
void update_input_window(int n)
{
	unsigned short	window_ack;
	
	trace(tl_data, "update_input_window(): cur=%d, inc=%d", in_window_used, n);

	in_window_used += n;

	while ( in_window_used > 512)
	{
		window_ack = htons(DEVICE_SERVER_COMMAND | DEVICE_SERVER_WINDOW);  /* 0xC000 */

		/* *** check dserver_out_buf is empty ! */
		if (write_buf_raw(dserver_fd,(unsigned char *)&window_ack, 2) < 0)
		{
			trace(tl_error, "update_input_window(): Error sending window update cmd, closing connection\n");
			close_connection();
		}
		in_window_used -= 512;
	}
}

void drop_modem_signals(void)
{
    int ret;
    
    ret = ioctl(ptyxm_fd, TIOCMGET, &current_state);	// get modem status
    if (ret)
    {
        trace(tl_error, "%s(): TIOCMGET error %d %d\n", __FUNCTION__, ret, errno);
    }
    else
    {
        current_state &= (~(TIOCM_DSR|TIOCM_CD|TIOCM_CTS));
        ret = ioctl(ptyxm_fd, PTX_IOCMSET, &current_state);	// set modem status
        if (ret)
        {
            trace(tl_error, "%s(): PTX_IOCMSET error %d %d\n", __FUNCTION__, ret, errno);
        }
    }
}

//****************************************************************************
// Set terminal modes on DEVICE_SERVER using previously stored local modes
// ****************************************************************************/
//
//	Arguments	: set_all : if true set all modes
//	Return values	: none
//
// Baud Rate represented as actual values, strings and hardware specific
//

void set_dserver_modes(int set_all)
{
	struct dservermode    dserver_mode_cmd;
	struct termios  *modes;
	int     iflag = 0, oflag = 0, lflag = 0, cflag = 0;
	buf_t       buf;
	int     ret;

	/* set up a device server set_modes command using our current modes */

	if (mode == pm_lite)
		return;


	modes = &dserver_termios_modes;

	dserver_mode_cmd.count = htons(DEVICE_SERVER_COMMAND |(dservermodesize-2) );
	dserver_mode_cmd.cmd = DS_TCP_STTY_SET;

#if 0
	{
		 char buf[512];
		sprintf(buf, "Iflag: %s%s%s%s%s%s%s%s%s%s%s%s%s\n",
	         (modes->c_iflag & IGNBRK)?"IGNBRK ":"",
	         (modes->c_iflag & BRKINT)?"BRKINT ":"",
	         (modes->c_iflag & IGNPAR)?"IGNPAR ":"",
	         (modes->c_iflag & PARMRK)?"PARMRK ":"",
	         (modes->c_iflag & INPCK)?"INPCK ":"",
	         (modes->c_iflag & ISTRIP)?"ISTRIP ":"",
	         (modes->c_iflag & INLCR)?"INLCR ":"",
	         (modes->c_iflag & IGNCR)?"IGNCR ":"",
	         (modes->c_iflag & ICRNL)?"ICRNL ":"",
	         (modes->c_iflag & IUCLC)?"IUCLC ":"",
	         (modes->c_iflag & IXON)?"IXON ":"",
	         (modes->c_iflag & IXANY)?"IXANY ":"",
	         (modes->c_iflag & IXON)?"IXON ":"");
		trace(tl_debug, buf);
	
		sprintf(buf, "OFlag: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
	         (modes->c_oflag & OPOST) ?"OPOST ":"",
	         (modes->c_oflag & OLCUC) ?"OLCUC ":"",
	         (modes->c_oflag & ONLCR) ?"ONLCR ":"",
	         (modes->c_oflag & OCRNL) ?"OCRNL ":"",
	         (modes->c_oflag & ONOCR) ?"ONOCR ":"",
	         (modes->c_oflag & OLCUC) ?"OLCUC ":"",
	         (modes->c_oflag & ONLRET) ?"ONLRET ":"",
	         (modes->c_oflag & OFILL) ? "OFILL ":"",
	         (modes->c_oflag & OFDEL) ? "OFDEL ":"",
	         (modes->c_oflag & NLDLY) ? "NLDLY ":"",
	         (modes->c_oflag & CR1) ? "CR1 ":"",
	         (modes->c_oflag & CR2) ? "CR2 ":"",
	         (modes->c_oflag & TAB1) ? "TAB1 ":"",
	         (modes->c_oflag & TAB2) ? "TAB2 ":"",
			         (modes->c_oflag & VTDLY) ? "VTDLY ":"",
	         (modes->c_oflag & FFDLY) ? "FFDLY ":"");
		trace(tl_debug, buf);

		sprintf(buf,"Cflag: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
			(modes->c_cflag & CLOCAL) ? "CLOCAL ":"",
			(modes->c_cflag & CREAD) ? "CREAD ":"",
			(modes->c_cflag & CSTOPB) ? "CSTOPB ":"",
			(modes->c_cflag & HUPCL) ? "HUPCL ":"",
			(modes->c_cflag & PARENB) ? "PARENB ":"",
			(modes->c_cflag & PARODD) ? "PARODD ":"",
			(modes->c_cflag & MTS_TCSETA_SYNC) ? "MTS_TCSETA_SYNC ":"",
			((modes->c_cflag & CBAUD) == B50) ? "B50 ":"",
			((modes->c_cflag & CBAUD) == B75) ? "B75 ":"",
			((modes->c_cflag & CBAUD) == B110) ? "B110 ":"",
			((modes->c_cflag & CBAUD) == B134) ? "B134 ":"",
			((modes->c_cflag & CBAUD) == B150) ? "B150 ":"",
			((modes->c_cflag & CBAUD) == B200) ? "B200 ":"",
			((modes->c_cflag & CBAUD) == B300) ? "B300 ":"",
			((modes->c_cflag & CBAUD) == B600) ? "B600 ":"",
			((modes->c_cflag & CBAUD) == B1200) ? "B1200 ":"",
			((modes->c_cflag & CBAUD) == B1800) ? "B1800 ":"",
			((modes->c_cflag & CBAUD) == B2400) ? "B2400 ":"",
			((modes->c_cflag & CBAUD) == B4800) ? "B4800 ":"",
			((modes->c_cflag & CBAUD) == B9600) ? "B9600 ":"",
			((modes->c_cflag & CBAUD) == B19200) ? "B19200 ":"",
			((modes->c_cflag & CBAUD) == B38400) ? "B38400 ":"",
			((modes->c_cflag & CBAUD) == B57600) ? "B57600 ":"" ,
			((modes->c_cflag & CBAUD) == B115200) ? "B115200 ":"" ,
			((modes->c_cflag & CBAUD) == B230400) ? "B230400 ":"" ,
			((modes->c_cflag & CS8) == CS5) ? "CS5 ":"",
			((modes->c_cflag & CS8) == CS6) ? "CS6 ":"",
			((modes->c_cflag & CS8) == CS7) ? "CS7 ":"",
			((modes->c_cflag & CS8) == CS8) ? "CS8 ":"",
			(modes->c_cflag & CRTSCTS) ? "CRTSCTS ":"");
		trace(tl_debug, buf);

		sprintf(buf,"Lflag: %s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
	        (modes->c_lflag & ISIG) ? "ISIG ":"",
	        (modes->c_lflag & ICANON) ? "ICANON ":"",
	        (modes->c_lflag & XCASE) ? "XCASE ":"",
	        (modes->c_lflag & ECHO) ? "ECHO ":"",
	        (modes->c_lflag & ECHOE) ? "ECHOE ":"",
	        (modes->c_lflag & ECHONL) ? "ECHONL ":"",
	        (modes->c_lflag & NOFLSH) ? "NOFLSH ":"",
	        (modes->c_lflag & ECHOCTL) ? "ECHOCTL ":"",
	        (modes->c_lflag & ECHOPRT) ? "ECHOPRT ":"",
	        (modes->c_lflag & ECHOKE) ? "ECHOKE ":"",
	        (modes->c_lflag & FLUSHO) ? "FLUSHO ":"",
	        (modes->c_lflag & PENDIN) ? "PENDIN ":"",
	        (modes->c_lflag & TOSTOP) ? "TOSTOP ":"",
	        (modes->c_lflag & IEXTEN) ? "IEXTEN ":"");
		trace(tl_debug, buf);
	}
#endif

	/*
	** The Termios structures used by the host dont always match
	** the MTS ones so translate ALL elements
	** DO NOT OVERWRITE the Termios structures though
	** otherwise the reads will be wrong
	*/
	iflag = ((modes->c_iflag & IGNBRK) ? MTS_IGNBRK : 0) |
	        ((modes->c_iflag & BRKINT) ? MTS_BRKINT : 0) |
	        ((modes->c_iflag & IGNPAR) ? MTS_IGNPAR : 0) |
	        ((modes->c_iflag & PARMRK) ? MTS_PARMRK : 0) |
	        ((modes->c_iflag & INPCK ) ? MTS_INPCK  : 0) |
	        ((modes->c_iflag & ISTRIP) ? MTS_ISTRIP : 0) |
	        ((modes->c_iflag & INLCR ) ? MTS_INLCR  : 0) |
	        ((modes->c_iflag & IGNCR ) ? MTS_IGNCR  : 0) |
	        ((modes->c_iflag & ICRNL ) ? MTS_ICRNL  : 0) |
	        ((modes->c_iflag & IUCLC ) ? MTS_IUCLC  : 0) |
	        ((modes->c_iflag & IXON  ) ? MTS_IXON   : 0) |
	        ((modes->c_iflag & IXANY ) ? MTS_IXANY  : 0) |
	        ((modes->c_iflag & IXOFF ) ? MTS_IXOFF  : 0) |
	        ((modes->c_iflag & IMAXBEL) ? MTS_IMAXBEL : 0);

	oflag = ((modes->c_oflag & OPOST) ? MTS_OPOST : 0) |
	        ((modes->c_oflag & OLCUC) ? MTS_OLCUC : 0) |
	        ((modes->c_oflag & ONLCR) ? MTS_ONLCR : 0) |
	        ((modes->c_oflag & OCRNL) ? MTS_OCRNL : 0) |
	        ((modes->c_oflag & ONOCR) ? MTS_ONOCR : 0) |
	        ((modes->c_oflag & OLCUC) ? MTS_OLCUC : 0) |
	        ((modes->c_oflag & ONLRET) ? MTS_ONLRET : 0) |
	        ((modes->c_oflag & OFILL) ? MTS_OFILL : 0) |
	        ((modes->c_oflag & OFDEL) ? MTS_OFDEL : 0) |
	        ((modes->c_oflag & NLDLY) ? MTS_NLDLY : 0) |
	        ((modes->c_oflag & CR1) ? MTS_CR1 : 0) |
	        ((modes->c_oflag & CR2) ? MTS_CR2 : 0) |
	        ((modes->c_oflag & TAB1) ? MTS_TAB1 : 0) |
	        ((modes->c_oflag & TAB2) ? MTS_TAB2 : 0) |
	        ((modes->c_oflag & VTDLY) ? MTS_VTDLY : 0) |
	        ((modes->c_oflag & FFDLY) ? MTS_FFDLY : 0);

	cflag = 0 |
	        /*        ((modes->c_cflag & CLOCAL) ? MTS_CLOCAL : 0) | */
	        ((modes->c_cflag & CREAD) ? MTS_CREAD : 0) |
	        ((modes->c_cflag & CSTOPB) ? MTS_CSTOPB : 0) |
	        ((modes->c_cflag & HUPCL) ? MTS_HUPCL : 0) |
	        ((modes->c_cflag & PARENB) ? MTS_PARENB : 0) |
	        ((modes->c_cflag & PARODD) ? MTS_PARODD : 0) |
	        /* ((modes->c_cflag & LOBLK) ? MTS_LOBLK : 0) | */
	        ((modes->c_cflag & MTS_TCSETA_SYNC) ? MTS_TCSETA_SYNC : 0) |  

	        (((modes->c_cflag & CBAUD) == B50) ? MTS_B50 : 0) |
	        (((modes->c_cflag & CBAUD) == B110) ? MTS_B110 : 0) |
	        (((modes->c_cflag & CBAUD) == B134) ? MTS_B134 : 0) |
	        (((modes->c_cflag & CBAUD) == B75)     ? MTS_B75     : 0) |
	        (((modes->c_cflag & CBAUD) == B150)    ? MTS_B150    : 0) |
	        (((modes->c_cflag & CBAUD) == B200)    ? MTS_B200    : 0) |
	        (((modes->c_cflag & CBAUD) == B300)    ? MTS_B300    : 0) |
	        (((modes->c_cflag & CBAUD) == B600)    ? MTS_B600    : 0) |
	        (((modes->c_cflag & CBAUD) == B1200)   ? MTS_B1200   : 0) |
	        (((modes->c_cflag & CBAUD) == B1800)   ? MTS_B1800   : 0) |
	        (((modes->c_cflag & CBAUD) == B2400)   ? MTS_B2400   : 0) |
	        (((modes->c_cflag & CBAUD) == B4800)   ? MTS_B4800   : 0) |
	        (((modes->c_cflag & CBAUD) == B9600)   ? MTS_B9600   : 0) |
	        (((modes->c_cflag & CBAUD) == B19200)  ? MTS_B19200  : 0) |
	        (((modes->c_cflag & CBAUD) == B38400)  ? MTS_B38400  : 0) |
	        (((modes->c_cflag & CBAUD) == B57600)  ? MTS_B57600  : 0) |
	        (((modes->c_cflag & CBAUD) == B115200) ? MTS_B115200 : 0) |
	        (((modes->c_cflag & CBAUD) == B230400) ? MTS_B230400 : 0) |

	        ((modes->c_cflag & CS6) ? MTS_CS6 : 0) |
	        ((modes->c_cflag & CS7) ? MTS_CS7 : 0) |
	        ((modes->c_cflag & CRTSCTS) ? (MTS_CTSFLOW | MTS_RTSFLOW) : 0);

	lflag = ((modes->c_lflag & ISIG) ? MTS_ISIG : 0) |
	        ((modes->c_lflag & ICANON) ? MTS_ICANON : 0) |
	        ((modes->c_lflag & XCASE) ? MTS_XCASE : 0) |
	        ((modes->c_lflag & ECHO) ? MTS_ECHO : 0) |
	        ((modes->c_lflag & ECHOE) ? MTS_ECHOE : 0) |
	        ((modes->c_lflag & ECHONL) ? MTS_ECHONL : 0) |
	        ((modes->c_lflag & NOFLSH) ? MTS_NOFLSH : 0) |
	        ((modes->c_lflag & ECHOCTL) ? MTS_ECHOCTL : 0) |
	        ((modes->c_lflag & ECHOPRT) ? MTS_ECHOPRT : 0) |
	        ((modes->c_lflag & ECHOKE) ? MTS_ECHOKE : 0) |
	        ((modes->c_lflag & FLUSHO) ? MTS_FLUSHO : 0) |
	        ((modes->c_lflag & PENDIN) ? MTS_PENDIN : 0) |
	        ((modes->c_lflag & TOSTOP) ? MTS_TOSTOP : 0) |
	        ((modes->c_lflag & IEXTEN) ? MTS_IEXTEN : 0);


	dserver_mode_cmd.iflag_low  = iflag & 0xFF;
	dserver_mode_cmd.iflag_high = (iflag >> 8) & 0xFF;

	dserver_mode_cmd.oflag_low  = oflag & 0xFF;
	dserver_mode_cmd.oflag_high = (oflag >> 8) & 0xFF;

	dserver_mode_cmd.cflag_low  = cflag & 0xFF;
	dserver_mode_cmd.cflag_high = (cflag >> 8) & 0xFF;

	dserver_mode_cmd.lflag_low  = lflag & 0xFF;
	dserver_mode_cmd.lflag_high = (lflag >> 8) & 0xFF;
	set_all = 0;
	if (set_all)
	{
		dserver_mode_cmd.imask_high = 0xFF;
		dserver_mode_cmd.imask_low  = 0xFF;
		dserver_mode_cmd.omask_high = 0xFF;
		dserver_mode_cmd.omask_low  = 0xFF;
		dserver_mode_cmd.cmask_high = 0xFF;
		dserver_mode_cmd.cmask_low  = 0xFF;
		dserver_mode_cmd.lmask_high = 0xFF;
		dserver_mode_cmd.lmask_low  = 0xFF;
	}
	else
	{
		dserver_mode_cmd.imask_low  = DEVICE_SERVER_IFLAGS & 0xFF;
		dserver_mode_cmd.imask_high = (DEVICE_SERVER_IFLAGS >> 8) & 0xFF;
		dserver_mode_cmd.omask_low  = DEVICE_SERVER_OFLAGS & 0xFF;
		dserver_mode_cmd.omask_high = (DEVICE_SERVER_OFLAGS >> 8) & 0xFF;
		dserver_mode_cmd.cmask_low  = DEVICE_SERVER_CFLAGS & 0xFF;
		dserver_mode_cmd.cmask_high = (DEVICE_SERVER_CFLAGS >> 8) & 0xFF;
		dserver_mode_cmd.lmask_low  = DEVICE_SERVER_LFLAGS & 0xFF;
		dserver_mode_cmd.lmask_high = (DEVICE_SERVER_LFLAGS >> 8) & 0xFF;
	}
	// if we are to put set tty command in buffer then attempt to do it
	// otherwise just send it to dserver
	if ( (info.dscmd != DS_TCP_STTY_SET) || !ChkPutDsCmdPktFwdBuf(&info, (char *)&dserver_mode_cmd, dservermodesize) )
	{
		forward_frame(&info);		// forward pkt fwd buf before sending command

		/* copy cmd to buffer */
		buf_init(&buf);
		buf_init(&dserver_in_buf);
	
		buf_append(&buf, (char *) &dserver_mode_cmd, dservermodesize);
	
		/* write to device server */
		out_window_size -= buf.len;
	
		if (tl_debug < trace_level)
		{
			my_hd(buf.data, buf.len);
		}
		
		trace(tl_debug, "set_dserver_modes() Sending DS_TCP_STTY_SET cmd");
		ret = write_buf_raw(dserver_fd, buf.data, buf.len);
	
		if (ret != buf.len)
		{
			trace(tl_error, "error writing tty modes, closing connection %d", ret);
			close_connection();
		}
		if ((DServerFeatures & TPSFEAT_IOLANDS)==0)
		{
			write_dserver_ctrl(dserver_fd, DS_TCP_STTY_REPORT_ON);
		}
	}
}

void set_RTS_DTR(int rts, int dtr)
{
	int ret;
	trace(tl_debug, "Update RTS/DTR (%x/%x):",rts,dtr);

	// are signals to be put into pkt fwd buf ?
	if (info.dscmd == (DS_TCP_SET_DTR + DS_TCP_CLR_DTR +
					   DS_TCP_SET_RTS + DS_TCP_CLR_RTS) )
	{
		info.dscmd = (rts ? DS_TCP_SET_RTS : DS_TCP_CLR_RTS);
		write_dserver_ctrl(dserver_fd, info.dscmd);		// write_dserver_ctrl will put command in pkt fwd buf
		info.dscmd = (dtr ? DS_TCP_SET_DTR : DS_TCP_CLR_DTR);
		write_dserver_ctrl(dserver_fd, info.dscmd);		// write_dserver_ctrl will put command in pkt fwd buf
	}
	else
	{
		ret = write_dserver_udp_ctrl_wait(rts ? DS_UDP_SET_RTS : DS_UDP_CLR_RTS);
		ret = write_dserver_udp_ctrl_wait(dtr ? DS_UDP_SET_DTR : DS_UDP_CLR_DTR);
		if ( ret < 0 )
		{
			trace(tl_error, "set_RTS_DTR(): Setting RTS/DTR signals failed, ret=%d, closing connection",ret);
			close_connection();
		}
	}
	trace(tl_debug, " %s_RTS", rts?"SET":"CLR");
	trace(tl_debug, " %s_DTR", dtr ? "SET" : "CLR");
}


	
//*****************************************************************************
//  tp_read -   reads data from network using SSL socket or tcp socket.
//
int  tp_read( int fd, unsigned char *buf, int size )
{
	int ret;

#ifdef  USE_SSL
	int err;

	if (fd == -1)
		return -1;

	if ( sslcfg.enabled )
	{
		ret = SSL_read( ssl, buf, size );
		switch( err = SSL_get_error( ssl, ret ) )
		{
			case SSL_ERROR_NONE:
			if ( ret <= 0 )
			{
				trace(tl_info, "SSL read - no data\n");
				return -1;
			}
			read_ssl = 0;
			break;

			case SSL_ERROR_WANT_READ:
			trace(tl_info, "SSL read - blocked\n");
			read_ssl = 1;
			break;

			default:
			trace(tl_error, "SSL read - error - %d; ret = %d\n", err, ret);
			if ( err == SSL_ERROR_SYSCALL && ret == 0 )
				return ret;
			else
				return -1;
		}
	}
	else
#endif  //USE_SSL

		ret = read( fd, buf, size );

	return(ret);
}


//*****************************************************************************
//  tp_read_wait -  reads data from fd until size bytes are received
//                  or ptim time-out occurs waiting to receive.  
//                  If NULL ptime given then it will wait forever
//
int tp_read_wait(int fd, unsigned char *buf, int size, struct timeval *ptim)
{
	struct timeval  tim_local, *ptim_local;
	int count, ret;
	int rcv_len;
	fd_set read_set;

	count = size;
	rcv_len = 0;

	while (1)
	{
		// read in  data
		ret = tp_read(fd, (unsigned char *)buf, count);
		if (ret <= 0 )
		{
			return(ret);
		}
		// finished receiving requested data
		if (ret == count)
		{
			rcv_len += ret;
			return(rcv_len);
		}
		count -= ret;
		rcv_len += ret;
		if (ptim)
		{
			tim_local.tv_sec = ptim->tv_sec;
			tim_local.tv_usec = ptim->tv_usec;
			ptim_local = &tim_local;
		}
		else
		{
			ptim_local = NULL;
		}
		// wait until header recieved 
		FD_ZERO( &read_set );
		FD_SET( fd, &read_set );
		ret = select(FD_SETSIZE, &read_set, NULL, NULL, ptim_local );

		// if time-out then return error
		if (ret == 0)
		{
			trace(tl_debug, "timed out waiting on select() for read data: %s", strerror(errno));
			return(-1);
		}
		else if (ret == -1)
		{
			trace(tl_debug, "error on select() data receive: %s", strerror(errno));
			return(-1);
		}
		if ( !(FD_ISSET( fd, &read_set)) )
		{
			return(-1);
		}
	} 	// while receiving data
}


//********************************************************************
// reads client I/O access data from dserver and waits for data for one
// I/O command to be completly recieved.  Will use I/O keep-alive for 
// time-out if configured
//
int read_dserver_iodata_wait(int fd, dserver_packet_t *type, buf_t * buf)
{
	struct timeval  tim;
	io_packet_t io_header;
	int ret;
	int short count = 0;

	*type = DEVICE_SERVER_DATA;

	// if keep-alive configured then set time-out, otherwise wait forever
	if (keepalive_time)
	{
		tim.tv_sec  = keepalive_time;
		tim.tv_usec = 0;
	}
	
	// receive I/O Access header
	ret = tp_read_wait(fd, (unsigned char *)&io_header, IO_HEADER_SIZE, (keepalive_time ? &tim: NULL));
	if (ret <= 0)
	{
		trace(tl_debug, "error on reading I/O Access header: %s", strerror(errno));
		return(ret);
	}

	// process I/O access header
	count = ntohs(io_header.datalength);
	if ((count < 0) || (count > (int)sizeof(buf->data)))
	{
		trace(tl_error, "I/O data count invalid :%d", count);
		return(-1);
	}
	trace(tl_data, "I/O Access header received from dserver: io_type = 0x%x, count = %d\n", 
						io_header.iotype, ret);

	switch (io_header.iotype)
	{
		case IOCMD_KEEP_ALIVE:
		{
			// receive I/O Access keep-alive command
			ret = tp_read_wait(fd, (unsigned char *)&io_header.io_u.keep_alive.interval, count, (keepalive_time ? &tim: NULL));
			if (ret <= 0)
			{
				trace(tl_debug, "error on reading I/O Access keep-alive data: %s", strerror(errno));
				return(-1);
			}
			// acknoledge we received I/O Access keep-alive response
			keepalive_sent = 0;
			*type = DEVICE_SERVER_NONE;
			break;
		}
		case MB_ASCII: 
		case MB_RTU:
		case IO_API:
		{
			// receive I/O Access data
			ret = tp_read_wait(fd, buf->data, count, (keepalive_time ? &tim: NULL));
			if (ret <= 0)
			{
				trace(tl_debug, "error on reading I/O Access data: %s", strerror(errno));
				return(-1);
			}
			buf->len += ret;
			*type = DEVICE_SERVER_DATA;
			break;
		}
		case NOTDEF:
		default:
		{
			trace(tl_error, "I/O Access Type/command invalid :%d", io_header.iotype);
			ret = -1;
			break;
		}
	}	// end switch io_type
	return(ret);
}

//*****************************************************************************
// Returns < 0 if error
//
// host_port pointw to ipv4|hostname:portnum or [ipv6]:portnum
int get_tcp_hostport(char *host_port, char **TCPhost, char **TCPport)
{
   int port;
   char *phost = NULL;
   char *pport = NULL;

	if (host_port == NULL)
	{
		 return(-1);
	}
	// search for "[" to see if we have a literal IPv6 address
	phost = strchr((host_port), '[');
	// we have a literal IPv6 address
	if (phost != NULL)
	{
		// now search for "]", must have one
		pport = strchr(phost, ']');
		if ( pport == NULL)
		{
			 trace (tl_debug,"Missing ending bracket ] in IPv6 address\n");
			return(-1);		// error, missing ending bracket
		}
		else
		{
			// check if a port string exist
			if (strlen(pport) == 0)
			{
	 			 trace (tl_debug,"Missing port number \n");
				 return(-1);		// error, missing port number
			}
				
			pport = pport + 1;		// increment pass "]"
			// 
			if (*pport != ':')
			{
				 trace (tl_debug,"Missing port seperator : \n");
				return(-1);		// error, missing ending ":"
			}

			if (pport != NULL)
				 *pport = 0;				// null out ":"
			pport = pport + 1;				// increment pass ":"
			// check if a port string exist
			if (strlen(pport) == 0)
			{
				 trace (tl_debug,"Missing port number after : \n");
				return(-1);		// error, missing port number
			}
		}
		goto done_parse;
	}   // end of having IPv6 literal address
	
   // search for host and port seperator ":"
   pport = strchr(host_port, ':');
   // found ":", so first port is the host
   if (pport != NULL)
   {
		*pport = 0;				// null out ":"
		pport = pport + 1; 		// increment pointer to port
		phost = host_port;
		// if no port then set pointer back to NULL
		if (strlen(pport) == 0)
		{
			pport = NULL;
		}
		if (strlen(phost) == 0)
		{
		   trace (tl_debug,"Specified host can not be blank\n");
			return(-1);
		}
		if (strlen(phost) > MAX_HOST_NAMELEN)
		{
   		trace (tl_debug,"Host name too long, must be less than %d\n", MAX_HOST_NAMELEN);
			return(-1);
		}
	}
	// must be just the port, no host specified
	else
	{
		pport = host_port;
	}

done_parse:
	//  check port range
	if (pport != NULL)
	{
		port = atoi(pport);
		if ( (port < 0) || (port < WELLKNOWN) )
		{
			trace (tl_debug,"Port number must e in range: %d < TCP# > 65535\n", WELLKNOWN);
			return(-1);
		}
	}
	*TCPhost = phost;
	*TCPport = pport;
	return(0);
}

//*****************************************************************************
//  wait_for_tty_open_close 
//		- wait for the specified amount of time for the application to 
//		  open or close the port and take the appropriate action. 
//		  If a NULL ptime given then function will wait for ever for
//	  Returns -1 if tty close received or error
//			    0 if timeout
//			    1 if open recieved
//
int wait_for_tty_open_close(struct timeval *ptim)
{
	struct timeval  tim_local, *ptim_local;
	int ret= -1;
	int prev_slave_is_open = 0;
	fd_set read_set;

	trace(tl_debug, "wait_for_tty_open_close(): Waiting for tty Open/Close ");

	while (tty_connected)
	{
		if (ptim)
		{
			tim_local.tv_sec = ptim->tv_sec;
			tim_local.tv_usec = ptim->tv_usec;
			ptim_local = &tim_local;
		}
		else
		{
			ptim_local = NULL;
		}

		// wait for tty open/close or time out 
		// We only need to read from the control status tty to detect open/close
		FD_ZERO( &read_set );
		FD_SET(ptyxc_fd, &read_set);
		ret = select(FD_SETSIZE, &read_set, NULL, NULL, ptim_local);

		// if time-out then we will just return 0
		if (ret == 0)
		{
			trace(tl_debug, "wait_for_tty_open_close(): Timed-out on select() while waiting waiting for slave tty open,close ");
			break;
		}
		
		if (ret == -1)
		{
				trace(tl_debug, "wait_for_tty_open_close(): Error on select() while waiting for slave tty open, closing tty: %s", strerror(errno));
	  			close_tty();
				break;
		}
		
		prev_slave_is_open = slave_is_open;
		if ( (ret = process_tty_ctrl()) < 0)	// get and process any ctrl statuses
		{
			trace(tl_error, "wait_for_tty_open_close(): process_tty_ctrl error (%d)\n", ret);
			ret = -1;
			break;		// exit with error
		}
		if (slave_is_open)
		{
			trace(tl_info, "wait_for_tty_open_close(): CTRLSTATUS_OPEN recieved\n");
			ret = 1;
			break;
		}
		else
		{
			// if slave was open but is now not then we received a close
			if (prev_slave_is_open)
			{
				// we process a close or error
				trace(tl_info, "wait_for_tty_open_close(): CTRLSTATUS_CLOSE recieved\n");
				ret = -1;
				break;	
			}
		}
	}  // end while tty_connected

	return(ret);
}

void handle_signal(int sig_num)
{

	// need to exit for these signals
	if ( (sig_num == SIGTERM) || (sig_num == SIGINT) )
	{
		trace( tl_error, "Exiting after catching signal SIGTERM or SIGINT ,signum=%d \n",  sig_num );
	}
	else
	{
		trace( tl_error, "Exiting after catching UNKNOWN signal, signum=%d \n", sig_num );	
	}
	close_tty();
	trace( tl_error, "Exiting after catching signal(%d)\n", sig_num );
	exit(-sig_num);		 
}


/*
	the format of the response containing the Server Features is:
	0x06
	PORT NUMBER		1 byte
	PRODUCT STR		variable length text, delimited with <space>
	<space>			1 byte
	VERSION STR		7 bytes
	SERVER FEAT		4 bytes (network order)
*/
uint32_t get_tps_feat(unsigned char *data,int datalen)
{
	int offset;
    uint32_t feat;
	
	offset=datalen-1;	// point to end of data
	while(offset >= 2 && data[offset]!=' ')
		offset--;
	offset+=8;	// point past the space and VERSION STR
	
	if (offset > datalen-4)
		return(0);	// SERVER FEAT doesn't exist in the response
	
	memcpy(&feat,&data[offset],sizeof(feat));
	return(feat);
}


int dserver_out_available(forwarding_info_t *pInfo)
{
	int val = 0;
	
	if (mode == pm_full)
	{
		val = out_window_size;	// # of bytes we can still send to the server
		if (pInfo->forwarding)
		{
			val -= pInfo->count;
		}
		if (val > (int)SMSIZEOF(buf_t2,data))
		{
			val = SMSIZEOF(buf_t2,data);
		}
		if (val < 0)
		{
			 val = 0;
		}
	}
	else
	{
		val=SMSIZEOF(buf_t2,data);
	}
	return(val);
}




#ifdef USE_SSL
//******************************************************************************
//
//  Used by SSL to copy the pass phrase into its own data space for use.

static int tp_pem_passwd_cb(char *buf, int size, int rwflag, void *password)
{
	UNUSED_VAR( rwflag );
	UNUSED_VAR( password );

	trace( tl_error, "Private Key Passphrase is not supported in TruePort\n" );
	return( 0 );
}

//******************************************************************************

static RSA *tp_tmp_rsa_cb(SSL *s, int is_export, int keylength)
{
	static RSA *rsa_tmp=NULL;

	UNUSED_VAR( s );
	UNUSED_VAR( is_export );

	trace( tl_info,"generating tmp RSA key\n" );
	if ( rsa_tmp == NULL )
	{
#if OPENSSL_VERSION_NUMBER < 0x00908000L
        rsa_tmp=RSA_generate_key( keylength,RSA_F4,NULL,NULL );
#else
        BIGNUM *e;
        e = BN_new();
        BN_set_word(e, RSA_F4);
        rsa_tmp = RSA_new();
        if (!RSA_generate_key_ex(rsa_tmp, keylength, e, NULL))
        {
            RSA_free(rsa_tmp);
            rsa_tmp = NULL;
        }
        BN_free(e);
#endif
	}
	return( rsa_tmp );
}
#endif  //USE_SSL


// verifies whether the TruePort connection is available
// 
BOOL is_tp_conn_avail(void)
{
	BOOL bRet = 0;

	if (dserver_connected)		// dserver_connected will be set if TCP and SSL is up
	{
		bRet = TRUE;
	}

	// if TCP and/or SSL is up and were are in full mode, 
	// make sure we've finished detecting the protocol
	if (bRet  && mode == pm_full)
	{
		if (state != s_data_transfer)
		{
			bRet = FALSE;
		}
	}
	// set current trueport Connection connection state
	tp_connected = bRet;
	//debug, uncomment when required
//	trace(tl_debug, "is_tp_conn_avail(): trueport Connection is %s  ", (bRet ? "AVAILABLE" : "NOT AVAILABLE"));

	
	return bRet;
}


BOOL IsNoUDP(void)
{
	// check if dserver supports it and if we have it configured
	if ( (DServerFeatures & TPSFEAT_NO_UDP) && (!use_legacy_UDP) )
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

