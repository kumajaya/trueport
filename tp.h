/******************************************************************
 Module: tp.h

 Description: Device Server Protocol Definitions for TruePort

 Copyright (c) 1999-2017 Perle Systems Limited. All rights reserved.

*******************************************************************/

#ifndef _TP_H
#define _TP_H

#define	TP_VERSION		"6.10.0"

#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21))
#include <linux/soundcard.h>
#define TP_USE_SOUNDCARD_IOCTLS
#endif
#endif

#define WELLKNOWN		1023				// TCP Max Well known port

// Following max value should be synced up with the 
// "MAX_PORTS" varialbe in the tar_install.sh script file and the 
// " MAX_TTY" variable in the addports script file
#define MAX_DEVICES	256000		// max installable ports 

#define PTYX_CTRL_MAJOR		61
#define PTYX_MASTER_MAJOR	62
#define PTYX_SLAVE_MAJOR	63

#define PTYX_NUM_PTYS		MAX_DEVICES			// absolute maximum allowed to be installed

#define PTYX_CTRL_NAME 		"txc"
#define PTYX_MASTER_NAME	"txm"
#define PTYX_SLAVE_NAME 	"tps"

#define DEVICE_SERVER_MODEM    0x20000
#define DEVICE_SERVER_DIRECT   2048

#define  UNUSED_VAR(x) ((x)=(x))


#ifndef TRUE
#define TRUE 	(1)
#define FALSE 	(0)
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef BOOL
#define BOOL int
#endif

#define OK 	(0)
#define	FAILURE	(-1)				/* Failure indication */
#define DS_BUF_SIZE     4096

#define CFG_DECIMAL			0x0000
#define CFG_HEXIDECIMAL		0x1000

typedef enum {
    pm_lite, pm_full
} protocol_mode_t;

#define  CONFLINELEN    (256)		// maximum config line length

typedef enum {
	CMD_INIT, /* initialize */
	CMD_EXEC,
} CMD;


/* Get How flags from State field */
#define  TPS_HOW(X)     (((X)&TPS_OPEN_FLAGS)>>14)

/*
** These defines determine if slave driver required to be loaded before
** the master driver, or vice versa
*/
#define MASTER_REQD_FIRST
/*#define SLAVE_REQD_FIRST*/
 
/*************************************************
*   Definitions for TPS/TPS driver interface 
**************************************************/

/* State flags */
#define  TPS_WAIT_FOR_OPEN 		0x0001
#define  TPS_OPEN_NDELAY   		0x0002
#define  TPS_WAIT_FOR_DRAIN		0x0010
#define  TPS_GOT_DRAIN_ACK 		0x0020
#define  TPS_EXCLUSIVE     		0x0040
#define  TPS_READ_FLUSHING 		0x0080
#define  TPS_CLOSING_DOWN  		0x0100
#define  TPS_NEEDS_BREAK   		0x0200
#define  TPS_NEEDS_TERMIO  		0x0400
#define  TPS_NEEDS_CMD     		0x0800
#define  TPS_DCD_UP        		0x1000

#define  TPS_OPEN_MODEM    		0x4000
#define  TPS_OPEN_DIRECT   		0x8000
#define  TPS_OPEN_PMODEM   		0xC000
#define  TPS_OPEN_FLAGS    		0xC000   /* mask for open mode */

#define  MAX_VERSION_LEN    	80

/* How open types */
#define  TPS_HOW_MODEM     1
#define  TPS_HOW_DIRECT    2
#define  TPS_HOW_PMODEM    3

/*
** Extra proto messages exchanged between daemon and master driver
*/
#define  TP_PROTO_OPEN				0x80  // daemon <-- Driver, application opened slave tty port
#define  TP_PROTO_DCD_UP			0x80  // daemon --> Driver, DCD is up, and update modem state
#define  TP_PROTO_NEWMODES			0x81  // daemon <-- Driver, set termio modes
#define  TP_PROTO_DCD_DOWN			0x81  // daemon --> Driver, DCD is down, and update modem state
#define  TP_PROTO_CLOSE				0x82  // daemon <-- Driver, application closed slave tty port
#define	TP_PROTO_HANGUP				0x82  // daemon <-- Driver, perform tty hang-up
#define  TP_PROTO_DO_DRAIN			0x83  // daemon <-- Driver
#define	TP_PROTO_LSRUPDATE  		0x83  // daemon <-- Driver, update driver with LSR state (ie rx parity, framing, over-run error, and BI)
#define	TP_PROTO_TP_CONNECTION		0x84  // daemon <-- Driver,	trueport connection status, 0 down, 1 up
										  // this means TCP, SSL and Full mode protocol is up) 
#define	TP_PROTO_RTSDTR_UPDATE		0x85  // daemon <-- Driver,	update RTS and DTR status
#define	TP_PROTO_SET_OPEN_WAIT		0x85  // daemon <-- Driver,	set open wait time/mode
#define	TP_PROTO_SYNC_FLUSH_END		0x86  // daemon <-- Driver,	flush complete on dserver
#define	TP_PROTO_DRAIN_ACK			0x87  // daemon <-- Driver, drain complete on dserver
#define	TP_PROTO_GOT_BREAK			0x88  // daemon <-- Driver, received BREAK from dserver
#define	TP_PROTO_GIVE_BREAK			0x88  // daemon <-- Driver, send BREAK to dserver
#define	TP_PROTO_READ_FLUSH			0x89  // daemon <-- Driver, read flush
#define	TP_PROTO_WRITE_FLUSH		0x89  // daemon <-- Driver, write flush
#define	TP_PROTO_BREAKON			0x8a  // daemon <-- Driver, turn break on
#define	TP_PROTO_UNHANGUP			0x8a  // daemon <-- Driver, perform tty unhangup
#define	TP_PROTO_BREAKOFF			0x8b  // daemon <-- Driver, turn break off

/*
** IMPORTANT! IT IS VITAL THAT TP_PROTO_VERSION IS FIRST, AND THAT THE
** OTHERS HAVE NUMERICALLY SEQUENTIAL VALUES. SEE sign_version IN
** trueport.c!
*/
#define	TP_PROTO_VERSION				0x8C	// TPM --> daemon
#define	TP_PROTO_DAEMON_VERSION		0x8D	// internal to daemon
#define	TP_PROTO_TPM_VERSION			0x8E	// TPM --> daemon
#define	TP_PROTO_TPS_VERSION			0x8F	// TPS --> daemon

struct newmodes
{
   char     Cmd;     /* See below */
   char     How;     /* MODEM/DIRECT/PMODEM (see above) */
   char     pad[2];
   int      Flag;    /* O_ flags */
   struct   termios Termios;
};

struct versions
{
   char     Cmd;
   char     Pad [3];
   char     VerM [MAX_VERSION_LEN];
   char     VerS [MAX_VERSION_LEN];
   int      State;
   struct   termios Termios;
};

#define CAN_SLEEP 1
#define NO_SLEEP  0

/*************************************
*   Definitions for DEVICE_SERVER interface
**************************************/

typedef struct dserver_cmd_s
{
   unsigned short count;
   unsigned char  command;
   unsigned char  data;
} dserver_cmd_t;

#define TPPKT_HDR_SIZE 2

struct dservermode
{
   unsigned short count;
   unsigned char  cmd;
   unsigned char  iflag_low;
   unsigned char  iflag_high;
   unsigned char  imask_low;
   unsigned char  imask_high;
   unsigned char  oflag_low;
   unsigned char  oflag_high;
   unsigned char  omask_low;
   unsigned char  omask_high;
   unsigned char  cflag_low;
   unsigned char  cflag_high;
   unsigned char  cmask_low;
   unsigned char  cmask_high;
   unsigned char  lflag_low;
   unsigned char  lflag_high;
   unsigned char  lmask_low;
   unsigned char  lmask_high;
   unsigned char  badpad;     /* vomit */
};


#define dservermodesize 19

/* immediate keep-alive command structure */
typedef struct keep_alive_s
{
	unsigned short  interval;			// will use configured keep-alive value here 
} keep_alive_t;

#pragma pack(1)
typedef struct keepalive_cmd_s
{
	unsigned short count;
	unsigned char  cmd;
	keep_alive_t    keepalive_data;
} keepalive_cmd_t;

/* DS_TCP_FEATURE_ACK command structure */
typedef struct feature_ack_cmd_s
{
   unsigned short count;
   unsigned char  cmd;
	uint32_t        tpfeatures;
} feature_ack_cmd_t;
#pragma pack()

/*
**  Client I/O Access commands and data packet format and defines
*/
typedef enum 
{	
	NOTDEF=0, 
	MB_ASCII, 
	MB_RTU, 
	IO_API,
} io_type_t;

// I/O Access commands
#define IOCMD_KEEP_ALIVE 0x80

typedef enum
{
	OPMODE_TYPE_NONE=0,
	OPMODE_TYPE_OPTIMIZELAN,
	OPMODE_TYPE_LOWLATENCY,
	OPMODE_TYPE_PACKETIDLETIMEOUT,
	OPMODE_TYPE_CUSTOM,
} opmode_type_t;


#define IO_HEADER_SIZE 3		// keep in sync with IO_packet_s below
#pragma pack(1)
typedef struct io_packet_s
{
	unsigned char	   	iotype;			// I/O access type or I/O command
	unsigned short		datalength;		// Network order
	union
	{
		unsigned char		data;
		keep_alive_t 		keep_alive;

	} io_u;
} io_packet_t;
#pragma pack()


/*
** Control Messages exchanged between DEVICE_SERVER and TruePort in-line (TCP)
*/
#define  DS_TCP_SEND_BREAK       0x00  /* daemon <-> Device Server */
#define  DS_TCP_STTY_SET         0x02  /* daemon --> Device Server */
#define  DS_TCP_CD1400_STATE     0x02  /* daemon <-- Device Server */
#define  DS_TCP_STTY_REPORT_ON   0x03  /* daemon --> Device Server */
#define  DS_TCP_STTY_REPORT_OFF  0x04  /* daemon --> Device Server */
#define  DS_TCP_SYNC_FLUSH_END   0x05  /* daemon <-> Device Server */
#define  DS_TCP_PORT_NUMBER      0x06  /* daemon <-- Device Server */
#define  DS_TCP_DRAIN_PORT       0x07  /* daemon --> Device Server */
#define  DS_TCP_DRAIN_ACK        0x08  /* daemon <-- Device Server */
#define  DS_TCP_LSR_NODATA       0x09  /* daemon <-- Device Server ; unsolicited when enabled by DS_UDP_LSRMST_INSERT */
#define  DS_TCP_MST              0x0a  /* daemon <-- Device Server ; unsolicited when enabled by DS_UDP_LSRMST_INSERT */
#define  DS_TCP_SEND_BREAKON     0x0b  /* daemon --> Device Server */
#define  DS_TCP_SEND_BREAKOFF    0x0c  /* daemon --> Device Server */
#define  DS_TCP_SEND_SYNCDRAIN   0x0d  /* daemon --> Device Server */
#define  DS_TCP_STTY_XREPORT_ON  0x0e  /* daemon --> Device Server (extended report mode; LSR & MSR info) - TCP equivalent of UDP based DS_UDP_LSRMST_INSERT */

#define DS_TCP_FEATURE_ACK		0x10		// feature support ack	(daemon ---> Device Server)
#define	DS_TCP_SET_DTR				0x11  	// set DTR on					(daemon ---> Device Server)
#define	DS_TCP_CLR_DTR				0x12  	// set DTR off				(daemon ---> Device Server)
#define	DS_TCP_SET_RTS				0x13  	// set RTS on					(daemon ---> Device Server)
#define	DS_TCP_CLR_RTS				0x14  	// set RTS off				(daemon ---> Device Server)

/* psuedo-types used internally */
#define DEVICE_SERVER_DATA      		0xDA
#define DEVICE_SERVER_DATA_INCOMPLETE	0xDB
#define	DEVICE_SERVER_UPDATE_WINDOW		0xDC
#define DEVICE_SERVER_DATA_QUEUED		0xDD
#define DEVICE_SERVER_QUEUE_EMPTY		0xDE
#define DEVICE_SERVER_NONE      		0xFA


/*
** Out-of-band messages sent from TruePort to Device Server (TCP Urgent data)
*/
#define  DS_URG_TCP_PACKETMODE_REQ  0x02   /* daemon --> Device Server */
#define  DS_URG_TCP_PACKETMODE_ACK  0x06   /* daemon <-- Device Server */

/*
** Control messages exchanged between daemon and Device Server as UDP messages
*/
#define  DS_UDP_RESET              0x00     /* daemon --> Device Server */
#define  DS_UDP_TCXON                  0x01     /* daemon --> Device Server */
#define  DS_UDP_TCXOFF                 0x02     /* daemon --> Device Server */
#define  DS_UDP_WFLUSH                 0x03     /* daemon --> Device Server */
#define  DS_UDP_RFLUSH                 0x04     /* daemon --> Device Server */
#define  DS_UDP_WR_FLUSH               0x05     /* daemon --> Device Server */
#define  DS_UDP_ACK                    0x06     /* daemon <-- Device Server */
#define  DS_UDP_DRAIN_POLL             0x07     /* daemon --> Device Server */
#define  DS_UDP_DRAIN_CLEAR            0x08     /* daemon --> Device Server */
#define  DS_UDP_KEEP_ALIVE             0x09     /* daemon --> Device Server */

#define  DS_UDP_NAK                    0x15     /* daemon <-- Device Server */
#define  DS_UDP_SYN                    0x16     /* daemon <-- Device Server */
#define  DS_UDP_WAK                    0x27     /* daemon <-- Device Server */

#define DS_UDP_GET_MODEM_STATUS        0x30     // get modem status
#define DS_UDP_GET_COMM_STATUS         0x31     // get comm status
#define DS_UDP_LSRMST_INSERT           0x32     // insert line and modem changes
#define DS_UDP_SET_BREAK_ON            0x33     // set break on
#define DS_UDP_SET_BREAK_OFF           0x34     // set break off
#define DS_UDP_IMMEDIATE_CHAR          0x35     // send character immediately
#define DS_UDP_SET_DTR                 0x36     // set DTR on
#define DS_UDP_CLR_DTR                 0x37     // set DTR off
#define DS_UDP_SET_RTS                 0x38     // set RTS on
#define DS_UDP_CLR_RTS                 0x39     // set RTS off
#define DS_UDP_GET_DTRRTS              0x3a     // get DTRRTS

// for No UDP suppport we will maintane the above defines and set the top bit to indicate that it
// is an immediate command
#define DS_IMM_CMD_MASK	(unsigned short)0x80

// new TCP immediate commands, can not conflict with above UDP commands
#define DS_TCP_IMM_next_command	0x40	// start next new tcp immediate command here
/* control flags for count field */
#define DEVICE_SERVER_COUNT_MASK        0x3FFF
#define DEVICE_SERVER_COMMAND           0x8000
#define DEVICE_SERVER_WINDOW            0x4000

#define  DEVICE_SERVER_UDP_PORT         668  	// the neighbour of the beast */
#define  DEVICE_SERVER_UDP_TIME         250000 // one quarter second delay */
#define  DEVICE_SERVER_IO_PORT			 33816 	// default device serverI/O access TCP port

/* termio/termios bit flags. The following #defines are taken from the MTS
   include files. In most cases, they are mostly the same as the definitions
   in sys/termio.h, but some systems use incompatible values. The definitions
   here should be used when setting dservermodes, in preference to those
   used on the host system.
*/

#ifdef OLD_FIRMWARE
/* control characters */
#define MTS_B0       0
#define MTS_B50      1
#define MTS_B75      2
#define MTS_B110     3
#define MTS_B134     4
#define MTS_B150     5
#define MTS_B200     6
#define MTS_B300     7
#define MTS_B600     8
#define MTS_B1200    9
#define MTS_B1800    10
#define MTS_B2400    11
#define MTS_B4800    12
#define MTS_B9600    13
#define MTS_B19200   14
#define MTS_B38400   15
#else

/* control characters NEW FIRMWARE! */
#define MTS_B0       0
#define MTS_B50      1
#define MTS_B75      2
#define MTS_B110     3
#define MTS_B134     4
#define MTS_B150     5
#define MTS_B200     6
#define MTS_B300     7
#define MTS_B600     8
#define MTS_B1200    9
#define MTS_B1800    10
#define MTS_B2400    11
#define MTS_B4800    12
#define MTS_B9600    13
#define MTS_B19200   14
#define MTS_B38400   15
#define MTS_B57600   1     /* Used to be B50 */
#define MTS_B115200  3     /* Used to be B110 */
#define MTS_B230400  4     /* Used to be B134 */

/* Software engineering note.... 

The NT driver still has the old defines but pushes the bits called
"B50" into the structure if 57600 baud is requested. This is bad
software engineering. The code is very hard to understand. It took me
quite a while before I realized what was going on when I tried looking
for the define for 115200 in the header files and couldn't find it.

The above way is a reasonable way of handling something like this. For
the moment the not supported baud rates are defined to "NOTSUP". As it
is these will generate compile-time errors, allowing us to be very
sure they are no longer used. Or we could define that to be "-1" to
allow runtime verification of undefined (impossible) baud rates. 

Note also that the comments refer to the old versions, so that the
situation is properly cross-referenced. 

-- REW
*/


#endif


#define MTS_VINTR    0
#define MTS_VQUIT    1
#define MTS_VERASE   2
#define MTS_VKILL    3
#define MTS_VEOF     4
#define MTS_VEOL     5
#define MTS_VEOL2    6
#define MTS_VMIN     4
#define MTS_VTIME    5
#define MTS_VSWTCH   7
#define MTS_VSTART   8
#define MTS_VSTOP    9
#define MTS_VSUSP    10
#define MTS_VDSUSP   11
#define MTS_VREPRINT 12
#define MTS_VDISCARD 13
#define MTS_VWERASE  14
#define MTS_VLNEXT   15

/* input modes iflag */
#define MTS_IGNBRK   0000001
#define MTS_BRKINT   0000002
#define MTS_IGNPAR   0000004
#define MTS_PARMRK   0000010
#define MTS_INPCK    0000020
#define MTS_ISTRIP   0000040
#define MTS_INLCR    0000100
#define MTS_IGNCR    0000200
#define MTS_ICRNL    0000400
#define MTS_IUCLC    0001000
#define MTS_IXON     0002000
#define MTS_IXANY    0004000
#define MTS_IENQAK   0000000     /* Not used */
#define MTS_IXOFF    0010000
#define MTS_IMAXBEL  0020000

/* output modes  oflag */
#define MTS_OPOST    0000001
#define MTS_OLCUC    0000002
#define MTS_ONLCR    0000004
#define MTS_OCRNL    0000010
#define MTS_ONOCR    0000020
#define MTS_ONLRET   0000040
#define MTS_OFILL    0000100
#define MTS_OFDEL    0000200
#define MTS_NLDLY    0000400
#define MTS_NL0      0000000
#define MTS_NL1      0000400
#define MTS_CRDLY    0003000 
#define MTS_CR0      0000000
#define MTS_CR1      0001000
#define MTS_CR2      0002000
#define MTS_CR3      0003000
#define MTS_TABDLY   0014000
#define MTS_TAB0     0000000
#define MTS_TAB1     0004000
#define MTS_TAB2     0010000
#define MTS_TAB3     0014000
#define MTS_XTABS    0014000
#define MTS_BSDLY    0020000
#define MTS_BS0      0000000
#define MTS_BS1      0020000
#define MTS_VTDLY    0040000
#define MTS_VT0      0000000
#define MTS_VT1      0040000
#define MTS_FFDLY    0100000
#define MTS_FF0      0000000
#define MTS_FF1      0100000
#define MTS_PAGEOUT  0200000
#define MTS_WRAP     0400000
#define MTS_CTSFLOW  0020000
#define MTS_RTSFLOW  0040000

/* control modes cflag */

#define MTS_CBAUD       0000017
#define MTS_CSIZE       0000060
#define MTS_CS5         0000000
#define MTS_CS6         0000020
#define MTS_CS7         0000040
#define MTS_CS8         0000060
#define MTS_CSTOPB      0000100
#define MTS_CREAD       0000200
#define MTS_PARENB      0000400
#define MTS_PARODD      0001000
#define MTS_HUPCL       0002000
#define MTS_CLOCAL      0004000
#define MTS_RCV1EN      0010000
#define MTS_XMT1EN      0020000
#define MTS_LOBLK       0040000
#define MTS_XCLUDE      0100000
#define MTS_TCSETA_SYNC 0100000   
#define MTS_PAREXT      04000000

/* line discipline 0 modes  lflag */

#define MTS_ISIG     0000001
#define MTS_ICANON   0000002
#define MTS_XCASE    0000004
#define MTS_ECHO     0000010
#define MTS_ECHOE    0000020
#define MTS_ECHOK    0000040
#define MTS_ECHONL   0000100
#define MTS_NOFLSH   0000200
#define MTS_TOSTOP   0000400
#define MTS_ECHOCTL  0001000
#define MTS_ECHOPRT  0002000
#define MTS_ECHOKE   0004000
#define MTS_DEFECHO  0010000
#define MTS_FLUSHO   0020000
#define MTS_PENDIN   0040000
#define MTS_IEXTEN   0100000  /* POSIX flag - enable POSIX extensions */

/* enable masks for use in dservermodes */
#define  DEVICE_SERVER_IFLAGS  (MTS_IXON|MTS_IXANY|MTS_IXOFF|MTS_IGNBRK|MTS_BRKINT|MTS_IGNPAR|MTS_PARMRK|MTS_INPCK|MTS_ISTRIP)
#define  DEVICE_SERVER_OFLAGS  0
#define  DEVICE_SERVER_CFLAGS  (MTS_CBAUD|MTS_CSIZE|MTS_CSTOPB|MTS_PARENB|MTS_PARODD|MTS_HUPCL|MTS_CLOCAL|MTS_CTSFLOW|MTS_RTSFLOW|MTS_TCSETA_SYNC)
#define  DEVICE_SERVER_LFLAGS  0

/* bit flags for CD1400_STATE message */
#define  CD_CD    0x80        /* CD1400 DSR INPUT  */
#define  CD_RTS   0x40        /* CD1400 CTS INPUT  */
#define  CD_RI    0x20        /* CD1400 RI  INPUT  */
#define  CD_DTR   0x10        /* CD1400 CD  INPUT  */
#define  CD_DSR   0x02        /* CD1400 DTR OUTPUT */
#define  CD_CTS   0x01        /* CD1400 RTS OUTPUT */

// bit flags for MST message

#define MST_DTR     0x01
#define MST_RTS     0x02
#define MST_CTS     0x10
#define MST_DSR     0x20
#define MST_RI      0x40
#define MST_DCD     0x80

// bit flags for LSR_NODATA message

#define LSRNODATA_OE    0x02	
#define LSRNODATA_PE    0x04	
#define LSRNODATA_FE    0x08	
#define LSRNODATA_BI    0x10	

#define  DEVICE_SERVER_MAGIC   0x4FE97718
#define  PARENT            0
#define  CHILD             1

#define  DTPS_OPEN      0x0001
#define  DTPS_CLOSE     0x0002
#define  DTPS_WRITE     0x0004
#define  DTPS_READ      0x0008
#define  DTPS_IOCTL     0x0010
#define  DTPS_CMD       0x0020
#define  DTPS_SPECIAL   0x0040
#define  DTPS_PROC      0x0080
#define  DTPS_FAIL      0x4000
#define  DTPS_TPM       0x8000
#define  DTPM_OPEN      ( DTPS_TPM | DTPS_OPEN )
#define  DTPM_CLOSE     ( DTPS_TPM | DTPS_CLOSE )
#define  DTPM_WRITE     ( DTPS_TPM | DTPS_WRITE )
#define  DTPM_READ      ( DTPS_TPM | DTPS_READ )
#define  DTPM_IOCTL     ( DTPS_TPM | DTPS_IOCTL )
#define  DTPM_CMD       ( DTPS_TPM | DTPS_CMD )
#define  DTPS_FPROC     ( DTPS_FAIL | DTPS_PROC )
#define  DTPM_FAIL      ( DTPS_TPM  | DTPS_FAIL )
#define  DTPS_FOPEN     ( DTPS_FAIL | DTPS_OPEN )
#define  DTPS_FCLOSE    ( DTPS_FAIL | DTPS_CLOSE )
#define  DTPS_FWRITE    ( DTPS_FAIL | DTPS_WRITE )
#define  DTPS_FREAD     ( DTPS_FAIL | DTPS_READ )
#define  DTPS_FIOCTL    ( DTPS_FAIL | DTPS_IOCTL )
#define  DTPS_FCMD      ( DTPS_FAIL | DTPS_CMD )
#define  DTPM_FOPEN     ( DTPM_FAIL | DTPM_OPEN )
#define  DTPM_FCLOSE    ( DTPM_FAIL | DTPM_CLOSE )
#define  DTPM_FWRITE    ( DTPM_FAIL | DTPM_WRITE )
#define  DTPM_FREAD     ( DTPM_FAIL | DTPM_READ )
#define  DTPM_FIOCTL    ( DTPM_FAIL | DTPM_IOCTL )
#define  DTPM_FCMD      ( DTPM_FAIL | DTPM_CMD )

#define  FORCE_CMD      1
#define  TRANQUILITY    0     /* No Force */

#if defined(TP_USE_SOUNDCARD_IOCTLS)
#define PTX_IOC			SOUND_MIXER_READ_VOLUME		//	('p' << 24) + ('t' << 16) + ('x' << 8)
#define PTX_IOCMSET		SOUND_MIXER_READ_BASS		//	PTX_IOC + 1
#define PTX_IOCLSET		SOUND_MIXER_READ_TREBLE		//	PTX_IOC + 2
#define PTX_IOCXCSGET	SOUND_MIXER_READ_SYNTH		//	PTX_IOC + 3
#define PTX_IOCDRAINEND	SOUND_MIXER_READ_PCM			//	PTX_IOC + 4
#define PTX_IOCNETSTAT	SOUND_MIXER_READ_SPEAKER	//PTX_IOC + 5
#define PTX_IOCOWTSET	SOUND_MIXER_READ_LINE		//	PTX_IOC + 6
#else
#define PTX_IOC			('p' << 24) + ('t' << 16) + ('x' << 8)
#define PTX_IOCMSET		PTX_IOC + 1		// set modem signal
#define PTX_IOCLSET		PTX_IOC + 2		// set line status info
#define PTX_IOCDRAINEND	PTX_IOC + 3		// drain complete
#define PTX_IOCNETSTAT	PTX_IOC + 4		// update network
#define PTX_IOCOWTSET	PTX_IOC + 5		// give ptyx, the open wait time in msec
										// -1=ignore network status, -2=wait forever
#endif												

//  bit definition for ptyx_struct.ctrl_status
#define CTRLSTATUS_SIGNALS		0x00000001	// update DTR, RTS signals
#define CTRLSTATUS_TERMIOS		0x00000002	// update termios settings
#define CTRLSTATUS_BREAK		0x00000004	// send break signal
#define CTRLSTATUS_OPEN			0x00000008	// slave port opened
#define CTRLSTATUS_CLOSE		0x00000010	// slave port closed
#define CTRLSTATUS_BREAKON		0x00000020	// send break on
#define CTRLSTATUS_BREAKOFF		0x00000040	// send break off
#define CTRLSTATUS_DRAIN		0x00000080	// drain port
#define CTRLSTATUS_FLUSHREAD	0x00000100	// flush read
#define CTRLSTATUS_FLUSHWRITE	0x00000200	// flush write
#define CTRLSTATUS_STOP			0x00000400	// flush write
#define CTRLSTATUS_START		0x00000800	// flush write

#define DEFAULT_OUT_WINDOW_SIZE          1536 		// Default out_window_size

// some configuration min/max/default defines
#define	MIN_RETRY_TIME			1			// minumum client reconnect retry time in seconds
#define	MAX_RETRY_TIME			255
#define DEFAULT_RETRY_TIME   	30			// Default client connection retry time (seconds)

#define	MIN_RETRY_NUM			-1
#define	MAX_RETRY_NUM			255
#define DEFAULT_RETRY_NUM    	-1 		// Default number of client connection retry attempts (-1=forever)


#define OPENWAIT_FOREVER				-2			// Value for -openwaittime option that will cause driver to block indefinately when on port open
#define OPENWAIT_ALWAYS_SUCCESSFUL		-1			// Value for -openwaittime option that will cause driver to alway return successfully on port open
#define	MIN_OPENWAIT_TIME				-2
#define	MAX_OPENWAIT_TIME				65535
#define DEFAULT_OPEN_WAIT_TIME			5			// Default time to wait for for network connection before returning to the app

#define MAX_MASTER_OPEN_WAIT_TIME		30			// Maxim open wait time for master driver to be opened by tpd

#define	MIN_CLOSEDELAY_TIME				0
#define	MAX_CLOSEDELAY_TIME				65535
#define	DEFAULT_DELAY_CLOSE_TCP_TIME	3  		// Default time to delay before closing the TCP link when the serial port is closed

#define	MIN_PKTIDLE_TIME					0
#define	MAX_PKTIDLE_TIME					65535
#define DEFAULT_IDLE_TIME_PACKET_TIMEOUT 	10			// Default data group idle timeout (msec)

#define DEFAULT_KEEPALIVE_TIME	30		// Default keep-alive time, 30 seconds


#define MAX_HOST_NAMELEN 64	// Maximum host name string


#define LM_MAX_SEND_BUF_SIZE	512		// Lite Mode maximum send buffer size




#endif   /* _TP_H */
