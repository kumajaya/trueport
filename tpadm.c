/******************************************************************
Module: TruePort Admin Tool
 
 Description: TruePort Admin Tool for UNIX
 
	This program is used to administer the configuration
	file that is used by the TruePort Daemon


 Copyright (c) 1999-2016 Perle Systems Limited. All rights reserved.
 
*******************************************************************/

/****************************************************************************
 * Include files and external linkages              
 ****************************************************************************/

#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <getopt.h>
#include "tp.h"
#include "tp-autogen.h"
#include "pkt_forwarding.h"

/****************************************************************************
 * Local constant definitions                 
 ****************************************************************************/

#ifndef TRUE
#define TRUE		(1)
#define FALSE  	(0)
#endif

#define OK 			(0)
#define FAILURE	(-1)        // Failure indication

#define  MAX_PORTS MAXINSTPORTS         // Maximum ports installed
#define NARGS  	100          // Max config file tokens
#define	NSLOTS	(MAX_PORTS * 2 + 20)	/* Max config file entries incl comments*/
#define NRESTART	10          // Max restarts per entry
#define LINESZ		512         // Max config file line length

#define CFG_DECIMAL			0x0000
#define CFG_HEXIDECIMAL		0x1000


/****************************************************************************
 * Type definitions                        *
 ****************************************************************************/

enum Type { DELETE, VALID, COMMENT };

struct Tpadm
{
	pid_t       cpid;           // Child PID
	enum Type   type;          // Entry type: VALID/COMMENT/DELETE
	char        *argv[NARGS];  // Argv list for execv
};                         		// Instance of a TruePort Daemon

enum Cmd { UNDEF, ADD, REMOVE, LIST, START };


struct Action
{
	enum Cmd	cmd;
	int Mode;
	char *keepalive;
	char *TCPhost;
	char 	*TCPport;
	long first_TCPport;
	char *TTYname;
	char *portstart;
	char *portrange;
	int hangup;
#ifdef USE_SSL
	int SSL_enabled;
#endif   //USE_SSL
	char *TCPcopy_host;
	char *TCPcopy_port;
	int pkt_fwd_enabled;
	char *TRACEnum;
	// client actions
	int client;
	char *retrysec;
	char *retrynum;
	int client_nodisc;
	io_type_t 	iotype;
	int server;
	opmode_type_t opmode_type;
	char *pktidletime;
	char *openwaittime;
	char *closedelaytime;
	int connect_on_init;
	int norestorenet;
	int useudp;				// 0 - don't use legacy UDP protocol, 1 - use it
};



static struct Tpadm  tpadm[NSLOTS]; /* Parsed config file data */
static struct Action action;     /* Command action required */

const char ConfigDir[]  	= { "/etc/trueport/" };
const char ConfigFile[] 	= { "config.tp" };
const char	TpadmLock[]  	= { "LOCK.tp" };
const char	PktFwdCfgFile[] = { "/etc/trueport/pktfwdcfg.tp" };

/* These are the arg strings for the config file */
const char Tpdbin[] =       { "/usr/bin/trueportd" };
const char TCPPORTarg[] =       { "-port" };
const char TTYarg[] =       { "-tty" };
const char MODEarg[] =      { "-trueport" };
//const char *ttydir =         "/dev/";
const char *ttydir = "";
const char *ttyinfix =       "";
const char  PKT_FWD_arg[] = { "-pf" };
const char HUParg[] =       { "-hup" };
const char TERMarg[] =      { "-term" };
const char KEEParg[] =      { "-ka" };
const char TRACEarg[] =     { "-trace" };
const char ALLSTART[] =     { "ALL" };
const char CLIENTarg[] =    { "-client" };
const char SERVERarg[] =    { "-server" };
const char RETRYSECarg[] =  { "-retrytime" };
const char RETRYNUMarg[] =  { "-retrynum" };
const char NODISCarg[] =    { "-nodisc" };
const char IOarg[] =        { "-io" };
const char IOMBASCIIarg[] = { "mb_ascii" };
const char IOMBRTUarg[] =   { "mb_rtu" };
const char IOAPIarg[] =     { "io_api" };
const char OPMODEarg[]={"-opmode"};
const char OPMODE_NAME_OPTIMIZELAN[]={"optimize_lan"};
const char OPMODE_NAME_LOWLATENCY[]={"low_latency"};
const char OPMODE_NAME_PACKETIDLETIMEOUT[]={"packet_idle_timeout"};
const char OPMODE_NAME_CUSTOM[]={"custom"};
const char PKTIDLETIMEarg[]={"-pktidletime"};
const char CONNECTONINITarg[]={"-initconnect"};
const char OPENWAITTIMEarg[]={"-openwaittime"};
const char CLOSEDELAYTIMEarg[]={"-closedelaytime"};
const char NORESTORENETarg[]={"-norestorenet"};
const char USEUDParg[]={"-useudp"};
const char NOUDParg[]={"-noudp"};

// Some configuration defualts
const char DEFAULT_keepalive[] = { "30" };

static char Tpdpath[LINESZ];


FILE *pConfig;                		/* Pointer to the Config File */
static char ConfigLine[LINESZ];    /* Max Config File line */

void	tidyup(void);              /* tidy up trace files afnd restore */
pid_t	dAemon(void);              /* fork and become a daemon */
int FindTcp(int startslot);
int FindTty(void);
void StartSlot(int);
void PrintSlot(int);
void ListConfig(void);
void DoCmd(void);
void AddEntry( int nslot );
void ParseConfig(void);
void WriteConfig(void);
void CheckConfig(void);
void CmdParse(int,char **);
char *FindOpt(char **,const char *);
void GenErr(char *,int);
void tpexit(int);
void catch_signal(int sig_num);


enum ITEM_TYPE { ITEM_EMPTY, ITEM_COMMENT, ITEM_GLOBAL, ITEM_PORT };


// Packet Forwarding structures and variables.

typedef struct pkt_fwd_port_cfg_st
{
	unsigned short	    forwarding;        	// options for packet forwarding
	unsigned short	    start_transmit_rule;
	unsigned short	    end_transmit_rule;
	unsigned short	    packet_size;       	// maximum packet size
	unsigned short	    idle_time;         	// idle time in msec
	unsigned short	    force_time;        	// time to force transmit in msec
	unsigned char		trigger_char1;     	// transmit if char is encountered
	unsigned char		trigger_char2;     	// transmit if char is encountered
	unsigned char		start_frame1;      	// start of frame marker
	unsigned char		start_frame2;      	// start of frame marker
	unsigned char		end_frame1;        	// end of frame marker
	unsigned char		end_frame2;        	// end of frame marker
} PKT_FWD_PORT_CFG;


struct pkt_fwd_cfg_items_st
{
	char    	   		*data;
	char				*host;
	char				*port;
	int            		type;
	PKT_FWD_PORT_CFG	*pfcfg;
};

struct pkt_fwd_cfg_items_st pkt_fwd_cfg_items[NSLOTS];


//	Packet forward prototypes

static void	pkt_fwd_configure( void );
static int 	read_pkt_fwd_config( void );
static char 	*pkt_fwd_service_options( int slot, char *opt, char *arg );
static void 	get_new_pkt_fwd_input( PKT_FWD_PORT_CFG *pfcfg );
static int 	get_and_verify_input( char *prompt,
                                  long lower_limit,
                                  long upper_limit,
                                  int  format,
                                  unsigned long *retValue );
static int GetTCPHostPort(char *host_port, char **TCPhost, char **TCPport);
static int 	get_yes_no( char *prompt );
static void 	write_pkt_fwd_config( void );
static void 	remove_pkt_fwd_config( void );


#ifdef   USE_SSL

#define  MAX_PASSPHRASE_LEN     32
#define	 MAX_SSL_VERSIONS		5


typedef struct ssl_port_cfg_st
{
	char  *certfile;
	char  *keyfile;
	char  pass_phrase[MAX_PASSPHRASE_LEN];
	char  *cafile;
	int   ssl_type;
	int   ssl_version;
	int   do_authentication;
	char  *countryName;
	char  *stateOrProvinceName;
	char  *localityName;
	char  *organizationName;
	char  *organizationalUnitName;
	char  *commonName;
	char  *pkcs9_emailAddress;
} SSL_PORT_CFG;


struct ssl_cfg_items_st
{
	char           *data;
	char			*host;
	char			*port;
	int            type;
	SSL_PORT_CFG   *sslcfg;
};


// Strings for version.
char	*ssl_methods_strings[] =
    {
        "any",
        "TLSv1",
        "SSLv3",
        "TLSv1.1",
        "TLSv1.2"
    };


const char  SslCfgFile[] = { "/etc/trueport/sslcfg.tp" };
const char  SSLarg[]     = { "-ssl" };
#define		DEFAULT_SSL_CERT_FILE		"/etc/trueport/sslcert.pem"
#define		DEFAULT_SSL_CA_FILE			"/etc/trueport/ca.pem"
struct ssl_cfg_items_st ssl_cfg_items[NSLOTS];

static void ssl_configure(void);
static char *stralloc(char *str);
static int  read_ssl_config(void);
static char *ssl_service_options( int slot, char *opt, char *arg);
static void get_new_ssl_input( SSL_PORT_CFG *sslcfg );
static void write_ssl_config( void );
static void remove_ssl_config( void );

#endif   //USE_SSL



//******************************************************************************
//
//    Main program
//
//    Arguments   : -
//    Return values  : -
//

int main (int argc, char *argv [])
{
	struct stat lockstat;

	/* Initialise */
	strcpy(Tpdpath,Tpdbin);

	/* Must be root */
	if (getuid() != 0)
	{
		GenErr("Not root !",-1);
		exit(FAILURE);
	}

	/* Install signal handler */
	signal (2, catch_signal);
	signal (15, catch_signal);

	/* Change working directory */
	if (chdir(ConfigDir) == FAILURE)
	{
		perror("tpadm : Can't change to working directory");
		exit(FAILURE);
	}

	/* Stat the locking file */
	if (stat(TpadmLock,&lockstat)==FAILURE) /* No lock file */
	{
		creat(TpadmLock,O_RDONLY);
	}
	else
	{
		GenErr("Lock File exists !",-1);
		exit(FAILURE);
	}

//	printf( "\n" );		// provide a blank line before any prompts or data is printed.

	/* Parse the Config File */
	ParseConfig();

	/* Now Switch on Command Line - add:remove:start:list */
	CmdParse(argc,argv);

	/* Do specified TruePort action in the config file */
	DoCmd();

	/* Deallocate lock and exit */
	tpexit(0);
	exit(0);	// needed to remove compile warning
}



//*****************************************************************************
/* Exit nicely */

void tpexit(int exitcode)
{
	unlink(TpadmLock);
	exit(exitcode);
}


void catch_signal(int sig_num)
{
	signal(sig_num, catch_signal);
	GenErr( "\nExiting after catching signal - ", sig_num );
	tpexit (-sig_num);
}




//*****************************************************************************
/* Check for conflicts with the supplied args */

void CheckConfig()
{
	int nslot;
	int tcperrflg = 0;
	int ttyerrflg = 0;

	if ((nslot=FindTty()) != FAILURE)	/* Check TTY */
	{
		ttyerrflg++;
	}
	else if (
             (action.iotype == NOTDEF) && 
             ((nslot=FindTcp(0)) != FAILURE) ) 	/* Check TCP */
	{
		tcperrflg++;
	}

	if (ttyerrflg)
	{
		GenErr("ERROR! - TTY port conflict with configuration line",nslot+1);
		PrintSlot(nslot); /* print */
		tpexit(FAILURE);
	}
	if (tcperrflg)
	{
		if(action.client)
		{
			GenErr("WARNING! - TCP port conflict with configuration line",nslot+1);
			PrintSlot(nslot); /* print */
		}
		else
		{
			GenErr("ERROR! - TCP port conflict with configuration line",nslot+1);
			PrintSlot(nslot); /* print */
			tpexit(FAILURE);
		}
	}
}


//*****************************************************************************
// Do specified tpadm command

void DoCmd(void)
{
	int nslot;

	switch(action.cmd)
	{
		case LIST:
		{
			ListConfig();
			break;
		}

		case ADD:
		{
			int     port, portrange;
			int     i;
			char    *szTCPport;
//			char    ttyNameBase[6], ttyName[6], ttyNameTmp[20];     
			char    ttyName[6], ttyNameTmp[20];     
	
			for(nslot=0; nslot < NSLOTS; nslot++)   /* find first free */
			{
				if (tpadm[nslot].type != DELETE)
				{
					continue;
				}
  				// If port range is not set then assume a port range of 1 port.
    			if( action.portrange )
				{ 
        			portrange = atoi(action.portrange);
				}
    			else
				{
        			portrange = 1;
				}
				if( (nslot + portrange) >= NSLOTS )
				{
					GenErr("Too many port entries",-1);
					tpexit( FAILURE );
				}
				action.first_TCPport = atoi(action.TCPport);
				port = atoi( action.portstart );
//				strncpy( ttyNameBase, action.TTYname, 6 );
				for( i = 0; i < portrange; i++ )
				{
					szTCPport = malloc(20);
					// don't increment the TCP port if we are adding 
					// multiple Client I/O access ports
					if(action.iotype != NOTDEF)
					{
						sprintf( szTCPport, "%ld", action.first_TCPport );
					}
					else
					{
						sprintf( szTCPport, "%ld", action.first_TCPport + i );
					}
					action.TCPport = szTCPport;
					// don't add port number if range wasn't specified
					if (action.portrange)
					{
						sprintf( ttyNameTmp, "%d", port + i );
					}
					else
					{
//						sprintf( ttyNameTmp, "%s", ttyNameBase );
						GenErr("--range option required",-1);
						tpexit( FAILURE );
					}
					strncpy( ttyName, ttyNameTmp, 5 );  // Value 5 is used in AddENtry.
					ttyName[5] = '\0';
					action.TTYname = ttyName;
					AddEntry( nslot + i );
				}
#ifdef	USE_SSL
				if ( action.SSL_enabled )
				{
					ssl_configure();
				}
#endif	//USE_SSL
				if ( action.opmode_type==OPMODE_TYPE_CUSTOM )
				{
					pkt_fwd_configure();
				}
				break;

			} // end for nslot < NSLOTS

			if (nslot < NSLOTS)
			{
				WriteConfig();
			}
			else
			{
				GenErr("Too many config lines (including comments). Maximum:", NSLOTS);
				tpexit(FAILURE);
			}
			break;
		}  // end case ADD:

		case REMOVE:
		{
			int nslot,  match_cnt;

			match_cnt = 0;
			for(nslot=0; (nslot < NSLOTS); nslot++)
			{
				nslot = FindTcp(nslot);
				// match found
				if (nslot != FAILURE)
				{
					PrintSlot(nslot); /* print and mark for delete */
					tpadm[nslot].type = DELETE;
					match_cnt++;
				}
				// no more matches found
				else
				{
					break;
				}
			}
			if (match_cnt)
			{
				WriteConfig();
#ifdef	USE_SSL
				remove_ssl_config();
#endif	//USE_SSL
				remove_pkt_fwd_config();
			}
			else
			{
				GenErr("-d entry not found !",-1);
				tpexit(FAILURE);
			}
			break;
		}

		case START:
		{
			int     nslot, i;
			int match_cnt = 0;
			int     portrange, tcpPort;
			char    szTCPport[20];

			if ( (action.TCPport != NULL) && !strcasecmp(action.TCPport, ALLSTART))
			{
				tidyup();
				for(nslot=0; nslot < NSLOTS; nslot++)
				{
					StartSlot(nslot);
				}
			}
			else
			{
				if ( action.portrange )
				{
					portrange = atoi(action.portrange);
				}
				else
				{
					portrange = 1;
				}

				tcpPort = atoi(action.TCPport);
				for( i = 0; i < portrange; i++ )
				{
					sprintf( szTCPport, "%d", tcpPort + i );
					if (action.TCPport != NULL)
					{
						action.TCPport = szTCPport;
					}
					for(nslot=0; (nslot < NSLOTS); nslot++)
					{
						nslot = FindTcp(nslot);
						// match found
						if (nslot != FAILURE)
						{
							StartSlot(nslot);
							match_cnt++;
						}
						// no more matches found
						else
						{
							break;
						}
					}
				}
				if (!match_cnt)
				{
					GenErr("-s entry not found !",-1);
				}
			}
			break;
		}
    	case UNDEF:
		{
			printf ("illegal case!\n");
			tpexit (1);
		}
	}  // end switch(action.cmd)
}

//*****************************************************************************
//
//

void AddEntry( int nslot )
{
    int i, ttyn;   /* counters and markers */
    
    i = 0;
    tpadm[nslot].argv[i++] = (char *)Tpdpath;
    if (action.Mode)
	{
        tpadm[nslot].argv[i++] = (char *)MODEarg;
		// only put UDP options in file if configured for full mode
		// in Lite mode these options are meaningless
		if (action.useudp)
		{
			tpadm[nslot].argv[i++] = (char *)USEUDParg;
		}
		else
		{
			tpadm[nslot].argv[i++] = (char *)NOUDParg;
		}
	}
#ifdef  USE_SSL
    if( action.SSL_enabled )
        tpadm[nslot].argv[i++] = (char *)SSLarg;
#endif  //USE_SSL
	tpadm[nslot].argv[i++] = (char *) OPMODEarg;
	if (action.opmode_type==OPMODE_TYPE_OPTIMIZELAN)
	{
		tpadm[nslot].argv[i++] = (char *)OPMODE_NAME_OPTIMIZELAN;
	}
	else if (action.opmode_type==OPMODE_TYPE_LOWLATENCY)
	{
		tpadm[nslot].argv[i++] = (char *)OPMODE_NAME_LOWLATENCY;
	}
	else if (action.opmode_type==OPMODE_TYPE_PACKETIDLETIMEOUT)
	{
		tpadm[nslot].argv[i++] = (char *)OPMODE_NAME_PACKETIDLETIMEOUT;
	}
	else if (action.opmode_type==OPMODE_TYPE_CUSTOM)
	{
		tpadm[nslot].argv[i++] = (char *)OPMODE_NAME_CUSTOM;
	}
	
	if (action.opmode_type==OPMODE_TYPE_PACKETIDLETIMEOUT && action.pktidletime)
	{
		tpadm[nslot].argv[i++] = (char *)PKTIDLETIMEarg;
		tpadm[nslot].argv[i++] = (char *)action.pktidletime;
	}
	if (action.openwaittime)
	{
		tpadm[nslot].argv[i++] = (char *)OPENWAITTIMEarg;
		tpadm[nslot].argv[i++] = (char *)action.openwaittime;
	}
	if( action.hangup )
		 tpadm[nslot].argv[i++] = (char *)HUParg;
	tpadm[nslot].argv[i++] = (char *)TTYarg;
	ttyn = i;
	tpadm[nslot].argv[i] = malloc(128);
	strcpy( tpadm[nslot].argv[i], ttydir );
	strcat( tpadm[nslot].argv[i++], action.TTYname );
	tpadm[nslot].argv[i++] = (char *)TCPPORTarg;
	tpadm[nslot].argv[i++] = action.TCPport;

	if ( (action.client) && (action.TCPhost != NULL) )
	{
		tpadm[nslot].argv[i++] = (char *)CLIENTarg;
		tpadm[nslot].argv[i++] = (char *)action.TCPhost;
		if (action.retrysec != NULL)
		{
			tpadm[nslot].argv[i++] = (char *)RETRYSECarg;
			tpadm[nslot].argv[i++] = (char *)action.retrysec;
		}
		if (action.retrynum != NULL)
		{
			tpadm[nslot].argv[i++] = (char *)RETRYNUMarg;
			tpadm[nslot].argv[i++] = action.retrynum;
		}
		if (action.client_nodisc)
		{
			tpadm[nslot].argv[i++] = (char *)NODISCarg;
		}
		if (action.connect_on_init)
		{
			tpadm[nslot].argv[i++] = (char *)CONNECTONINITarg;
		}
		if (action.norestorenet)
		{
			tpadm[nslot].argv[i++] = (char *)NORESTORENETarg;
		}
		if (action.closedelaytime)
		{
			tpadm[nslot].argv[i++] = (char *)CLOSEDELAYTIMEarg;
			tpadm[nslot].argv[i++] = (char *)action.closedelaytime;
		}
		if (action.iotype != NOTDEF)
		{
			tpadm[nslot].argv[i++] = (char *)IOarg;
			switch (action.iotype)
			{
				case MB_ASCII:
					tpadm[nslot].argv[i++] = (char *)IOMBASCIIarg;
					break;
				case MB_RTU:
					tpadm[nslot].argv[i++] = (char *)IOMBRTUarg;
					break;
				case IO_API:
					tpadm[nslot].argv[i++] = (char *)IOAPIarg;
					break;
				case NOTDEF:
				default:
					break;
			}
		}
	} // end if client
	if ( (action.server || (!action.server && !action.client)) && (action.TCPhost != NULL) )
	{
		tpadm[nslot].argv[i++] = (char *)SERVERarg;
		tpadm[nslot].argv[i++] = (char *)action.TCPhost;

	}
	
	tpadm[nslot].argv[i++] = (char *)KEEParg;
	if (action.keepalive != NULL)
   	tpadm[nslot].argv[i++] = action.keepalive;
    else
		tpadm[nslot].argv[i++] = (char *)DEFAULT_keepalive;
	if ( action.TRACEnum != NULL )
	{
			tpadm[nslot].argv[i++] = (char *)TRACEarg;
			tpadm[nslot].argv[i++] = action.TRACEnum;
	}

	tpadm[nslot].argv[i++] = NULL;
	tpadm[nslot].argv[i++] = NULL;
        
    /* Now check for conflicts */
    action.TTYname = tpadm[nslot].argv[ttyn];

    CheckConfig();

    /* Configuration OK */
    tpadm[nslot].type = VALID;
}


//*****************************************************************************
/* Print Slot */

void PrintSlot(int nslot)
{
	int nargs = 0;

	if (tpadm[nslot].type == VALID)
	{
		while(tpadm[nslot].argv[nargs])
		{
			fprintf(stderr,"%s ",tpadm[nslot].argv[nargs]);
			nargs ++;
		}
		fprintf(stderr,"\n");
	}
}



//*****************************************************************************
/* Return option string (next string) for specified arg vector and option */

char *FindOpt(char **argv,const char *opt)
{
	int nargs = 0;
	while(argv[nargs])
	{
		char *argn = argv[nargs+1];
		if (!strcmp(argv[nargs], opt) && (argn != NULL))
		{
			return(argn);
		}
		nargs ++;
	}
	return(NULL);
}



//*****************************************************************************
// Find first slot, starting from given start slot, for matching TCPhost or
// TCPport only or matching combination.
// Note if matching on TCPport only no server or client host can exist
//    Returns -  slot number

int FindTcp(int startslot)
{
	int nslot;
	char *narghost = NULL;
	char *nargport = NULL;

	for(nslot = startslot; nslot < NSLOTS; nslot++)
	{
		if (tpadm[nslot].type == VALID)
		{
			nargport = FindOpt(tpadm[nslot].argv, TCPPORTarg);
			// should be only server or client not both
			if ( (narghost = FindOpt(tpadm[nslot].argv, CLIENTarg)) == NULL)
			{
				narghost = FindOpt(tpadm[nslot].argv, SERVERarg);
			}

			// match host only
			if ( (action.TCPhost != NULL) && (action.TCPport == NULL) )
			{
				if ( (narghost != NULL) && !strcmp(narghost, action.TCPhost) )
				{
					return(nslot);
				}
			}
			// match host and port
			else if ( (action.TCPhost != NULL) && (action.TCPport !=NULL) )
			{
				if ( ((narghost != NULL) && !strcmp(narghost, action.TCPhost)) &&
				        ((nargport != NULL) && !strcmp(nargport, action.TCPport)) )
				{
					return(nslot);
				}
			}  // just match port for entries with no narghost
			else if ( (action.TCPhost == NULL) && (action.TCPport != NULL) && (narghost == NULL))
			{
				if ( (nargport != NULL) && !strcmp(nargport, action.TCPport) )
				{
					return(nslot);
				}
			}

		}
		//		else if (tpadm[nslot].type == DELETE)
		//		{
		//			return(FAILURE);
		//		}
	}
	return(FAILURE);
}

//*****************************************************************************
// Find first slot for TTYname - return slot number

int FindTty(void)
{
	int nslot;

	for(nslot=0; nslot < NSLOTS; nslot++)
	{
		if (tpadm[nslot].type == VALID)
		{
			char *narg = FindOpt(tpadm[nslot].argv,TTYarg);
			if (narg)
			{
				if (!strcmp(narg,action.TTYname))
				{
					return(nslot);
				}
			}
			else
			{
				return(FAILURE);
			}
		}
		else if (tpadm[nslot].type == DELETE)
		{
			return(FAILURE);
		}
	}
	return(FAILURE);
}



//*****************************************************************************

void StartSlot(int nslot)
{
	pid_t cpid;

	if (tpadm[nslot].type != VALID)
	{
		return;
	}
//	PrintSlot(nslot);
	if ( (cpid = dAemon()) > 0  )  /* parent process - original tpadm */
	{
		tpadm[nslot].cpid = cpid;
		/*GenErr("starting daemon PID =",cpid);*/
	}
	else              /* child */
	{
		execv(Tpdpath,tpadm[nslot].argv);
		exit(FAILURE);       /* failure ! */
	}
}


pid_t dAemon(void)
{
	pid_t cpid;

	/* fork and make the child process a daemon */
	/* returns 0 to child, pid_t to parent */

	if ((cpid = fork()) == 0 )     /* Child process */
	{
		if (setsid() == FAILURE)
		{
			perror("tpadm : Can't become daemon");
			exit(FAILURE);
		}
		close(0);
		close(1);
		close(2);
	}
	else if (cpid == FAILURE)  /* Can't fork */
	{
		perror("tpadm : Can't fork\n");
		tpexit(FAILURE);
	}

	return(cpid);
}


//*****************************************************************************

void tidyup(void)
{
	FILE *ptr;
	static char RestoreScripts[] = \
	                               { "for s in `ls restore_*.sh`\ndo\nsh $s\nrm -F $s\ndone 2>/dev/null" };
	static char TraceFiles[] = \
	                           { "for s in `ls trace.*`\ndo\nrm -F $s\ndone 2>/dev/null" };


	if ((ptr = popen(RestoreScripts, "r")) == NULL)
	{
		GenErr("Can't cleanup!",-1);
		tpexit(FAILURE);
	}
	pclose(ptr);

	if ((ptr = popen(TraceFiles, "r")) == NULL)
	{
		GenErr("Can't cleanup!",-1);
		tpexit(FAILURE);
	}
	pclose(ptr);
}


//*****************************************************************************

void ParseConfig(void)
{
	int nslot;
	char *tmpline;
	int tmplen;

	if ( (pConfig=fopen( ConfigFile,"r" ))==(FILE *)NULL )
	{
		perror( "tpadm : Can't open config file" );
		tpexit( FAILURE );
	}
	/* Clear the structure */

	for( nslot=0;nslot<NSLOTS;nslot++ )
	{
		tpadm[nslot].type = DELETE;
		tpadm[nslot].argv[0] = NULL;
		tpadm[nslot].cpid = 0;
	}
	nslot = 0;

	/* Read and parse config file */
	while( (fgets( ConfigLine,LINESZ,pConfig )!=NULL) )
	{
		if ( nslot < NSLOTS )   /* Config file OK */
		{
			/* get some store for this line */
			tmpline = malloc( (tmplen=strlen( ConfigLine ))+1 );

			strcpy( tmpline,ConfigLine );

			/* Now parse it - comment or command ? */
			if ( *tmpline != '#' && tmplen > 1 ) /* Comment */
			{
				int   ntok = 0;   /* Num tokens/line */
				char *ptok;

				while( (ptok = strtok( tmpline," \n\t#" )) && ntok < NARGS )
				{
					tmpline = NULL;
					tpadm[nslot].argv[ntok] = ptok;
					strcpy( tpadm[nslot].argv[ntok],ptok );
					ntok ++;
				}
				tpadm[nslot].argv[ntok] = NULL;
				tpadm[nslot].type = VALID;
			}
			else
			{
				tpadm[nslot].argv[0] = tmpline;
				tpadm[nslot].argv[1] = NULL;
				tpadm[nslot].type = COMMENT;
			}
			nslot ++;
		}
		else
		{
			GenErr( "Configuration file error - lines >",NSLOTS );
			tpexit( FAILURE );
		}
	}
	
	fclose( pConfig );

	/* Now check the parsed configuration for conflicts and errors */
	for( nslot = 0; nslot < NSLOTS ; nslot++ )
	{
		int   narg;

		/* For each VALID entry */
		if ( tpadm[nslot].type == VALID )
		{
			/* Check args on this line */
			if ( strcmp( tpadm[nslot].argv[0],Tpdpath ) ) /* Name wrong ? */
			{
				GenErr( "Incorrect TruePort command name, line:",nslot+1 );
				tpexit( FAILURE );
			}

			// This loop seems to force the last option on the command line to have
			//    an argument. I don't know why this is neccesary. If I find out
			//    I will post it here.
			for( narg=1; tpadm[nslot].argv[narg]; narg++ )
			{
				if ( !tpadm[nslot].argv[narg] || !tpadm[nslot].argv[narg+1] )
				{
					GenErr( "Null arg configuration syntax error line",nslot+1 );
					tpexit( FAILURE );
				}
				/*
				** If this is an option followed by an argument,
				** increment the argument count
				*/
				if ( *tpadm[nslot].argv[narg] == '-' && *tpadm[nslot].argv[narg+1] != '-' )
					narg++;
			}
			/* Now check each entry against all others */
			/* Cheat - set this slot to COMMENT to exclude from search */
			tpadm[nslot].type = COMMENT;
			/* Get TCP port number */
			action.TCPport = FindOpt( tpadm[nslot].argv, TCPPORTarg );
			/* Get Server TCP Host */
			if ( (action.TCPhost = FindOpt( tpadm[nslot].argv, SERVERarg )) != NULL)
			{
				if (FindOpt( tpadm[nslot].argv, CLIENTarg ) != NULL)
				{
					GenErr( "Port entry can not be set for both client and server on line",nslot+1 );
					tpexit( FAILURE );
				}
			}
			else
			{
				/* Get Client TCP Host */
				action.TCPhost = FindOpt( tpadm[nslot].argv, CLIENTarg );
				if(action.TCPhost)
					action.client = 1;
			}
			/* Get TTY name */
			action.TTYname = FindOpt( tpadm[nslot].argv,TTYarg );
			// Checking if I/O Acess set
			 if( FindOpt(tpadm[nslot].argv,IOarg) != NULL )
				action.iotype = MB_ASCII;  // just picked something beside NOTDEF
			 else
				action.iotype = NOTDEF;

			/* Check it ! */
			CheckConfig( );
			tpadm[nslot].type = VALID;
		}
	}
}



//*****************************************************************************
/* List config file */

void ListConfig(void)
{
	int nslot;
	int match_cnt = 0;

	if ( (action.TCPport != NULL) && !strcasecmp(action.TCPport, ALLSTART))
	{
		for(nslot = 0; nslot < NSLOTS; nslot++)
		{
			PrintSlot(nslot);
		}
	}
	else
	{
		for(nslot=0; (nslot < NSLOTS); nslot++)
		{
			nslot = FindTcp(nslot);
			// match found
			if (nslot != FAILURE)
			{
				PrintSlot(nslot);
				match_cnt++;
			}
			// no more matches found
			else
			{
				break;
			}
		}
		if (!match_cnt)
		{
			GenErr("-l entry not found !",-1);
			tpexit(FAILURE);
		}
	}
}

//*****************************************************************************

void CmdParse(int argc, char **argv)
{
	int   c,errflg, tmp;
	extern char *optarg;
	extern int optind, optopt;
	static struct option long_options[] =
	{
		{"openwaittime",    1, 0, 0},	// option_index 0
		{"closedelaytime",  1, 0, 0},	// option_index 1
		{"initconnect",     0, 0, 0},	// option_index 2
		{"opmode",          1, 0, 0},	// option_index 3
		{"pktidletime",     1, 0, 0},	// option_index 4
		{"norestorenet",    0, 0, 0},	// option_index 5
		{"useudp",          0, 0, 0},	// option_index 6
		{"noudp",           0, 0, 0},	// option_index 7
		{"index",           1, 0, 0},	// option_index 8
		{"range",           1, 0, 0},	// option_index 9
		{0,0,0,0}
	};
    /* getopt_long stores the option index here. */
	int option_index=0;

	action.cmd = UNDEF;
	action.TCPhost = NULL;
	action.TCPport = NULL;
	action.Mode = 1;			// Full mode by default.
	action.TTYname = NULL;
	action.TCPcopy_host = NULL;
	action.TCPcopy_port = NULL;
    action.portstart = NULL;
    action.portrange = NULL;
#ifdef  USE_SSL
    action.first_TCPport = -1;
#endif  //USE_SSL
	action.TRACEnum = NULL;
	action.client = 0;
	action.server = 0;
	action.retrysec = NULL;
	action.retrynum = NULL;
	action.client_nodisc = 0;		// default to disconnect TCP on TTY close
	action.iotype = NOTDEF;
	action.opmode_type = 0;
	action.pktidletime = NULL;
	action.openwaittime = NULL;
	action.closedelaytime = NULL;
	action.connect_on_init = 0;    // not specified
	action.norestorenet = 0;		// not specified
    action.useudp = 0;				// config defaults to noudp
	errflg = 0;


#ifdef USE_SSL
	while((c=getopt_long(argc,argv,"nmhFeoa:d:l:s:p:t:k:b:i:c:C:S:r:R:I:",long_options,&option_index))!=-1)
#else
		while((c=getopt_long(argc,argv,"nmhFoa:d:l:s:p:t:k:b:i:c:C:S:r:R:I:",long_options,&option_index))!=-1)
#endif	//USE_SSL
		{
			switch (c)
			{
				case 0:
				{
					switch(option_index)
					{
						case 0:		// openwaittime
							if (action.cmd != ADD)
								errflg++;
							
							action.openwaittime = optarg;
							tmp = atoi(optarg);
							if ( (tmp > MAX_OPENWAIT_TIME) || (tmp < MIN_OPENWAIT_TIME) )
							{
								fprintf(stderr,"tpadm : Port open wait time should be between %d and %d!\n",MIN_OPENWAIT_TIME, MAX_OPENWAIT_TIME);
								errflg++;
							}
							break;
							
						case 1:		// closedelaytime
							if (action.cmd != ADD)
								errflg++;
							
							action.closedelaytime = optarg;
							tmp = atoi(optarg);
							if ( (tmp > MAX_CLOSEDELAY_TIME) || (tmp < MIN_CLOSEDELAY_TIME) )
							{
								fprintf(stderr,"tpadm : Connection close delay time should be between %d and %d!\n",MIN_CLOSEDELAY_TIME, MAX_CLOSEDELAY_TIME);
								errflg++;
							}
							break;
							
						case 2:		// initconnect
							if (action.cmd != ADD)
								errflg++;
						
							action.connect_on_init = 1;
							break;
							
						case 3:	// operation mode
							if (action.cmd != ADD)
								errflg++;
							
							if (!strcmp(optarg,OPMODE_NAME_OPTIMIZELAN))
							{
								action.opmode_type=OPMODE_TYPE_OPTIMIZELAN;
							}
							else if (!strcmp(optarg,OPMODE_NAME_LOWLATENCY))
							{
								action.opmode_type=OPMODE_TYPE_LOWLATENCY;
							}
							else if (!strcmp(optarg,OPMODE_NAME_PACKETIDLETIMEOUT))
							{
								action.opmode_type=OPMODE_TYPE_PACKETIDLETIMEOUT;
							}
							else if (!strcmp(optarg,OPMODE_NAME_CUSTOM))
							{
								action.opmode_type=OPMODE_TYPE_CUSTOM;
							}
							else
							{
								fprintf(stderr,"tpadm :Invalid operation mode %s.\n",optarg);
								errflg++;
							}
							break;

						case 4:	// packet idle timeout
							if (action.cmd!=ADD)
								errflg++;
							
							action.pktidletime = optarg;
							tmp = atoi(optarg);
							if ( (tmp > MAX_PKTIDLE_TIME) || (tmp < MIN_PKTIDLE_TIME) )
							{
								fprintf(stderr,"tpadm : pktidletime should be between %d and %d!\n",MIN_PKTIDLE_TIME, MAX_PKTIDLE_TIME);
								errflg++;
							}
							break;
							
						case 5:	// norestorenet
							if (action.cmd != ADD)
								errflg++;
							
							action.norestorenet = 1;
							break;
						case 6:	// useudp
							if (action.cmd != ADD)
								errflg++;
							
							action.useudp = 1;
							break;
						case 7:	// noudp
							if (action.cmd != ADD)
								errflg++;
							
							action.useudp = 0;
							break;
						case 8:	// index
            				if(action.cmd!=ADD)
	                			errflg++;
							action.portstart = optarg;
							break;
						case 9:	// range
							if(action.cmd!=ADD && action.cmd!=START)
								errflg++;
            				action.portrange = optarg;
            				break;
					}
					break;
				}
				case  'a':  /* add option */
				{
					if (action.cmd != UNDEF)
						errflg++;
					action.cmd = ADD;
					// -a only accepts a port number
					action.TCPport = optarg;
					break;
				}
				case  'd':  /* remove option */
				{
					if (action.cmd != UNDEF)
						errflg++;
					action.cmd = REMOVE;
					if (GetTCPHostPort(optarg, &action.TCPhost, &action.TCPport) < 0)		// parse for TCP host and port
						errflg++;
					break;
				}
				case  's':  /* start option */
				{
					if (action.cmd!=UNDEF)
						errflg++;
					action.cmd = START;
					if (GetTCPHostPort(optarg, &action.TCPhost, &action.TCPport) < 0)		// parse for TCP host and port
						errflg++;
					break;
				}
				case  'l':  /* list option */
				{
					if (action.cmd!=UNDEF)
						errflg++;
					if (GetTCPHostPort(optarg, &action.TCPhost, &action.TCPport) < 0)		// parse for TCP host and port
						errflg++;
					action.cmd = LIST;
					break;
				}
				case  'c':  /* copy option - copy ssl config from specified port number to new port number */
				{
					if (action.cmd != ADD)
						errflg++;
					if (GetTCPHostPort(optarg, &action.TCPcopy_host, &action.TCPcopy_port) < 0)	// parse for TCP host and port
						errflg++;
					break;
				}
#ifdef   USE_SSL
				case  'e':  /* SSL encrypt option */
				{
					if (action.cmd != ADD)
						errflg++;
					action.SSL_enabled = TRUE;
					break;
				}
#endif   // USE_SSL
				case  'F':  /* packet forward option */
				{
					if (action.cmd != ADD)
						errflg++;
				action.pkt_fwd_enabled = TRUE;
					break;
				}
				case  'h':  /* SSL encrypt option */
				{
					if (action.cmd != ADD)
						errflg++;
					action.hangup = TRUE;
					break;
				}
				case  'k':  /* keepalive option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.keepalive = optarg;
					break;
				}
				case  'm':  /* full mode option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.Mode = 1;
					break;
				}
				case  'n':  /* lite mode option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.Mode = 0;
					break;
				}
//				case  'p':  /* TTY name option */
//				{
//					if (action.cmd!=ADD)
//						errflg++;
//					action.TTYname = optarg;
//					break;
//				}
				case  't':  /* trace option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.TRACEnum = optarg;
					break;
				}
				case  'C':  /* Client mode option */
				{
					if (action.cmd!=ADD)
						errflg++;
					
					if (strlen(optarg) > MAX_HOST_NAMELEN)
					{
						GenErr("Host name too long, must be less than",MAX_HOST_NAMELEN);
						errflg++;
					}

					action.TCPhost = optarg;
					action.client = 1;
					break;
				}
				case  'S':  /* Server mode option */
				{
					if (action.cmd!=ADD)
						errflg++;

					if (strlen(optarg) > MAX_HOST_NAMELEN)
					{
						GenErr("Host name too long, must be less than",MAX_HOST_NAMELEN);
						errflg++;
					}
					action.TCPhost = optarg;
					action.server = 1;
					break;
				}
				case  'r':  /* TCP connection retry time option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.retrysec = optarg;
					tmp = atoi(optarg);
					if ( (tmp > MAX_RETRY_TIME) || (tmp < MIN_RETRY_TIME) )
					{
						fprintf(stderr,"tpadm : Connection retry time-out should be between %d and %d seconds!\n",MIN_RETRY_TIME, MAX_RETRY_TIME);
						errflg++;
					}
					break;
				}
				case  'R':  /* TCP connection number of retry attemps option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.retrynum = optarg;
					tmp = atoi(optarg);
					if ( (tmp > MAX_RETRY_NUM) || (tmp < MIN_RETRY_NUM))
					{
						fprintf(stderr,"tpadm : Number of connection retries should be between %d and %d!\n",MIN_RETRY_NUM,MAX_RETRY_NUM);
						errflg++;
					}
					break;
				}
				case  'o':  /* Don't close TCP connection on TTY close option */
				{
					if (action.cmd!=ADD)
						errflg++;
					action.client_nodisc = 1;
					break;
				}
				case  'I':  /* Client I/O Access option */
				{
					if (action.cmd!=ADD)
						errflg++;
					if (!strcmp(optarg, IOMBASCIIarg))
					{
						action.iotype = MB_ASCII;
					}
					else if (!strcmp(optarg, IOMBRTUarg))
					{
						action.iotype = MB_RTU;
					}
					else if (!strcmp(optarg, IOAPIarg))
					{
						action.iotype = IO_API;
					}
					else
					{
						GenErr("Invalid -I argument !",-1);
						errflg++;
					}
					break;
				}
				case  ':':        /* argument for -? is missing */
				{
					errflg++;
					fprintf(stderr,"option -%c requires an argument\n",optopt);
					tpexit(FAILURE);
					break;
				}
				case  '?':
				{
					errflg++;
					fprintf(stderr,"option -%c not recognized\n", optopt);
					tpexit(FAILURE);
				}
			} // end switch
		}

	if (action.cmd == UNDEF )
	{
		errflg ++;
	}

	if ( (action.TCPport != NULL) && !strcasecmp( action.TCPport, ALLSTART ) )
	{
		if ( (action.cmd != START) && (action.cmd != LIST) )   /* ALL specifed but NOT START */
		{
			GenErr("ALL flag allowed with -s or -l only !",-1);
			errflg++;
		}
	}
	if (action.cmd == ADD)   /* Port name specified ? */
	{
//		if (!action.TTYname)
//		{
//			GenErr("-p option required!",-1);
//			errflg++;
//		}
//		else if (strlen(action.TTYname) > 25)
//		{
//			GenErr("-p name too long !",-1);
//			errflg++;
//		}
		if (!action.portstart)
		{
			GenErr("--index option required!",-1);
			errflg++;
		}
		if (!action.portrange)
		{
			GenErr("--range option required!",-1);
			errflg++;
		}

		if (action.client)
		{
			if (action.server)
			{
				GenErr("Port entry can not be set for both client and server !",-1);
				errflg++;
			}
			if (action.iotype != NOTDEF)
			{
				action.Mode = 0;		// Client I/O Access operates in lite mode only
			}
		}
		else
		// client not configured
		{
			if (action.retrysec != NULL)
			{
				GenErr("-r option allowed with -C only !",-1);
				errflg++;
			}
			if (action.retrynum != NULL)
			{
				GenErr("-R option allowed with -C only !",-1);
				errflg++;
			}
			if (action.client_nodisc)
			{
				GenErr("-o option allowed with -C only !",-1);
				errflg++;
			}
			if (action.connect_on_init)
			{
				GenErr("--initconnect option allowed with -C only !",-1);
				errflg++;
			}
			if (action.norestorenet)
			{
				GenErr("--norestorenet option allowed with -C only !",-1);
				errflg++;
			}

			if (action.iotype != NOTDEF)
			{
				GenErr("-I option allowed with -C only !",-1);
				errflg++;
			}
		}

		if (action.pkt_fwd_enabled) 
		{
			if (action.opmode_type)
			{
				GenErr("-F and --opmode options are mutually exclusive !",-1);
				errflg++;
			}
			action.opmode_type = OPMODE_TYPE_CUSTOM;
		}

		if( action.Mode == 0 && action.hangup  && !(action.client)) 
		{
			GenErr("hangup option (-h) is not supported in Lite mode when set to Server mode\n", -1 );
			errflg++;
		}

		// setting default for opmode
		if (!action.opmode_type)
		{
			action.opmode_type = OPMODE_TYPE_LOWLATENCY;
		}

	}

	if (errflg)
	{
		fprintf(stderr,"Usage: tpadm version %s \n", TP_VERSION);

		fprintf(stderr,"  list:   tpadm -l <TCP#> | <host>: | <host>:<TCP#> | ALL \n" );
		fprintf(stderr,"  add:    tpadm -a <TCP#> [-m | -n]\n");
		fprintf(stderr,"          [--opmode optimize_lan | low_latency | packet_idle_timeout | custom]\n");
		fprintf(stderr,"          [--pktidletime <milliseconds>] [--openwaittime <seconds>] \n");
#ifdef	USE_SSL
		fprintf(stderr,"          [-e | -F | -e -F [-c [<host>:]<TCP#>]] [-h] \n");
#else
		fprintf(stderr,"          [-F [-c [<host>:]<TCP#>]] [-h] \n");
#endif	//USE_SSL
		fprintf(stderr,"          [-C <host> [-r <seconds>] [-R <retry#>] [-o]\n");
		fprintf(stderr,"          [--initconnect] [--closedelaytime <seconds>] [--norestorenet]");
		fprintf(stderr,"\n");
		fprintf(stderr,"          [-I mb_ascii | mb_rtu | io_api]");
		fprintf(stderr,"] \n");
		fprintf(stderr,"          [-S <host>] [-k <seconds>] [-t <level>] \n");
		fprintf(stderr,"          [--useudp | --noudp] [--index <port>] [--range <range>]\n");
		fprintf(stderr,"  delete: tpadm -d <TCP#> | <host>: | <host>:<TCP#> \n");
		fprintf(stderr,"  start:  tpadm -s <TCP#> | <host>: | <host>:<TCP#>  [--range <range>] | ALL \n");
		tpexit(FAILURE);
	}
}


//*****************************************************************************
/* Rewrite config file */

void WriteConfig()
{
	int nslot;

	if ((pConfig=fopen(ConfigFile,"w"))==(FILE *)NULL)
	{
		perror("tpadm : Can't open config file");
		tpexit(FAILURE);
	}
	/* Write out the structure */

	for(nslot=0; nslot < NSLOTS; nslot++)
	{
		if (tpadm[nslot].type == VALID)
		{
			int nargs = 0;
			while(tpadm[nslot].argv[nargs])
			{
				fprintf(pConfig,"%s ",tpadm[nslot].argv[nargs]);
				nargs ++;
			}
			fprintf(pConfig,"\n");
		}
		else if (tpadm[nslot].type == COMMENT)
		{
			fprintf(pConfig,"%s",tpadm[nslot].argv[0]);
		}
	}
	fclose(pConfig);
}


void GenErr(char *errstr,int arg)
{
	if (arg >= 0)
		fprintf(stderr,"tpadm : %s %d\n",errstr,arg);
	else
		fprintf(stderr,"tpadm : %s\n",errstr);
}



//******************************************************************************
// Allocate memory and copy string
static char *stralloc(char *str)
{
	char *retval;

	retval=calloc(strlen(str)+1, 1);
	if (!retval)
	{
		GenErr( "Fatal memory allocation error", -1 );
		tpexit(2);
	}
	strcpy(retval, str);
	return retval;
}




#ifdef   USE_SSL

//******************************************************************************
//
//    Read in existing SSL config, prompt user for entries for new port config
//    and write out the resulting configuration.
//

void ssl_configure( void )
{
    int     i,j;
    int     first_slot = 0;
	int   copy_slot = 0;
    int     portrange;
	char    szTCPport[6];

	if ( read_ssl_config() < 0 )
		tpexit( FAILURE );

    // Look for first empty spot in ssl configuration table
    i = 0;
    while( ssl_cfg_items[i].type != ITEM_EMPTY && i < NSLOTS )
        i++;
    if( i >= NSLOTS ) 
	{
        GenErr("ssl_configure: Too many entries >",NSLOTS);
        tpexit(FAILURE);
    }
    else
		{
        first_slot = i;
    }
    if( action.portrange ) 
        portrange = atoi(action.portrange);
    else
        portrange = 1;
    if( (first_slot + portrange) >= NSLOTS )  
	{
        GenErr("ssl_configure: Range creates too many entries >",NSLOTS);
        tpexit(FAILURE);
    }
    // If this is the first slot then prompt user for configuration data.
    //  For all other ports in the range, copy from the first port.
    for( i = first_slot; i < first_slot + portrange; i++ ) 
	{
		if ( (ssl_cfg_items[i].sslcfg = calloc( sizeof(SSL_PORT_CFG), 1 )) == NULL )
		{
			GenErr( "ssl_configure - malloc error", -1 );
			tpexit(FAILURE);
		}
		ssl_cfg_items[i].type = ITEM_PORT;
		if (action.TCPhost)
		{
			ssl_cfg_items[i].host = stralloc(action.TCPhost);
		}
		sprintf( szTCPport, "%ld", (action.first_TCPport + i - first_slot) );
		ssl_cfg_items[i].port = stralloc(szTCPport);
		ssl_cfg_items[i].sslcfg->certfile = stralloc( DEFAULT_SSL_CERT_FILE );
		ssl_cfg_items[i].sslcfg->cafile = stralloc( DEFAULT_SSL_CA_FILE );
		
		if ( (action.TCPcopy_host == NULL) && (action.TCPcopy_port == NULL) && 
				(i == first_slot) ) 
		{
            get_new_ssl_input( ssl_cfg_items[i].sslcfg );
        }
        else 
		{
			for( j = 0; j < NSLOTS; j++ )
			{
				if ( (action.TCPcopy_host != NULL) && (action.TCPcopy_port != NULL) &&
				 			(ssl_cfg_items[j].host != NULL) )
				{
					 if ( (ssl_cfg_items[j].type == ITEM_PORT) && 
								!strcmp(action.TCPcopy_host, ssl_cfg_items[j].host) && 
								!strcmp(action.TCPcopy_port, ssl_cfg_items[j].port) ) 
					 {
						copy_slot = j;
			    	    break;
		       	}
			}
			if ( action.TCPcopy_host == NULL && action.TCPcopy_port != NULL )
			{
					 if ( ssl_cfg_items[j].type == ITEM_PORT && 
								!strcmp(action.TCPcopy_port, ssl_cfg_items[j].port) ) 
					 {
						copy_slot = j;
						break;
				   }
				}
			}
			if ( i >= NSLOTS )
			{
				GenErr("SSL copy port not found", -1);
				tpexit(FAILURE);
			}
		   	memcpy( ssl_cfg_items[i].sslcfg, ssl_cfg_items[copy_slot].sslcfg, sizeof(SSL_PORT_CFG) );
		}
    }
    
    // Write the ssl configuration.
    write_ssl_config();
}



//******************************************************************************

static int read_ssl_config( void )
{
	FILE  *fp;
	char  confline[CONFLINELEN];
	char  *arg, *opt, *errstr;
	int   slot, section_slot;
	int   i, line_number;
	char *tmphost, *tmpport;

	if ( (fp = fopen( SslCfgFile,"r" )) == (FILE *)NULL )
	{
		perror( "tpadm : Can't open ssl config file" );
		tpexit( FAILURE );
	}
	section_slot = slot = 0;
	line_number = 0;
	while( fgets( confline, CONFLINELEN, fp ) && slot < NSLOTS )
	{
		line_number++;
		opt=confline;
		while( isspace( *opt ) )
			opt++; /* remove initial whitespaces */
		for( i = strlen( opt )-1; i >= 0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		if ( opt[0]=='\0' || opt[0]=='#' || opt[0]==';' ) /* empty or comment */
		{
			ssl_cfg_items[slot].data = stralloc( confline );
			ssl_cfg_items[slot].type = ITEM_COMMENT;
			slot++;
			continue;
		}

		// Detect a new section, allocate memory for the SSL config structure and
		//    initialize the item slot.
		if ( opt[0]=='[' && opt[strlen( opt )-1]==']' )
		{
			opt++;
			opt[strlen( opt )-1]='\0';
			section_slot = slot;
			slot++;
			if (GetTCPHostPort(opt, &tmphost, &tmpport) < 0)
			{
				perror( "tpadm: Bad [host:port_number] in SSL config file\n" );
				tpexit(1);
			}
			if(tmphost)
				 ssl_cfg_items[section_slot].host = stralloc(tmphost);   // store host and port entry
			if(tmpport)
			ssl_cfg_items[section_slot].port = stralloc(tmpport);
			
			/* get some store for this line */
			ssl_cfg_items[section_slot].sslcfg = calloc( sizeof(SSL_PORT_CFG), 1 );
			if ( ssl_cfg_items[section_slot].sslcfg == NULL)
			{
				GenErr( "malloc error: sslcfg\n", -1 );
				tpexit(1);
			}
			ssl_cfg_items[section_slot].type = ITEM_PORT;
			continue;
		}
		if ( ssl_cfg_items[section_slot].type != ITEM_PORT )
		{
			GenErr( "SSL config file - line %d: Reading data with no port number", line_number );
			tpexit( 1 );
		}
		arg=strchr( confline, '=' );
		if ( !arg )
		{
			GenErr( "SSL config file - line %d: No '=' found", line_number );
			tpexit( 1 );
		}
		*arg++='\0'; /* split into option name and argument value */

		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */

		while( isspace( *arg ) )
			arg++; /* remove initial whitespaces */
		errstr=ssl_service_options( section_slot, opt, arg );
		if ( errstr != NULL )
		{
			GenErr( errstr, -1 );
			fclose( fp );
			return(-1);
		}

	} //while

	fclose( fp );
	return(0);

}



//******************************************************************************
//

static char *ssl_service_options( int slot, char *opt, char *arg)
{
	SSL_PORT_CFG   *sslcfg = ssl_cfg_items[slot].sslcfg;

	// certificate-file
	if ( !strcasecmp( opt, "certificate-file" ) )
	{
		if ( arg[0] )
			sslcfg->certfile = stralloc( arg );
		return NULL; /* OK */
	}

	/* ssl-type (client or server) */
	if ( !strcasecmp( opt, "ssl-type" ) )
	{
		if ( !strcasecmp( arg, "client" ) )
			sslcfg->ssl_type =  0;
		else if ( !strcasecmp( arg, "server" ) )
			sslcfg->ssl_type = 1;
		else
			return "argument should be either 'client' or 'server'";
		return NULL; /* OK */
	}

	/* ssl-version */
	if ( !strcasecmp( opt, "ssl-version" ) )
	{
		int i;
		for( i = 0; i < MAX_SSL_VERSIONS; i++ )
		{
			if ( !strcasecmp( arg, ssl_methods_strings[i] ) )
			{
				sslcfg->ssl_version = i;
				break;
			}
		}
		if ( i >= MAX_SSL_VERSIONS )
			return "argument should be either 'any', 'TLSv1', 'SSLv3, TLSv1.1 or TLSv1.2' ";
		return NULL; /* OK */
	}

	/* verify-peer */
	if ( !strcasecmp( opt, "verify-peer" ) )
	{
		if ( !strcasecmp( arg, "yes" ) )
			sslcfg->do_authentication = 1;
		else if ( !strcasecmp( arg, "no" ) )
			sslcfg->do_authentication = 0;
		else
			return "argument should be either 'yes' or 'no'";
		return NULL; /* OK */
	}

	// CA-file
	if ( !strcasecmp( opt, "CA-file" ) )
	{
		if ( arg[0] )
			sslcfg->cafile = stralloc( arg );
		return NULL; /* OK */
	}

	// country
	if ( !strcasecmp( opt, "country" ) )
	{
		if ( arg[0] )
			sslcfg->countryName = stralloc( arg );
		return NULL; /* OK */
	}

	// state-province
	if ( !strcasecmp( opt, "state-province" ) )
	{
		if ( arg[0] )
			sslcfg->stateOrProvinceName = stralloc( arg );
		return NULL; /* OK */
	}

	// local
	if ( !strcasecmp( opt, "locality" ) )
	{
		if ( arg[0] )
			sslcfg->localityName = stralloc( arg );
		return NULL; /* OK */
	}

	// organization
	if ( !strcasecmp( opt, "organisation" ) )
	{
		if ( arg[0] )
			sslcfg->organizationName = stralloc( arg );
		return NULL; /* OK */
	}

	// organization-unit
	if ( !strcasecmp( opt, "organisation-unit" ) )
	{
		if ( arg[0] )
			sslcfg->organizationalUnitName = stralloc( arg );
		return NULL; /* OK */
	}

	// common-name
	if ( !strcasecmp( opt, "common-name" ) )
	{
		if ( arg[0] )
			sslcfg->commonName = stralloc( arg );
		return NULL; /* OK */
	}

	// email
	if ( !strcasecmp( opt, "email" ) )
	{
		if ( arg[0] )
			sslcfg->pkcs9_emailAddress = stralloc( arg );
		return NULL; /* OK */
	}

	return NULL; /* OK */
}



//*****************************************************************************
//
//    Get new ssl config for a port by prompting users for input
//

static void get_new_ssl_input( SSL_PORT_CFG *sslcfg )
{
	char  input[256];

	printf( "Please enter the following SSL configuration data. \n" );
	printf( "\n" );

	//**** Certificate File Name *****
	while(1)
	{
		printf( "Certificate file name (full path and file name): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 128 )
			GenErr("String is too long, no more than 128 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			if ( sslcfg->certfile != NULL )
				free( sslcfg->certfile );
			sslcfg->certfile = stralloc( input );
			break;
		}
		else
			break;
	}

	//**** ssl type *****
	while(1)
	{
		printf( "SSL type (client or server): " );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strcasecmp(input, "client") == 0 )
		{
			sslcfg->ssl_type =  0;
			break;
		}
		else if ( strcasecmp( input, "server" ) == 0 )
		{
			sslcfg->ssl_type = 1;
			break;
		}
		else
			GenErr("Error in input", -1);
	}

	//**** ssl version *****
	while(1)
	{
		int i;

		printf( "SSL/TLS version (any, TLSv1, SSLv3, TLSv1.1, TLSv1.2): " );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';

		for( i = 0; i < MAX_SSL_VERSIONS; i++ )
		{
			if ( !strcasecmp( input, ssl_methods_strings[i] ) )
			{
				sslcfg->ssl_version = i;
				break;
			}
		}

		if ( i >= MAX_SSL_VERSIONS )
			GenErr( "Error in input", -1);
		else
			break;
	}

	//**** peer verification *****
	while(1)
	{
		printf( "Perform peer verification (y/n): " );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strcasecmp(input, "n") == 0 )
		{
			sslcfg->do_authentication =  0;
			goto end;
		}
		else if ( strcasecmp( input, "y" ) == 0 )
		{
			sslcfg->do_authentication = 1;
			break;
		}
		else
			GenErr("Error in input", -1);
	}

	//**** CA File Name *****
	while(1)
	{
		printf( "CA file name (full path and file name): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 128 )
			GenErr("String is too long, no more than 128 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			if ( sslcfg->certfile != NULL )
				free( sslcfg->cafile );
			sslcfg->cafile = stralloc( input );
			break;
		}
		else
			break;
	}

	//**** Country Name *****
	while(1)
	{
		int	len;
		printf( "Country (2 letter code): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		len = strlen(input);
		if ( input[len-1] == '\n' )
			input[len-1] = '\0';
		len = strlen(input);
		if ( len > 2 )
			GenErr("string is too long, it needs to be 2 bytes long", -1);
		else if ( len > 0 && len < 2 )
			GenErr("string is too short, it needs to be 2 bytes long", -1);
		else if ( len != 0 )
		{
			sslcfg->countryName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->countryName = NULL;
			break;
		}
	}

	//**** State or Province *****
	while(1)
	{
		printf( "State or Province: " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 128 )
			GenErr("String is too long, no more than 128 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->stateOrProvinceName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->stateOrProvinceName = NULL;
			break;
		}
	}

	//**** Locality *****
	while(1)
	{
		printf( "Locality (e.g. city): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 128 )
			GenErr("String is too long, no more than 128 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->localityName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->localityName = NULL;
			break;
		}
	}

	//**** Organization *****
	while(1)
	{
		printf( "Organisation (e.g. company): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 64 )
			GenErr("String is too long, no more than 64 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->organizationName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->organizationName = NULL;
			break;
		}
	}

	//**** Organizational Unit *****
	while(1)
	{
		printf( "Organisation Unit (e.g. section): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 64 )
			GenErr("String is too long, no more than 64 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->organizationalUnitName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->organizationalUnitName = NULL;
			break;
		}
	}

	//**** Common Name *****
	while(1)
	{
		printf( "Common Name (e.g. your name or your server's hostname): " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 64 )
			GenErr("String is too long, no more than 64 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->commonName = stralloc( input );
			break;
		}
		else
		{
			sslcfg->commonName = NULL;
			break;
		}
	}

	//**** Email Address *****
	while(1)
	{
		printf( "Email Address: " );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strlen( input ) > 128 )
			GenErr("String is too long, no more than 128 bytes long.", -1);
		else if ( strlen( input ) > 0 )
		{
			sslcfg->pkcs9_emailAddress = stralloc( input );
			break;
		}
		else
		{
			sslcfg->pkcs9_emailAddress = NULL;
			break;
		}
	}

end:
	return;
}



//*****************************************************************************
//
//    Write SSL config file
//

static void write_ssl_config( void )
{
	SSL_PORT_CFG   *sslcfg;
	int            nslot;
	FILE           *fp;
	char           *value;

	if ( (fp = fopen( SslCfgFile, "w" )) == (FILE *)NULL )
	{
		perror("tpadm : Can't open ssl config file for write");
		tpexit(FAILURE);
	}
	/* Write out the structure */

	for( nslot=0; nslot < NSLOTS; nslot++ )
	{
		if ( ssl_cfg_items[nslot].type == ITEM_PORT)
		{
			sslcfg = ssl_cfg_items[nslot].sslcfg;
			if (ssl_cfg_items[nslot].host == NULL)
			{
				// just write out [port]
				fprintf( fp, "[%s]\n", ssl_cfg_items[nslot].port );
			}
			else
			{
				// write out [host:port]
				fprintf( fp, "[%s:%s]\n", ssl_cfg_items[nslot].host, ssl_cfg_items[nslot].port );
			}

			if ( sslcfg->certfile )
				fprintf( fp, "certificate-file = %s\n", sslcfg->certfile );

			if ( sslcfg->ssl_type ==  0 )
				value = "client";
			else
				value = "server";
			fprintf( fp, "ssl-type = %s\n", value );

			fprintf( fp, "ssl-version = %s\n", ssl_methods_strings[sslcfg->ssl_version] );

			if ( sslcfg->do_authentication == 0 )
				value =  "no";
			else
				value =  "yes";
			fprintf( fp, "verify-peer = %s\n", value );

			if ( sslcfg->cafile )
				fprintf( fp, "CA-file = %s\n", sslcfg->cafile );

			if ( sslcfg->countryName )
				fprintf( fp, "country = %s\n", sslcfg->countryName );

			if ( sslcfg->stateOrProvinceName )
				fprintf( fp, "state-province = %s\n", sslcfg->stateOrProvinceName );

			if ( sslcfg->localityName )
				fprintf( fp, "locality = %s\n", sslcfg->localityName );

			if ( sslcfg->organizationName )
				fprintf( fp, "organisation = %s\n", sslcfg->organizationName );

			if ( sslcfg->organizationalUnitName )
				fprintf( fp, "organisation-unit = %s\n", sslcfg->organizationalUnitName );

			if ( sslcfg->commonName )
				fprintf( fp, "common-name = %s\n", sslcfg->commonName );

			if ( sslcfg->pkcs9_emailAddress )
				fprintf( fp, "email = %s\n", sslcfg->pkcs9_emailAddress );

		}
		else if (ssl_cfg_items[nslot].type == ITEM_COMMENT)
		{
			fprintf( fp, "%s\n", ssl_cfg_items[nslot].data);
		}
	}
	fclose(fp);
}



//******************************************************************************
//
//    Remove the port data specifed in the action structure from the ssl
//    configuration data.
//

static void remove_ssl_config( void )
{
	int   i;

	read_ssl_config();
	for( i = 0; i < NSLOTS; i++ )
	{
		if ( ssl_cfg_items[i].type == ITEM_PORT )
		{
						if ( action.TCPhost != NULL )
			{
				// remove all entries that match this host
				if ( (action.TCPport == NULL) && (ssl_cfg_items[i].host != NULL) )
				{
					if (!strcmp(action.TCPhost, ssl_cfg_items[i].host))
					{
						ssl_cfg_items[i].type = ITEM_EMPTY;
					}
				}
				else
				{
					// remove exact match
					if ( (ssl_cfg_items[i].host != NULL) && (ssl_cfg_items[i].port != NULL) )
					{
						if ( (!strcmp(action.TCPhost, ssl_cfg_items[i].host)) && (!strcmp(action.TCPport, ssl_cfg_items[i].port)) )
						{
							ssl_cfg_items[i].type = ITEM_EMPTY;
						}
					}
				}
			}
			else
			{
				// remove just port entries
				if ( (ssl_cfg_items[i].host == NULL) && (ssl_cfg_items[i].port != NULL) )
				{
					if (!strcmp(action.TCPport, ssl_cfg_items[i].port) )
					{
						ssl_cfg_items[i].type = ITEM_EMPTY;
					}
				}
			}
		}
	} // end for loop
	write_ssl_config();
}

#endif   //USE_SSL



//*****************************************************************************
//
//	Packet Forwarding Code.
//
//*****************************************************************************


//******************************************************************************
//
//    Read in existing packet forward  config, prompt user for entries for
//    new port config and write out the resulting configuration.
//

void pkt_fwd_configure( void )
{
    int     i, j;
    int     first_slot = 0;
	int   copy_slot = 0;
    int     portrange;
	char    szTCPport[6];

	if ( read_pkt_fwd_config() < 0 )
	{
		tpexit( FAILURE );
	}
    i = 0;
    while( pkt_fwd_cfg_items[i].type != ITEM_EMPTY && i < NSLOTS )
        i++;
    if( i >= NSLOTS ) 
	{
        GenErr("pkt_fwd_configure: Too many entries >",NSLOTS);
        tpexit(FAILURE);
    }
    else
		{
        first_slot = i;
    }
    if( action.portrange ) 
        portrange = atoi(action.portrange);
    else
        portrange = 1;
    if( (first_slot + portrange) >= NSLOTS )  
	{
        GenErr("pkt_fwd_configure: Range creates too many entries >",NSLOTS);
        tpexit(FAILURE);
    }
    for( i = first_slot; i < first_slot + portrange; i++ ) 
	{
			if ( (pkt_fwd_cfg_items[i].pfcfg = calloc( sizeof(PKT_FWD_PORT_CFG), 1 )) == NULL )
			{
				GenErr( "pkt_fwd_configure - malloc error", -1 );
				tpexit(FAILURE);
			}
			pkt_fwd_cfg_items[i].type = ITEM_PORT;
			if (action.TCPhost)
			{
				pkt_fwd_cfg_items[i].host = stralloc(action.TCPhost);
			}
		sprintf( szTCPport, "%ld", action.first_TCPport + i - first_slot );
		pkt_fwd_cfg_items[i].port = stralloc(szTCPport);
		
		if ( (action.TCPcopy_host == NULL) && (action.TCPcopy_port == NULL) && 
				(i == first_slot) ) 
	{
            get_new_pkt_fwd_input( pkt_fwd_cfg_items[i].pfcfg );
	}
        else 
	{
			for( j = 0; j < NSLOTS; j++ )
		{
			if ( (action.TCPcopy_host != NULL) && (action.TCPcopy_port != NULL) &&
								(pkt_fwd_cfg_items[j].host != NULL) )
			{
					 if ( (pkt_fwd_cfg_items[j].type == ITEM_PORT) && 
								!strcmp(action.TCPcopy_host, pkt_fwd_cfg_items[j].host) && 
								!strcmp(action.TCPcopy_port, pkt_fwd_cfg_items[j].port) ) 
				 {
						copy_slot = j;
			        break;
		       }
			}
			if ( action.TCPcopy_host == NULL && action.TCPcopy_port != NULL )
			{
					 if ( pkt_fwd_cfg_items[j].type == ITEM_PORT && 
								!strcmp(action.TCPcopy_port, pkt_fwd_cfg_items[j].port) ) 
				 {
						copy_slot = j;
			        break;
		       }
			}
		}
      if ( i >= NSLOTS )
	   {
			 GenErr("Packet Forwarding copy port not found", -1);
		    tpexit(FAILURE);
	   }
		   	memcpy( pkt_fwd_cfg_items[i].pfcfg, pkt_fwd_cfg_items[copy_slot].pfcfg, sizeof(PKT_FWD_PORT_CFG) );
	}
	}
	write_pkt_fwd_config();
}



//******************************************************************************

int read_pkt_fwd_config( void )
{
	FILE  *fp;
	char  confline[CONFLINELEN];
	char  *arg, *opt, *errstr;
	int   slot, section_slot;
	int   i, line_number;
	char  *tmphost, *tmpport;

	if ( (fp = fopen( PktFwdCfgFile,"r" )) == (FILE *)NULL )
	{
		perror( "tpadm : Can't open packet forward config file" );
		tpexit( FAILURE );
	}
	section_slot = slot = 0;
	line_number = 0;
	while( fgets( confline, CONFLINELEN, fp ) && slot < NSLOTS )
	{
		line_number++;
		opt=confline;
		while( isspace( *opt ) )
			opt++; /* remove initial whitespaces */
		for( i = strlen( opt )-1; i >= 0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		if ( opt[0]=='\0' || opt[0]=='#' || opt[0]==';' ) /* empty or comment */
		{
			pkt_fwd_cfg_items[slot].data = stralloc( confline );
			pkt_fwd_cfg_items[slot].type = ITEM_COMMENT;
			slot++;
			continue;
		}

		// Detect a new section, allocate memory for the packet forward config structure and
		//    initialize the item slot.
		if ( opt[0]=='[' && opt[strlen( opt )-1]==']' )
		{
			opt++;
			opt[strlen( opt )-1]='\0';
			section_slot = slot;
			slot++;
			if (GetTCPHostPort(opt, &tmphost, &tmpport) < 0)
			{
				perror( "tpadm: Bad [host:port_number] in packet forward config file\n" );
				tpexit(1);
			}
			if (tmphost)
				 pkt_fwd_cfg_items[section_slot].host = stralloc(tmphost);   // store host and port entry
			if (tmpport)
			pkt_fwd_cfg_items[section_slot].port = stralloc(tmpport);

			/* get some store for this line */
			pkt_fwd_cfg_items[section_slot].pfcfg = calloc( sizeof(PKT_FWD_PORT_CFG), 1 );
			if ( pkt_fwd_cfg_items[section_slot].pfcfg == NULL)
			{
				GenErr( "malloc error: pfcfg\n", -1 );
				tpexit(1);
			}
			pkt_fwd_cfg_items[section_slot].type = ITEM_PORT;
			continue;
		}
		if ( pkt_fwd_cfg_items[section_slot].type != ITEM_PORT )
		{
			GenErr( "Packet forward config file - line %d: Reading data with no port number", line_number );
			tpexit( 1 );
		}
		arg=strchr( confline, '=' );
		if ( !arg )
		{
			GenErr( "Packet forward config file - line %d: No '=' found", line_number );
			tpexit( 1 );
		}
		*arg++='\0'; /* split into option name and argument value */

		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */

		while( isspace( *arg ) )
			arg++; /* remove initial whitespaces */

		errstr=pkt_fwd_service_options( section_slot, opt, arg );
		if ( errstr != NULL )
		{
			GenErr( errstr, -1 );
			fclose( fp );
			return(-1);
		}

	} //while

	fclose( fp );
	return(0);
}



//******************************************************************************
//

char *pkt_fwd_service_options( int slot, char *opt, char *arg )
{
	PKT_FWD_PORT_CFG	*pfcfg = pkt_fwd_cfg_items[slot].pfcfg;

	//***** Packet Definition ************
	// packet size
	if ( !strcasecmp(opt, "packet_size") )
	{
		if ( read_and_verify_input( arg, 1, 1024, CFG_DECIMAL, &pfcfg->packet_size ) < 0 )
		{
			return "argument should be decimal number 1 - 1024 ";
		}
		else if ( pfcfg->packet_size != 0 )
		{
			pfcfg->forwarding |= PKT_FORWARD_ON_COUNT;
		}
		return NULL; /* OK */
	}

	// idle time
	if ( !strcasecmp(opt, "idle_time") )
	{
		if ( read_and_verify_input( arg, 0, 65535, CFG_DECIMAL, &pfcfg->idle_time ) < 0 )
		{
			return "argument should be decimal number 0 - 65535 ";
		}
		else if ( pfcfg->idle_time != 0 )
		{
			pfcfg->forwarding |= PKT_FORWARD_ON_IDLE;
		}
		return NULL; /* OK */
	}

	// force time
	if ( !strcasecmp(opt, "force_transmit_time") )
	{
		if ( read_and_verify_input( arg, 0, 65535, CFG_DECIMAL, &pfcfg->force_time ) < 0 )
		{
			return "argument should be decimal number 0 - 65535 ";
		}
		else if ( pfcfg->force_time != 0 )
		{
			pfcfg->forwarding |= PKT_FORWARD_ON_TIME;
		}
		return NULL; /* OK */
	}

	// end_trigger1_char
	if ( !strcasecmp(opt, "end_trigger1_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->trigger_char1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_ON_CHAR1;
		return NULL; /* OK */
	}

	// end_trigger2_char
	if ( !strcasecmp(opt, "end_trigger2_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->trigger_char2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_ON_CHAR2;
		return NULL; /* OK */
	}

	//***** Frame Definition ************
	// SOF1
	if ( !strcasecmp(opt, "SOF1_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->start_frame1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_START_CHAR1;
		return NULL; /* OK */
	}

	// SOF2
	if ( !strcasecmp(opt, "SOF2_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->start_frame2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_START_CHAR2;
		return NULL; /* OK */
	}

	// transmit_SOF_chars
	if ( !strcasecmp(opt, "transmit_SOF_chars") )
	{
		if (!strcasecmp(arg, "on"))
			pfcfg->start_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
		else if (!strcasecmp(arg, "off"))
			pfcfg->start_transmit_rule = PKT_FORWARD_TRANS_STRIP;
		else
			return "argument should be either 'off' or 'on'";
		return NULL; /* OK */
	}

	// EOF1
	if ( !strcasecmp(opt, "EOF1_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->end_frame1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_END_CHAR1;
		return NULL; /* OK */
	}

	// EOF2
	if ( !strcasecmp(opt, "EOF2_char") )
	{
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pfcfg->end_frame2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pfcfg->forwarding |= PKT_FORWARD_END_CHAR2;
		return NULL; /* OK */
	}


	// end_transmit_rule
	if ( !strcasecmp(opt, "trigger_forwarding_rule") )
	{
		if (!strcasecmp(arg, "trigger"))
			pfcfg->end_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
		else if (!strcasecmp(arg, "trigger+1"))
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_1;
		else if (!strcasecmp(arg, "trigger+2"))
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_2;
		else if (!strcasecmp(arg, "strip-trigger"))
		{
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_STRIP;
		}
		else
			return "argument should be either 'trigger', 'trigger+1', 'trigger+2' or 'strip-trigger'";

		return NULL; /* OK */
	}

	return NULL; /* OK */
}



//*****************************************************************************
//
//    Get new packet forwarding config for a port by prompting users for input
//

void get_new_pkt_fwd_input( PKT_FWD_PORT_CFG *pfcfg )
{
	char  			input[256];
	unsigned long	retValue;
	int				rc;

	printf( "\n" );
	printf( "Please enter the following Packet Forwarding configuration data. \n" );
	printf( "  The value in square brackets [ ] is the default value used if \n" );
	printf( "  the 'Enter' key is pressed without any other characters.\n" );
	printf( "\n" );

	//**** Packet definition *****
	if ( get_yes_no( "Enable Packet Definition (y/n): " ) == 0 )
	{
		goto frame_definition;	// Skip rest of Packet definition if not enabled.
	}

	//**** Packet Size *****
	rc = get_and_verify_input( "Packet Size [0] ( 1 - 1024): ", 1,
	                           1024, CFG_DECIMAL, &retValue );
	if ( rc > 0 )
	{
		pfcfg->packet_size = (unsigned short )retValue;
		if ( pfcfg->packet_size > 0 )
			pfcfg->forwarding |= PKT_FORWARD_ON_COUNT;
	}

	//**** Idle Time *****
	rc = get_and_verify_input( "Idle Time ([0] - 65535): ", 0, 65535, CFG_DECIMAL, &retValue );
	if ( rc > 0 )
	{
		pfcfg->idle_time = (unsigned short )retValue;
		if ( pfcfg->idle_time > 0 )
			pfcfg->forwarding |= PKT_FORWARD_ON_IDLE;
	}

	//**** Force Time *****
	rc = get_and_verify_input( "Force Transmit Time ([0] - 65535): ", 0,	65535, CFG_DECIMAL, &retValue );
	if ( rc > 0 )
	{
		pfcfg->force_time = (unsigned short )retValue;
		if ( pfcfg->force_time > 0 )
			pfcfg->forwarding |= PKT_FORWARD_ON_TIME;
	}

	//**** End Trigger1 *****
	if ( get_yes_no( "Enable End Trigger1 (y/n): " ) == 1 )
	{
		pfcfg->forwarding |= PKT_FORWARD_ON_CHAR1;
		get_and_verify_input( "End Trigger1 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
		pfcfg->trigger_char1 = (unsigned char )retValue;
	}
	else
		goto pkt_fwd_input_exit;	// if not defining any Trigger then we are done.

	//**** End Trigger 2 *****
	if ( get_yes_no( "Enable End Trigger2 (y/n): " ) == 1 )
	{
		pfcfg->forwarding |= PKT_FORWARD_ON_CHAR2;
		get_and_verify_input( "End Trigger2 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
		pfcfg->trigger_char2 = (unsigned char )retValue;
	}
	goto forwarding_rule;	// go define Trigger rule.


	//**** Frame Definition *****
frame_definition:

	//**** Define SOF1 *****
	if ( get_yes_no( "Enable Frame Definition (y/n): " ) == 0 )
	{
		goto pkt_fwd_input_exit;	// if not enabling frame definition we are done.
	}
	else
	{
		pfcfg->forwarding |= PKT_FORWARD_START_CHAR1;
		get_and_verify_input( "SOF1 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
		pfcfg->start_frame1 = (unsigned char )retValue;
	}

	//**** Define SOF2 *****
	if ( get_yes_no( "Enable SOF2 (y/n): " ) == 1 )
	{
		pfcfg->forwarding |= PKT_FORWARD_START_CHAR2;
		get_and_verify_input( "SOF2 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
		pfcfg->start_frame2 = (unsigned char )retValue;
	}

	//**** Transmit SOF Characters ? *****
	while(1)
	{
		printf( "Transmit SOF Character(s) ([on]/off): " );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';

		if ( strlen( input ) == 0 || strcasecmp(input, "on") == 0 )
		{
			pfcfg->start_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
			break;
		}
		else if ( strcasecmp( input, "off" ) == 0 )
		{
			pfcfg->start_transmit_rule = PKT_FORWARD_TRANS_STRIP;
			break;
		}
		else
			GenErr("Error in input", -1);
	}

	//**** Define EOF1 ***** Always do this if Frame forwarding is enabled.
	pfcfg->forwarding |= PKT_FORWARD_END_CHAR1;
	get_and_verify_input( "EOF1 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
	pfcfg->end_frame1 = (unsigned char )retValue;

	//**** Define EOF2 *****
	if ( get_yes_no( "Enable EOF2 (y/n): " ) == 1 )
	{
		pfcfg->forwarding |= PKT_FORWARD_END_CHAR2;
		get_and_verify_input( "EOF2 Character ([0] - ff): ", 0, 0xff, CFG_HEXIDECIMAL, &retValue );
		pfcfg->end_frame2 = (unsigned char )retValue;
	}

	//**** Forwarding Rule *****
forwarding_rule:
	while(1)
	{
		printf( "Enter the Forwarding Rule ([trigger], trigger+1, trigger+2, strip-trigger): " );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';

		if ( strlen( input ) == 0 || strcasecmp(input, "trigger") == 0 )
		{
			pfcfg->end_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
			break;
		}
		else if ( strcasecmp( input, "trigger+1" ) == 0 )
		{
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_1;
			break;
		}
		else if ( strcasecmp( input, "trigger+2" ) == 0 )
		{
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_2;
			break;
		}
		else if ( strcasecmp( input, "strip-trigger" ) == 0 )
		{
			pfcfg->end_transmit_rule = PKT_FORWARD_TRANS_STRIP;
			break;
		}
		else
			GenErr("Error in input", -1);
	}

pkt_fwd_input_exit:
	return;
}



//*****************************************************************************
//
//	Read in a line from stdin. Verifiy that the DECIMAL or HEXIDECIMAL value is
//	less than the specified limit.
//
//	Return	1 - Value is within limits
//			0 - No input was given.
//			-1 - Error in input in either format or range of values.
//

int get_and_verify_input(	char *prompt,
                          long	lower_limit,
                          long upper_limit,
                          int format,
                          unsigned long *retValue )
{
	char  			input[256];
	int				intValue;
	unsigned int	uintValue;
	int				result;
	int				i;

	while (1)
	{
		printf( "%s", prompt );
		if ( fgets( input, 256, stdin ) == NULL )
		{
			GenErr( "Error reading input", -1 );
		}
		if ( input[strlen(input)-1] == '\n' )
		   input[strlen(input)-1] = '\0';
		*retValue = 0;

		if ( strlen(input) == 0 )
			return 0;

		errno = 0;
		result = 0;
		if ( format == CFG_DECIMAL )
		{
			for( i=0; i < strlen( input ); i++ )
			{
				if ( !isdigit(input[i]) )
				{
					result = -1;
					break;
				}
			}
			if ( result == 0 )
			{
				result = sscanf( &input[0], "%d", &intValue);
				*retValue = (unsigned long)intValue;
			}
		}
		else
		{
			for( i=0; i < strlen( input ); i++ )
			{
				if ( !isxdigit(input[i]) )
				{
					result = -1;
					break;
				}
			}

			if ( result == 0 )
			{
				result = sscanf( &input[0], "%x", &uintValue);
				*retValue = (unsigned long)uintValue;
			}
		}

		if ( result > 0  && errno == 0)
		{
			if ( *retValue >= lower_limit && *retValue <= upper_limit )
				return 1;
		}
		printf( "Error in input, please re-enter!\n" );
	}
}


//*****************************************************************************
//
//	get_yes_no()
//
//	Waits for a yes or now answer to the specified prompt.
//


int get_yes_no( char *prompt )
{
	char  	input[256];

	while(1)
	{
		printf( "%s", prompt );
		if ( fgets( input, 256, stdin  ) == NULL )
		{
			GenErr( "Error reading input", -1 );
			continue;
		}
		if ( input[strlen(input)-1] == '\n' )
			input[strlen(input)-1] = '\0';
		if ( strcasecmp(input, "n") == 0 )
		{
			return 0;
		}
		else if ( strcasecmp( input, "y" ) == 0 )
		{
			return 1;
		}
		else
			GenErr("Error in input", -1);
	}
}


//*****************************************************************************
//
//    Write Packet Forwarding config file
//
static void write_pkt_fwd_config( void )
{
	PKT_FWD_PORT_CFG	*pfcfg;
	int					nslot;
	FILE 				*fp;
	char				*value, *fwd_rule;

	if ( (fp = fopen( PktFwdCfgFile, "w" )) == (FILE *)NULL )
	{
		perror("tpadm : Can't open packet forwarding config file for write");
		tpexit(FAILURE);
	}

	/* Write out the structure */
	for( nslot=0; nslot < NSLOTS; nslot++ )
   {
		if ( pkt_fwd_cfg_items[nslot].type == ITEM_PORT)
		{
			pfcfg = pkt_fwd_cfg_items[nslot].pfcfg;

			if (pkt_fwd_cfg_items[nslot].host == NULL)
			{
				// just write out [port]
				fprintf( fp, "[%s]\n", pkt_fwd_cfg_items[nslot].port );
			}
			else
			{
				// write out [host:port]
				fprintf( fp, "[%s:%s]\n", pkt_fwd_cfg_items[nslot].host, pkt_fwd_cfg_items[nslot].port );
			}
			
			// determine trigger forwarding rule to be written to config file later
			switch( pfcfg->end_transmit_rule )
			{
				case PKT_FORWARD_TRANS_TRIG:
					fwd_rule =  "trigger";
					break;
					case PKT_FORWARD_TRANS_TRIG_1:
					fwd_rule =  "trigger+1";
					break;
				case PKT_FORWARD_TRANS_TRIG_2:
					fwd_rule =  "trigger+2";
					break;
				case PKT_FORWARD_TRANS_STRIP:
					fwd_rule =  "strip-trigger";
					break;
			}

			// Packet Definition fields are filled out ?
			if ( pfcfg->packet_size || pfcfg->idle_time || pfcfg->force_time ||
						pfcfg->forwarding & PKT_FORWARD_ON_CHAR1 )
			{
				// write out Packet Definition fields
				fprintf( fp, "packet_size = %d\n", pfcfg->packet_size );
				fprintf( fp, "idle_time = %d\n", pfcfg->idle_time );
				fprintf( fp, "force_transmit_time = %d\n", pfcfg->force_time );
				if ( pfcfg->forwarding & PKT_FORWARD_ON_CHAR1 )
				{
					fprintf( fp, "end_trigger1_char = %0x\n", pfcfg->trigger_char1 );
					if ( pfcfg->forwarding & PKT_FORWARD_ON_CHAR2 )
					{
						fprintf( fp, "end_trigger2_char = %0x\n", pfcfg->trigger_char2 );
					}
					fprintf( fp, "trigger_forwarding_rule = %s\n", fwd_rule );
				}
			}
			else
			{
				// write out Frame Definiton fields
				if ( pfcfg->forwarding & PKT_FORWARD_START_CHAR1 )
				{
					fprintf( fp, "SOF1_char = %0x\n", pfcfg->start_frame1 );
					if ( pfcfg->forwarding & PKT_FORWARD_START_CHAR2 )
					{
						fprintf( fp, "SOF2_char = %0x\n", pfcfg->start_frame2 );
					}
					if ( pfcfg->start_transmit_rule == PKT_FORWARD_TRANS_TRIG )
					{
						value =  "on";
					}
					else
					{
						value =  "off";
					}
					fprintf( fp, "transmit_SOF_chars = %s\n", value );
					if ( pfcfg->forwarding & PKT_FORWARD_END_CHAR1 )
					{
						fprintf( fp, "EOF1_char = %0x\n", pfcfg->end_frame1 );
	
						if ( pfcfg->forwarding & PKT_FORWARD_END_CHAR2 )
						{
							fprintf( fp, "EOF2_char = %0x\n", pfcfg->end_frame2 );
						}
					}
				}
				fprintf( fp, "trigger_forwarding_rule = %s\n", fwd_rule );
			}
		}  // end if type == ITEM_PORT
		
		else if (pkt_fwd_cfg_items[nslot].type == ITEM_COMMENT)
		{
			fprintf( fp, "%s\n", pkt_fwd_cfg_items[nslot].data);
		}
	}
	fclose(fp);
}



//******************************************************************************
//
//    Remove the port data specifed in the action structure from the packet
//    forward configuration data.
//

static void remove_pkt_fwd_config( void )
{
	int   i;

	read_pkt_fwd_config();
	for( i = 0; i < NSLOTS; i++ )
	{
		if ( pkt_fwd_cfg_items[i].type == ITEM_PORT )
		{
			if ( action.TCPhost != NULL )
			{
				// remove all entries that match this host
				if ( (action.TCPport == NULL) && (pkt_fwd_cfg_items[i].host != NULL) )
				{
					if (!strcmp(action.TCPhost, pkt_fwd_cfg_items[i].host))
					{
						pkt_fwd_cfg_items[i].type = ITEM_EMPTY;
					}
				}
				else
				{
					// remove exact match
					if ( (pkt_fwd_cfg_items[i].host != NULL) && (pkt_fwd_cfg_items[i].port != NULL) )
					{
						if ( (!strcmp(action.TCPhost, pkt_fwd_cfg_items[i].host)) && (!strcmp(action.TCPport, pkt_fwd_cfg_items[i].port)) )
						{
							pkt_fwd_cfg_items[i].type = ITEM_EMPTY;
						}
					}
				}
			}
			else
			{
				// remove just port entries
				if ( (pkt_fwd_cfg_items[i].host == NULL) && (pkt_fwd_cfg_items[i].port != NULL) )
				{
					if (!strcmp(action.TCPport, pkt_fwd_cfg_items[i].port) )
					{
						pkt_fwd_cfg_items[i].type = ITEM_EMPTY;
					}
				}
			}
		}
	} // end for loop
	write_pkt_fwd_config();
}



//*****************************************************************************
//
//	Read in a line from stdin. Verifiy that the DECIMAL or HEXIDECIMAL value is
//	less than the specified limit.
//
//  Return 1 - Value is within limits
//         0 - No input was given.
//        -1 - Error in input in either format or range of values.
//

int read_and_verify_input(	char *input,
                           long lower_limit,
                           long upper_limit,
                           int format,
                           void *retValue )
{
	int				intValue;
	unsigned int	uintValue;
	int				i;

	errno = 0;
	if ( format == CFG_DECIMAL )
	{
		for( i=0; i < strlen( input ); i++ )
		{
			if ( !isdigit(input[i]) )
			{
				return -1;
			}
		}

		if ( sscanf( input, "%d", &intValue) == 0 || errno != 0 )
			return -1;
		if ( (intValue < lower_limit || intValue > upper_limit) && intValue != 0 )
			return -1;
		*(unsigned short *)retValue = (unsigned short)intValue;
		return 1;
	}

	else
	{
		for( i=0; i < strlen( input ); i++ )
		{
			if ( !isxdigit(input[i]) )
			{
				return -1;
			}
		}

		if ( sscanf( input, "%x", &uintValue) == 0 || errno != 0 )
			return -1;
		// Allow value of 0 to pass.
		if ( (uintValue < lower_limit || uintValue > upper_limit) && uintValue != 0 )
			return -1;
		*(unsigned char *)retValue = (unsigned char)uintValue;
		return 1;
	}
}


//*****************************************************************************
// Returns < 0 if error
static int GetTCPHostPort(char *host_port, char **TCPhost, char **TCPport)
{
	int port;
	char *phost = NULL;
	char *pport = NULL;

	if (host_port == NULL)
	{
		 return(-1);
	}
	// search for "[" to see if we have a literal IPv6 address
	phost = strchr(host_port, '[');
	// we have a literal IPv6 address
	if (phost != NULL)
	{
		 phost = phost + 1;					// increment pass "["
		// now search for ending "]"
		pport = strchr(phost, ']');
		if ( pport == NULL)
		{
 			fprintf(stderr,"tpadm : Missing ending bracket ] in IPv6 address\n");
			return(-1);		// error, missing ending bracket
		}
		else
		{
			phost = phost - 1;	// include bracket for IPv6 address
			// check if a port string exist
			if (strlen(pport) == 0)
			{
				pport = NULL;			// for IPv6 address we don't require :
	 			goto  done_parse;		// done parsing, now check port if required
			}
				
			pport = pport + 1;		// increment pass "]"
			// 
			if (*pport != ':')
			{
				 return(-1);		// error, missing ending ":"
			}
			*pport = 0;				// null out ":"
			pport = pport + 1;				// increment pass ":"
			// check if a port string exist
			if (strlen(pport) == 0)
			{
				 pport = NULL;
			}
			goto  done_parse;		// done parsing, now check port if required
		}
	}
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
			GenErr("Specified host can not be blank\n", -1);
			return(-1);
		}
		if (strlen(phost) > MAX_HOST_NAMELEN)
		{
			GenErr("Host name too long, must be less than",MAX_HOST_NAMELEN);
			return(-1);
		}
	}
	// must be just the port, no host specified
	else
	{
		pport = host_port;
	}
	
done_parse:
	//  if we have a port and it's not the string ALL then check it
	if ( (pport != NULL) && strcasecmp(pport, ALLSTART) )
	{
		port = atoi(pport);
		if ( (port < 0) || (port < WELLKNOWN) )
		{
			fprintf(stderr,"tpadm : Specify TCP# in range: %d < TCP# > 65535\n", WELLKNOWN);
			return(-1);
		}
	}
	*TCPhost = phost;
	*TCPport = pport;
	return(0);
}

