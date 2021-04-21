//*****************************************************************************
//
//	Description : This file contains SSL initialization, configuration, and
//					utility functions for the line and user services which
//					support	SSL.
//
//*****************************************************************************

#ifdef	USE_SSL

/****************************************************************************
 *      Include files and external linkages                                 *
 ****************************************************************************/

#include	<string.h>
#include	<ctype.h>
#include <inttypes.h>
#include	<termio.h>
#include	<openssl/ssl.h>
#include	<openssl/err.h>

#include	"tp.h"
#include 	"pkt_forwarding.h"
#include 	"trueport.h"
#include	"ssl_tp.h"

int get_tcp_hostport(char *host_port, char **TCPhost, char **TCPport);


// Table used to convert the configured ssl version and type to an SSL Method.

#if ! defined (OPENSSL_VERSION_NUMBER)
#error "openssl version is not set"
#endif

#if (OPENSSL_VERSION_NUMBER < 0x100000f)
SSL_METHOD * (*ssl_methods[5][2]) (void) =
#else
const SSL_METHOD * (*ssl_methods[5][2]) (void) =
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
{
	{ SSLv23_client_method,	SSLv23_server_method	},	// 	SSL any version
	{ TLSv1_client_method, 	TLSv1_server_method		},	//	TLS V1
	{ SSLv3_client_method, 	SSLv3_server_method		},	//	SSL V3
	{ TLSv1_1_client_method, 	TLSv1_1_server_method		},	//	TLS V1.1
	{ TLSv1_2_client_method, 	TLSv1_2_server_method		},	//	TLS V1.2
};
#else
{
	{ TLS_client_method,	TLS_server_method		},	// 	SSL any version
	{ TLS_client_method, 	TLS_server_method		},	//	TLS V1
	{ TLS_client_method, 	TLS_server_method		},	//	SSL V3
	{ TLS_client_method, 	TLS_server_method		},	//	TLS V1.1
	{ TLS_client_method, 	TLS_server_method		},	//	TLS V1.2
};
#endif
// Strings for version. Used for debug (trace) purposes.
char	*ssl_methods_strings[] =
{
	"any",
	"TLSv1",
	"SSLv3",
	"TLSv1.1",
	"TLSv1.2"
};

// this should match the strings above
typedef enum {
	SSL_METHOD_ANY,
	SSL_METHOD_TLSV1,
	SSL_METHOD_SSLV3,
	SSL_METHOD_TLSV1_1,
	SSL_METHOD_TLSV1_2
} SSL_METHODS;

static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};



static int parse_ssl_config(char *file_name, char *tcp_host, int net_port);
static char *stralloc(char *);
static DH *get_dh512(void);
static DH *load_dh_param(char *dhfile);

extern	SSL_CFG 	sslcfg;
extern	BIO 		*bio_err;		//used for debug for SSL



//******************************************************************************
//
//	Fill in the specified configuration structure with hard coded values
//		and call the parse_config() routine to read the configuration file
//		and fill in the remaining values.

int	get_ssl_config( char *tcp_host, int net_port_num )
{
	FILE		*fd;
	int 		fileHasPassPhrase = FALSE;
	char 		keydata[257];

	// Clear configuration structure and reset enabled to TRUE as we wouldn't be
	//	here if SSL was not configured.
	memset( (void *)&sslcfg, 0, sizeof(SSL_CFG) );
	sslcfg.enabled = TRUE;

	// Parse config file
	if ( parse_ssl_config( DEFAULT_SSL_CFG_FILE, tcp_host, net_port_num ) < 0 )
	{
	   trace( tl_error, "Parsing of SSL config file failed\n" );
	   return(-1);
	}
	sslcfg.ssl_method = (*ssl_methods[ sslcfg.ssl_version ][ sslcfg.ssl_type ])();
	trace( tl_info, "SSL version = %s\n", ssl_methods_strings[sslcfg.ssl_version] );

	// There is no user configuration for ciphers; we hard-code the list 
	sslcfg.cipher = SSL_CIPHER_LIST;

	//	Check to see if the private key is encrypted. This is not supported.
	//	Note: the private key must be included in the certificate file. Seperate
	//			key files are not supported
	fd = fopen( sslcfg.certfile, "r" );
	if ( fd != NULL ) 
	{
		while( fgets( keydata, sizeof(keydata), fd ) != NULL ) 
		{
			keydata[strlen(keydata)-1] = 0;
			if ( strstr( keydata, "ENCRYPTED" ) )
			{
				fileHasPassPhrase = TRUE;
				break;
			}
		}
		fclose( fd );
	}
	else
		sslcfg.certfile = NULL;

	if ( fileHasPassPhrase ) 
	{
		trace( tl_error, "Encrypted private keys are not supported in TruePort\n" );
		return( -1 );
	}
	return 0;
}


//******************************************************************************
//
//	This is a common routine for any task to call to initialize the SSL
//	environment useing the specified SSL configuration.
//

int ssl_init( SSL_CTX **p_ssl_ctx, pem_password_cb *passwd_cb,
				RSA *(*tmp_rsa_cb)(SSL *ssl,int is_export, int keylength) )
{
	SSL_CTX	*ctx;
	DH 		*dh = NULL;

	SSL_library_init();
	SSL_load_error_strings();

	if( *p_ssl_ctx != NULL )
		SSL_CTX_free( *p_ssl_ctx );
	
	*p_ssl_ctx = SSL_CTX_new( sslcfg.ssl_method );
	ctx = *p_ssl_ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    switch (sslcfg.ssl_version)
    {
        case SSL_METHOD_ANY:
            break;
        case SSL_METHOD_TLSV1:
            SSL_CTX_set_min_proto_version(ctx,  TLS1_VERSION);
            SSL_CTX_set_max_proto_version(ctx,  TLS1_VERSION);
            break;
        case SSL_METHOD_SSLV3:
            SSL_CTX_set_min_proto_version(ctx,  SSL3_VERSION);
            SSL_CTX_set_max_proto_version(ctx,  SSL3_VERSION);
            break;
        case SSL_METHOD_TLSV1_1:
            SSL_CTX_set_min_proto_version(ctx,  TLS1_1_VERSION);
            SSL_CTX_set_max_proto_version(ctx,  TLS1_1_VERSION);
            break;
        case SSL_METHOD_TLSV1_2:
            SSL_CTX_set_min_proto_version(ctx,  TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ctx,  TLS1_2_VERSION);
            break;
    }
#endif

	SSL_CTX_set_default_passwd_cb( ctx, passwd_cb );

	if ( !set_cert_stuff( ctx, sslcfg.certfile, NULL ) ) 
	{
		return -1;
	}

	if ( sslcfg.cipher )
	{
		if ( SSL_CTX_set_cipher_list( ctx, sslcfg.cipher ) == 0 ) 
		{
			trace( tl_status, "Error setting cipher list\n" );
			return -1;
		}
	}
  
  	if (sslcfg.certfile)
		dh = load_dh_param(sslcfg.certfile);

	if (dh != NULL) 
	{
		trace( tl_info, "Setting temp DH parameters\n");
	}
	else {
		trace( tl_info,"Using default temp DH parameters\n");
		dh=get_dh512();
	}

	SSL_CTX_set_tmp_dh(ctx,dh);
	DH_free(dh);


	// used for EXPORT type ciphers
	SSL_CTX_set_tmp_rsa_callback( ctx, tmp_rsa_cb );

	// If authentication is enabled, then load CA List file locations.
	//	We will require host to have one file with Certificate Authority (CA)
	//  certificates in pem format.
	//	Set verify option to require a certificate be required and verified.
	//	Set client CA list for server to send to client.
	if ( sslcfg.do_authentication ) 
	{
		if ( !SSL_CTX_load_verify_locations( ctx, sslcfg.cafile, NULL ) ) 
		{
			trace( tl_error, "Could not load Certificate Authority (CA) list file.\n" );
			return -1;
		}
		SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL );
		if( sslcfg.cafile != NULL && sslcfg.ssl_type == SSL_SERVER )
			SSL_CTX_set_client_CA_list( ctx, SSL_load_client_CA_file( sslcfg.cafile ) );
	}
	else {
		SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, NULL );
	}
	return(0);

}



//******************************************************************************

int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file)
{
	if ( cert_file != NULL ) 
	{

		if ( SSL_CTX_use_certificate_file( ctx, cert_file, SSL_FILETYPE_PEM ) <= 0 ) 
		{
			trace( tl_error,"Error with Certificate file.\n" );
			trace( tl_error, " - %s\n", ERR_reason_error_string( ERR_get_error() ) );
			return( 0 );
		}

		if( key_file == NULL )
			key_file = cert_file;
		if ( SSL_CTX_use_PrivateKey_file( ctx, key_file, SSL_FILETYPE_PEM ) <= 0 ) 
		{
			trace( tl_error,"Error with Key file.\n" );
			trace( tl_error, " - %s\n", ERR_reason_error_string( ERR_get_error() ) );
			return( 0 );
		}

		/* Now we know that a key and cert have been set against
		 * the SSL context */
		if ( !SSL_CTX_check_private_key( ctx ) ) 
		{
			trace( tl_error,"Key does not verify with certificate\n" );
			trace( tl_error, " - %s\n", ERR_reason_error_string( ERR_get_error() ) );
			return( 0 );
		}
	}
	return( 1 );
}


//******************************************************************************

int	check_cert( SSL *ssl )
{
	X509		*peerCert;
	X509_NAME	*xn;
	char 		buf[256];
	CertName	*cn;
	int			i;
	CertName 	certNames[7];

	if ( SSL_get_verify_result( ssl )!=X509_V_OK ) 
	{
		trace( tl_status, "Certificate was not valid\n");
		return 0;
	}

	/*Check the certificate data*/

	if ( (peerCert = SSL_get_peer_certificate( ssl )) == NULL ) 
	{ 
		trace( tl_status, "Could not obtain peer's certificate.\n\n");
		return(0);
	}
	xn = X509_get_subject_name( peerCert );

	certNames[0].name = sslcfg.countryName;
	certNames[0].nid  = NID_countryName;
	certNames[1].name = sslcfg.stateOrProvinceName;
	certNames[1].nid  = NID_stateOrProvinceName;
	certNames[2].name = sslcfg.localityName;
	certNames[2].nid  = NID_localityName;
	certNames[3].name = sslcfg.organizationName;
	certNames[3].nid  = NID_organizationName;
	certNames[4].name = sslcfg.organizationalUnitName;
	certNames[4].nid  = NID_organizationalUnitName;
	certNames[5].name = sslcfg.commonName;
	certNames[5].nid  = NID_commonName;
	certNames[6].name = sslcfg.pkcs9_emailAddress;
	certNames[6].nid  = NID_pkcs9_emailAddress;

	for( i = 0; i < 7; i++ ) 
	{
		cn = &certNames[i];
		if( cn->name != NULL  &&
			(( X509_NAME_get_text_by_NID( xn, cn->nid, buf, sizeof(buf)) == -1) ||
			strcmp( buf, cn->name ) != 0 ) )
		{

				X509_free(peerCert);
				trace( tl_status, "Certificate did not match configuration\n");
				return 0;
		}
	}

	X509_free(peerCert);
	return 1;
}



//******************************************************************************
//

static char *ssl_service_options(CMD cmd, char *opt, char *arg) 
{


	/* CAfile */
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.cafile = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "CA-file"))
			break;
		if(arg[0]) /* not empty */
			sslcfg.cafile = stralloc(arg);
		else
			sslcfg.cafile = NULL;
		return NULL; /* OK */
	}

	/* cert */
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.certfile = "/etc/trueport/sslcert.pem";
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "certificate-file"))
			break;
		if( arg[0] )
			sslcfg.certfile = stralloc(arg);
		return NULL; /* OK */
	}

	/* key */
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.keyfile=NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "key"))
			break;
		sslcfg.keyfile=stralloc(arg);
		return NULL; /* OK */
	}

	/* ssl-type (client or server) */
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.ssl_type = 0;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "ssl-type"))
			break;
		if(!strcasecmp(arg, "client"))
			sslcfg.ssl_type =  SSL_CLIENT;
		else if(!strcasecmp(arg, "server"))
			sslcfg.ssl_type = SSL_SERVER;
		else
			return "argument should be either 'client' or 'server'";
		return NULL; /* OK */
	}


	/* ssl-version */
	switch(cmd) 
	{

	int	i;

	case CMD_INIT:
		sslcfg.ssl_type = 0;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "ssl-version"))
			break;
		for( i = 0; i < MAX_SSL_VERSIONS; i++ )	{
			if (!strcasecmp( arg, ssl_methods_strings[i] )) 
			{
				sslcfg.ssl_version =  i;
				break;
			}
		}

		if( i >= MAX_SSL_VERSIONS )
			return "argument should be 'any', 'TLSv1' or 'SSLv3'";

		return NULL; /* OK */
	}


	/* verify-peer */
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.do_authentication = 0;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "verify-peer"))
			break;
		if(!strcasecmp(arg, "yes"))
			sslcfg.do_authentication = TRUE;
		else if(!strcasecmp(arg, "no"))
			sslcfg.do_authentication = FALSE;
		else
			return "argument should be either 'yes' or 'no'";
		return NULL; /* OK */
	}

	// country
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.countryName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "country"))
			break;
		if( arg[0] )
			sslcfg.countryName = stralloc(arg);
		return NULL; /* OK */
	}

	// state-province
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.stateOrProvinceName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "state-province"))
			break;
		if( arg[0] )
			sslcfg.stateOrProvinceName = stralloc(arg);
		return NULL; /* OK */
	}

	// local
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.localityName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "locality"))
			break;
		if( arg[0] )
			sslcfg.localityName = stralloc(arg);
		return NULL; /* OK */
	}

	// organization
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.organizationName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "organisation"))
			break;
		if( arg[0] )
			sslcfg.organizationName = stralloc(arg);
		return NULL; /* OK */
	}

	// organization-unit
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.organizationalUnitName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "organisation-unit"))
			break;
		if( arg[0] )
			sslcfg.organizationalUnitName = stralloc(arg);
		return NULL; /* OK */
	}

	// common-name
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.commonName = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "common-name"))
			break;
		if( arg[0] )
			sslcfg.commonName = stralloc(arg);
		return NULL; /* OK */
	}

	// email
	switch(cmd) 
	{
	case CMD_INIT:
		sslcfg.pkcs9_emailAddress = NULL;
		break;
	case CMD_EXEC:
		if(strcasecmp(opt, "email"))
			break;
		if( arg[0] )
			sslcfg.pkcs9_emailAddress = stralloc(arg);
		return NULL; /* OK */
	}


	if(cmd==CMD_EXEC)
		return "option_not_found";
	return NULL; /* OK */
}


//******************************************************************************
//
//
//

static int parse_ssl_config( char *file_name, char *tcp_host, int net_port )
{
	FILE 	*fp;
	char 	confline[CONFLINELEN], *arg, *opt, *errstr;
	int 	i;
	long	section_number = -1;
	int		line_number;
	char  *tmphost, *tmpport;

	fp=fopen( file_name, "r" );
	if ( !fp ) 
	{
		trace( tl_error, "error opening ssl config file: %s\n", file_name );
		return(-1);
	}
	line_number = 0;
	while( fgets( confline, CONFLINELEN, fp ) ) 
	{
		line_number++;
		opt=confline;
		while( isspace( *opt ) )
			opt++; /* remove initial whitespaces */
		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		if( opt[0]=='\0' || opt[0]=='#' || opt[0]==';' ) /* empty or comment */
			continue;
		if ( opt[0]=='[' && opt[strlen( opt )-1]==']' ) 
		{ /* new section */

			// Correct port number configuration processing is done.
			if ( section_number != -1 ) 
				break;

			opt++;
			opt[strlen( opt )-1]='\0';
			if (get_tcp_hostport(opt, &tmphost, &tmpport) < 0)
			{
				trace( tl_error, "parse_ssl_config(): Bad [%s:%s] in SSL config file \n", tmphost, tmpport );
				return(-1);
			}
			
			if (tcp_host != NULL)
			{
			   // if host doesn't match then go to next section
			   if ( tmphost == NULL || strcmp(tmphost, tcp_host) )
			   {
				  continue;
			   }
			}
			if (  net_port == atoi(tmpport) )
			{
				section_number = net_port;
				ssl_service_options( CMD_INIT, NULL, NULL );
			}
			continue;
		}
		// Do not parse config data if not the proper section.
		if( section_number == -1 )
			continue;
			
		arg=strchr( confline, '=' );
		if ( !arg ) 
		{
			trace( tl_error, "file %s line %d: No '=' found", file_name, line_number );
			fclose( fp );
			return( -1 );
		}
		*arg++='\0'; /* split into option name and argument value */
		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		while( isspace( *arg ) )
			arg++; /* remove initial whitespaces */

		errstr=ssl_service_options( CMD_EXEC, opt, arg );
		if ( errstr != NULL ) 
		{
			trace( tl_error, "SSL config error: %s\n", errstr );
			fclose( fp );
			return(-1);
		}

	} //while

	fclose( fp );
	if ( section_number == -1 ) 
	{
		trace( tl_error, "SSL configuration entry %s:%d not found\n", tcp_host, net_port );
		return(-1);		// configuration for specified net port not found.
	}
		
	trace( tl_debug, "SSL config file parsing is done\n" );
	return(0);
}



//******************************************************************************
//	 Allocate static string

static char *stralloc(char *str)
{
	char *retval;

	retval=calloc(strlen(str)+1, 1);
	if (!retval) 
	{
		trace( tl_error, "Fatal memory allocation error" );
		exit(2);
	}
	strcpy(retval, str);
	return retval;
}


//******************************************************************************

static DH *get_dh512(void)
{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
#else
    BIGNUM *dh_p, *dh_g;
	dh_p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh_g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh_p == NULL) || (dh_g == NULL))
		return(NULL);
    DH_set0_pqg(dh, dh_p, NULL, dh_g);
#endif
	return(dh);
}



//******************************************************************************

static DH *load_dh_param(char *dhfile)
{
	DH *ret=NULL;
	BIO *bio;

	if ((bio=BIO_new_file(dhfile,"r")) == NULL) 
	{
		goto err;
	}
	ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);

err:
	if (bio != NULL) BIO_free(bio);
	return(ret);
}

/* End of sslcfg.c */

#endif	// USE_SSL

