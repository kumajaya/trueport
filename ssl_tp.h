//*****************************************************************************
//
//	ssl_tp.h
//
//	This file provides access to the trueport ssl initialization and configuration
//	routines and structures.

#if ! defined (OPENSSL_VERSION_NUMBER)
#error "openssl version is not set"
#endif

#define	SSL_CLIENT		0
#define	SSL_SERVER		1

#define	MAX_SSL_VERSIONS			5
#define MAX_PASSPHRASE_LEN		32

#define DEFAULT_SSL_CFG_FILE		"/etc/trueport/sslcfg.tp"

#define SSL_ACCEPT_OR_CONNECT_TIMEOUT_SECS		30


typedef struct	ssl_cfg_st
{
	int					enabled;
	char				*certfile;
	char				*keyfile;
	char				*certfile2;
	char				*keyfile2;
	char 				pass_phrase[MAX_PASSPHRASE_LEN];	
	char				*cafile;
	char				*cipher;
#if (OPENSSL_VERSION_NUMBER < 0x100000f)
	SSL_METHOD			*ssl_method;
#else
	const	SSL_METHOD	*ssl_method;
#endif
	int					ssl_version;
	int					ssl_type;
	int					do_authentication;
	char				*countryName;
	char				*stateOrProvinceName;
	char				*localityName;
	char				*organizationName;
	char				*organizationalUnitName;
	char				*commonName;
	char				*pkcs9_emailAddress;
} SSL_CFG;


typedef struct certName_st
{
	char	*name;
	int		nid;
}CertName; 



//*****************************************************************************
//
//	Library prototypes.

int ssl_init( 	SSL_CTX **p_ssl_ctx, pem_password_cb *passwd_cb, 
					RSA *(*tmp_rsa_cb)(SSL *ssl,int is_export, int keylength) );
int	get_ssl_config(char *tcp_host, int net_port_num);
int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file);
int	check_cert( SSL *ssl );


// TruePort does not configure ciphers. We choose "ALL" here and let the 	         // There is no user configuration for ciphers; we hard-code the list
//      Device server make the choice. ( "ALL" includes ADH ).
#define SSL_CIPHER_LIST "ALL:!KRB5"

