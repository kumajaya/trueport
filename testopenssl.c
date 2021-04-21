#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#define DATA "conftest.sslincver"

//******************************************************************************

int main(void)
{
    FILE *fd;
    int rc;

    fd = fopen(DATA,"w");
    if (fd == NULL)
            exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", (unsigned int)OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
		exit(1);

#ifdef	CHECK_LIBS
	if ( SSLeay() != OPENSSL_VERSION_NUMBER )
	{
		printf( "*************************************************\n" );
		printf( "Openssl version: header=%x, library=%x\n", (unsigned int)OPENSSL_VERSION_NUMBER, (unsigned int)SSLeay() );
		printf( "*************************************************\n" );
		exit( 2 );
	}
	
	if ( OPENSSL_VERSION_NUMBER < 0x0090707f)
	{
		printf( "*************************************************\n" );
		printf( "Openssl version: header=%x, library=%x\n", (unsigned int)OPENSSL_VERSION_NUMBER, (unsigned int)SSLeay() );
		printf( "*************************************************\n" );
		exit( 3 );
	}
	printf( "*************************************************\n" );
	printf( "Openssl version: header=%x, library=%x\n", (unsigned int)OPENSSL_VERSION_NUMBER, (unsigned int)SSLeay() );
	printf( "*************************************************\n" );
#endif	//CHECK_LIBS
	
	exit(0);
}

