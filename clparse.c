/******************************************************************
 Module: clparse.c

 Description: Command line parser for TruePort

 Version: @(#)clparse.c	1.2

 Copyright (c) Perle Systems Limited 1990-2016. All rights reserved.

*******************************************************************/

/****************************************************************************
 *									    *
 *		Written by : Kamal Mortoza				    *
 *									    *
 ****************************************************************************/


/*
	CLPARSE is a general purpose command line token parser
	designed to standardize command line parsing for utility
	programs.

	Command line tokens and the actions to perform are defined
	using a parse table described in CLPARSE.H, the header file.
*/


/****************************************************************************
 *	Maintenance history						    *
 ****************************************************************************/

/*
	Date		Name	Ver	Revision
	----		----	---	--------
	07-Feb-91	KM	1.00	Initial coding
	08-Feb-91	KM	1.00	Added unresolved token handling
	11-Feb-91	KM	1.00	Added name list creation
	13-Feb-91	KM	1.00	Added set spec'd value flags
	15-Feb-91	KM	1.00	Added variable length token matching
	27-Jan-99	RMC	2.00	Various incompatible changes

*/


/****************************************************************************
 *	Include files							    *
 ****************************************************************************/

#include	<stdio.h>			/* Standard 'C' I/O header */
#include 	<stdlib.h>
#include	<string.h>			/* String handling func's */
#include	"clparse.h"			/* CLPARSE header file */



/****************************************************************************
 *	Global data definitions						    *
 ****************************************************************************/

/*
	Misc constant definitions
*/
#define		NO	0		/* Logical NO */
#define		YES	!(NO)		/* Logical YES */
#define		FAILURE	(-1)		/* Error return code */

	int	mlen[128];			/* Temps for match counts */



/****************************************************************************
 *	Forward function declarations					    *
 ****************************************************************************/

int	proctoken(char *arg[], int cn, int argc, struct clparse_st *ptab);
long	getvalue(char *s);
int	findtoken(char *a, struct clparse_st *p);



/****************************************************************************
 *	Main parse routine						    *
 ****************************************************************************/

/*
	clparse()	: Parse a command line
	Call sequence	: ret = clparse(argc, argv, ptab);
	Arguments	: argc=argument count, argv=ptr array to tokens, 
			  ptab=Ptr to parse table,
	Return values	: 0 if parse OK, else index of bad argument 
*/
int	clparse(int argc, char *argv[], struct clparse_st *ptab)
{
	int	x;				/* Temp worker */
	int	i = 0;				/* Temp arg # */

	for (i = 1; i < argc;)			/* Check all args */
	   if ((x = proctoken(argv, i, argc - i, ptab)) == 0) /* Proc token */
	   {
	      return i;				/* Return error if error */
	   }
	   else
	      i += x;				/* Bump token # */

	return 0;				/* Return success */
}


/****************************************************************************
 *	Search for an action token					    *
 ****************************************************************************/

/*
	proctoken()	: Process next command line arg
	Call sequence	: ret = proctoken(arg, cn, argc, ptab);
	Arguments	: arg=command arg, cn=current token index,
			  argc=# of tokens left, ptab=ptr to parse table
	Return values	: number of arguments processed, 0 if invalid
*/
int	proctoken(char *arg[], int cn, int argc, struct clparse_st *ptab)
{
	int	i;

	if ((i = findtoken(arg[cn], ptab)) != FAILURE)/* If token found */
	{
	   ptab += i;
	   switch (ptab->flags)		/* Branch on flag type */
	   {
		 /*
			set/reset group
		 */
	     case CLF_BSET	: *((char *) ptab->ptr) = YES;
			  break;
		 case CLF_WSET	: *((int *) ptab->ptr) = YES;
			  break;
		 case CLF_SSET	: *((short *) ptab->ptr) = YES;
			  break;
		 case CLF_BRESET: *((char *) ptab->ptr) = NO;
			  break;
		 case CLF_WRESET: *((int *) ptab->ptr) = NO;
			  break;
		 case CLF_SRESET: *((short *) ptab->ptr) = NO;
			  break;

		 /*
		 	AND/OR/XOR group
		 */
		 case CLF_BAND	: *((char *) ptab->ptr) &= ptab->value;
			  break;
		 case CLF_WAND	: *((int *) ptab->ptr) &= ptab->value;
			  break;
		 case CLF_SAND	: *((short *) ptab->ptr) &= ptab->value;
			  break;
		 case CLF_BOR	: *((char *) ptab->ptr) |= ptab->value;
			  break;
		 case CLF_WOR	: *((int *) ptab->ptr) |= ptab->value;
			  break;
		 case CLF_SOR	: *((short *) ptab->ptr) |= ptab->value;
			  break;
		 case CLF_BXOR	: *((char *) ptab->ptr) ^= ptab->value;
			  break;
		 case CLF_WXOR	: *((int *) ptab->ptr) ^= ptab->value;
			  break;
		 case CLF_SXOR	: *((short *) ptab->ptr) ^= ptab->value;
			  break;

		 /*
			Sub-options group
		 */
		 case CLF_SUBOPT: if (argc)
		  {
			 return(proctoken(arg, cn + 1,
				argc - 1, ptab->sub) + 1);
		  }
		  else
			 return(NO);

		 /*
			Name list group
		 */
		 case CLF_NAMES	: if (argc)
		  {
			 if (ptab->ptr != NULL)
			 {
					*((char **) ptab->ptr) = arg[cn + 1];
				return(2);
			 }
		  }
		  else
			 return(NO);

		 case CLF_NAMELS: if (argc)
		  {
			 struct	clparse_st *p;

			 p = ptab->sub;
			 if ((p->ptr != NULL) &&
			 (p->token != NULL) &&
			 (*((int *) p->token) < p->value))
				/* Save token for user */
				 ((char **) p->ptr)[
				(*((int *) p->token))++
					   ] = arg[cn + 1];
			  return(2);
		   }
		   else
			  return(NO);

		 /*
			Set spec'd value group
		 */
		 case CLF_BINIT	: *((char *) ptab->ptr) = (char) ptab->value;
			  break;
		 case CLF_WINIT	: *((int *) ptab->ptr) = ptab->value;
			  break;
		 case CLF_SINIT	: *((short *) ptab->ptr) = (short) ptab->value;
			  break;
		 case CLF_LINIT : *((long *) ptab->ptr) = (long) ptab->value;
			  break;

		 /*
			Set value group
		 */
		 case CLF_BVAL	: if (argc)
		  {
			 *((unsigned char *) ptab->ptr) =
			  (unsigned char) getvalue(arg[cn + 1]);
			 return(2);
		  }
		  else
			 return(NO);

		 case CLF_WVAL	: if (argc)
		  {
			 *((int *) ptab->ptr) =
			  (int) getvalue(arg[cn + 1]);
			 return(2);
		  }
		  else
			 return(NO);

		 case CLF_SVAL	: if (argc)
		  {
			 *((short *) ptab->ptr) =
			  (short) getvalue(arg[cn + 1]);
			 return(2);
		  }
		  else
			 return(NO);

		 case CLF_LVAL	: if (argc)
		  {
			 *((long *) ptab->ptr) =
			  (long) getvalue(arg[cn + 1]);
			 return(2);
		  }
		  else
			 return(NO);

	   }
	   return(1);
	}
	else					/* Token not found */
	{
	   return (NO);

#ifdef user_defined
	   while (ptab->flags != CLF_EOT)	/* Move on to end of table */
	      ptab++;
	   if ((ptab->ptr != NULL) &&		/* If unresolved table req'd */
		 (ptab->token != NULL) &&	/* And array counter provided */
			 (*((int *) ptab->token) < ptab->value)) /* And space */
						/* Save token for user */
	       ((char **) ptab->ptr)[(*((int *) ptab->token))++] = arg[cn];

	   return(1);				/* Return 1 arg swallowed */
#endif
	}
}


/***************************************************************************
 *	Convert string to long value					   *
 ***************************************************************************/

/*
	getvalue()	: Convert ascii string to long
	Call sequence	: ret=getval(str);
	Arguments	: str=ascci string ptr
	Return values	: value
*/
long	getvalue(char *s)
{
	long	retval;

	if (!s)
	{
		fprintf (stderr, "Missing value\n");
		exit (-1);
	}

	if (*s == '0')				/* If leading zero present */
	{
	   if (s[1] == 'x')			/* If hex number */
	   {
	      sscanf(s + 2, "%lx", &retval);
	      return(retval);
	   }
	   else
	   {
	      sscanf(s, "%lo", &retval);
	      return(retval);
	   }
	}
	else
	   return(atol(s));
}

/****************************************************************************
 *	Search for best match to argument				    *
 ****************************************************************************/

/*
	findtoken()	: Search parse table for best match
	Call sequence	: ret = findtoken(a, p);
	Arguments	: a=arg string, p=parse table
	Return values	: FAILURE if no match, else index # of table
*/
int	findtoken(char *a, struct clparse_st *p)
{
	char	*pa, *pb;			/* Temp workers */
	int	i, j, k;

	j = 0;					/* Clear length array index */
	while (p->flags != CLF_EOT)		/* Do till end of table */
	{
	   pa = a;				/* Set ptr to arg */
	   pb = p->token;			/* Set ptr to token string */
	   i = 0;				/* Clear match count */
	   while (*pa && (*pa == *pb))		/* While chars & match OK */
	   {
	      pa++; pb++; i++;			/* Bump ptrs & count */
	   }
	   mlen[j++] = i;			/* Save count */
	   p++;
	}

	for (k = 0; k < j; k++)			/* Scan lengths */
	   if (mlen[k])
	      for (i = 0; i < j; i++)	/* If any match with next */
	         if ((i != k) && (mlen[k] > mlen[i])) /* If greater */
		    mlen[i] = 0;		/* Set other to 0 */


	for (k = 0; k < j; k++)			/* Scan list again */
	   if (mlen[k])				/* If non zero match */
	   {
	      for (i = k + 1; i < j; i++)	/* Scan remainder for dups */
	         if (mlen[k] == mlen[i])	/* If duplicate found */
		    return(FAILURE);		/* Set failure */
	      return(k);			/* Checked OK */
	   }

 	return(FAILURE);

}

