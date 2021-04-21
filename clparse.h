/*************************************************************************
 Module: clparse.h

 Description: Command line parser header file

 Version: @(#)clparse.h	1.2

 Copyright (c) Perle Systems Limited 1990-2006. All rights reserved.

**************************************************************************/

/****************************************************************************
 *									    *
 *		Written by : Kamal Mortoza				    *
 *									    *
 ****************************************************************************/


/*
	This header file provides the structure definitions and
	constant definitions for the trueport proprietary command
	line parser.
*/


/****************************************************************************
 *	Maintenance history						    *
 ****************************************************************************/

/*
	Date		Name	Ver	Revision
	----		----	---	--------
	02-Feb-91	KM	1.00	Initial coding
	13-Feb-91	KM	1.00	Added set spec'd value flags

*/


/****************************************************************************
 *	Parse table structure definitions				    *
 ****************************************************************************/

/*
	Parse table structure
*/
	struct	clparse_st
	{
   	   int	flags;				/* Token type flags */
	   int	value;				/* AND/OR/XOR value */
	   void	*ptr;				/* Ptr to variable */
	   char	*token;				/* Ptr to token */
	   struct clparse_st *sub;		/* Sub table ptr */
	};


/****************************************************************************
 *	Definitions for clparse_st.flags				    *
 ****************************************************************************/

/*
	Word/byte set/reset group
*/
#define	CLF_BSET	0x0001		/* Set byte to true */
#define	CLF_BRESET	0x0002		/* Set byte to false */
#define	CLF_WSET	0x0003		/* Set word to true */
#define	CLF_WRESET	0x0004		/* Set word to false */
#define	CLF_SSET	0x0005		/* Set short to true */
#define	CLF_SRESET	0x0006		/* Set short to false */

/*
	AND/OR/XOR group
*/
#define	CLF_BAND	0x0010		/* And value with byte */
#define	CLF_BOR		0x0011		/* OR value with byte */
#define	CLF_BXOR	0x0012		/* XOR value with byte */
#define	CLF_WAND	0x0013		/* AND value with word */
#define	CLF_WOR		0x0014		/* OR value with word */
#define	CLF_WXOR	0x0015		/* XOR value with word */
#define	CLF_SAND	0x0016		/* AND value with short */
#define	CLF_SOR		0x0017		/* OR value with short */
#define	CLF_SXOR	0x0018		/* XOR value with short */

/*
	Sub-options group
*/
#define	CLF_SUBOPT	0x0020		/* Select sub-options */

/*
	Name list group
*/
#define	CLF_NAMES	0x0030		/* Set single name */
#define	CLF_NAMELS	0x0031		/* Set name list */

/*
	Set spec'd value group
*/
#define	CLF_BINIT	0x0040		/* Set spec'd value in byte */
#define	CLF_WINIT	0x0041		/* Set spec'd value in int */
#define	CLF_SINIT	0x0042		/* Set spec'd value in short */
#define	CLF_LINIT	0x0043		/* Set spec'd value in long */
/*
	Set value group
*/
#define	CLF_BVAL	0x0050		/* Set value in byte */
#define	CLF_WVAL	0x0051		/* Set value in word */
#define	CLF_LVAL	0x0052		/* Set value in long */
#define	CLF_SVAL	0x0053		/* Set value in short */

/*
	End of list flag
*/
#define	CLF_EOT		-1		/* Flag end of parse table */



/* function definitions */

int     clparse(int argc, char *argv[], struct clparse_st *ptab);
