//******************************************************************
// Module: tp_ver.h
//
// Description: Configuration and Kernel conditional compile defines 
//              for TruePort
//
// Copyright (c) 1999-2009 Perle Systems Limited. All rights reserved.
//
//*******************************************************************

#ifndef _TP_VER_H
#define _TP_VER_H



// Paranoia
#if !defined(KERNEL_VERSION) 		// defined in version.h in later kernels 
# define KERNEL_VERSION(a,b,c)  (((a) << 16) + ((b) << 8) + (c))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)) /* Less than 2.6.16 kernel */
 #define RECEIVE_ROOM(tty) tty->ldisc.receive_room(tty)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
 #define RECEIVE_ROOM(tty)  tty->receive_room
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0))
 #define RECEIVE_ROOM(tty)  my_buffer_space_avail(tty)
#else
 #define RECEIVE_ROOM(tty)  tty_buffer_space_avail(tty->port)
#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))	// Less than 2.6.27 kernel.
	#define WRITE_WAKEUP(tty)	\
	do	\
	{	\
		if ( (test_bit(TTY_DO_WRITE_WAKEUP, &(tty)->flags)) && tty->ldisc.write_wakeup )	\
		{	\
			(tty->ldisc.write_wakeup)(tty);	\
		}	\
	} while (0)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))	/* Less than 2.6.31 kernel */
	#define WRITE_WAKEUP(tty)	\
	do	\
	{	\
		if ( (test_bit(TTY_DO_WRITE_WAKEUP, &(tty)->flags)) && tty->ldisc.ops->write_wakeup )	\
		{	\
			(tty->ldisc.ops->write_wakeup)(tty);	\
		}	\
	} while (0)
#else
	#define WRITE_WAKEUP(tty)	\
	do	\
	{	\
		if ( (test_bit(TTY_DO_WRITE_WAKEUP, &(tty)->flags)) && tty->ldisc->ops->write_wakeup )	\
		{	\
			(tty->ldisc->ops->write_wakeup)(tty);	\
		}	\
	} while (0)
#endif 


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))	/* Less than 2.6.27 kernel */
	#define RECEIVE_BUF(tty) (tty->ldisc.receive_buf)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))	/* Less than 2.6.31 kernel */
	#define RECEIVE_BUF(tty) (tty->ldisc.ops->receive_buf)
#else
	#define RECEIVE_BUF(tty) (tty->ldisc->ops->receive_buf)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)	// Less than or equal to 3.9.0
	#define TTY_TO(tty) (tty)
#else
	#define TTY_TO(tty) (tty->port)
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)	// Greater than or equal to 2.6.20
	#define STRUCT_TERMIOS struct ktermios
#else
	#define STRUCT_TERMIOS struct termios
#endif



#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))	// Less than 2.6.27 kernel.
	#define FLUSH_BUFFER(tty) 				\
	do 												\
	{  												\
		if (tty->ldisc.flush_buffer)			\
		{												\
			tty->ldisc.flush_buffer(tty);	\
		} 												\
	} while (0)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))	/* Less than 2.6.31 kernel */
	#define FLUSH_BUFFER(tty)						\
	do															\
	{															\
		if (tty->ldisc.ops->flush_buffer)			\
		{														\
			tty->ldisc.ops->flush_buffer(tty);	\
		}														\
	} while (0)
#else
	#define FLUSH_BUFFER(tty)						\
	do															\
	{															\
		if (tty->ldisc->ops->flush_buffer)			\
		{														\
			tty->ldisc->ops->flush_buffer(tty);	\
		}														\
	} while (0)
#endif




#endif // _TP_VER_H




