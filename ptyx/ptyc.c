/*******************************************************************************
 Module: ptyc.c
 
 Description: TruePort control status driver for Linux
 
 Copyright (c) Perle Systems Limited 1999-2016
 All rights reserved
 
*******************************************************************************/

#include <linux/version.h>

#if ! defined (LINUX_VERSION_CODE)
#error "Kernel version is not set"
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif

#include <linux/module.h>	/* For EXPORT_SYMBOL */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif


#define BUILDING_PTY_C 1
#include <linux/devpts_fs.h>

#include <linux/serial.h>

#include "../tp_ver.h"
#include "../tp.h"
#include "ptyx.h"


//********************************************************************
// Ctrl operations and functions
//********************************************************************

static void ptyx_ctrl_close(struct tty_struct *tty, struct file * filp)
{
	struct ptyx_struct *ptyx_info;
	unsigned long flags;
	int line;

	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_ctrl_close(???): ENTER tty=0x%p, jiffies=%lu \n",tty, jiffies));

	if (!tty)
	{
		return;
	}

	line = tty->index - TTY_DRIVER(minor_start);
	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_ctrl_close(%d):  tty=0x%p, jiffies=%lu \n", 
		 	line, tty, jiffies));

	if (tty->count > 1)
	{
		ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_ctrl_close(%d): count=%d!!\n", line, tty->count));
	} 
	
	wake_up_interruptible(&tty->read_wait);
	wake_up_interruptible(&tty->write_wait);

	ptyx_info = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[line];

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	ptyx_info->c_tty = NULL;		// NULL out our copy of the ctrl's tty
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	
	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_ctrl_close(%d): Exit - tty=0x%p, jiffies=%lu \n", line, tty, jiffies));

}


  
static int ptyx_ctrl_write_room(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info;

	if (!tty || !tty->driver_data)		// paranoia
		return 0;

	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	if (!tty || tty->stopped || (ptyx_info->flags & SLAVE_CLOSING) )
		return 0;

	return RECEIVE_ROOM(tty);
}

//	The Control tty will pass all statuses in raw mode to the dameon
// so in this case we can	return the true count in the buffer.
//
static int ptyx_ctrl_chars_in_buffer(struct tty_struct *tty)
{
    return 0;
}


//*****************************************************************************
//
//		ctrl ioctl functions
//
//	NOTE:	The TIOCMGET and TIOCMSET functions/ioctl commands rely on the
//			driver_data member of the slave and ctrl ttys pointing to the
//			the same data (ie. same memory location).
//*****************************************************************************

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_ctrl_ioctl(struct tty_struct *tty, struct file *file,
									unsigned int cmd, unsigned long arg)
#else
static int ptyx_ctrl_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
#endif

{
	struct ptyx_struct *ptyx_info;

	if (!tty) 
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_ctrl_ioctl(): called with NULL tty!\n"));
		return -EIO;
	}

	ptyx_info = (struct ptyx_struct *)tty->driver_data;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_ctrl_ioctl(%d): called cmd=0x%x\n", ptyx_info->line, cmd));


	switch(cmd) 
	{
		default:
		{
			 ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_ctrl_ioctl(%d): Don't support any ioctls right now \n", ptyx_info->line));
		}
	} // end switch
	return -ENOIOCTLCMD;
}



#ifdef CONFIG_COMPAT

#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,39))		// greater that or equal to 2.6.39
static long ptyx_ctrl_compat_ioctl(struct tty_struct* tty, unsigned int cmd, unsigned long arg)
{
	return ptyx_ctrl_ioctl(tty, cmd, (unsigned long) compat_ptr(arg));
}
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21))	// Greater than 2.6.21 kernel.
static long ptyx_ctrl_compat_ioctl(struct tty_struct* tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	return ptyx_ctrl_ioctl(tty, file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

#endif


static int ptyx_ctrl_open(struct tty_struct *tty, struct file *filp)
{
	int	retval = -ENODEV;
	int	line = -1;		// initialize to invalid
	struct	ptyx_struct *ptyx_info;
	unsigned long flags;

	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_ctrl_open(???): Enter, tty=0x%p, filp=0x%p, jiffies=%lu \n", 
			 			tty, filp, jiffies));
	if (!tty)
	{
		goto out;
	}
	
	line = tty->index - TTY_DRIVER(minor_start);

	if ((line < 0) || (line >= max_installed_ports))
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_ctrl_open(???): Invalid port, line = %d \n", line ));
		goto out;
	}
	
	retval = -EIO;
	
	if (tty->count > 1)
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_ctrl_open(%d): ERROR - count=%d, o only allow one ctrl open \n", line, tty->count ));
		goto out;
	}
	wake_up_interruptible(&tty->read_wait);
	wake_up_interruptible(&tty->write_wait);

	ptyx_info = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[line];
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	tty->driver_data = ptyx_info;
#endif	
	PTYX_LOCK(&ptyx_info->port_lock, flags);
//	ptyx_info->line = line;
	ptyx_info->c_tty = tty;		// set ctrl's tty in private data
	
	// wake up slave if it's waiting on open
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	
	retval = 0;


out:
 	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_ctrl_open(%d): Exit tty=0x%p, returning %d, jiffies=%lu \n", 
		 		line, tty, retval, jiffies));

	return retval;
}



struct tty_operations ptyx_ops_control = 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	.install			= ptyx_common_install,
	.cleanup			= ptyx_common_cleanup,
#endif
	.open 				= ptyx_ctrl_open,
	.close 				= ptyx_ctrl_close,
	.write 				= NULL,
	.put_char			= NULL,
	.flush_chars		= NULL,
	.write_room 		= ptyx_ctrl_write_room,
	.chars_in_buffer 	= ptyx_ctrl_chars_in_buffer,
	.unthrottle 		= NULL,

	.flush_buffer 		= NULL,
	.ioctl 				= ptyx_ctrl_ioctl,
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21))	// Greater than 2.6.21 kernel.
	.compat_ioctl		= ptyx_ctrl_compat_ioctl,
#endif
#endif
	.set_termios 		= NULL,
	.tiocmget 			= NULL,
	.tiocmset 			= NULL
};

