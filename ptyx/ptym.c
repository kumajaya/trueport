/*******************************************************************************
 Module: ptym.c
 
 Description: TruePort Master driver for Linux
 
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
// Master operations and functions
//********************************************************************

static void ptyx_master_close(struct tty_struct *tty, struct file * filp)
{
	struct ptyx_struct *ptyx_info;
	unsigned long flags;
	struct tty_struct *s_tty = NULL;	// slave's tty pointer
	int line;

	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_master_close(???): ENTER tty=0x%p, jiffies=%lu \n",tty, jiffies));
	
	if (!tty)
	{
		return;
	}

	line = tty->index - TTY_DRIVER(minor_start);
	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_master_close(%d):  tty=0x%p, jiffies=%lu \n", 
		 	line, tty, jiffies));

	if (tty->count > 1)
	{
		ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_master_close(%d): count=%d!!\n", line, tty->count));
	} 
	
    set_bit(TTY_IO_ERROR, &tty->flags);
	wake_up_interruptible(&tty->read_wait);
	wake_up_interruptible(&tty->write_wait);

	ptyx_info = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[line];
	
	PTYX_LOCK(&ptyx_info->port_lock, flags);

	s_tty = ptyx_info->s_tty;
	if (s_tty)
	{
		ptyx_info->flags &= ~SLAVE_ACTIVE;		// clear SLAVE_ACTIVE so no wait_until_sent on slave closing
        PTYX_UNLOCK(&ptyx_info->port_lock, flags);
		tty_hangup(s_tty);
        PTYX_LOCK(&ptyx_info->port_lock, flags);
	}
	
	ptyx_info->delta_msr_wait_done = TRUE;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	wake_up_interruptible(&ptyx_info->delta_msr_wait);
	wake_up_interruptible(&ptyx_info->open_wait);	// should never happen
	PTYX_LOCK(&ptyx_info->port_lock, flags);

	ptyx_info->pending_drain_end = 0;
	ptyx_info->network_status = 0;

	ptyx_info->m_tty = NULL;		// NULL out our copy of the master's tty
	ptyx_info->line = 0;

	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	
	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_master_close(%d): Exit - tty=0x%p, jiffies=%lu \n", line, tty, jiffies));
}


/*
 * The unthrottle routine is called by the line discipline to signal
 * that it can receive more characters.  For PTY's, the TTY_THROTTLED
 * flag is always set, to force the line discipline to always call the
 * unthrottle routine when there are fewer than TTY_THRESHOLD_UNTHROTTLE 
 * characters in the queue.  This is necessary since each time this
 * happens, we need to wake up any sleeping processes that could be
 * (1) trying to send data to the pty, or (2) waiting in wait_until_sent()
 * for the pty buffer to be drained.
 */
static void ptyx_master_unthrottle(struct tty_struct * tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *s_tty;
	unsigned long flags;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!s_tty)
		return;

	tty_wakeup(s_tty);
	set_bit(TTY_THROTTLED, &tty->flags);
}


/*
 * WSH 05/24/97: modified to 
 *   (1) use space in tty->flip instead of a shared temp buffer
 *	 The flip buffers aren't being used for a pty, so there's lots
 *	 of space available.  The buffer is protected by a per-pty
 *	 semaphore that should almost never come under contention.
 *   (2) avoid redundant copying for cases where count >> receive_room
 * N.B. Calls from user space may now return an error code instead of
 * a count.
 */


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10))		// less then 2.6.10
static int ptyx_master_write(struct tty_struct * tty, int from_user,
			const unsigned char *buf, int count)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *s_tty;
	unsigned long flags;
	int c = 0;
	int n, room;
	char *temp_buffer;
	
	if (!tty || !tty->driver_data)		// paranoia
		return 0;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_master_write(%d): buf=0x%p, count=%d\n", ptyx_info->line, buf, count));
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!s_tty || tty->stopped || (ptyx_info->flags & SLAVE_CLOSING) )
		return 0;

	if (from_user) 
	{
		down(&tty->flip.pty_sem);
		temp_buffer = &tty->flip.char_buf[0];
		while (count > 0) 
		{
			/* check space so we don't copy needlessly */ 
			n = RECEIVE_ROOM(s_tty);
			if (n > count)
				n = count;
			if (!n) break;

			n  = min(n, PTY_BUF_SIZE);
			n -= copy_from_user(temp_buffer, buf, n);
			if (!n) 
			{
				if (!c)
					c = -EFAULT;
				break;
			}

			/* check again in case the buffer filled up */
			room = RECEIVE_ROOM(s_tty);
			if (n > room)
				n = room;
			if (!n) break;
			buf   += n; 
			c     += n;
			count -= n;
			RECEIVE_BUF(s_tty)(s_tty, temp_buffer, 0, n);

		}
		up(&tty->flip.pty_sem);
	}
	else 
	{
		c = RECEIVE_ROOM(s_tty);
		if (c > count)
		{
			c = count;
		}
		RECEIVE_BUF(s_tty)(s_tty, buf, 0, c);
	}
	ptyx_info->icount.rx+=c;

	return c;
}
#else // greater than or equal to  2.6.10

static int ptyx_master_write(struct tty_struct * tty, 
			const unsigned char *buf, int count)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *s_tty;
	unsigned long flags;
	int c = 0;
	
	if (!tty || !tty->driver_data)		// paranoia
		return 0;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_master_write(%d): buf=0x%p, count=%d\n", ptyx_info->line, buf, count));
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!s_tty || tty->stopped || (ptyx_info->flags & SLAVE_CLOSING) )
		return 0;

    if (count > 0) 
    {
        /* Stuff the data into the input queue of the other end */
        c = tty_insert_flip_string(TTY_TO(s_tty), buf, count);
        /* And shovel */
        if (c) 
        {
            tty_flip_buffer_push(TTY_TO(s_tty));
            tty_wakeup(s_tty);
        }
    }
            
	ptyx_info->icount.rx+=c;

	return c;
}
#endif

static int ptyx_master_write_room(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *s_tty;
	unsigned long flags;

	if (!tty || !tty->driver_data)		// paranoia
		return 0;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!s_tty || tty->stopped || (ptyx_info->flags & SLAVE_CLOSING) )
		return 0;

	return RECEIVE_ROOM(s_tty);
}

/*
 *	WSH 05/24/97:  Modified for asymmetric MASTER/SLAVE behavior
 *	The chars_in_buffer() value is used by the ldisc select() function 
 *	to hold off writing when chars_in_buffer > WAKEUP_CHARS (== 256).
 *	The pty driver chars_in_buffer() Master/Slave must behave differently:
 *
 *      The Master side needs to allow typed-ahead commands to accumulate
 *      while being canonicalized, so we report "our buffer" as empty until
 *	some threshold is reached, and then report the count. (Any count >
 *	WAKEUP_CHARS is regarded by select() as "full".)  To avoid deadlock 
 *	the count returned must be 0 if no canonical data is available to be 
 *	read. (The N_TTY ldisc.chars_in_buffer now knows this.)
 *  
 */
static int ptyx_master_chars_in_buffer(struct tty_struct *tty)
{
    return 0;
}



//*****************************************************************************
//
//		master ioctl functions
//
//	NOTE:	The TIOCMGET and TIOCMSET functions/ioctl commands rely on the
//			driver_data member of the slave and master ttys pointing to the
//			the same data (ie. same memory location).
//*****************************************************************************

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_master_ioctl(struct tty_struct *tty, struct file *file,
									unsigned int cmd, unsigned long arg)
#else
static int ptyx_master_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
#endif
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *s_tty;
	unsigned long flags;

	if (!tty || !tty->driver_data)		// paranoia
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(): called with NULL tty!\n"));
		return -EIO;
	}

	ptyx_info = (struct ptyx_struct *)tty->driver_data;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): called cmd=0x%x\n", ptyx_info->line, cmd));
	
#ifdef PTYX_PARANOIA_CHECK
	if ( s_tty && (s_tty->driver_data == NULL) )
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): called with s_tty->driver_data=ptyx_info = NULL \n", ptyx_info->line));
 		return -EIO; 
	}
#endif // PTYX_PARANOIA_CHECK

	switch(cmd) 
	{
	case TIOCSBRK:
	case TCSBRK:
	case TCSBRKP:
	{
 		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): cmd=TIOCSBRK/TCSBRK/TCSBRKP \n", ptyx_info->line));

		if (s_tty)
		{
#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(3,9,0))		
			 tty_insert_flip_char(s_tty->port, 0, TTY_BREAK);
			 tty_flip_buffer_push(s_tty->port);
#else
			 tty_insert_flip_char(s_tty, 0, TTY_BREAK);
			 tty_flip_buffer_push(s_tty);
#endif
	 		return 0;

		}
		else
		{
	 		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): TIOCSBRK/TCSBRK/TCSBRKP failed, no slave\n", ptyx_info->line));
			return -EIO; 
		}
	}
	case TCGETS:
	{
		STRUCT_TERMIOS *tmp_termios;

		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): cmd=TCGETS\n", ptyx_info->line));
	
		if (s_tty)
		{
#if (LINUX_VERSION_CODE <  KERNEL_VERSION(3,7,0))		// Less than 3.7.0
			tmp_termios = s_tty->termios;
#else
			tmp_termios = &s_tty->termios;
#endif
		}
		else
		{
 	 		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): TCGETS, SLAVE NOT OPEN, returning default termios\n", ptyx_info->line));
			// slave not open so use the slave's default termios
			tmp_termios = &ptyx_info->s_driver->init_termios;
		}
#if (LINUX_VERSION_CODE >  KERNEL_VERSION(2,6,23))		// Greater than 2.6.23
#ifdef TCGETS2
		if (kernel_termios_to_user_termios_1((struct termios *)arg, tmp_termios))
#else
		if (kernel_termios_to_user_termios((struct termios *)arg, tmp_termios))
#endif
#else
		if (kernel_termios_to_user_termios((struct termios *)arg, tmp_termios))
#endif
		{
			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): return -EFAULT\n", ptyx_info->line));
			return -EFAULT;
		}
	
		return 0;

	//this was added/modifed to work around the change made in kernel 2.6. 
	// The 2.6 tiocmset() function masks off all bits that are not 
	// DTE output signals which does not allow the TruePort deamon to set 
	// the DCE ouput pin status in the driver.
	}
	case PTX_IOCMSET:		
	{
		unsigned int curdelta, modem_status;

		if (get_user(arg, (unsigned int *) arg))
			return -EFAULT;

		PTYX_LOCK(&ptyx_info->port_lock, flags);
		modem_status = ptyx_info->modem_status;
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);

		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): PTX_IOCMSET: arg=%0lx, old value = %0x\n", 
			 			ptyx_info->line, arg, modem_status ));

		curdelta=(arg ^ modem_status);

		// only increment RI count on the trailing edge transition
		if ((curdelta & TIOCM_RI) && (arg & TIOCM_RI))
		{
			curdelta = curdelta & ~TIOCM_RI;
		}

		PTYX_LOCK(&ptyx_info->port_lock, flags);
		ptyx_info->modem_status = modem_status = (modem_status & (TIOCM_DTR|TIOCM_RTS)) | (arg & ~(TIOCM_DTR|TIOCM_RTS));
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);

		if (curdelta & TIOCM_RI)
			ptyx_info->icount.rng++;
		
		if (curdelta & TIOCM_CD)
			ptyx_info->icount.dcd++;
		
		if (curdelta & TIOCM_DSR)
			ptyx_info->icount.dsr++;
		
		if (curdelta & TIOCM_CTS)
			ptyx_info->icount.cts++;

		if (curdelta)
		{
	 		PTYX_LOCK(&ptyx_info->port_lock, flags);
	 		ptyx_info->delta_msr_wait_done = TRUE;
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			wake_up_interruptible(&ptyx_info->delta_msr_wait);
		}

		if (modem_status & TIOCM_CD)
		{
			wake_up_interruptible(&ptyx_info->open_wait);
		}

		return 0;
	}
	case PTX_IOCLSET:
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): cmd=PTX_IOCLSET \n", ptyx_info->line));

		if (get_user(arg, (unsigned int *) arg))
			return -EFAULT;

		if (arg & LSRNODATA_OE)
			ptyx_info->icount.overrun++;

		if (arg & LSRNODATA_PE)
			ptyx_info->icount.parity++;
		
		if (arg & LSRNODATA_FE)
			ptyx_info->icount.frame++;
		
		if (arg & LSRNODATA_BI)
		{
			ptyx_info->icount.brk++;
			if (s_tty)
			{
#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(3,9,0))		
				 tty_insert_flip_char(s_tty->port, 0, TTY_BREAK);
				 tty_flip_buffer_push(s_tty->port);
#else
				 tty_insert_flip_char(s_tty, 0, TTY_BREAK);
				 tty_flip_buffer_push(s_tty);
#endif
			}
			else
			{
				 ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): PTX_IOCLSET-LSRNODATA_BI failed, no slave\n", ptyx_info->line));
				 return -EIO; 				 
			}
		}
		return 0;
	}
	case PTX_IOCDRAINEND:
	{
	 	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): cmd=PTX_IOCDRAINEND \n", ptyx_info->line));

		PTYX_LOCK(&ptyx_info->port_lock, flags);
		ptyx_info->pending_drain_end = 0;
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);

		return 0;
	}	
	case PTX_IOCNETSTAT:
	{

		if (get_user(arg, (unsigned int *) arg))
			return -EFAULT;

		PTYX_LOCK(&ptyx_info->port_lock, flags);
		ptyx_info->network_status = arg;
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			
		if (arg)
		{
			PTYX_LOCK(&ptyx_info->port_lock, flags);
			if (ptyx_info->flags & SLAVE_ACTIVE) 
			{
				set_ctrl_status(ptyx_info,CTRLSTATUS_SIGNALS);
			}
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
		}

		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): PTX_IOCNETSTAT network %s\n",
			 			ptyx_info->line, ( arg ? "UP" : "DOWN")));
		return 0;
	}	
	case PTX_IOCOWTSET:
	{
		int wait_time;

	 	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_ioctl(%d): cmd=PTX_IOCOWTSET \n", ptyx_info->line));
		
		if (get_user(wait_time, (int *) arg))
			return -EFAULT;

		PTYX_LOCK(&ptyx_info->port_lock, flags);
		ptyx_info->open_wait_time = wait_time;
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);

		return 0;
	}
	} // end switch

	return -ENOIOCTLCMD;
}


#ifdef CONFIG_COMPAT

#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,39))		// greater that or equal to 2.6.39
static long ptyx_master_compat_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
	return ptyx_master_ioctl(tty, cmd, (unsigned long) compat_ptr(arg));
}
#elif (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21))	// Greater than 2.6.21 kernel.
static long ptyx_master_compat_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	return ptyx_master_ioctl(tty, file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

#endif


#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_master_tiocmget(struct tty_struct *tty, struct file *file)
#else
static int ptyx_master_tiocmget(struct tty_struct *tty)
#endif
{
	struct ptyx_struct *ptyx_info;

	if (!tty || !tty->driver_data)
		 return -EIO;

	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_tiocmget(%d):  value=%d  \n", ptyx_info->line, ptyx_info->modem_status)); 

	
	return ptyx_info->modem_status;
}

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_master_tiocmset(struct tty_struct *tty, struct file *file,
									       unsigned int set, unsigned int clear)
#else
static int ptyx_master_tiocmset(struct tty_struct *tty, unsigned int set, unsigned int clear)
#endif
{
	struct ptyx_struct *ptyx_info;

	if (!tty || !tty->driver_data)
		 return -EIO;

	ptyx_info = (struct ptyx_struct *) tty->driver_data;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_tiocmset(%d):\n   set=%0x; clear=%0x, nval=%0x, oval=%0x \n",
				ptyx_info->line, set, clear, (set & ~clear), ptyx_info->modem_status ));

	ptyx_info->modem_status = set & ~clear;
	return 0;
}



//*****************************************************************************
static void ptyx_master_flush_buffer(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *s_tty;
	unsigned long flags;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_master_flush_buffer): Enter\n"));

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	s_tty = ptyx_info->s_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!s_tty)
		return;

	FLUSH_BUFFER(s_tty);

}


static int ptyx_master_open(struct tty_struct *tty, struct file *filp)
{
	int	retval = -ENODEV;
	int	line = -1;		// initialize to invalid
	struct	ptyx_struct *ptyx_info;
	unsigned long flags;

	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_master_open(???): Enter, tty=0x%p, filp=0x%p, jiffies=%lu \n", 
			 			tty, filp, jiffies));
	
	if (!tty)
	{
		goto out;
	}
	
	line = tty->index - TTY_DRIVER(minor_start);

	if ((line < 0) || (line >= max_installed_ports))
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_master_open(???): Invalid port, line = %d \n", line ));
		goto out;
	}
	
	retval = -EIO;
	
	if (tty->count > 1)
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_master_open(%d): ERROR - count=%d, o only allow one master open \n", line, tty->count ));
		goto out;
	}

	ptyx_info = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[line];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	tty->driver_data = ptyx_info;
#endif	

	PTYX_LOCK(&ptyx_info->port_lock, flags);
//	// control tty needs to be already open
//	if (!ptyx_info->c_tty)
//	{
//		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_master_open(%d): ERROR - control tty not open!! \n", line ));
//		PTYX_UNLOCK(&ptyx_info->port_lock, flags);
//		goto out;
//	}
	ptyx_info->line = line;
	ptyx_info->m_tty = tty;		// set master's tty in private data
	
	// wake up slave if it's waiting on open
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	wake_up_interruptible(&ptyx_info->open_wait);

	set_bit(TTY_THROTTLED, &tty->flags);
	set_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
	retval = 0;


out:
 	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_master_open(%d): Exit tty=0x%p, returning %d, jiffies=%lu \n", 
		 		line, tty, retval, jiffies));

	return retval;
}


static void ptyx_master_set_termios(struct tty_struct *tty, STRUCT_TERMIOS *old_termios)
{
	
	ptyx_print(PTYX_DEBUG_TERMIOS, ("ptyx_master_set_termios: called current->state=%lx\n",current->state));

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(3,7,0))		// Less than 3.7.0
	tty->termios->c_cflag &= ~(CSIZE | PARENB);
	tty->termios->c_cflag |= (CS8 | CREAD);
#else
	tty->termios.c_cflag &= ~(CSIZE | PARENB);
	tty->termios.c_cflag |= (CS8 | CREAD);
#endif

	ptyx_print(PTYX_DEBUG_TERMIOS, ("ptyx_master_set_termios: return current->state=%lx\n",current->state));
}


struct tty_operations ptyx_ops_master = 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	.install			= ptyx_common_install,
	.cleanup			= ptyx_common_cleanup,
#endif
	.open 				= ptyx_master_open,
	.close 				= ptyx_master_close,
	.write 				= ptyx_master_write,
	.put_char			= NULL,
	.flush_chars		= NULL,
	.write_room 		= ptyx_master_write_room,
	.chars_in_buffer 	= ptyx_master_chars_in_buffer,
	.unthrottle 		= ptyx_master_unthrottle,

	.flush_buffer 		= ptyx_master_flush_buffer,
	.ioctl 				= ptyx_master_ioctl,
#ifdef CONFIG_COMPAT
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21))	// Greater than 2.6.21 kernel.
	.compat_ioctl		= ptyx_master_compat_ioctl,
#endif
#endif
	.set_termios 		= ptyx_master_set_termios,
	
	.tiocmget 			= ptyx_master_tiocmget,
	.tiocmset 			= ptyx_master_tiocmset,
};

