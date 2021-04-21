/*******************************************************************************
 Module: ptys.c
 
 Description: TruePort Slave driver for Linux
 
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
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
// Slave operations and functions
//********************************************************************

static void ptyx_slave_close(struct tty_struct *tty, struct file * filp)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *m_tty = NULL;
	unsigned long flags;
	int line;

	if (!tty || !tty->driver_data)		// paranoia
		return;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;
	line = tty->index - TTY_DRIVER(minor_start);

	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_slave_close(%d): Enter tty=0x%p, jiffies=%lu, tty->count=%d \n", 
		 						line,tty, jiffies, tty->count));

	// if tty-count greater than one then one then it's not the last close
	if (tty->count > 1)
	{
 		ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_slave_close(%d): Exit, Not the last close, count=%d\n", line, tty->count));
		return;
	}

	wake_up_interruptible(&tty->read_wait);
	wake_up_interruptible(&tty->write_wait);

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	// notify the line discipline to only process XON/XOFF characters.
	tty->closing = 1;
	ptyx_info->flags |= SLAVE_CLOSING;

	m_tty = ptyx_info->m_tty;

	/// if we have valid master tty
	if ( m_tty && (m_tty == ptyx_info->m_driver->ttys[line]) )	// second part paranoia
	{
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);
		wake_up_interruptible(&m_tty->read_wait);
		wake_up_interruptible(&m_tty->write_wait);
		PTYX_LOCK(&ptyx_info->port_lock, flags);

		// Now we wait for the transmit buffer to clear, ie wait for drain
		if ( (ptyx_info->closing_wait != USF_CLOSING_WAIT_NONE) && (ptyx_info->flags & SLAVE_ACTIVE) )
		{
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			tty_wait_until_sent(tty, msec_to_jiffies((long)ptyx_info->closing_wait));
			PTYX_LOCK(&ptyx_info->port_lock, flags);
		}
		// drop signals if required
		if ( _C_FLAG(tty, HUPCL) )
		{
			 ptyx_info->modem_status &= ~(TIOCM_DTR|TIOCM_RTS);
			 set_ctrl_status(ptyx_info, CTRLSTATUS_SIGNALS);  // update server signals (DTR,RTS)
		}
		// On the last close we inform the daemon that the tty is closed
		clr_ctrl_status(ptyx_info, CTRLSTATUS_OPEN);
		set_ctrl_status(ptyx_info,CTRLSTATUS_CLOSE);
		ctrl_status_snd(ptyx_info, flags);		// inform daemon to get new ctrl status 
		if (ptyx_info->blocked_open)
		{
			if (ptyx_info->close_delay)
			{
				set_current_state(TASK_INTERRUPTIBLE);
  				PTYX_UNLOCK(&ptyx_info->port_lock, flags);
				schedule_timeout(msec_to_jiffies((long)ptyx_info->close_delay));
				PTYX_LOCK(&ptyx_info->port_lock, flags);
			}
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			wake_up_interruptible(&ptyx_info->open_wait);
			PTYX_LOCK(&ptyx_info->port_lock, flags);

		}
	}

	ptyx_info->flags &= ~SLAVE_ACTIVE;
	set_current_state(TASK_INTERRUPTIBLE);
	
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	schedule_timeout(msec_to_jiffies((long)500));
	PTYX_LOCK(&ptyx_info->port_lock, flags);

	tty->closing = 0;
	ptyx_info->flags &= ~SLAVE_CLOSING;
	ptyx_info->s_tty = NULL;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	
	ptyx_print(PTYX_DEBUG_CLOSE, ("ptyx_slave_close(%d): Exit - tty=0x%p, jiffies=%lu \n", line, tty, jiffies));

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
static void ptyx_slave_unthrottle(struct tty_struct * tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *m_tty; 
	unsigned long flags;
	
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!m_tty)
		return;
	tty_wakeup(m_tty);
	set_bit(TTY_THROTTLED, &tty->flags);
}

int slave_dump_data(struct ptyx_struct *ptyx_info)
{
	int val2ret=0;
	unsigned long flags;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	if ( (ptyx_info->network_status == 0) && (ptyx_info->open_wait_time == OPENWAIT_ALWAYS_SUCCESSFUL) )
	{
		val2ret=1;
	}
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	return(val2ret);
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
static int ptyx_slave_write(struct tty_struct * tty, int from_user,
	 				const unsigned char *buf, int count)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *m_tty;
	unsigned long flags;
	int c = 0;
	int n, room;
	char *temp_buffer;
	
	if (!tty || !tty->driver_data)		// paranoia
		return 0;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;
	
	ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_slave_write(%d): buf=0x%p, count=%d\n", ptyx_info->line, buf, count));

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if ( !m_tty || tty->stopped )
		return 0;

	if (from_user) 
	{
		down(&tty->flip.pty_sem);
		temp_buffer = &tty->flip.char_buf[0];
		while (count > 0) 
		{
			/* check space so we don't copy needlessly */ 
			n = RECEIVE_ROOM(m_tty);
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
			room = RECEIVE_ROOM(m_tty);
			if (n > room)
				n = room;
			if (!n) break;
			buf   += n; 
			c     += n;
			count -= n;
			if ( !slave_dump_data(ptyx_info) )
			{
				RECEIVE_BUF(m_tty)(m_tty, temp_buffer, 0, n);
			}
			else
			{
				ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_slave_write(%d): dumping %d bytes of data from user\n", ptyx_info->line, n));
			}
		}
		up(&tty->flip.pty_sem);
	}
	else   
	{
		c = RECEIVE_ROOM(m_tty);

		if (c > count)
		{
			c = count;
		}
		if ( !slave_dump_data(ptyx_info) )
		{
			RECEIVE_BUF(m_tty)(m_tty, buf, 0, c);
		}
		else
		{
			ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_slave_write(%d): dumping %d bytes of data from user\n", ptyx_info->line, c));
		}
	}
	ptyx_info->icount.tx += c;

	return c;
}
#else // greater than or equal to  2.6.10
static int ptyx_slave_write(struct tty_struct * tty,
	 				const unsigned char *buf, int count)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *m_tty;
	unsigned long flags;
	int c = 0;
	
	if (!tty || !tty->driver_data)		// paranoia
		return 0;
  
	ptyx_info = (struct ptyx_struct *) tty->driver_data;
	
	ptyx_print(PTYX_DEBUG_WRITE, ("ptyx_slave_write(%d): buf=0x%p, count=%d\n", ptyx_info->line, buf, count));

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if ( !m_tty || tty->stopped )
		return 0;
	    
        if (!slave_dump_data(ptyx_info))
        {
            if (count > 0) 
            {
                /* Stuff the data into the input queue of the other end */
                c = tty_insert_flip_string(TTY_TO(m_tty), buf, count);
                /* And shovel */
                if (c) 
                {
                    tty_flip_buffer_push(TTY_TO(m_tty));
                    tty_wakeup(m_tty);
                }
            }
        }
        else
        {
            c = count;
        }
 
	ptyx_info->icount.tx += c;

	return c;
}
#endif // end greater than or equal to 2.6.10

 
 
static int ptyx_slave_write_room(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *m_tty;
	unsigned long flags;

	if (!tty || !tty->driver_data)		// paranoia
		return 0;

	ptyx_info = (struct ptyx_struct *) tty->driver_data;


	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!m_tty || tty->stopped)
		return 0;

	return RECEIVE_ROOM(m_tty);
}

/*
 *  
 *	The Slave side passes all characters in raw mode to the Master side's
 *	buffer where they can be read immediately, so in this case we can
 *	return the true count in the buffer.
 */
static int ptyx_slave_chars_in_buffer(struct tty_struct *tty)
{
    return 0;
}


static int get_serial_info(struct ptyx_struct *ptyx_info, struct serial_struct * retinfo)
{
	struct serial_struct tmp;
	unsigned long flags;

	if (!retinfo)
		return -EFAULT;
    
	memset(&tmp, 0, sizeof(tmp));
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	tmp.close_delay = ptyx_info->close_delay/10;
	tmp.closing_wait = 
			(ptyx_info->closing_wait == USF_CLOSING_WAIT_NONE) ? ASYNC_CLOSING_WAIT_NONE : ptyx_info->closing_wait/10;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	if (copy_to_user(retinfo,&tmp,sizeof(*retinfo)))		 
		return -EFAULT;
	return 0;
}

static int set_serial_info(struct ptyx_struct *ptyx_info, struct serial_struct * new_info)
{
	struct serial_struct new_serial;
	int  retval = 0;
	int close_delay,closing_wait;
	unsigned long flags;

	if (copy_from_user(&new_serial,new_info,sizeof(new_serial)))
	{
		return -EFAULT;
	}
	close_delay = new_serial.close_delay*10;
	closing_wait = (new_serial.closing_wait == ASYNC_CLOSING_WAIT_NONE) ? USF_CLOSING_WAIT_NONE : new_serial.closing_wait*10;
	if (!capable(CAP_SYS_ADMIN)) 
	{
	 	PTYX_LOCK(&ptyx_info->port_lock, flags);
		if (close_delay != ptyx_info->close_delay)
		{
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			return -EPERM;
		}
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);
		goto check_and_exit;
	}

	/*
	 * OK, past this point, all the error checking has been done.
	 * At this point, we start making changes.....
	 */
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	ptyx_info->close_delay = close_delay;
	ptyx_info->closing_wait = closing_wait;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);


check_and_exit:
	return retval;
}

// ptyx_slave_stop() and ptyx_slave_start()
// 
// These routines are called before setting or resetting tty->stopped.
// They enable or disable output, as necessary.
//
static void ptyx_slave_stop(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *m_tty;
	unsigned long flags;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	// if no master then return
	if (!m_tty) 
	{
		return;
	}
	
	set_ctrl_status_snd(ptyx_info,CTRLSTATUS_STOP);
	return;

}


static void ptyx_slave_start(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *m_tty;
	unsigned long flags;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	// if no master then return
	if (!m_tty) 
	{
		return;
	}

	set_ctrl_status_snd(ptyx_info,CTRLSTATUS_START);
	return;
}


//*****************************************************************************
//
//  slave ioctl functions
//
//  note: use tty_check_change() to make sure that we are not
//        changing the state of a terminal when we are not a process
//        in the forground.  See tty_io.c
// 
//*****************************************************************************

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_slave_ioctl(struct tty_struct *tty, struct file *file,
									unsigned int cmd, unsigned long arg)
#else
static int ptyx_slave_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
#endif

{
	struct ptyx_struct *ptyx_info;
	struct tty_struct *m_tty;
	struct serial_icounter_struct cnow,cprev;
	unsigned long flags;
	int retval;

	if (!tty) 
	{
		 ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(???): called with NULL tty!\n"));
		return -EIO;
	}

	ptyx_info = (struct ptyx_struct *)tty->driver_data;
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if ( !((m_tty) && ( m_tty == ptyx_info->m_driver->ttys[ptyx_info->line])) )
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): No Master tty or Invalid m_tty=0x%p \n", ptyx_info->line, m_tty));
 		return -EIO; 
	}

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): called cmd=%x\n", ptyx_info->line, cmd));

	switch(cmd) 
	{
	case TIOCGICOUNT:
	{	
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): cmd=TIOCGICOUNT \n", ptyx_info->line));
		cnow = ptyx_info->icount;
		
		if (copy_to_user((void *)arg, &cnow, sizeof(cnow)))
			return -EFAULT;
		
		return 0;
	}		
	case TIOCMIWAIT:
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): cmd=TIOCMIWAIT \n", ptyx_info->line));
		/* get the current counters */
		cprev = ptyx_info->icount;
		while (1)
		{
			PTYX_LOCK(&ptyx_info->port_lock, flags);
			ptyx_info->delta_msr_wait_done = FALSE;
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			wait_event_interruptible( ptyx_info->delta_msr_wait, (ptyx_info->delta_msr_wait_done == TRUE ) );
			/* see if a signal did it */
			if (signal_pending(current))
				return -ERESTARTSYS;
			
			cnow = ptyx_info->icount;
			if (cnow.rng == cprev.rng && cnow.dsr == cprev.dsr &&
					cnow.dcd == cprev.dcd && cnow.cts == cprev.cts)
			{
				return -EIO; /* no change => error */
			}
			if ( ((arg & TIOCM_RNG) && (cnow.rng != cprev.rng)) ||
					((arg & TIOCM_DSR) && (cnow.dsr != cprev.dsr)) ||
					((arg & TIOCM_CD)  && (cnow.dcd != cprev.dcd)) ||
					((arg & TIOCM_CTS) && (cnow.cts != cprev.cts)) )
			{
				return 0;
			}
			cprev = cnow;
		}
	
		return 0;
	}	
	case TIOCGSERIAL:
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TIOCGSERIAL:  arg=%0lx.\n", ptyx_info->line, arg));

		return get_serial_info(ptyx_info, (struct serial_struct *) arg);
	}				   
	case TIOCSSERIAL:
	{
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TIOCSSERIAL:  arg=%0lx.\n", ptyx_info->line, arg));
		return set_serial_info(ptyx_info,
					   (struct serial_struct *) arg);
		break;
   } 
	case TCFLSH:
	{
		// The linux tty driver doesn't have a flush input routine for 
		// the driver, assuming all backed up data is in the line discipline
		// buffers.  However, this is deffinately not true in our case
		// an for that mater any hardware that has recieve FIFO's.  
		// Here, we service the ioctl, but then lie and say we didn't
		// so the line discipline will process the flush also to remove
		// any buffers from the line disipline
		
		if ( (retval = tty_check_change(tty)) )
			return retval;

		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCFLSH:  arg=%0lx.\n", ptyx_info->line, arg));

		switch(arg) 
		{
		case TCIFLUSH:
		case TCIOFLUSH:
		{
		 	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCFLSH: doing TCIFLUSH/TCIOFLUSH \n", ptyx_info->line));
			set_ctrl_status_snd(ptyx_info,CTRLSTATUS_FLUSHREAD);
			if (arg == TCIFLUSH) 
				 break;
		}
		case TCOFLUSH: /* flush output, or the receive buffer */
		{	
 		 	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCFLSH: doing TCOFLUSH \n", ptyx_info->line));
			// This is handled in the tty_ioctl.c code with will call my ptyx_slave_flush_buffer
			break;
		}
		default:
		{
			/* POSIX.1 says return EINVAL if we got a bad arg */
			return (-EINVAL);
		}
		} // end switch
		/* pretend we didn't recognize this IOCTL */
		return(-ENOIOCTLCMD) ;
	} 
	//	TCSETA,TCSETS,TCSETAW,TCSETSW handled by tty layer and our set_termios
	// functions
	case TCSETAF:
	case TCSETSF:
	{
		// The linux tty driver doesn't have a flush input routine for 
		// the driver, assuming all backed up data is in the line discipline
		// buffers.  However, this is deffinately not true in our case
		// an for that mater any hardware that has recieve FIFO's.  
		// Here, we service the ioctl, but then lie and say we didn't
		// so the line discipline will process the flush also to remove
		// any buffers from the line disipline

		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCSETAF/TCSETSF \n", ptyx_info->line));

		if ( (retval = tty_check_change(tty)) )
			return retval;

		set_ctrl_status_snd(ptyx_info,CTRLSTATUS_FLUSHREAD);

		// pretend we didn't recognize this, so tty will do the wait to drain and
		// flush the line displine recieve buffers
		return(-ENOIOCTLCMD);
	}
	case TCXONC:
	{
		// The Linux Line Discipline (LD) handles TCXONC for us if we let 
		// it, but for TCION/TCIOFF it sends down the XOFF and XON characters, wether SW 
		// flow control is on or not.  We will handle the  TCXONC 
		// ioctl so that we can  do this the "right way" based on the 
		// setting of hardware or software flow control.
		ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC:  arg=%0lx.\n", ptyx_info->line, arg));

		if ( (retval = tty_check_change(tty)) )
			return retval;

		switch(arg) 
		{
		case TCOON:
		{
			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC: doing TCOON \n", ptyx_info->line ));
			ptyx_slave_start(tty);
			return 0;
		}
		case TCOOFF:
		{
			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC: doing TCOON \n", ptyx_info->line ));
			ptyx_slave_stop(tty);
			return 0;
		}
		case TCION:
 		case TCIOFF:
		{
			unsigned int modem_status, rts_delta;
			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC: doing TCION \n", ptyx_info->line ));

			// if RST flow control set then lower/raise RTS to flow off
			if ( _C_FLAG(tty, CRTSCTS) )
			{
	 			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC: CRTSCTS set \n", ptyx_info->line ));
				PTYX_LOCK(&ptyx_info->port_lock, flags);
				modem_status = ptyx_info->modem_status;
				// if RTS up then bring it down to HW flow off and inform dserver 
				if ( modem_status & TIOCM_RTS	)
				{
					if (arg == TCIOFF)
					{
						 modem_status &= ~TIOCM_RTS;			// HW flow off		 
					}
				}
				else
				{
					if (arg == TCION)
					{
						modem_status |= TIOCM_RTS;
					}
				}
				// if RTS changed then tell daemon about it
				rts_delta = (modem_status ^ ptyx_info->modem_status) & TIOCM_RTS;
				ptyx_info->modem_status = modem_status;
				PTYX_UNLOCK(&ptyx_info->port_lock, flags);
				if (rts_delta)
				{
//					set_ctrl_status(ptyx_info,CTRLSTATUS_SIGNALS);
//			 		ctrl_status_snd(ptyx_info);		// inform daemon to get new ctrl status
					set_ctrl_status_snd(ptyx_info, CTRLSTATUS_SIGNALS);		// inform daemon to get new ctrl status 
				}
			}
			// if SW flow control on then break and let tty handle sending XON or XOFF char
			if ( _I_FLAG(tty, IXOFF) )
			{
	 			ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_ioctl(%d): TCXONC: IXOFF set \n", ptyx_info->line ));
				break;
			}
			else
			{		// nothing to do
				 return 0;
			}
		}
		default:
		{
			return(-EINVAL);
		}
		}  // end switch
		// pretend we didn't recognize this, so tty will do it's normal processing
		return -ENOIOCTLCMD;
	}
	} // end switch
	
	return -ENOIOCTLCMD;
}



#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))	// Less than 2.6.27 kernel.
static void ptyx_slave_break_ctl(struct tty_struct *tty, int break_state)
#else
static int ptyx_slave_break_ctl(struct tty_struct *tty, int break_state)
#endif
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_break_ctl(%d): break_state=%d \n", ptyx_info->line, break_state));
	if (break_state == -1)	// turn on break
	{
		set_ctrl_status_snd(ptyx_info,CTRLSTATUS_BREAKON);
	}
	else					// turn off break
	{
		set_ctrl_status_snd(ptyx_info,CTRLSTATUS_BREAKOFF);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))	// Greater or equal than 2.6.27 kernel.
	return 0;
#endif
}

#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_slave_tiocmget(struct tty_struct *tty, struct file *file)
#else
static int ptyx_slave_tiocmget(struct tty_struct *tty)
#endif
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	unsigned int modem_status;
	unsigned long flags;
	
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	modem_status = ptyx_info->modem_status;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_tiocmget(%d): value = %0x\n", ptyx_info->line, modem_status ));
	return (modem_status);
}


#if (LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,39))		// Less than 2.6.39
static int ptyx_slave_tiocmset(struct tty_struct *tty, struct file *file,
									       unsigned int set, unsigned int clear)
#else
static int ptyx_slave_tiocmset(struct tty_struct *tty, unsigned int set, unsigned int clear)
#endif
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	unsigned int new_val;
	unsigned long flags;
	struct tty_struct *m_tty = NULL;

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	new_val = ptyx_info->modem_status;
	new_val	|= set;
	new_val &= ~clear;
   
	ptyx_info->modem_status = new_val;
    m_tty = ptyx_info->m_tty;

	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_tiocmset:\n   set=%0x; clear=%0x, nval=%0x, oval=%0x\n",
				set, clear, new_val, ptyx_info->modem_status ));

	// if we have a master tty
	if (m_tty) 
	{
        set_ctrl_status_snd(ptyx_info,CTRLSTATUS_SIGNALS);
        schedule();
    }
	return 0;
}


static void ptyx_slave_flush_buffer(struct tty_struct *tty)
{
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	struct tty_struct *m_tty;
	unsigned long flags;

	ptyx_print(PTYX_DEBUG_IOCTL, ("ptyx_slave_flush_buffer(%d): Enter \n",ptyx_info->line));

	PTYX_LOCK(&ptyx_info->port_lock, flags);
	m_tty = ptyx_info->m_tty;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	if (!m_tty)
		return;

	FLUSH_BUFFER(m_tty);
	set_ctrl_status_snd(ptyx_info, CTRLSTATUS_FLUSHWRITE);
}

// block open until we are ready
// Note - assumes being called with ptyx_info->port_lock locked
//
static int slave_block_til_ready(struct tty_struct *tty, struct file * filp, unsigned long flags)
{
	DECLARE_WAITQUEUE(wait, current);
	struct ptyx_struct *ptyx_info=(struct ptyx_struct *) tty->driver_data;
	int retval=0;
	int do_clocal = 0;
//	unsigned long flags;

	if (tty->flags & (1 << TTY_IO_ERROR))
	{
		return -EIO;
	}
	ptyx_print(PTYX_DEBUG_BLOCK_TIL_READY, ("slave_block_til_ready(%d): open_wait_time=%d nonblock=%s\n",
		  						ptyx_info->line, ptyx_info->open_wait_time,filp->f_flags & O_NONBLOCK?"yes":"no"));
	if ( (ptyx_info->open_wait_time >= 0) || ( ptyx_info->open_wait_time == -2) )
	{
		unsigned long orig_jiffies=jiffies;
		long timeout=-1;
		long delaytime = msec_to_jiffies(1000);   // delay 1 sec between checks

		if (ptyx_info->open_wait_time >= 0)
		{
			timeout = msec_to_jiffies((long)ptyx_info->open_wait_time);
		}
		
		// we need to wait for the network connection to be established
		add_wait_queue(&ptyx_info->open_wait, &wait);
		ptyx_info->blocked_open++;
		for ( ;; )
		{
			set_current_state(TASK_INTERRUPTIBLE);
			if (ptyx_info->network_status)
				break;
			
			if (signal_pending(current))
			{
				retval = -ERESTARTSYS;
				break;
			}
			if ( (ptyx_info->open_wait_time != OPENWAIT_FOREVER) && 
				 ( (ptyx_info->open_wait_time == 0) || 
					time_after(jiffies, orig_jiffies + timeout) ||
					!ptyx_info->m_tty  ) )
			{
				// don't wait for network connection
				retval = -EIO;
				break;
			}
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			PTTY_UNLOCK(tty);
			schedule_timeout(delaytime);
			PTTY_LOCK(tty);
			PTYX_LOCK(&ptyx_info->port_lock, flags);
		} // end for(;;)
		remove_wait_queue(&ptyx_info->open_wait, &wait);
		set_current_state(TASK_RUNNING);
		ptyx_info->blocked_open--;
	}

	if (ptyx_info->network_status)
	{
		set_ctrl_status(ptyx_info,CTRLSTATUS_SIGNALS);  // update server signals (DTR,RTS)
		ctrl_status_snd(ptyx_info, flags);		// inform daemon to get new ctrl status 
	}
	
	if ((filp->f_flags & O_NONBLOCK))
	{
		ptyx_print(PTYX_DEBUG_BLOCK_TIL_READY, ("slave_block_til_ready(%d): returning %d\n",
			 					ptyx_info->line, retval));
		return(retval);
	}
#if (LINUX_VERSION_CODE <  KERNEL_VERSION(3,7,0))		// Less than 3.7.0
	if (tty->termios->c_cflag & CLOCAL)	// don't need DCD
#else
	if (tty->termios.c_cflag & CLOCAL)	// don't need DCD
#endif
	{
		do_clocal = 1;
	}
	else
	{
		retval = 0;	// reset the return value to 0 for now
	}
	
	add_wait_queue(&ptyx_info->open_wait, &wait);
	ptyx_info->blocked_open++;
	for ( ;; )
	{
		set_current_state(TASK_INTERRUPTIBLE);
		if (do_clocal || (ptyx_info->modem_status & TIOCM_CD))
			break;
		
		if (signal_pending(current))
		{
			retval = -ERESTARTSYS;
			break;
		}
		PTYX_UNLOCK(&ptyx_info->port_lock, flags);
		PTTY_UNLOCK(tty);
		schedule();
		PTTY_LOCK(tty);
		PTYX_LOCK(&ptyx_info->port_lock, flags);
	} // end for(;;)
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&ptyx_info->open_wait, &wait);
	ptyx_info->blocked_open--;
	return(retval);
}


/*
	on opens we have 2 modes of operation
	Wait for TCP connection
		In this mode, we will wait the specified time for the TCP connection to
		be established.  On return, if the TCP connection is down, we will return
		an error.
	Don't wait for TCP connection 
		In this mode, we do not wait for the TCP connection to be established.
		On return, if the TCP connection is down, we will return no error.
		
	In either case, blocking and clocal settings are obeyed.  So if we need
	to wait for DCD, we will wait for the network connection to be established.
*/

static int ptyx_slave_open(struct tty_struct *tty, struct file * filp)
{
	int	retval = -ENODEV;
	int	line = -1;		// initialize to invalid
	struct	ptyx_struct *ptyx_info;
	struct tty_struct *m_tty = NULL;	// master's tty
	unsigned long flags;

	if (!tty)
	{
		goto out;
	}

	line = tty->index - TTY_DRIVER(minor_start);
	if ((line < 0) || (line >= max_installed_ports))
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(???): Enter Invalid port, line = %d \n", line ));
		goto out;
	}

	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): Enter - tty=0x%p, filp=0x%p, jiffies=%lu, tty->count=%d \n", 
			 			line,tty, filp, jiffies, tty->count));

	retval = -EIO;

	ptyx_info = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[line];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	tty->driver_data = ptyx_info;
#endif	

	PTYX_LOCK(&ptyx_info->port_lock, flags);
//	ptyx_info->line = line;
	m_tty = ptyx_info->m_tty;
	
	// If there's a master's tty  and it's equal to the one stored in our private
	// data then continue, else wait for up to MAX_MASTER_OPEN_WAIT_TIME seconds before returning error
	if ( !( m_tty && (m_tty == ptyx_info->m_driver->ttys[line]) ) )
	{
		unsigned long orig_jiffies=jiffies;
		long timeout = msec_to_jiffies((long)MAX_MASTER_OPEN_WAIT_TIME*1000);
		long delaytime = msec_to_jiffies(1000);   // delay 1 sec between checks
		DECLARE_WAITQUEUE(wait, current);

		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): Master not open, waiting ...., timeout=%lu, delaytime=%lu \n",
			 						line, timeout, delaytime ));

		//Prepare to accept the wakeup, then release our locks and release control.
		add_wait_queue(&ptyx_info->open_wait, &wait);
		ptyx_info->blocked_open++;
		for ( ; ; )
		{
			set_current_state(TASK_INTERRUPTIBLE);

			if ( time_after(jiffies, orig_jiffies + timeout) )
			{
				ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): ERROR - Timed out waiting for Master to open \n", line ));
				break;
			}
			// has the master been opened yet ?
			if ( ( (m_tty = ptyx_info->m_tty) != NULL) && (m_tty == ptyx_info->m_driver->ttys[line]) )
			{
		 		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): Master now open, continue \n", line ));
				break;		// yes, break out and continue
			}
			if (signal_pending(current))
			{		
				ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): wait interrupted by signal, Exiting \n", line ));
				retval = -ERESTARTSYS;				
				break;
			}
			PTYX_UNLOCK(&ptyx_info->port_lock, flags);
			schedule_timeout(delaytime);
			PTYX_LOCK(&ptyx_info->port_lock, flags);

			ptyx_print(PTYX_DEBUG_BLOCK_TIL_READY, ("ptyx_slave_open(%d): woken up while waiting for master,  jiffies=%lu \n",
									line, jiffies ));

		} // end for(;;)
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&ptyx_info->open_wait, &wait);
		ptyx_info->blocked_open--;
			
		// check if master opened 
		if ( m_tty == NULL)
			 goto out_unlock;
	}

	set_bit(TTY_THROTTLED, &tty->flags);
	set_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);

	if ( _C_FLAG(tty, CBAUD ) )
	{
		ptyx_info->modem_status |= (TIOCM_DTR | TIOCM_RTS);
		set_ctrl_status(ptyx_info,CTRLSTATUS_SIGNALS);
		ctrl_status_snd(ptyx_info, flags);		// inform daemon to get new ctrl status 
	}
	
	// if first open of slave device then inform the daemon
	if ( !( ptyx_info->flags & SLAVE_ACTIVE) )
	{
 		clr_ctrl_status(ptyx_info,CTRLSTATUS_CLOSE);
		set_ctrl_status(ptyx_info,CTRLSTATUS_OPEN);
		ctrl_status_snd(ptyx_info, flags);		// inform daemon to get new ctrl status 
	}

	retval = slave_block_til_ready(tty, filp, flags);
	
	if (retval)
	{
		ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): returning after block_til_ready with %d\n",line,retval));
		goto out_unlock;
	}

	ptyx_info->s_tty = tty;		// set slave's tty
	ptyx_info->flags |= SLAVE_ACTIVE;

	retval = 0;

out_unlock:
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
	
out:
 	ptyx_print(PTYX_DEBUG_OPEN, ("ptyx_slave_open(%d): Exit tty=0x%p, returning %d, jiffies=%lu \n", 
		 			line, tty, retval, jiffies));

	return retval;
}


static void ptyx_slave_set_termios(struct tty_struct *tty, STRUCT_TERMIOS *old_termios)
{
	struct ptyx_struct *ptyx_info = (struct ptyx_struct *)tty->driver_data;
	
	ptyx_print(PTYX_DEBUG_TERMIOS, ("ptyx_slave_set_termios(%d): called current->state=%lx\n", 
		 				ptyx_info->line, current->state));

	set_ctrl_status_snd(ptyx_info, CTRLSTATUS_TERMIOS);
	schedule();							// check this later to see if I need it

	ptyx_print(PTYX_DEBUG_TERMIOS, ("ptyx_slave_set_termios(%d): return current->state=%lx\n",
		 				ptyx_info->line, current->state));
}


static void ptyx_slave_wait_until_sent(struct tty_struct *tty, int timeout)
{
	struct ptyx_struct *ptyx_info = (struct ptyx_struct *)tty->driver_data;
	unsigned long orig_jiffies, char_time, flags;

	ptyx_print(PTYX_DEBUG_WAIT_UNTIL_SENT, ("ptyx_slave_wait_until_sent(%d): timeout=%d, jiff=%lu\n",
		 						ptyx_info->line, timeout, jiffies));
	if (slave_dump_data(ptyx_info))
	{
		return;
	}
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	ptyx_info->pending_drain_end = 1;
	set_ctrl_status(ptyx_info, CTRLSTATUS_DRAIN);
	ctrl_status_snd(ptyx_info, flags);		// inform daemon to get new ctrl status 
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

	orig_jiffies = jiffies;
	char_time = msec_to_jiffies(10);
	
	/* We go through the loop at least once because we can't tell
	 * exactly when the last character exits the shifter.  There can
	 * be at least two characters waiting to be sent after the buffers
	 * are empty.
	 */
	do 
	{
//		ptyx_print(PTYX_DEBUG_WAIT_UNTIL_SENT, ("ptyx_slave_wait_until_sent(%d): (jiff=%lu)...\n", ptyx_info->line, jiffies));

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(char_time);
		if (signal_pending(current))
			break;
		if (timeout && time_after(jiffies, orig_jiffies + timeout))
			break;
		
	} 
	while (ptyx_info->pending_drain_end);

	set_current_state(TASK_RUNNING);
	ptyx_print(PTYX_DEBUG_WAIT_UNTIL_SENT, ("ptyx_slave_wait_until_sent(%d): (jiff=%lu)...done\n",ptyx_info->line, jiffies));
}


struct tty_operations ptyx_ops_slave = 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	.install			= ptyx_common_install,
	.cleanup			= ptyx_common_cleanup,
#endif
	.open 				= ptyx_slave_open,
	.close 				= ptyx_slave_close,
	.write 				= ptyx_slave_write,
//	.put_char			= NULL,
//	.flush_chars		= NULL,
	.write_room 		= ptyx_slave_write_room,
	.chars_in_buffer	= ptyx_slave_chars_in_buffer,
	.flush_buffer 		= ptyx_slave_flush_buffer,
	.ioctl 				= ptyx_slave_ioctl,
//	.throttle			= NULL,	
	.unthrottle 		= ptyx_slave_unthrottle,
//	.send_xchar		= NULL,
	.set_termios 		= ptyx_slave_set_termios,
//	.set_ldisc			= NULL,
	.stop 				= ptyx_slave_stop,
	.start 				= ptyx_slave_start,
//	.hangup				= NULL,
	.break_ctl 			= ptyx_slave_break_ctl,
	.wait_until_sent 	= ptyx_slave_wait_until_sent,
	.tiocmget 			= ptyx_slave_tiocmget,
	.tiocmset 			= ptyx_slave_tiocmset,
};



