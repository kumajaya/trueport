/*******************************************************************************
 Module: ptyx.h
 
 Description: TruePort common driver defines
 
 Copyright (c) Perle Systems Limited 1999-2009
 All rights reserved
 
*******************************************************************************/


// *****  global variables.

extern unsigned int	max_installed_ports;



/* Set of debugging defines */
#define PTYX_DEBUG_OPEN					0x00000001
#define PTYX_DEBUG_CLOSE				0x00000002
#define PTYX_DEBUG_WRITE				0x00000004
#define PTYX_DEBUG_IOCTL				0x00000008
#define PTYX_DEBUG_WAIT_UNTIL_SENT	0x00000010
#define PTYX_DEBUG_BLOCK_TIL_READY	0x00000020
#define PTYX_DEBUG_TERMIOS				0x00000040
#define PTYX_DEBUG_MISC					0x00000080
#define PTYX_DEBUG_SPIN_LOCK			0x00000100

// uncomment line below and set ptyx_debug_level for debug tracing 
//#define PTYX_DEBUG

extern unsigned long  ptyx_debug_level; 

#define PTYX_PARANOIA_CHECK


#define TTY_DRIVER(x)	(tty->driver->x)


#if defined(PTYX_DEBUG)
#define ptyx_print(flag, expr)				\
{														\
	if ( (flag & ptyx_debug_level) != 0)	\
		printk expr ;								\
}
#else
#define ptyx_print(flag, expr) {}
#endif


#define	PTYX_LOCK(slock, flags)					\
		do {						\
  		ptyx_print(PTYX_DEBUG_SPIN_LOCK, ("PTYX_LOCK: %s:%d slock = 0x%p \n", __FUNCTION__, __LINE__, slock)); \
		spin_lock_irqsave(slock, flags); \
		} while (0)
		
#define	PTYX_UNLOCK(slock, flags)					\
		do {						\
		spin_unlock_irqrestore(slock, flags); \
  		ptyx_print(PTYX_DEBUG_SPIN_LOCK, ("PTYX_UNLOCK: %s:%d slock = 0x%p \n", __FUNCTION__, __LINE__, slock)); \
		} while (0)


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#define PTTY_LOCK(arg) {}
#define PTTY_UNLOCK(arg) {}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
#define PTTY_LOCK(arg) tty_lock()
#define PTTY_UNLOCK(arg) tty_unlock()
#else
#define PTTY_LOCK(arg) tty_lock(arg)
#define PTTY_UNLOCK(arg) tty_unlock(arg)
#endif 

#ifndef USF_CLOSING_WAIT_NONE
#define USF_CLOSING_WAIT_NONE   (~0U)
#endif

#define msec_to_jiffies(x)  ((x) * HZ / 1000)

#define	DEFAULT_CLOSE_DELAY			500		// 0.5 sec
#define DEFAULT_CLOSING_WAIT_TIME	30000		// 30 sec


struct ptyx_struct 
{
	int	magic;
	unsigned int line;
	wait_queue_head_t open_wait;
	unsigned int modem_status;
	struct serial_icounter_struct icount;
	wait_queue_head_t delta_msr_wait;
	int delta_msr_wait_done;
	int blocked_open; 				// # of blocked opens
	unsigned int close_delay;		// in msec.  If set and there are blocked opens, time to wait before signaling block processes to recheck for DCD 
	unsigned int closing_wait;	// in msec.  If set, time to wait for tx to drain before closing ; (~0=disabled, 0=forever) 
	unsigned int ctrl_status;		// ptyx master/slave driver control statuses
	int pending_drain_end;
	int network_status;				// network status (0=down, 1=up)
	int open_wait_time;				// if <0, don't wait for TCP connection.  If >=0, wait specified time for TCP connection
	unsigned int	flags;			// common flags
	struct tty_struct *s_tty;		// pointer to slave tty structure
	struct tty_driver *s_driver; // pointer to slave driver structure
	struct tty_struct *m_tty;		// pointer to master tty structure
	struct tty_driver *m_driver;	// pointer to slave driver structure
	struct tty_struct *c_tty;		// pointer to control tty structure
	struct tty_driver *c_driver;	// pointer to control driver structure
	spinlock_t port_lock;			// lock to protect setting/reading of shared driver_data
};


// defines for ptyx_info flags
#define SLAVE_ACTIVE		0x00000001		// indicates that at least 1 slave is active
#define SLAVE_CLOSING	0x00000004		// slave tty is in the process of clossing


// common functions

extern void set_ctrl_status(struct ptyx_struct *ptyx_info, unsigned int status);
extern void ctrl_status_snd(struct ptyx_struct *ptyx_info, unsigned long flags);
extern void set_ctrl_status_snd(struct ptyx_struct *ptyx_info, unsigned int status);
extern void clr_ctrl_status(struct ptyx_struct *ptyx_info, unsigned int status);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
extern int 	ptyx_common_install(struct tty_driver *driver, struct tty_struct *tty);
extern void ptyx_common_cleanup(struct tty_struct *tty);
#endif 
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))&&(LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)))
extern int my_buffer_space_avail(struct tty_struct *tty);
#endif





