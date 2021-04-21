/*******************************************************************************
 Module: ptymod.c
 
 Description: TruePort ptyx module code 
 
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
#include <linux/slab.h>			//kmalloc prototypes
#include <asm/uaccess.h>
#include <asm/bitops.h>

#define BUILDING_PTY_C 1
#include <linux/devpts_fs.h>

#include <linux/serial.h>

#include "../tp_ver.h"
#include "../tp.h"
#include "ptyx.h"


//unsigned long  ptyx_debug_level = -1;
//unsigned long  ptyx_debug_level =	PTYX_DEBUG_OPEN 
//											|  PTYX_DEBUG_CLOSE
//											|  PTYX_DEBUG_WRITE
//											|  PTYX_DEBUG_IOCTL
//											|  PTYX_DEBUG_WAIT_UNTIL_SENT
//											|  PTYX_DEBUG_BLOCK_TIL_READY
//											|  PTYX_DEBUG_TERMIOS
//											|  PTYX_DEBUG_MISC
//											|  PTYX_DEBUG_SPIN_LOCK
;

unsigned long  ptyx_debug_level = 0;



/*
    The SLAVE_ACTIVE flag is necessary because if the open fails, and returns
    an error, the tty layer calls the close to cleanup.  Unfortunately, if
    the open failed because the network connection is down, when the close
    is called, it tries to "wait_til_sent" and delays for 30 seconds by default.
    The SLAVE_ACTIVE flag is used to bypass the wait_til_sent when there are no
    active slaves.
*/


// The following variable is a command line parameter to the ptyx module.
// It is used to configure the maximum number of ports to install 

unsigned int	max_installed_ports = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
module_param(max_installed_ports, int, (S_IRUSR  | S_IRGRP | S_IROTH) );
#else
MODULE_PARM( max_installed_ports, "i" );
#endif

MODULE_PARM_DESC(max_installed_ports, "Maximum number of ports installed by ptyx module");


struct tty_driver *ptyx_master_driver, *ptyx_slave_driver, *ptyx_control_driver;

// an array of pointers to lines ptyx_info
struct ptyx_struct	**pty_state_table = NULL;

//********************************************************************
//  Common helper functions used by both master and slave
//********************************************************************

// needs to be called with ptyx_info->port_lock locked
void set_ctrl_status(struct ptyx_struct *ptyx_info, unsigned int status)
{
	ptyx_info->ctrl_status |= status;
}

// needs to be called with ptyx_info->port_lock locked
void clr_ctrl_status(struct ptyx_struct *ptyx_info, unsigned int status)
{
	ptyx_info->ctrl_status &= (~status);
}

// New control status is already set 
// just need to wakeup control tty to send new status to daemon
//   Note: * This funcction assumes it is called with ptyx_info-port_lock locked 
//
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10))		// less then 2.6.10
void ctrl_status_snd(struct ptyx_struct *ptyx_info, unsigned long flags)
{
	struct tty_struct *c_tty;
	unsigned int	snd_ctrl_status;

	c_tty = ptyx_info->c_tty;

	if ( !c_tty )
	{
		return;
	}

	if (RECEIVE_ROOM(c_tty) < sizeof(snd_ctrl_status))
	{
		ptyx_print(PTYX_DEBUG_WRITE, ("set_ctrl_status_snd(%d): No room to send control status to control receive_room=%d \n",
							ptyx_info->line, RECEIVE_ROOM(c_tty) ));
		return;
	}
	// get status and send, clearing out status
	snd_ctrl_status = ptyx_info->ctrl_status;
	ptyx_info->ctrl_status = 0;
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

 	ptyx_print(PTYX_DEBUG_WRITE, ("set_ctrl_status_snd(%d): ctrl_status = 0x%x \n",ptyx_info->line, snd_ctrl_status));

	RECEIVE_BUF(c_tty)(c_tty, (unsigned char *)&snd_ctrl_status, 0, sizeof(snd_ctrl_status));

	wake_up_interruptible(&c_tty->read_wait);
	PTYX_LOCK(&ptyx_info->port_lock, flags);

}
#else // greater than or equal to  2.6.10

void ctrl_status_snd(struct ptyx_struct *ptyx_info, unsigned long flags)
{
	struct tty_struct *c_tty;
	unsigned int snd_ctrl_status;
	int c = 0;
	
	c_tty = ptyx_info->c_tty;

	if ( !c_tty )
	{
		return;
	}

	// get status and send, clearing out status
	snd_ctrl_status = ptyx_info->ctrl_status;
	ptyx_info->ctrl_status = 0;
	
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);
 	ptyx_print(PTYX_DEBUG_WRITE, ("set_ctrl_status_snd(%d): ctrl_status = 0x%x \n",ptyx_info->line, snd_ctrl_status));

    /* Stuff the data into the input queue of the other end */
    c = tty_insert_flip_string(TTY_TO(c_tty), (unsigned char *)&snd_ctrl_status, sizeof(snd_ctrl_status));
    /* And shovel */
    if (c) 
    {
        tty_flip_buffer_push(TTY_TO(c_tty));
        tty_wakeup(c_tty);
    }
	PTYX_LOCK(&ptyx_info->port_lock, flags);
}
#endif

// set the given control status in send signal to daemon to get new status
// Note: * This call should not be called with ptyx_info->port_lock locked 
//			 * if entire control status can't be written then no status is sent
//
void set_ctrl_status_snd(struct ptyx_struct *ptyx_info, unsigned int status)
{
	unsigned long flags;
	
	PTYX_LOCK(&ptyx_info->port_lock, flags);
	ptyx_info->ctrl_status = ptyx_info->ctrl_status | status;
	ctrl_status_snd(ptyx_info, flags);
	PTYX_UNLOCK(&ptyx_info->port_lock, flags);

}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)

static void ptyx_common_port_destroy(struct tty_port *port)
{
	kfree(port);
}

const struct tty_port_operations ptyx_common_port_ops = {
	.destruct = ptyx_common_port_destroy,
};

/**
 *	ptyx_common_install	-	install method
 *	@driver: the driver in use
 *	@tty: the tty being bound
 *
 *	Look up and bind the tty and the driver together. Initialize
 *	any needed private data (in our case the termios)
 */

int ptyx_common_install(struct tty_driver *driver, struct tty_struct *tty)
{
	int 				idx = tty->index;
	struct	tty_port	*port;
	int 				ret = -ENOMEM;

	port = kmalloc(sizeof *port, GFP_KERNEL);
	if (!port)
		return ret;
	
	tty_port_init(port);
	port->ops = &ptyx_common_port_ops;
	ret = tty_port_install(port, driver, tty);

	if (ret == 0)
		tty->driver_data = ((struct ptyx_struct **)TTY_DRIVER(driver_state))[idx];
	else
		tty_port_put(port);
	return ret;
}


/**
 *	ptyx_common_cleanup	-	called on the last tty kref drop
 *	@tty: the tty being destroyed
 *
 *	Called asynchronously when the last reference to the tty is dropped.
 *	We cannot destroy the tty->driver_data port kref until this point
 */

 
void ptyx_common_cleanup(struct tty_struct *tty)
{
	tty->driver_data = NULL;	/* Bug trap */
	tty_port_put(tty->port);
}

#endif

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))&&(LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)))
int my_buffer_space_avail(struct tty_struct *tty)
{
	int n = 32768 - tty->port->buf.memory_used;
	if (n < 0)
		return 0;
	return n;
}
#endif


//********************************************************************
// global module type functions
//********************************************************************
extern struct tty_operations ptyx_ops_master;
extern struct tty_operations ptyx_ops_slave;
extern struct tty_operations ptyx_ops_control;

static int __init ptyx_init(void)
{
	int i, retval=0;
	struct ptyx_struct *ptyx_info;

	printk("Perle TruePort Driver v%s, Initializing %d ports\n", TP_VERSION, max_installed_ports);

	if ( (max_installed_ports > PTYX_NUM_PTYS) || (max_installed_ports < 1) )
	{
		printk("ptyx module input paramater max_installed_ports=%d is invalid \n", max_installed_ports);
		retval = -EINVAL;
		goto init_out;
	}
	
	ptyx_master_driver = alloc_tty_driver(max_installed_ports);
	if (!ptyx_master_driver)
	{
		printk("Couldn't allocate ptyx master driver \n");
		retval = -ENOMEM;
		goto init_out;
	}
	
	ptyx_slave_driver = alloc_tty_driver(max_installed_ports);
	if (!ptyx_slave_driver)
	{
		printk("Couldn't allocate ptyx slave driver \n");
		retval = -ENOMEM;
		goto init_out;
	}

	ptyx_control_driver = alloc_tty_driver(max_installed_ports);
	if (!ptyx_control_driver)
	{
		printk("Couldn't allocate ptyx ctrl status driver \n");
		retval = -ENOMEM;
		goto init_out;
	}

	pty_state_table = kmalloc( max_installed_ports * sizeof(struct ptyx_struct *), GFP_KERNEL);

	if (!pty_state_table )
	{
		retval = -ENOMEM;
		goto init_out;
	}
	else
	{
		memset(pty_state_table, 0,  max_installed_ports * sizeof(struct ptyx_struct *));
	}

	for (i = 0; i < max_installed_ports; i++)
	{
		ptyx_info = pty_state_table[i]  = kmalloc(sizeof(struct ptyx_struct), GFP_KERNEL);

		if (!ptyx_info)
		{
			retval = -ENOMEM;
			goto init_out;
		}
		else
		{
			memset(ptyx_info , 0, sizeof(struct ptyx_struct));
		}
		
		ptyx_info->line = -1;
		init_waitqueue_head(&ptyx_info->open_wait);
		init_waitqueue_head(&ptyx_info->delta_msr_wait);
		ptyx_info->close_delay = DEFAULT_CLOSE_DELAY;
		ptyx_info->closing_wait = DEFAULT_CLOSING_WAIT_TIME;
		ptyx_info->modem_status = TIOCM_DTR | TIOCM_RTS;    // the default baud is 38400 so default DTR and RTS on
		ptyx_info->open_wait_time = DEFAULT_OPEN_WAIT_TIME * 1000; // convert to ms
		spin_lock_init(&ptyx_info->port_lock);
		ptyx_info->m_driver = ptyx_master_driver;
		ptyx_info->s_driver = ptyx_slave_driver;
		ptyx_info->c_driver = ptyx_control_driver;
	}
	
// Master Driver 
	ptyx_master_driver->owner = THIS_MODULE;
	ptyx_master_driver->magic = TTY_DRIVER_MAGIC;
	ptyx_master_driver->driver_name = "ptyx_master";
	ptyx_master_driver->name = PTYX_MASTER_NAME;
	ptyx_master_driver->major = PTYX_MASTER_MAJOR;
	ptyx_master_driver->minor_start = 0;
	ptyx_master_driver->type = TTY_DRIVER_TYPE_SERIAL;
	ptyx_master_driver->subtype = SERIAL_TYPE_NORMAL;
	ptyx_master_driver->init_termios = tty_std_termios;
	ptyx_master_driver->init_termios.c_iflag = 0;
	ptyx_master_driver->init_termios.c_oflag = 0;
	ptyx_master_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	ptyx_master_driver->init_termios.c_lflag = 0;
	ptyx_master_driver->flags =  TTY_DRIVER_REAL_RAW;
	ptyx_master_driver->driver_state = pty_state_table;		// global pointer ot private data
	tty_set_operations(ptyx_master_driver, &ptyx_ops_master);


// Slave driver
	ptyx_slave_driver->owner = THIS_MODULE;
	ptyx_slave_driver->magic = TTY_DRIVER_MAGIC;
	ptyx_slave_driver->driver_name = "ptyx_slave";
	ptyx_slave_driver->name = PTYX_SLAVE_NAME;
	ptyx_slave_driver->major = PTYX_SLAVE_MAJOR;
	ptyx_slave_driver->minor_start = 0;
	ptyx_slave_driver->type = TTY_DRIVER_TYPE_SERIAL;
	ptyx_slave_driver->subtype = SERIAL_TYPE_NORMAL;
	ptyx_slave_driver->init_termios = tty_std_termios;
	ptyx_slave_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	ptyx_slave_driver->flags =  TTY_DRIVER_REAL_RAW;
	ptyx_slave_driver->driver_state = pty_state_table;		// global pointer ot private data
	tty_set_operations(ptyx_slave_driver, &ptyx_ops_slave);

	// Control status Driver 
	ptyx_control_driver->owner = THIS_MODULE;
	ptyx_control_driver->magic = TTY_DRIVER_MAGIC;
	ptyx_control_driver->driver_name = "ptyx_control";
	ptyx_control_driver->name = PTYX_CTRL_NAME;
	ptyx_control_driver->major = PTYX_CTRL_MAJOR;
	ptyx_control_driver->minor_start = 0;
	ptyx_control_driver->type = TTY_DRIVER_TYPE_SERIAL;
	ptyx_control_driver->subtype = SERIAL_TYPE_NORMAL;
	ptyx_control_driver->init_termios = tty_std_termios;
	ptyx_control_driver->init_termios.c_iflag = 0;
	ptyx_control_driver->init_termios.c_oflag = 0;
	ptyx_control_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	ptyx_control_driver->init_termios.c_lflag = 0;
	ptyx_control_driver->flags =  TTY_DRIVER_REAL_RAW;
	ptyx_control_driver->driver_state = pty_state_table;		// global pointer ot private data
	tty_set_operations(ptyx_control_driver, &ptyx_ops_control);

	if ( (retval = tty_register_driver(ptyx_control_driver)) < 0 )
	{
 		put_tty_driver(ptyx_control_driver);
		printk("Couldn't register ptyx control status driver, retval=%d3 \n", retval);
	}

	if ( (retval = tty_register_driver(ptyx_slave_driver)) < 0 )
	{
		put_tty_driver(ptyx_slave_driver);
		printk("Couldn't register ptyx slave driver, retval=%d \n", retval);
		goto init_out;
	}

	if ( (retval = tty_register_driver(ptyx_master_driver)) < 0 )
	{
 		put_tty_driver(ptyx_slave_driver);
		printk("Couldn't register ptyx master driver, retval=%d \n", retval);
	}

init_out:
 
	return retval;
}

static void __exit ptyx_finish(void) 
{
	int e1, i;
	
	ptyx_print(PTYX_DEBUG_MISC, ("ptyx_finish(): unregistering driver \n"));

	if ( (e1 = tty_unregister_driver(ptyx_master_driver)) )
	{
		printk("ptyx_finish(): ptyx faied to unregister master TTY driver (%d) \n", e1);
	}
	put_tty_driver(ptyx_master_driver);

	if ( (e1 = tty_unregister_driver(ptyx_slave_driver)) )
	{
		printk("ptyx_finish(): ptyx faied to unregister slave TTY driver (%d) \n", e1);
	}
	put_tty_driver(ptyx_slave_driver);

	if ( (e1 = tty_unregister_driver(ptyx_control_driver)) )
	{
		printk("ptyx_finish(): ptyx faied to unregister control status TTY driver (%d) \n", e1);
	}
	put_tty_driver(ptyx_control_driver);
	
	if (pty_state_table)
	{
	 	for (i = 0; i < max_installed_ports; i++)
		{
			if (pty_state_table[i])
			{
				 kfree(pty_state_table[i]);
			}
		}
		kfree(pty_state_table);
	}
	
	printk("Perle TruePort Driver v%s unloading\n", TP_VERSION);
}

module_init(ptyx_init);
module_exit(ptyx_finish);

MODULE_DESCRIPTION("Perle TruePort pty driver");
MODULE_AUTHOR("");

MODULE_LICENSE("GPL");


