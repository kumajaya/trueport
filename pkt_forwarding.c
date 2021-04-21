//*****************************************************************************
//
//	Description : This file contains code to implement the packet forwarding
//					feature. This includes the actual packet forwarding
//					functions well as reading the configuration.
//
//*****************************************************************************

#include 	<stdio.h>
#include	<stdlib.h>
#include 	<sys/unistd.h>
#include	<inttypes.h>
#include	<string.h>
#include	<ctype.h>
#include	<sys/time.h>
#include	<termios.h>
#include	<errno.h>
#include <netinet/in.h>
#include	"tp.h"
#include	"pkt_forwarding.h"
#include	"trueport.h"

int write_dserver_data(int fd, buf_t *dstbuf, unsigned char *srcbuf, int srcbuf_len);


static void push_char_frame(forwarding_info_t *pInfo, unsigned char ch);
static void push_char_end( forwarding_info_t *pInfo,unsigned char ch );
static void store_char( forwarding_info_t *pInfo, unsigned char ch );

static long get_time_left( struct timeval *start_time, unsigned short time_out );

static int parse_pkt_fwd_config( forwarding_info_t *pInfo, char *file_name, char *tcp_host, int net_port );
static char *pkt_fwd_service_options( forwarding_info_t *pInfo, CMD cmd, char *opt, char *arg);
int get_tcp_hostport(char *host_port, char **TCPhost, char **TCPport);


// resets the pktforwarding buffer
//
void ResetPktFwdBuf(forwarding_info_t *pInfo)
{
		pInfo->data_count = 0;
		if (UseNewPktFwdLogic(pInfo))
		{
			pInfo->curr_data_count = 0;
			pInfo->pCurrDataPkt =  &pInfo->char_buf[0];
			pInfo->char_buf_ptr = pInfo->pCurrDataPkt + TPPKT_HDR_SIZE;
			pInfo->count = TPPKT_HDR_SIZE;			// adjust count for pkt header
		}
		else
		{
			pInfo->count = 0;
			pInfo->char_buf_ptr = &pInfo->char_buf[0];
		}
		pInfo->dscmd = 0;
}

// Check if we are configured to use new TruePort full mode pkt fwd logic inwhich
// we put some commands into the pkt fwd buf
//
int UseNewPktFwdLogic(forwarding_info_t *pInfo)
{
	// check if in full mode and only on idle is configured
	if ( (mode == pm_full) && (( pInfo->forwarding & PKT_FORWARD_ON_IDLE) && !(pInfo->forwarding & ~PKT_FORWARD_ON_IDLE)) )
	{
		return TRUE;
	}
	return FALSE;
}


//******************************************************************************
//
// process the received buffer and put characters in the packet forwarding
// buffer based on forwarding config
//
void process_packet_forwarding( forwarding_info_t *pInfo, buf_t2 *buf )
{
	unsigned char	ch;
	int restartforcetimeflag = 0;
	int ret;
	
	if (pInfo->forwarding == 0)
	{
		// forwarding not configured
		dserver_out_buf.offset = 0;
		dserver_out_buf.len = 0;
		ret = write_dserver_data(dserver_fd, &dserver_out_buf, buf->data_ptr, buf->len);
		// if error writeing data then close network connection
		if (ret < 0)
		{
			 trace(tl_error, "process_packet_forwarding(): write_dserver_data() returned error ret=%d, Closing connection \n", ret);
			 close_connection();
		}
		buf->len = 0;
	}
	else
	{
	DEBUG_FORWARDING(trace (tl_debug,"process_packet_forwarding: start, pInfo 0x%p, forwarding 0x%x, buffer length %d\n", \
						pInfo, pInfo->forwarding, buf->len));
		// forwarding configured
		pInfo->write_blocked = FALSE;
		// While there is data left and
		while( buf->len > 0 && !pInfo->write_blocked )
		{
			pInfo->stored_char = FALSE;
			ch = *buf->data_ptr++;
			buf->len--;
			if (pInfo->forwarding & PKT_FORWARD_ON_FRAME)
			{
				DEBUG_FORWARDING(trace (tl_debug,"push_char: PKT_FORWARD_ON_FRAME\n"));
				push_char_frame(pInfo, ch);
			}
			else
			{
				if (pInfo->data_count== 0)
				{
					 restartforcetimeflag = TRUE;
				}
				else
				{
					 restartforcetimeflag = FALSE;
				}
				if (pInfo->forwarding & PKT_FORWARD_ON_CHAR)
				{
					DEBUG_FORWARDING(trace (tl_debug,"push_char: PKT_FORWARD_ON_CHAR\n"));
					push_char_end(pInfo, ch);
				}
				if (pInfo->forwarding & PKT_FORWARD_ON_TIME)
				{
					DEBUG_FORWARDING(trace (tl_debug,"push_char: PKT_FORWARD_ON_TIME\n"));
					if (restartforcetimeflag)
					{
						DEBUG_FORWARDING(trace (tl_debug,"push_char: restart forward on timer\n"));
						gettimeofday(&pInfo->force_time_start, NULL);
					}
					// forward when a total time is reached
					store_char(pInfo, ch);
				}

				if (pInfo->forwarding & PKT_FORWARD_ON_IDLE)
				{
					DEBUG_FORWARDING(trace (tl_debug,"push_char: PKT_FORWARD_ON_IDLE\n"));
					DEBUG_FORWARDING(trace (tl_debug,"push_char: restart idle timer\n"));
					gettimeofday(&pInfo->idle_time_start, NULL);
					// forward when the idle timer expires
					store_char(pInfo, ch);
				}


				if (pInfo->forwarding & PKT_FORWARD_ON_COUNT)
				{
					// forward when a count is reached
					DEBUG_FORWARDING(trace (tl_debug,"push_char: PKT_FORWARD_ON_COUNT\n"));
					store_char(pInfo, ch);
					if ( buf->len == 0 && pInfo->data_count >= pInfo->packet_size  )
					{
						forward_frame(pInfo);
					}
				}
			}
		}
	}
	DEBUG_FORWARDING(trace (tl_debug,"process_packet_forwarding: end, pInfo 0x%p\n", pInfo));
}



//******************************************************************************
//
// put character in the correct buffer based if forwarding frame
//

static void push_char_frame(forwarding_info_t *pInfo, unsigned char ch)
{
	DEBUG_FORWARDING( trace (tl_debug,"push_char_frame: start, pInfo 0x%p, state %d, ch %x\n",\
	                          pInfo, pInfo->forward_state, ch));

	switch (pInfo->forward_state)
	{
		case FORWARD_STATE_START_1OF1:
		if (ch == pInfo->start_frame1)
		{
			switch (pInfo->start_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				break;
				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo, ch);
				break;
				default:
				break;
			}
			if (pInfo->forwarding & PKT_FORWARD_END_CHAR2)
			{
				pInfo->forward_state = FORWARD_STATE_END_1OF2;
			}
			else
			{
				pInfo->forward_state = FORWARD_STATE_END_1OF1;
			}
		}
		break;

		case FORWARD_STATE_START_1OF2:
		if (ch == pInfo->start_frame1)
		{
			switch (pInfo->start_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				break;
				case PKT_FORWARD_TRANS_TRIG:
				pInfo->saved_ch = ch;
				break;
				default:
				break;
			}
			pInfo->forward_state = FORWARD_STATE_START_2OF2;
		}
		break;

		case FORWARD_STATE_START_2OF2:
		if (ch == pInfo->start_frame2)
		{
			switch (pInfo->start_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				break;
				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo,pInfo->saved_ch);
				pInfo->stored_char = FALSE;
				store_char(pInfo, ch);
				break;
				default:
				break;
			}
			if (pInfo->forwarding & PKT_FORWARD_END_CHAR2)
			{
				pInfo->forward_state = FORWARD_STATE_END_1OF2;
			}
			else
			{
				pInfo->forward_state = FORWARD_STATE_END_1OF1;
			}
		}
		else
		{
			if (ch == pInfo->start_frame1)
			{
				switch (pInfo->start_transmit_rule)
				{
					case PKT_FORWARD_TRANS_STRIP:
					break;
					case PKT_FORWARD_TRANS_TRIG:
					pInfo->saved_ch = ch;
					break;
					default:
					break;
				}
			}
			else
			{
				pInfo->forward_state = FORWARD_STATE_START_1OF2;
			}
		}
		break;

		case FORWARD_STATE_END_1OF1:
		if (ch == pInfo->end_frame1)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo, ch);
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG_1:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF1;
				break;
				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF2;
				break;
				default:
				break;
			}
		}
		else
		{
			store_char(pInfo, ch);
		}
		break;

		case FORWARD_STATE_END_1OF2:
		if (ch == pInfo->end_frame1)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				pInfo->saved_ch = ch;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				case PKT_FORWARD_TRANS_TRIG_1:
				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				break;
				default:
				break;
			}
			pInfo->forward_state = FORWARD_STATE_END_2OF2;
		}
		else
		{
			store_char(pInfo, ch);
		}
		break;

		case FORWARD_STATE_END_2OF2:
		if (ch == pInfo->end_frame2)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo, ch);
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG_1:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF1;
				break;
				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF2;
				break;
				default:
				break;
			}
		}
		else
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				store_char(pInfo,pInfo->saved_ch);
				pInfo->stored_char = FALSE;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				case PKT_FORWARD_TRANS_TRIG_1:
				case PKT_FORWARD_TRANS_TRIG_2:
				break;
				default:
				break;
			}
			if (ch == pInfo->end_frame1)
			{
				switch (pInfo->end_transmit_rule)
				{
					case PKT_FORWARD_TRANS_STRIP:
					pInfo->saved_ch = ch;
					break;
					case PKT_FORWARD_TRANS_TRIG:
					case PKT_FORWARD_TRANS_TRIG_1:
					case PKT_FORWARD_TRANS_TRIG_2:
					store_char(pInfo, ch);
					break;
					default:
					break;
				}
			}
			else
			{
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_END_1OF2;
			}
		}
		break;

		case FORWARD_STATE_WAITING_1OF1:
		store_char(pInfo, ch);
		forward_frame(pInfo);
		pInfo->forward_state = pInfo->base_state;
		break;

		case FORWARD_STATE_WAITING_1OF2:
		store_char(pInfo, ch);
		pInfo->forward_state = FORWARD_STATE_WAITING_2OF2;
		break;

		case FORWARD_STATE_WAITING_2OF2:
		store_char(pInfo, ch);
		forward_frame(pInfo);
		pInfo->forward_state = pInfo->base_state;
		break;

		default:
		break;
	}
	DEBUG_FORWARDING( trace (tl_debug,"push_char_frame: end state %d\n",pInfo->forward_state));
}



//******************************************************************************
//
// put character in the correct buffer based if forwarding end char
//

static void push_char_end( forwarding_info_t *pInfo,unsigned char ch )
{
	DEBUG_FORWARDING( trace (tl_debug,"push_char_end: start, pInfo 0x%p, state %d\n",\
	                         	pInfo, pInfo->forward_state));

	switch (pInfo->forward_state)
	{
	case FORWARD_STATE_END_1OF1:
	{
		if (ch == pInfo->trigger_char1)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				pInfo->stored_char = TRUE;
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;

				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo, ch);
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;

				case PKT_FORWARD_TRANS_TRIG_1:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF1;
				break;

				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF2;
				break;

				default:
				break;
			}
		}
		else
		{
			store_char(pInfo, ch);
		}
		break;
		}
	case FORWARD_STATE_END_1OF2:
	{
		if (ch == pInfo->trigger_char1)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				pInfo->saved_ch = ch;
				pInfo->stored_char = TRUE;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				case PKT_FORWARD_TRANS_TRIG_1:
				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				break;
				default:
				break;
			}
			pInfo->forward_state = FORWARD_STATE_END_2OF2;
		}
		else
		{
			store_char(pInfo, ch);
		}
		break;
	}
	case FORWARD_STATE_END_2OF2:
	{
		if (ch == pInfo->trigger_char2)
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				pInfo->stored_char = TRUE;
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				store_char(pInfo, ch);
				forward_frame(pInfo);
				pInfo->forward_state = pInfo->base_state;
				break;
				case PKT_FORWARD_TRANS_TRIG_1:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF1;
				break;
				case PKT_FORWARD_TRANS_TRIG_2:
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_WAITING_1OF2;
				break;
				default:
				break;
			}
		}
		else
		{
			switch (pInfo->end_transmit_rule)
			{
				case PKT_FORWARD_TRANS_STRIP:
				store_char(pInfo,pInfo->saved_ch);
				pInfo->stored_char = FALSE;
				break;
				case PKT_FORWARD_TRANS_TRIG:
				case PKT_FORWARD_TRANS_TRIG_1:
				case PKT_FORWARD_TRANS_TRIG_2:
				break;
				default:
				break;
			}
			if (ch == pInfo->trigger_char1)
			{
				switch (pInfo->end_transmit_rule)
				{
					case PKT_FORWARD_TRANS_STRIP:
					pInfo->saved_ch = ch;
					pInfo->stored_char = TRUE;
					break;
					case PKT_FORWARD_TRANS_TRIG:
					case PKT_FORWARD_TRANS_TRIG_1:
					case PKT_FORWARD_TRANS_TRIG_2:
					store_char(pInfo, ch);
					break;
					default:
					break;
				}
			}
			else
			{
				store_char(pInfo, ch);
				pInfo->forward_state = FORWARD_STATE_END_1OF2;
			}
		}
		break;
	}
	case FORWARD_STATE_WAITING_1OF1:
	{
		store_char(pInfo, ch);
		forward_frame(pInfo);
		pInfo->forward_state = pInfo->base_state;
		break;
	}
	case FORWARD_STATE_WAITING_1OF2:
	{
		store_char(pInfo, ch);
		pInfo->forward_state = FORWARD_STATE_WAITING_2OF2;
		break;
	}
	case FORWARD_STATE_WAITING_2OF2:
	{
		store_char(pInfo, ch);
		forward_frame(pInfo);
		pInfo->forward_state = pInfo->base_state;
		break;
	}
	default:
		break;
	}
	DEBUG_FORWARDING( trace (tl_debug,"push_char_end: end state %d\n",pInfo->forward_state));
}


//******************************************************************************
//
// save the char and status in our flip buffer
//
static void store_char( forwarding_info_t *pInfo, unsigned char ch )
{
	DEBUG_FORWARDING( trace (tl_debug,"store_char: start pInfo=0x%p, stored_char=%d, count=%d, data_count=%d char = %c \n",\
	                         pInfo, pInfo->stored_char,pInfo->count, pInfo->data_count, ch));
	if (!pInfo->stored_char)
	{
		// reset char_buf_ptr jic not initialized
		if( (pInfo->char_buf_ptr == NULL) || (UseNewPktFwdLogic(pInfo) && (pInfo->pCurrDataPkt == NULL)) )
		{
			ResetPktFwdBuf(pInfo);
		}
		*pInfo->char_buf_ptr = ch;
		pInfo->char_buf_ptr++;
		pInfo->data_count++;
		pInfo->curr_data_count++;
		pInfo->count++;
		pInfo->stored_char = TRUE;
		// data or total pkt fwd buf exceeded then forward
		if ( (pInfo->data_count == MAX_DATA_PKT_FWD_COUNT) || 
						(pInfo->count == MAX_PKT_FWD_BUF_SIZE) )
		{
			forward_frame(pInfo);
		}
	}
	DEBUG_FORWARDING( trace (tl_debug,"store_char: end stored_char=%d, count=%d, data_count=%d \n",pInfo->stored_char,pInfo->count,  pInfo->data_count));
}


//******************************************************************************
//
// forward the frame based on forwarding config
//

void  forward_frame( forwarding_info_t *pInfo )
{
	 int ret;
	 
   if (pInfo->data_count)
   {
		DEBUG_FORWARDING( trace (tl_debug, "forward_frame: start - count=%d, data_count=%d, curr_data_count=%d \n", pInfo->count, pInfo->data_count,  pInfo->curr_data_count ));
		if (UseNewPktFwdLogic(pInfo) )
		{
			// if theres a current data length then setup data pkt count  
			if ( (pInfo->pCurrDataPkt != NULL) && pInfo->curr_data_count)
			{
				*pInfo->pCurrDataPkt = (unsigned char)((((uint16_t)pInfo->curr_data_count)>> 8) & 0xFF);
				*(pInfo->pCurrDataPkt+1) = (unsigned char)(((uint16_t)pInfo->curr_data_count) & 0xFF);
			}
			else	// if no current data then strip of pkt header
			{
				pInfo->count -= TPPKT_HDR_SIZE;
			}
		}
		dserver_out_buf.offset = 0;
		ret = write_dserver_data(dserver_fd, &dserver_out_buf, 
	   						(unsigned char *) &pInfo->char_buf, pInfo->count);
		if (ret < 0)
		{
			 trace(tl_error, "forward_frame(): write_dserver_data() returned error ret=%d, Closing connection \n", ret);
			 close_connection();
		}

		if ( dserver_out_buf.len > 0 )
		{
		   pInfo->write_blocked = TRUE;
		}
		ResetPktFwdBuf(pInfo);
		DEBUG_FORWARDING( trace (tl_debug, "forward_frame: end \n" ));
   }
}



//******************************************************************************
//
//		set_time_out()
//
//		Determine the smallest interval before a timer will elapse.
//
//		Set this interval in the time_out variable.
//

struct timeval *set_time_out( forwarding_info_t *pInfo, struct timeval *time_out)
{
	long	time_left;
	long	smallest_time_left = -1;

	time_out->tv_sec = 0;
	time_out->tv_usec = 0;

    if (ptyx_ctrl_status)
    {
        return time_out;
    }
    
	if (pInfo->forwarding)
	{
		if ( (pInfo->forwarding & PKT_FORWARD_ON_IDLE) && (pInfo->data_count != 0) )
		{
			if ( (smallest_time_left = get_time_left( &pInfo->idle_time_start, pInfo->idle_time )) <= 0 )
            {
				return time_out;
            }
		}

		if ( (pInfo->forwarding & PKT_FORWARD_ON_TIME) && (pInfo->data_count != 0) )
		{
			if ( (time_left = get_time_left( &pInfo->force_time_start, pInfo->force_time )) <= 0 )
            {
				return time_out;
            }
			else if ( smallest_time_left == -1 || time_left < smallest_time_left )
            {
				smallest_time_left = time_left;
            }
		}
	}
	if ( keepalive_time )
	{
		if ( (time_left = get_time_left( &pInfo->keepalive_start, keepalive_time * 1000 )) <= 0 )
        {
			return time_out;
        }
		else if ( smallest_time_left == -1 || time_left < smallest_time_left )
        {
			smallest_time_left = time_left;
        }
	}
	if ( client_tcp_host && delay_close_tcp_flag)
	{
		if ( (time_left = get_time_left( &pInfo->delay_close_tcp_start, delay_close_tcp_time * 1000 )) <= 0 )
        {
			return time_out;
        }
		else if ( smallest_time_left == -1 || time_left < smallest_time_left )
        {
			smallest_time_left = time_left;
        }
	}

	if ( smallest_time_left == -1 )
		return NULL;	// no timeout configured.
	else
	{
		time_out->tv_sec = smallest_time_left / 1000000;
		time_out->tv_usec = smallest_time_left % 1000000;
		return time_out;
	}
}



//******************************************************************************
//
//		get_time_left()
//
//		Determine the time left before the specified timer elapses.
//		The time_out value is in milliseconds.
//
//		Returns value in microseconds.
//

static long get_time_left( struct timeval *start_time, unsigned short time_out )
{
	struct timeval curr_time;
	unsigned long	elapsed_time;

	gettimeofday( &curr_time, NULL );

	if ( curr_time.tv_usec < start_time->tv_usec)
	{
		elapsed_time = (1000000 + curr_time.tv_usec - start_time->tv_usec);
		elapsed_time += (curr_time.tv_sec - start_time->tv_sec - 1) * 1000000;
	}
	else
	{
		elapsed_time = (curr_time.tv_usec - start_time->tv_usec);
		elapsed_time += (curr_time.tv_sec - start_time->tv_sec) * 1000000;
	}

	if ( (time_out * 1000 ) < elapsed_time )
		return 0;
	else
		return (time_out * 1000 - elapsed_time);
}



//******************************************************************************
//
//		check_time_out()
//
//		Determine the elapsed time since "start_time". If it is greater than
//		"time_out" (value in milliseconds), then return 1. Else return 0
//
//

int check_time_out( struct timeval *start_time, unsigned short time_out )
{
	struct timeval curr_time;
	unsigned long	elapsed_time;

	gettimeofday( &curr_time, NULL );

	/* Perform the carry for the later subtraction by updating y. */
	if ( curr_time.tv_usec < start_time->tv_usec)
	{
		elapsed_time = (1000000 + curr_time.tv_usec - start_time->tv_usec);
		elapsed_time += (curr_time.tv_sec - start_time->tv_sec - 1) * 1000000;
	}
	else
	{
		elapsed_time = (curr_time.tv_usec - start_time->tv_usec);
		elapsed_time += (curr_time.tv_sec - start_time->tv_sec) * 1000000;
	}

	if ( elapsed_time >= (unsigned long)time_out * 1000 )
		return 1;
	else
		return 0;
}



//******************************************************************************
//
//	Fill in the specified configuration structure with hard coded values
//		and call the parse_pkg_fwd_config() routine to read the configuration file
//		and fill in the remaining values.

int	get_pkt_fwd_config( forwarding_info_t *pInfo, char *tcp_host, int net_port_num )
{

	if ( MAX_PKT_FWD_BUF_SIZE > DS_BUF_SIZE )
	{
		trace (tl_error, "Packet forward buffer (%d) must be smaller than dserver network buffer (%d).\n",
		       MAX_PKT_FWD_BUF_SIZE, DS_BUF_SIZE );
		return -1;
	}

	pInfo->char_buf_ptr = &pInfo->char_buf[0];

	// Parse config file
	if (parse_pkt_fwd_config( pInfo, DEFAULT_PKT_FWD_CFG_FILE, tcp_host, net_port_num ) < 0 )
	{
		return -1;
	}

	if (pInfo->forwarding & (PKT_FORWARD_START_CHAR1|PKT_FORWARD_START_CHAR2))
	{
		if (pInfo->forwarding & PKT_FORWARD_START_CHAR2)
		{
			pInfo->forward_state = FORWARD_STATE_START_1OF2;
			pInfo->base_state = FORWARD_STATE_START_1OF2;
		}
		else
		{
			pInfo->forward_state = FORWARD_STATE_START_1OF1;
			pInfo->base_state = FORWARD_STATE_START_1OF1;
		}
	}
	else if (pInfo->forwarding & (PKT_FORWARD_ON_CHAR1|PKT_FORWARD_ON_CHAR2))
	{
		if (pInfo->forwarding & PKT_FORWARD_ON_CHAR2)
		{
			pInfo->forward_state = FORWARD_STATE_END_1OF2;
			pInfo->base_state = FORWARD_STATE_END_1OF2;
		}
		else
		{
			pInfo->forward_state = FORWARD_STATE_END_1OF1;
			pInfo->base_state = FORWARD_STATE_END_1OF1;
		}
	}

	if (tcp_host == NULL)
	{
		
		DEBUG_FORWARDING(\
					trace (tl_debug, "get_pkt_fwd_config: host=NULL, port=%d, pInfo=%p \n", \
					 		net_port_num, pInfo ));
	}
	else
	{
		DEBUG_FORWARDING(\
					trace (tl_debug, "get_pkt_fwd_config: host %s, port %d, pInfo=%p \n", \
					 		tcp_host, net_port_num, pInfo ));
	}
	DEBUG_FORWARDING(\
	         		trace (tl_debug, "     forwarding 0x%x, start rule 0x%x, end rule 0x%x \n",\
	                        pInfo->forwarding,pInfo->start_transmit_rule, pInfo->end_transmit_rule));
	DEBUG_FORWARDING(\
	          		trace (tl_debug, "     end_trigger_char1 0x%x, end_trigger2 0x%x \n",\
	                        pInfo->trigger_char1,pInfo->trigger_char2 ));
	DEBUG_FORWARDING(\
	           		trace (tl_debug, "     packet_size %d, idle time %d, force time %d \n",\
	                        pInfo->packet_size, pInfo->idle_time,pInfo->force_time ) );
	DEBUG_FORWARDING(\
	           		trace (tl_debug, "     frame start 1 0x%x, start 2 0x%x, end 1 0x%x, end 2 0x%x\n",\
	                        pInfo->start_frame1,pInfo->start_frame2,pInfo->end_frame1,pInfo->end_frame2));

	return 0;
}



//******************************************************************************
//
static int parse_pkt_fwd_config( forwarding_info_t *pInfo, 
								char *file_name, char *tcp_host, int net_port )
{
	FILE 	*fp;
	char 	confline[CONFLINELEN], *arg, *opt, *errstr;
	int 	i;
	long	section_number = -1;
	int		line_number;
	char  *tmphost, *tmpport;
	
	fp=fopen( file_name, "r" );
	if ( !fp )
	{
		trace( tl_error, "error opening packet forwarding config file: %s\n", file_name );
		return(-1);
	}
	line_number = 0;
	while( fgets( confline, CONFLINELEN, fp ) )
	{
		line_number++;
		opt=confline;
		while( isspace( *opt ) )
			opt++; /* remove initial whitespaces */
		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		if ( opt[0]=='\0' || opt[0]=='#' || opt[0]==';' ) /* empty or comment */
			continue;
		if ( opt[0]=='[' && opt[strlen( opt )-1]==']' )
		{ /* new section */

			// Correct port number configuration processing is done.
			if ( section_number != -1 )
				break;

			opt++;
			opt[strlen( opt )-1]='\0';
			if (get_tcp_hostport(opt, &tmphost, &tmpport) < 0)
			{
				perror("tpadm: Bad [host:port_number] in SSL config file\n" );
				return(-1);
			}
			if (tcp_host != NULL)
			{
			   // if host doesn't match then go to next section
			   if ( tmphost == NULL || strcmp(tmphost, tcp_host) )
			   {
				  continue;
			   }
			}
			if (  net_port == atoi(tmpport) )
			{
				section_number = net_port;
				errstr = pkt_fwd_service_options( pInfo, CMD_INIT, NULL, NULL );
				if ( errstr != NULL )
				{
					trace( tl_error, "Packet Forwarding 0 config error: %s\n", errstr );
					fclose( fp );
					return(-1);
				}
			}
			continue;
		}
		// Do not parse config data if not the proper section.
		if ( section_number == -1 )
			continue;

		arg=strchr( confline, '=' );
		if ( !arg )
		{
			trace( tl_error, "file %s line %d: No '=' found", file_name, line_number );
			fclose( fp );
			return( -1 );
		}
		*arg++='\0'; /* split into option name and argument value */
		for( i=strlen( opt )-1; i>=0 && isspace( opt[i] ); i-- )
			opt[i]='\0'; /* remove trailing whitespaces */
		while( isspace( *arg ) )
			arg++; /* remove initial whitespaces */

		errstr = pkt_fwd_service_options( pInfo, CMD_EXEC, opt, arg );
		if ( errstr != NULL )
		{
			trace( tl_error, "Packet Forwarding 1 config error: %s\n", errstr );
			fclose( fp );
			return(-1);
		}

	} //while

	fclose( fp );
	if ( section_number == -1 )
	{
		trace( tl_error, "Packet Forwarding entry %s:%d not found\n", tcp_host, net_port );
		return(-1);		// configuration for specified net port not found.
	}
	trace( tl_debug, "Parsing packet forwarding config file pasing is done\n" );
	return(0);
}



//******************************************************************************
//
static char *pkt_fwd_service_options( forwarding_info_t *pInfo, CMD cmd, char * opt, char * arg)
{

	if ( cmd == CMD_INIT )
	{
		pInfo->forwarding = 0;
	}

	/* packet size */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->packet_size = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "packet_size"))
			break;
		if ( read_and_verify_input( arg, 1, 1024, CFG_DECIMAL, &pInfo->packet_size ) < 0 )
		{
			return "argument should be decimal number 1 - 1024 ";
		}
		else if ( pInfo->packet_size != 0 )
		{
			pInfo->forwarding |= PKT_FORWARD_ON_COUNT;
		}
		return NULL; /* OK */
	}

	/* idle time */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->idle_time = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "idle_time"))
			break;
		if ( read_and_verify_input( arg, 0, 65535, CFG_DECIMAL, &pInfo->idle_time ) < 0 )
		{
			return "argument should be decimal number 0 - 65535 ";
		}
		else if ( pInfo->idle_time != 0 )
		{
			pInfo->forwarding |= PKT_FORWARD_ON_IDLE;
		}

		return NULL; /* OK */
	}

	/* force time */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->force_time = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "force_transmit_time"))
			break;
		if ( read_and_verify_input( arg, 0, 65535, CFG_DECIMAL, &pInfo->force_time ) < 0 )
		{
			return "argument should be decimal number 0 - 65535 ";
		}
		else if ( pInfo->force_time != 0 )
		{
			pInfo->forwarding |= PKT_FORWARD_ON_TIME;
		}
		return NULL; /* OK */
	}

	/* start_transmit_rule */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->start_transmit_rule = PKT_FORWARD_TRANS_TRIG;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "transmit_SOF_chars"))
			break;
		if (!strcasecmp(arg, "on"))
			pInfo->start_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
		else if (!strcasecmp(arg, "off"))
			pInfo->start_transmit_rule = PKT_FORWARD_TRANS_STRIP;
		else
			return "argument should be either 'off' or 'on'";

		return NULL; /* OK */
	}


	/* start_frame1 */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->start_frame1 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "SOF1_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->start_frame1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_START_CHAR1;
		// Do not allow the other rules if packet framing is enabled.
		pInfo->forwarding &= ~(PKT_FORWARD_ON_COUNT | PKT_FORWARD_ON_IDLE | PKT_FORWARD_ON_TIME);
		return NULL; /* OK */
	}


	/* start_frame2 */
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->start_frame2 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "SOF2_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->start_frame2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_START_CHAR2;
		return NULL; /* OK */
	}

	// end_frame1
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->end_frame1 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "EOF1_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->end_frame1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_END_CHAR1;
		return NULL; /* OK */
	}

	// end_frame2
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->end_frame2 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "EOF2_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->end_frame2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_END_CHAR2;
		return NULL; /* OK */
	}

	// trigger_char1
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->trigger_char1 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "end_trigger1_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->trigger_char1 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_ON_CHAR1;
		return NULL; /* OK */
	}

	// trigger_char2
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->trigger_char2 = 0;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "end_trigger2_char"))
			break;
		if ( read_and_verify_input( arg, 0, 0xff, CFG_HEXIDECIMAL, &pInfo->trigger_char2 ) < 0 )
		{
			return "argument should be hexidecimal number 00 - FF ";
		}
		pInfo->forwarding |= PKT_FORWARD_ON_CHAR2;
		return NULL; /* OK */
	}

	// end_transmit_rule
	switch(cmd)
	{
		case CMD_INIT:
		pInfo->end_transmit_rule = PKT_FORWARD_TRANS_TRIG;
		break;
		case CMD_EXEC:
		if (strcasecmp(opt, "trigger_forwarding_rule"))
			break;
		if (!strcasecmp(arg, "trigger"))
			pInfo->end_transmit_rule =  PKT_FORWARD_TRANS_TRIG;
		else if (!strcasecmp(arg, "trigger+1"))
			pInfo->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_1;
		else if (!strcasecmp(arg, "trigger+2"))
			pInfo->end_transmit_rule = PKT_FORWARD_TRANS_TRIG_2;
		else if (!strcasecmp(arg, "strip-trigger"))
			pInfo->end_transmit_rule = PKT_FORWARD_TRANS_STRIP;
		else
			return "argument should be either 'trigger', 'trigger+1', 'trigger+2' or 'strip-trigger'";

		return NULL; /* OK */
	}

	if (cmd==CMD_EXEC)
		return "option_not_found";

	return NULL; /* OK */
}



//*****************************************************************************
//
//	Read in a line from stdin. Verifiy that the DECIMAL or HEXIDECIMAL value is
//	less than the specified limit.
//
//	Return	1 - Value is within limits
//			-1 - Error in input in either format or range of values.
//

int read_and_verify_input(	char *input,
                           long lower_limit,
                           long upper_limit,
                           int format,
                           void *retValue )
{
	int				intValue;
	unsigned int	uintValue;
	int				i;

	errno = 0;
	if ( format == CFG_DECIMAL )
	{
		for( i=0; i < strlen( input ); i++ )
		{
			if ( !isdigit(input[i]) )
			{
				return -1;
			}
		}

		if ( sscanf( input, "%d", &intValue) == 0 || errno != 0 )
			return -1;
		if ( (intValue < lower_limit || intValue > upper_limit) && intValue != 0 )
			return -1;
		*(unsigned short *)retValue = (unsigned short)intValue;
		return 1;
	}

	else
	{
		for( i=0; i < strlen( input ); i++ )
		{
			if ( !isxdigit(input[i]) )
			{
				return -1;
			}
		}

		if ( sscanf( input, "%x", &uintValue) == 0 || errno != 0 )
			return -1;
		if ( (uintValue < lower_limit || uintValue > upper_limit) && uintValue != 0 )
			return -1;
		*(unsigned char *)retValue = (unsigned char)uintValue;
		return 1;
	}
}

// this function will attempt to put the given inline dserver command into the 
// packet forwarding buffer.
//   returns  TRUE - command was sucessfully put into pkt fwd buffer
//            FALSE - can not put command into buffer it should be forwarded to dserver
//
int ChkPutDsCmdPktFwdBuf(forwarding_info_t *pInfo, char *dscmd_ptr, int dscmd_size)
{
	pInfo->dscmd = 0; 	//clear dscmd 

	// Is pkt fwd idel configured ?
	if (!UseNewPktFwdLogic(pInfo) )
		return FALSE;

	// if no data in pkt fwd buffer then don't put command
	if (pInfo->data_count == 0)
		return FALSE;

	// if dserver cmd won't fit in pkt fwd buffer then forward it
	if ( (MAX_PKT_FWD_BUF_SIZE - pInfo->count) < dscmd_size )
	{
		forward_frame(pInfo);
		return FALSE;
	}
	
	// fill in data pkt header and reset current data count if required
	if (pInfo->curr_data_count)
	{
		*pInfo->pCurrDataPkt = (unsigned char)(((htons((uint16_t)pInfo->curr_data_count))>> 8) & 0xFF);
		*(pInfo->pCurrDataPkt+1) = (unsigned char)((htons((uint16_t)pInfo->curr_data_count)) & 0xFF);
		pInfo->curr_data_count = 0;		// reset current data count
	}
	else
	{
		// no current data so back up char_buf_ptr
		pInfo->char_buf_ptr -= TPPKT_HDR_SIZE;
		pInfo->count -= TPPKT_HDR_SIZE;	// strip off pkt header

	}
	
	// copy dserver command to pkt fwd buffer
	memcpy( pInfo->char_buf_ptr, dscmd_ptr, dscmd_size);

	pInfo->count += dscmd_size + TPPKT_HDR_SIZE; // set up for next data pkt header    
	pInfo->char_buf_ptr +=  (dscmd_size + TPPKT_HDR_SIZE); 
	pInfo->pCurrDataPkt = (pInfo->char_buf_ptr - TPPKT_HDR_SIZE);		// put pointer to next data pkt after this command
	trace( tl_debug, "ChkPutDsCmdPktFwdBuf(): cmd=0x%x going into Pkt Fwd Buf., count=%d \n", *(dscmd_ptr+TPPKT_HDR_SIZE), pInfo->count  );

	return TRUE;

}
