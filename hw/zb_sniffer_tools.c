/***************************************************************************
*                      ZBOSS ZigBee Pro 2007 stack                         *
*                                                                          *
*          Copyright (c) 2013 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*          Copyright (c) 2012 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*          Copyright (c) 2011 DSR Corporation Denver CO, USA.              *
*                       http://www.dsr-wireless.com                        *
*                                                                          *
*                            All rights reserved.                          *
*                                                                          *
*                                                                          *
* ZigBee Pro 2007 stack, also known as ZBOSS (R) ZB stack is available     *
* under either the terms of the Commercial License or the GNU General      *
* Public License version 2.0.  As a recipient of ZigBee Pro 2007 stack,    *
* you may choose which license to receive this code under (except as noted *
* in per-module LICENSE files).                                            *
*                                                                          *
* ZBOSS is a registered trademark of DSR Corporation AKA Data Storage      *
* Research LLC.                                                            *
*                                                                          *
* GNU General Public License Usage                                         *
* This file may be used under the terms of the GNU General Public License  *
* version 2.0 as published by the Free Software Foundation and appearing   *
* in the file LICENSE.GPL included in the packaging of this file.  Please  *
* review the following information to ensure the GNU General Public        *
* License version 2.0 requirements will be met:                            *
* http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.                   *
*                                                                          *
* Commercial Usage                                                         *
* Licensees holding valid DSR Commercial licenses may use this file        *
* in accordance with the DSR Commercial License Agreement provided with    *
* the Software or, alternatively, in accordance with the terms contained   *
* in a written agreement between you and DSR.                              *
****************************************************************************
PURPOSE:
*/

#include "zb_common.h"

#include "zb_cc25xx.h"

#ifdef ZB_SNIFFER_USB_TRACE
#include "hal_board.h"
#include "usb_uart.h"
#elif defined ZB_SNIFFER_SERIAL_TRACE
#include "zb_8051_serial.h"
#else
#error Sniffer trace type is not defined: use ZB_SNIFFER_USB_TRACE or ZB_SNIFFER_SERIAL_TRACE
#endif

#include "util_buffer.h"
#include "zb_sniffer_tools.h"

ringBuf_t rbTxBuf;

void zb_sniffer_init()
{
  ZB_MEMSET((void*)&g_izb, 0, sizeof(zb_intr_globals_t));

  zb_8051_init_timer();
  init_zu2400();

  bufInit(&rbTxBuf);
#ifndef ZB_SNIFFER_USB_TRACE
  zb_init_8051_serial();
#else
  usbUartInit(UART_BAUDRATE_115200);
  ZB_SNIFFER_TURN_ON_LED();
#endif
  ZB_ENABLE_ALL_INTER();
}

void zb_start_sniffer(zb_uint8_t channel)
{
  /* Received channel is in range of supported ZB channels*/
  if (channel >= ZB_TRANSCEIVER_START_CHANNEL_NUMBER &&
      channel <= ZB_TRANSCEIVER_MAX_CHANNEL_NUMBER)
  {
    /* Flush output buffer to prevent old chanel's packets appearance
       in the output of a new capture */
    bufFlush(&rbTxBuf);

    ZB_TRANSCEIVER_SET_CHANNEL(channel);
    ISFLUSHRX();
    ISRXON();
    
#ifndef ZB_SNIFFER_USB_TRACE
    ZB_SET_SERIAL_TRANSMIT_FLAG();
    ZB_ENABLE_SERIAL_INTER();
#endif
    
  }
}

void zb_clear_sniffer()
{
  /* Stop serial transmit, if enabled */
#ifndef ZB_SNIFFER_USB_TRACE
  ZB_CLEAR_SERIAL_TRANSMIT_FLAG();
  ZB_DISABLE_SERIAL_INTER();
#endif
  
  /* Turn off radio */
  ISRFOFF();
  ISFLUSHRX();

  /* Clear output buffer */
  bufFlush(&rbTxBuf);
}

zb_bool_t check_fcf(zb_uint16_t fcf)
{
  zb_bool_t ret = ZB_FALSE;
  /* Frame type is bigger than 0x03 (unknown) */
  zb_int16_t curr = !(fcf & (1 << 2));
  if (curr)
  {
    /* Reserved FCF bits 9-7 must be 000 */
    curr = !(fcf & (7 << 7));
    if (curr)
    {
      /* SAM != reserved (0x02) */
      curr = !((!(fcf & (1 << 11))) && (fcf & (1 << 10)));
      if (curr)
      {
        /* DAM != reserved (0x02) */
        curr = !((!(fcf & (zb_uint16_t)(1 << 15))) && (fcf & (1 << 14)));
        if (curr)
        {
          ret = ZB_TRUE;
        }
      }
    }
  }
  return ret;
}

#define ZB_SNIFFER_CHECK_MSB(byte) (byte & (1 << 7))  

void zb_put_out_queue()
{
  zb_uint8_t len;
  zb_sniffer_err_e not_enough_space;
  zb_sniffer_hdr_t hdr;

  ZB_MEMSET(&hdr, 0, ZB_SNIFFER_HDR_SIZE);

  not_enough_space = bufIsFull(&rbTxBuf) ? ZB_SNIFFER_OUT_BUF_OVERFLOW : ZB_SNIFFER_OK;
  if (!not_enough_space)
  {
    zb_uint8_t i;
    zb_bool_t accept_frame = ZB_TRUE;
    zb_uint8_t buf[ZB_SNIFFER_BUF_SIZE];
    /* zb_uint16_t fcf; */
    zb_uint8_t crc;
    
    len = RFD;
    /* Check the reserved 7th bit of length field */
    if (ZB_SNIFFER_CHECK_MSB(len))
    {
      accept_frame = ZB_FALSE;
    }
    /* Max packet length - 127 b, ignore 7th byte to prevent buffer overflow */
    len &= 0x7F;
    buf[0] = len;
    if (len >= ZB_SNIFFER_BUF_SIZE)
    {
      /* Packet length is larger than buffer size;
	 don't change buffer size to value less than 128 b */
      not_enough_space = ZB_SNIFFER_TOO_BIG_LEN;
    }
    if (!not_enough_space)
    {
      /* Read packet payload */
      for (i = 1; i<=len; i++)
      {
	buf[i] = RFD;
      }
      /* Include length byte */
      len++;
      /* Check FCF reserved bits with source &
	 destination addressing modes */
      /* fcf = *((zb_uint16_t *)&buf[1]); */
      /* Auto CRC is enabled: check CRC OK bit */
      crc = buf[len - 1];
      accept_frame &= (ZB_SNIFFER_CHECK_MSB(crc)) ? ZB_TRUE : ZB_FALSE;
      /* accept_frame &= check_fcf(fcf); */
      if (accept_frame)
      {
	if (bufHasEnoughSpace(&rbTxBuf, len + sizeof(hdr)))
	{
	  hdr.len = len + ZB_SNIFFER_HDR_SIZE;
	  hdr.type = ZB_SNIFFER_OK;
          hdr.tail = 0;
	  bufPut(&rbTxBuf, (zb_uint8_t *)(&hdr), sizeof(hdr));
	  bufPut(&rbTxBuf, buf, len);
	}
	else
	{
	  /* There is no space in output buffer for the whole packet */
	  not_enough_space = ZB_SNIFFER_OUT_BUF_OVERFLOW;
	}
      }
    }
  }
  if (not_enough_space)
  {
    if (not_enough_space == ZB_SNIFFER_TOO_BIG_LEN)
    {
      RFST = 0xED; /* flush rxfifo */
      RFST = 0xE3; /* rx on */
    }
    else if (not_enough_space == ZB_SNIFFER_OUT_BUF_OVERFLOW)
    {
      bufFlush(&rbTxBuf);
    }
    /* Tell about problem happened to the host */
    hdr.len = sizeof(zb_sniffer_hdr_t);
    hdr.type = not_enough_space;
    hdr.tail = 0;
    /* Header with ZB_MAC_TRANSPORT_TYPE_TRACE signals about error */
    bufPut(&rbTxBuf, (zb_uint8_t *)(&hdr), sizeof(hdr));
  }
}

void zb_sniffer_logic_iteration()
{ 
#ifndef ZB_SNIFFER_USB_TRACE
  zb_uint8_t nbytes = bufNumBytes(&rbTxBuf);
 
  if (bufNumBytes(&rbTxBuf) && !SER_CTX().tx_in_progress)
  {
    ZB_SET_SERIAL_TRANSMIT_FLAG();
  }
  else
  {
    ZB_GO_IDLE();
  }
#else
  usbUartProcess();
#endif
}
