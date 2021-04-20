/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020-21 Intel Corporation.
 */

#ifndef IOSM_IPC_IMEM_OPS_H
#define IOSM_IPC_IMEM_OPS_H

#include "iosm_ipc_mux_codec.h"

/* Maximum length of the cdev device names */
#define IPC_CDEV_NAME_LEN 32

/* Maximum wait time for blocking read */
#define IPC_READ_TIMEOUT 500

/* The delay in ms for defering the unregister */
#define SIO_UNREGISTER_DEFER_DELAY_MS 1

/* Default delay till CP PSI image is running and modem updates the
 * execution stage.
 * unit : milliseconds
 */
#define PSI_START_DEFAULT_TIMEOUT 3000

/* Default time out when closing SIO, till the modem is in
 * running state.
 * unit : milliseconds
 */
#define BOOT_CHECK_DEFAULT_TIMEOUT 400

/* IP MUX and DSS channel range */
#define IP_MUX_SESSION_START 1
#define IP_MUX_SESSION_END 8

#define IP_DSS_SESSION_START 9
#define IP_DSS_SESSION_END 13

#define DSS_SESSION_START IPC_WWAN_DSS_ID_0
#define DSS_SESSION_END IPC_WWAN_DSS_ID_4

#define NET_SESSION_START 1
#define MAX_NET_SESSION 13

#define DSS_CHANNEL_START IPC_WWAN_DSS_ID_0
#define DSS_CHANNEL_END IPC_WWAN_DSS_ID_4

/**
 * imem_sys_mbim_open - Open a mbim link to CP.
 * @ipc_imem:	Imem instance.
 *
 * Return: channel instance on success, NULL for failure
 */
struct ipc_mem_channel *imem_sys_mbim_open(struct iosm_imem *ipc_imem);

/**
 * imem_sys_cdev_close - Release a sio link to CP.
 * @ipc_cdev:		iosm sio instance.
 */
void imem_sys_cdev_close(struct iosm_cdev *ipc_cdev);

/**
 * imem_sys_cdev_read - Copy the rx data to the user space buffer and free the
 *		       skbuf.
 * @ipc_cdev:	Pointer to iosm_cdev structi.
 * @buf:	Pointer to destination buffer.
 * @size:	Size of destination buffer.
 * @skb:	Pointer to source buffer.
 *
 * Return: Number of bytes read and failure value on error
 */
ssize_t imem_sys_cdev_read(struct iosm_cdev *ipc_cdev, unsigned char __user *buf,
			   size_t size, struct sk_buff *skb);

/**
 * imem_sys_cdev_write - Route the uplink buffer to CP.
 * @ipc_cdev:		iosm_cdev instance.
 * @buf:		Pointer to source buffer.
 * @count:		Number of data bytes to write.
 * @blocking_write:	if true wait for UL data completion.
 *
 * Return: Number of bytes read and failure value on error
 */
int imem_sys_cdev_write(struct iosm_cdev *ipc_cdev,
			const unsigned char __user *buf, int count,
			bool blocking_write);

/**
 * imem_sys_cdev_receive - Receive downlink characters from CP, the downlink
 *		skbuf is added at the end of the downlink or rx list.
 * @ipc_cdev:    Pointer to ipc char data-struct
 * @skb:        Pointer to sk buffer
 * Returns:  0 on success
 */
int imem_sys_cdev_receive(struct iosm_cdev *ipc_cdev, struct sk_buff *skb);

/**
 * imem_sys_wwan_open - Open packet data online channel between network layer
 *			and CP.
 * @ipc_imem:		Imem instance.
 * @if_id:		ip link tag of the net device.
 *
 * Return: Channel ID on success and failure value on error
 */
int imem_sys_wwan_open(struct iosm_imem *ipc_imem, int if_id);

/**
 * imem_sys_wwan_close - Close packet data online channel between network layer
 *			 and CP.
 * @ipc_imem:		Imem instance.
 * @if_id:		IP link id net device.
 * @channel_id:		Channel ID to be closed.
 */
void imem_sys_wwan_close(struct iosm_imem *ipc_imem, int if_id,
			 int channel_id);

/**
 * imem_sys_wwan_transmit - Function for transfer UL data
 * @ipc_imem:		Imem instance.
 * @if_id:		link ID of the device.
 * @channel_id:		Channel ID used
 * @skb:		Pointer to sk buffer
 *
 * Return: 0 on success and failure value on error
 */
int imem_sys_wwan_transmit(struct iosm_imem *ipc_imem, int if_id,
			   int channel_id, struct sk_buff *skb);
/**
 * wwan_channel_init - Initializes WWAN channels and the channel for MUX.
 * @ipc_imem:		Pointer to iosm_imem struct.
 * @mux_type:		Type of mux protocol.
 */
void wwan_channel_init(struct iosm_imem *ipc_imem,
		       enum ipc_mux_protocol mux_type);
#endif
