/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020-21 Intel Corporation.
 */

#ifndef IOSM_IPC_MBIM_H
#define IOSM_IPC_MBIM_H

#include <linux/miscdevice.h>

#include "iosm_ipc_imem_ops.h"

/* IPC char. device default mode. Only privileged user can access. */
#define IPC_CHAR_DEVICE_DEFAULT_MODE 0600

#define IS_OPEN 0
#define IS_BLOCKING 1
#define WRITE_IN_USE 2
#define IS_DEINIT 3

/**
 * struct iosm_cdev_open_file - Reference to struct iosm_cdev
 * @ipc_cdev:	iosm_cdev instance
 */
struct iosm_cdev_open_file {
	struct iosm_cdev *ipc_cdev;
};

/**
 * struct iosm_cdev - State of the char driver layer.
 * @misc:		OS misc device component
 * @cdev_fop:		reference to iosm_cdev structure
 * @ipc_imem:		imem instance
 * @dev:		Pointer to device struct
 * @pcie:		PCIe component
 * @rx_pending_buf:	Storage for skb when its data has not been fully read
 * @misc:		OS misc device component
 * @devname:		Device name
 * @channel:		Channel instance
 * @rx_list:		Downlink skbuf list received from CP.
 * @read_sem:		Needed for the blocking read or downlink transfer
 * @poll_inq:		Read queues to support the poll system call
 * @flag:		Flags to monitor state of device
 * @wmaxcommand:	Max buffer size
 */
struct iosm_cdev {
	struct miscdevice misc;
	struct iosm_cdev_open_file *cdev_fop;
	struct iosm_imem *ipc_imem;
	struct device *dev;
	struct iosm_pcie *pcie;
	struct sk_buff *rx_pending_buf;
	char devname[IPC_CDEV_NAME_LEN];
	struct ipc_mem_channel *channel;
	struct sk_buff_head rx_list;
	struct completion read_sem;
	wait_queue_head_t poll_inq;
	unsigned long flag;
	u16 wmaxcommand;
};

/**
 * ipc_mbim_init - Initialize and create a character device for MBIM
 *		   communication.
 * @ipc_imem:	Pointer to iosm_imem structure
 * @name:	Pointer to character device name
 *
 * Returns: 0 on success
 */
struct iosm_cdev *ipc_mbim_init(struct iosm_imem *ipc_imem, const char *name);

/**
 * ipc_mbim_deinit - Frees all the memory allocated for the ipc mbim structure.
 * @ipc_mbim:	Pointer to the ipc mbim data-struct
 */
void ipc_mbim_deinit(struct iosm_cdev *ipc_mbim);

#endif
