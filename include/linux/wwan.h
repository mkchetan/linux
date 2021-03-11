/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2021, Linaro Ltd <loic.poulain@linaro.org> */

#ifndef __WWAN_H
#define __WWAN_H

#include <linux/device.h>
#include <linux/kernel.h>

/**
 * struct wwan_device - The structure that defines a WWAN device
 *
 * @id:		WWAN device unique ID.
 * @usage:	WWAN device usage counter.
 * @dev:	underlying device.
 * @list:	list to chain WWAN devices.
 * @ports:	list of attached wwan_port.
 * @port_idx:	port index counter.
 * @lock:	mutex protecting members of this structure.
 */
struct wwan_device {
	int id;
	unsigned int usage;

	struct device dev;
	struct list_head list;

	struct list_head ports;
	unsigned int port_idx;

	struct mutex lock;
};

/**
 * enum wwan_port_type - WWAN port types
 * @WWAN_PORT_AT:	AT commands.
 * @WWAN_PORT_MBIM:	Mobile Broadband Interface Model control.
 * @WWAN_PORT_QMI:	Qcom modem/MSM interface for modem control.
 * @WWAN_PORT_QCDM:	Qcom Modem diagnostic interface.
 * @WWAN_PORT_FIREHOSE: XML based command protocol.
 * @WWAN_PORT_MAX
 */
enum wwan_port_type {
	WWAN_PORT_AT,
	WWAN_PORT_MBIM,
	WWAN_PORT_QMI,
	WWAN_PORT_QCDM,
	WWAN_PORT_FIREHOSE,
	WWAN_PORT_MAX,
};

/**
 * struct wwan_port - The structure that defines a WWAN port
 *
 * @wwandev:		WWAN device this port belongs to.
 * @fops:		Port file operations.
 * @private_data:	underlying device.
 * @type:		port type.
 * @id:			port allocated ID.
 * @minor:		port allocated minor ID for cdev.
 * @list:		list to chain WWAN ports.
 */
struct wwan_port {
	struct wwan_device *wwandev;
	const struct file_operations *fops;
	void *private_data;
	enum wwan_port_type type;

	/* private */
	unsigned int id;
	int minor;
	struct list_head list;
};

#define to_wwan_dev(d) container_of(d, struct wwan_device, dev)

/**
 * wwan_create_dev - Create a new WWAN device
 * @parent: parent device of the WWAN device
 *
 * If parent is not NULL, WWAN core ensures that only one WWAN device is
 * allocated for a given parent. If a WWAN device with the specified parent
 * already exists, a reference is taken and the WWAN device is returned.
 *
 * This function must be balanced with a call to wwan_destroy_dev().
 *
 * Returns pointer to the wwan_device or NULL.
 */
struct wwan_device *wwan_create_dev(struct device *parent);

/**
 * wwan_create_dev - Destroy a WWAN device
 * @wwandev: wwan_device to destroy
 *
 * This releases a previoulsy created WWAN device.
 */
void wwan_destroy_dev(struct wwan_device *wwandev);

/**
 * wwan_add_port - Add a new WWAN port
 * @port: WWAN port to add
 *
 * Prior calling this function, caller must allocate and fill the wwan_port
 * with wwandev, fops, and type fields. A port is automatically exposed to
 * user as character device, and provided file operations will be used.
 *
 * This function must be balanced with a call to wwan_remove_port().
 *
 * Returns zero on success or a negative error code.
 */
int wwan_add_port(struct wwan_port *port);

/**
 * wwan_remove_port - Remove a WWAN port
 * @port: WWAN port to remove
 *
 * Remove a previously added port.
 */
void wwan_remove_port(struct wwan_port *port);

#endif /* __WWAN_H */
