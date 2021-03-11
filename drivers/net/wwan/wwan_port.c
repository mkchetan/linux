// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, Linaro Ltd <loic.poulain@linaro.org> */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/wwan.h>

#include "wwan_core.h"

#define WWAN_MAX_MINORS 128

static int wwan_major;
static DEFINE_IDR(wwan_port_idr);
static DEFINE_MUTEX(wwan_port_idr_lock);

static const char * const wwan_port_type_str[] = {
	"AT",
	"MBIM",
	"QMI",
	"QCDM",
	"FIREHOSE"
};

int wwan_add_port(struct wwan_port *port)
{
	struct wwan_device *wwandev = port->wwandev;
	struct device *dev;
	int minor, err;

	if (port->type >= WWAN_PORT_MAX || !port->fops || !wwandev)
		return -EINVAL;

	mutex_lock(&wwan_port_idr_lock);
	minor = idr_alloc(&wwan_port_idr, port, 0, WWAN_MAX_MINORS, GFP_KERNEL);
	mutex_unlock(&wwan_port_idr_lock);

	if (minor < 0)
		return minor;

	mutex_lock(&wwandev->lock);

	dev = device_create(wwan_class, &wwandev->dev,
			    MKDEV(wwan_major, minor), port,
			    "wwan%dp%u%s", wwandev->id, wwandev->port_idx,
			    wwan_port_type_str[port->type]);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		mutex_unlock(&wwandev->lock);
		goto error_free_idr;
	}

	port->id = wwandev->port_idx++;
	port->minor = minor;

	list_add(&port->list, &wwandev->ports);

	mutex_unlock(&port->wwandev->lock);

	return 0;

error_free_idr:
	mutex_lock(&wwan_port_idr_lock);
	idr_remove(&wwan_port_idr, minor);
	mutex_unlock(&wwan_port_idr_lock);

	return err;
}
EXPORT_SYMBOL_GPL(wwan_add_port);

void wwan_remove_port(struct wwan_port *port)
{
	struct wwan_device *wwandev = port->wwandev;

	WARN_ON(!wwandev);

	mutex_lock(&wwandev->lock);
	device_destroy(wwan_class, MKDEV(wwan_major, port->minor));
	list_del(&port->list);
	mutex_unlock(&wwandev->lock);

	mutex_lock(&wwan_port_idr_lock);
	idr_remove(&wwan_port_idr, port->minor);
	mutex_unlock(&wwan_port_idr_lock);
}
EXPORT_SYMBOL_GPL(wwan_remove_port);

static int wwan_port_open(struct inode *inode, struct file *file)
{
	const struct file_operations *new_fops;
	unsigned int minor = iminor(inode);
	struct wwan_port *port;
	int err = 0;

	mutex_lock(&wwan_port_idr_lock);
	port = idr_find(&wwan_port_idr, minor);
	if (!port) {
		mutex_unlock(&wwan_port_idr_lock);
		return -ENODEV;
	}
	mutex_unlock(&wwan_port_idr_lock);

	file->private_data = port->private_data ? port->private_data : port;
	stream_open(inode, file);

	new_fops = fops_get(port->fops);
	replace_fops(file, new_fops);
	if (file->f_op->open)
		err = file->f_op->open(inode, file);

	return err;
}

static const struct file_operations wwan_port_fops = {
	.owner	= THIS_MODULE,
	.open	= wwan_port_open,
	.llseek = noop_llseek,
};

int wwan_port_init(void)
{
	wwan_major = register_chrdev(0, "wwanport", &wwan_port_fops);
	if (wwan_major < 0)
		return wwan_major;

	return 0;
}

void wwan_port_deinit(void)
{
	unregister_chrdev(wwan_major, "wwanport");
	idr_destroy(&wwan_port_idr);
}
