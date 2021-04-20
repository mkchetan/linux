// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-21 Intel Corporation.
 */

#include <linux/poll.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>

#include "iosm_ipc_imem_ops.h"
#include "iosm_ipc_mbim.h"

#define IOCTL_WDM_MAX_COMMAND _IOR('H', 0xA0, __u16)
#define WDM_MAX_SIZE 4096

static struct mutex mbim_flock;		/* Mutex Lock for mbim read */
static struct mutex mbim_flock_wr;	/* Mutex Lock for mbim write */

/* MBIM IOCTL for configuring max MBIM packet size. */
static long ipc_mbim_fop_unlocked_ioctl(struct file *filp, unsigned int cmd,
					unsigned long arg)
{
	struct iosm_cdev *ipc_mbim =
		container_of(filp->private_data, struct iosm_cdev, misc);

	if (cmd != IOCTL_WDM_MAX_COMMAND ||
	    !access_ok((void __user *)arg, sizeof(ipc_mbim->wmaxcommand)))
		return -EINVAL;

	if (copy_to_user((void __user *)arg, &ipc_mbim->wmaxcommand,
			 sizeof(ipc_mbim->wmaxcommand)))
		return -EFAULT;

	return 0;
}

/* Open a shared memory device and initialize the head of the rx skbuf list. */
static int ipc_mbim_fop_open(struct inode *inode, struct file *filp)
{
	struct iosm_cdev *ipc_mbim =
		container_of(filp->private_data, struct iosm_cdev, misc);

	struct iosm_cdev_open_file *mbim_op = kzalloc(sizeof(*mbim_op),
						      GFP_KERNEL);
	if (!mbim_op)
		return -ENOMEM;

	if (test_and_set_bit(IS_OPEN, &ipc_mbim->flag)) {
		kfree(mbim_op);
		return -EBUSY;
	}

	ipc_mbim->channel = imem_sys_mbim_open(ipc_mbim->ipc_imem);

	if (!ipc_mbim->channel) {
		kfree(mbim_op);
		return -EIO;
	}

	mutex_lock(&mbim_flock);

	inode->i_private = mbim_op;
	ipc_mbim->cdev_fop = mbim_op;
	mbim_op->ipc_cdev = ipc_mbim;

	mutex_unlock(&mbim_flock);
	return 0;
}

/* Close a shared memory control device and free the rx skbuf list. */
static int ipc_mbim_fop_release(struct inode *inode, struct file *filp)
{
	struct iosm_cdev_open_file *mbim_op = inode->i_private;

	mutex_lock(&mbim_flock);
	if (mbim_op->ipc_cdev) {
		/* Complete all memory stores before clearing bit. */
		smp_mb__before_atomic();

		clear_bit(IS_OPEN, &mbim_op->ipc_cdev->flag);

		/* Complete all memory stores after clearing bit. */
		smp_mb__after_atomic();

		imem_sys_cdev_close(mbim_op->ipc_cdev);
		mbim_op->ipc_cdev->cdev_fop = NULL;
	}
	kfree(mbim_op);
	mutex_unlock(&mbim_flock);
	return 0;
}

/* Copy the data from skbuff to the user buffer */
static ssize_t ipc_mbim_fop_read(struct file *filp, char __user *buf,
				 size_t size, loff_t *l)
{
	struct iosm_cdev_open_file *mbim_op = filp->f_inode->i_private;
	struct sk_buff *skb = NULL;
	struct iosm_cdev *ipc_mbim;
	ssize_t read_byt;
	int ret_err;

	if (!access_ok(buf, size)) {
		ret_err = -EINVAL;
		goto err;
	}

	mutex_lock(&mbim_flock);

	if (!mbim_op->ipc_cdev) {
		ret_err = -EIO;
		goto err_free_lock;
	}

	ipc_mbim = mbim_op->ipc_cdev;

	if (!(filp->f_flags & O_NONBLOCK)) {
		/* Complete all memory stores before setting bit */
		smp_mb__before_atomic();

		set_bit(IS_BLOCKING, &ipc_mbim->flag);

		/* Complete all memory stores after setting bit */
		smp_mb__after_atomic();
	}

	/* First provide the pending skbuf to the user. */
	if (ipc_mbim->rx_pending_buf) {
		skb = ipc_mbim->rx_pending_buf;
		ipc_mbim->rx_pending_buf = NULL;
	}

	/* Check rx queue until skb is available */
	while (!skb && !(skb = skb_dequeue(&ipc_mbim->rx_list))) {
		if (!test_bit(IS_BLOCKING, &ipc_mbim->flag)) {
			ret_err = -EAGAIN;
			goto err_free_lock;
		}

		/* Suspend the user app and wait a certain time for data
		 * from CP.
		 */
		if (!wait_for_completion_interruptible_timeout
		(&ipc_mbim->read_sem, msecs_to_jiffies(IPC_READ_TIMEOUT))) {
			dev_err(ipc_mbim->dev, "Read timedout");
			ret_err = -ETIMEDOUT;
			goto err_free_lock;
		}

		if (test_bit(IS_DEINIT, &ipc_mbim->flag)) {
			ret_err = -EPERM;
			goto err_free_lock;
		}
	}

	read_byt = imem_sys_cdev_read(ipc_mbim, buf, size, skb);
	mutex_unlock(&mbim_flock);
	return read_byt;

err_free_lock:
	mutex_unlock(&mbim_flock);
err:
	return ret_err;
}

/* Route the user data to the shared memory layer. */
static ssize_t ipc_mbim_fop_write(struct file *filp, const char __user *buf,
				  size_t size, loff_t *l)
{
	struct iosm_cdev_open_file *mbim_op = filp->f_inode->i_private;
	struct iosm_cdev *ipc_mbim;
	bool is_blocking;
	ssize_t write_byt;
	int ret_err;

	if (!access_ok(buf, size)) {
		ret_err = -EINVAL;
		goto err;
	}

	mutex_lock(&mbim_flock_wr);

	if (!mbim_op->ipc_cdev) {
		ret_err = -EIO;
		goto err_free_lock;
	}

	ipc_mbim = mbim_op->ipc_cdev;

	is_blocking = !(filp->f_flags & O_NONBLOCK);

	if (test_bit(WRITE_IN_USE, &ipc_mbim->flag)) {
		ret_err = -EAGAIN;
		goto err_free_lock;
	}
	write_byt = imem_sys_cdev_write(ipc_mbim, buf, size, is_blocking);

	mutex_unlock(&mbim_flock_wr);
	return write_byt;

err_free_lock:
	mutex_unlock(&mbim_flock_wr);
err:
	return ret_err;
}

/* Poll mechanism for applications that use nonblocking IO */
static __poll_t ipc_mbim_fop_poll(struct file *filp, poll_table *wait)
{
	struct iosm_cdev *ipc_mbim =
		container_of(filp->private_data, struct iosm_cdev, misc);
	__poll_t mask = 0;

	/* Just registers wait_queue hook. This doesn't really wait. */
	poll_wait(filp, &ipc_mbim->poll_inq, wait);

	/* Test the fill level of the skbuf rx queue. */
	if (!test_bit(WRITE_IN_USE, &ipc_mbim->flag))
		mask |= EPOLLOUT | EPOLLWRNORM; /* writable */

	if (!skb_queue_empty(&ipc_mbim->rx_list) || ipc_mbim->rx_pending_buf)
		mask |= EPOLLIN | EPOLLRDNORM; /* readable */

	return mask;
}

struct iosm_cdev *ipc_mbim_init(struct iosm_imem *ipc_imem, const char *name)
{
	struct iosm_cdev *ipc_mbim = kzalloc(sizeof(*ipc_mbim), GFP_KERNEL);

	static const struct file_operations fops = {
		.owner = THIS_MODULE,
		.open = ipc_mbim_fop_open,
		.release = ipc_mbim_fop_release,
		.read = ipc_mbim_fop_read,
		.write = ipc_mbim_fop_write,
		.poll = ipc_mbim_fop_poll,
		.unlocked_ioctl = ipc_mbim_fop_unlocked_ioctl,
	};

	if (!ipc_mbim)
		return NULL;

	ipc_mbim->dev = ipc_imem->dev;
	ipc_mbim->pcie = ipc_imem->pcie;
	ipc_mbim->ipc_imem = ipc_imem;

	ipc_mbim->wmaxcommand = WDM_MAX_SIZE;

	mutex_init(&mbim_flock);
	mutex_init(&mbim_flock_wr);
	init_completion(&ipc_mbim->read_sem);

	skb_queue_head_init(&ipc_mbim->rx_list);
	init_waitqueue_head(&ipc_mbim->poll_inq);

	strncpy(ipc_mbim->devname, name, sizeof(ipc_mbim->devname) - 1);
	ipc_mbim->devname[IPC_CDEV_NAME_LEN - 1] = '\0';

	ipc_mbim->misc.minor = MISC_DYNAMIC_MINOR;
	ipc_mbim->misc.name = ipc_mbim->devname;
	ipc_mbim->misc.fops = &fops;
	ipc_mbim->misc.mode = IPC_CHAR_DEVICE_DEFAULT_MODE;

	if (misc_register(&ipc_mbim->misc)) {
		kfree(ipc_mbim);
		return NULL;
	}

	dev_set_drvdata(ipc_mbim->misc.this_device, ipc_mbim);

	return ipc_mbim;
}

void ipc_mbim_deinit(struct iosm_cdev *ipc_mbim)
{
	misc_deregister(&ipc_mbim->misc);

	/* Complete all memory stores before setting bit */
	smp_mb__before_atomic();

	set_bit(IS_DEINIT, &ipc_mbim->flag);

	/* Complete all memory stores after setting bit */
	smp_mb__after_atomic();

	if (test_bit(IS_BLOCKING, &ipc_mbim->flag)) {
		complete(&ipc_mbim->read_sem);
		complete(&ipc_mbim->channel->ul_sem);
	}

	mutex_lock(&mbim_flock);
	mutex_lock(&mbim_flock_wr);

	ipc_pcie_kfree_skb(ipc_mbim->pcie, ipc_mbim->rx_pending_buf);
	ipc_mbim->rx_pending_buf = NULL;
	skb_queue_purge(&ipc_mbim->rx_list);

	if (ipc_mbim->cdev_fop)
		ipc_mbim->cdev_fop->ipc_cdev = NULL;

	mutex_unlock(&mbim_flock_wr);
	mutex_unlock(&mbim_flock);

	kfree(ipc_mbim);
}
