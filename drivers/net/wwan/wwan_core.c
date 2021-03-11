// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, Linaro Ltd <loic.poulain@linaro.org> */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wwan.h>

#include "wwan_core.h"

static LIST_HEAD(wwan_list);	/* list of registered wwan devices */
static DEFINE_IDA(wwan_ida);
static DEFINE_MUTEX(wwan_global_lock);
struct class *wwan_class;

struct wwan_device *__wwan_find_by_parent(struct device *parent)
{
	struct wwan_device *wwandev;

	if (!parent)
		return NULL;

	list_for_each_entry(wwandev, &wwan_list, list) {
		if (wwandev->dev.parent == parent)
			return wwandev;
	}

	return NULL;
}

static void wwan_dev_release(struct device *dev)
{
	struct wwan_device *wwandev = to_wwan_dev(dev);

	kfree(wwandev);
}

static const struct device_type wwan_type = {
	.name    = "wwan",
	.release = wwan_dev_release,
};

struct wwan_device *wwan_create_dev(struct device *parent)
{
	struct wwan_device *wwandev;
	int err, id;

	mutex_lock(&wwan_global_lock);

	wwandev = __wwan_find_by_parent(parent);
	if (wwandev) {
		get_device(&wwandev->dev);
		wwandev->usage++;
		goto done_unlock;
	}

	id = ida_alloc(&wwan_ida, GFP_KERNEL);
	if (id < 0)
		goto done_unlock;

	wwandev = kzalloc(sizeof(*wwandev), GFP_KERNEL);
	if (!wwandev) {
		ida_free(&wwan_ida, id);
		goto done_unlock;
	}

	wwandev->dev.parent = parent;
	wwandev->dev.class = wwan_class;
	wwandev->dev.type = &wwan_type;
	wwandev->id = id;
	dev_set_name(&wwandev->dev, "wwan%d", wwandev->id);
	wwandev->usage = 1;
	INIT_LIST_HEAD(&wwandev->ports);

	err = device_register(&wwandev->dev);
	if (err) {
		put_device(&wwandev->dev);
		ida_free(&wwan_ida, id);
		wwandev = NULL;
		goto done_unlock;
	}

	list_add_tail(&wwandev->list, &wwan_list);

done_unlock:
	mutex_unlock(&wwan_global_lock);

	return wwandev;
}
EXPORT_SYMBOL_GPL(wwan_create_dev);

void wwan_destroy_dev(struct wwan_device *wwandev)
{
	mutex_lock(&wwan_global_lock);
	wwandev->usage--;

	if (wwandev->usage)
		goto done_unlock;

	/* Someone destroyed the wwan device without removing ports */
	WARN_ON(!list_empty(&wwandev->ports));

	list_del(&wwandev->list);
	device_unregister(&wwandev->dev);
	ida_free(&wwan_ida, wwandev->id);
	put_device(&wwandev->dev);

done_unlock:
	mutex_unlock(&wwan_global_lock);
}
EXPORT_SYMBOL_GPL(wwan_destroy_dev);

static int __init wwan_init(void)
{
	int err;

	wwan_class = class_create(THIS_MODULE, "wwan");
	if (IS_ERR(wwan_class))
		return PTR_ERR(wwan_class);

	err = wwan_port_init();
	if (err)
		goto err_class_destroy;

	return 0;

err_class_destroy:
	class_destroy(wwan_class);
	return err;
}

static void __exit wwan_exit(void)
{
	wwan_port_deinit();
	class_destroy(wwan_class);
}

//subsys_initcall(wwan_init);
module_init(wwan_init);
module_exit(wwan_exit);

MODULE_AUTHOR("Loic Poulain <loic.poulain@linaro.org>");
MODULE_DESCRIPTION("WWAN core");
MODULE_LICENSE("GPL v2");
