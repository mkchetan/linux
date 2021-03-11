/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2021, Linaro Ltd <loic.poulain@linaro.org> */

#ifndef __WWAN_CORE_H
#define __WWAN_CORE_H

#include <linux/device.h>
#include <linux/wwan.h>

#define to_wwan_dev(d) container_of(d, struct wwan_device, dev)

struct wwan_device *wwan_create_dev(struct device *parent);
void wwan_destroy_dev(struct wwan_device *wwandev);

int wwan_port_init(void);
void wwan_port_deinit(void);

extern struct class *wwan_class;

#endif /* WWAN_CORE_H */
