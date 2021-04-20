.. SPDX-License-Identifier: GPL-2.0-only

.. Copyright (C) 2020-21 Intel Corporation

.. _iosm_driver_doc:

===========================================
IOSM Driver for Intel M.2 PCIe based Modems
===========================================
The IOSM (IPC over Shared Memory) driver is a WWAN PCIe host driver developed
for linux or chrome platform for data exchange over PCIe interface between
Host platform & Intel M.2 Modem. The driver exposes interface conforming to the
MBIM protocol [1]. Any front end application ( eg: Modem Manager) could easily
manage the MBIM interface to enable data communication towards WWAN.

Basic usage
===========
MBIM functions are inactive when unmanaged. The IOSM driver only provides a
userspace interface of a character device representing MBIM control channel
and does not play any role in managing the functionality. It is the job of a
userspace application to detect port enumeration and enable MBIM functionality.

Examples of few such userspace application are:
- mbimcli (included with the libmbim [2] library), and
- Modem Manager [3]

Management Applications to carry out below required actions for establishing
MBIM IP session:
- open the MBIM control channel
- configure network connection settings
- connect to network
- configure IP network interface

Management application development
==================================
The driver and userspace interfaces are described below. The MBIM protocol is
described in [1] Mobile Broadband Interface Model v1.0 Errata-1.

MBIM control channel userspace ABI
----------------------------------

/dev/wwanctrl character device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The driver exposes an interface to the MBIM function control channel using char
driver as a sub driver. The userspace end of the control channel pipe is a
/dev/wwanctrl character device.

The /dev/wwanctrl device is created as a subordinate character device under
IOSM driver. The character device associated with a specific MBIM function
can be looked up using sysfs with matching the above device name.

Control channel configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The wMaxControlMessage field of the MBIM functional descriptor limits the
maximum control message size. The management application needs to negotiate
the control message size as per the requirements. See also the ioctl
documentation below.

Fragmentation
~~~~~~~~~~~~~
The userspace application is responsible for all control message
fragmentation and defragmentation as per MBIM specification.

/dev/wwanctrl write()
~~~~~~~~~~~~~~~~~~~~~
The MBIM control messages from the management application must not
exceed the negotiated control message size.

/dev/wwanctrl read()
~~~~~~~~~~~~~~~~~~~~
The management application must accept control messages of up the
negotiated control message size.

/dev/wwanctrl ioctl()
~~~~~~~~~~~~~~~~~~~~~
IOCTL_WDM_MAX_COMMAND: Get Maximum Command Size
This IOCTL command could be used by applications to fetch the Maximum Command
buffer length supported by the driver which is restricted to 4096 bytes.

.. code-block:: C
   :linenos:

    #include <stdio.h>
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <linux/types.h>
    int main()
    {
        __u16 max;
        int fd = open("/dev/wwanctrl", O_RDWR);
        if (!ioctl(fd, IOCTL_WDM_MAX_COMMAND, &max))
            printf("wMaxControlMessage is %d\n", max);
    }

MBIM data channel userspace ABI
-------------------------------

inmX network device
~~~~~~~~~~~~~~~~~~~~
The IOSM driver exposes IP link interface "inmX" of type "IOSM" for IP traffic.
Iproute network utility is used for creating "inmX" network interface and for
associating it with MBIM IP session. The Driver supports upto 8 IP sessions for
simultaneous IP communication.

The userspace management application is responsible for creating new IP link
prior to establishing MBIM IP session where the SessionId is greater than 0.

For example, creating new IP link for a MBIM IP session with SessionId 1:

  ip link add link wwan0 name inm1 type IOSM if_id 1

The driver will automatically map the "inm1" network device to MBIM IP session 1.

References
==========
[1] "MBIM (Mobile Broadband Interface Model) Errata-1"
      - https://www.usb.org/document-library/

[2] libmbim - "a glib-based library for talking to WWAN modems and
      devices which speak the Mobile Interface Broadband Model (MBIM)
      protocol"
      - http://www.freedesktop.org/wiki/Software/libmbim/

[3] Modem Manager - "a DBus-activated daemon which controls mobile
      broadband (2G/3G/4G) devices and connections"
      - http://www.freedesktop.org/wiki/Software/ModemManager/
