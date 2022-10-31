// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, INTEL CORPORATION. All rights reserved
 */

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/anon_inodes.h>
#include <linux/kernel.h>
#include <linux/vfio_pci_core.h>

static int nvmevf_pci_open_device(struct vfio_device *core_vdev)
{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	vfio_pci_core_finish_enable(vdev);
	return 0;
}

static const struct vfio_device_ops nvmevf_pci_ops = {
	.name = "nvme-vfio-pci",
	.init = vfio_pci_core_init_dev,
	.release = vfio_pci_core_release_dev,
	.open_device = nvmevf_pci_open_device,
	.close_device = vfio_pci_core_close_device,
	.ioctl = vfio_pci_core_ioctl,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = vfio_pci_core_read,
	.write = vfio_pci_core_write,
	.mmap = vfio_pci_core_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
};

static int nvmevf_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct vfio_pci_core_device *vdev;
	int ret;

	vdev = vfio_alloc_device(vfio_pci_core_device, vdev, &pdev->dev,
				&nvmevf_pci_ops);
	if (IS_ERR(vdev))
		return PTR_ERR(vdev);

	dev_set_drvdata(&pdev->dev, vdev);
	ret = vfio_pci_core_register_device(vdev);
	if (ret)
		goto out_put_dev;

	return 0;

out_put_dev:
	vfio_put_device(&vdev->vdev);
	return ret;
}

static void nvmevf_pci_remove(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *vdev = dev_get_drvdata(&pdev->dev);

	vfio_pci_core_unregister_device(vdev);
	vfio_put_device(&vdev->vdev);
}

static const struct pci_device_id nvmevf_pci_table[] = {
	/* Intel IPU NVMe Virtual Function */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x1457) },
	{}
};

MODULE_DEVICE_TABLE(pci, nvmevf_pci_table);

static struct pci_driver nvmevf_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = nvmevf_pci_table,
	.probe = nvmevf_pci_probe,
	.remove = nvmevf_pci_remove,
	.err_handler = &vfio_pci_core_err_handlers,
	.driver_managed_dma = true,
};

module_pci_driver(nvmevf_pci_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lei Rao <lei.rao@intel.com>");
MODULE_DESCRIPTION("NVMe VFIO PCI - Generic VFIO PCI driver for NVMe");
