/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022, INTEL CORPORATION. All rights reserved
 */

#ifndef NVME_VFIO_PCI_H
#define NVME_VFIO_PCI_H

#include <linux/kernel.h>
#include <linux/vfio_pci_core.h>
#include <linux/nvme.h>

struct nvme_live_mig_query_size {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[9];
	__u16	vf_index;
	__u16	rsvd2;
	__u32	rsvd3[5];
};

struct nvme_live_mig_suspend {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[9];
	__u16	vf_index;
	__u16	rsvd2;
	__u32	rsvd3[5];
};

struct nvme_live_mig_resume {
	__u8    opcode;
	__u8    flags;
	__u16   command_id;
	__u32   rsvd1[9];
	__u16   vf_index;
	__u16   rsvd2;
	__u32   rsvd3[5];
};

struct nvme_live_mig_save_data {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[5];
	__le64	prp1;
	__le64	prp2;
	__u16	vf_index;
	__u16	rsvd2;
	__u32	rsvd3[5];
};

struct nvme_live_mig_load_data {
	__u8    opcode;
	__u8    flags;
	__u16   command_id;
	__u32   rsvd1[5];
	__le64  prp1;
	__le64  prp2;
	__u16   vf_index;
	__u16	rsvd2;
	__u32	size;
	__u32   rsvd3[4];
};

enum nvme_live_mig_admin_opcode {
	nvme_admin_live_mig_query_data_size	= 0xC4,
	nvme_admin_live_mig_suspend		= 0xC8,
	nvme_admin_live_mig_resume		= 0xCC,
	nvme_admin_live_mig_save_data		= 0xD2,
	nvme_admin_live_mig_load_data		= 0xD5,
};

struct nvme_live_mig_command {
	union {
		struct nvme_live_mig_query_size query;
		struct nvme_live_mig_suspend	suspend;
		struct nvme_live_mig_resume	resume;
		struct nvme_live_mig_save_data	save;
		struct nvme_live_mig_load_data	load;
	};
};

struct nvmevf_migration_file {
	struct file *filp;
	struct mutex lock;
	bool disabled;
	u8 *vf_data;
	size_t total_length;
};

struct nvmevf_pci_core_device {
	struct vfio_pci_core_device core_device;
	int vf_id;
	u8 migrate_cap:1;
	u8 deferred_reset:1;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
	/* protect the reset_done flow */
	spinlock_t reset_lock;
	struct nvmevf_migration_file *resuming_migf;
	struct nvmevf_migration_file *saving_migf;
};

extern int nvme_submit_vf_cmd(struct pci_dev *dev, struct nvme_command *cmd,
			size_t *result, void *buffer, unsigned int bufflen);

#endif /* NVME_VFIO_PCI_H */
