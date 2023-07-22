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
#include <linux/interval_tree.h>

#include "nvme.h"

#define MAX_MIGRATION_SIZE (256 * 1024)

static int nvmevf_cmd_suspend_device(struct nvmevf_pci_core_device *nvmevf_dev)
{
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct nvme_live_mig_command c = { };
	int ret;

	c.suspend.opcode = nvme_admin_live_mig_suspend;
	c.suspend.vf_index = nvmevf_dev->vf_id;

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, NULL, 0);
	if (ret) {
		dev_warn(&dev->dev, "Suspend virtual function failed (ret=0x%x)\n", ret);
		return ret;
	}
	return 0;
}

static int nvmevf_cmd_resume_device(struct nvmevf_pci_core_device *nvmevf_dev)
{
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct nvme_live_mig_command c = { };
	int ret;

	c.resume.opcode = nvme_admin_live_mig_resume;
	c.resume.vf_index = nvmevf_dev->vf_id;

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, NULL, 0);
	if (ret) {
		dev_warn(&dev->dev, "Resume virtual function failed (ret=0x%x)\n", ret);
		return ret;
	}
	return 0;
}

static int nvmevf_cmd_query_data_size(struct nvmevf_pci_core_device *nvmevf_dev,
					  size_t *state_size)
{
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct nvme_live_mig_command c = { };
	size_t result;
	int ret;

	c.query.opcode = nvme_admin_live_mig_query_data_size;
	c.query.vf_index = nvmevf_dev->vf_id;

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, &result, NULL, 0);
	if (ret) {
		dev_warn(&dev->dev, "Query the states size failed (ret=0x%x)\n", ret);
		*state_size = 0;
		return ret;
	}
	*state_size = result;
	return 0;
}

static int nvmevf_cmd_save_data(struct nvmevf_pci_core_device *nvmevf_dev,
				    void *buffer, size_t buffer_len)
{
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct nvme_live_mig_command c = { };
	int ret;

	c.save.opcode = nvme_admin_live_mig_save_data;
	c.save.vf_index = nvmevf_dev->vf_id;

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, buffer, buffer_len);
	if (ret) {
		dev_warn(&dev->dev, "Save the device states failed (ret=0x%x)\n", ret);
		return ret;
	}
	return 0;
}

static int nvmevf_cmd_load_data(struct nvmevf_pci_core_device *nvmevf_dev,
				    struct nvmevf_migration_file *migf)
{
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct nvme_live_mig_command c = { };
	int ret;

	c.load.opcode = nvme_admin_live_mig_load_data;
	c.load.vf_index = nvmevf_dev->vf_id;
	c.load.size = migf->total_length;

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL,
			migf->vf_data, migf->total_length);
	if (ret) {
		dev_warn(&dev->dev, "Load the device states failed (ret=0x%x)\n", ret);
		return ret;
	}
	return 0;
}

static struct nvmevf_pci_core_device *nvmevf_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct nvmevf_pci_core_device, core_device);
}

static void nvmevf_disable_fd(struct nvmevf_migration_file *migf)
{
	mutex_lock(&migf->lock);

	/* release the device states buffer */
	kvfree(migf->vf_data);
	migf->vf_data = NULL;
	migf->disabled = true;
	migf->total_length = 0;
	migf->filp->f_pos = 0;
	mutex_unlock(&migf->lock);
}

static int nvmevf_release_file(struct inode *inode, struct file *filp)
{
	struct nvmevf_migration_file *migf = filp->private_data;

	nvmevf_disable_fd(migf);
	mutex_destroy(&migf->lock);
	kfree(migf);
	return 0;
}

static ssize_t nvmevf_save_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	struct nvmevf_migration_file *migf = filp->private_data;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	mutex_lock(&migf->lock);
	if (*pos > migf->total_length) {
		done = -EINVAL;
		goto out_unlock;
	}

	if (migf->disabled) {
		done = -EINVAL;
		goto out_unlock;
	}

	len = min_t(size_t, migf->total_length - *pos, len);
	if (len) {
		ret = copy_to_user(buf, migf->vf_data + *pos, len);
		if (ret) {
			done = -EFAULT;
			goto out_unlock;
		}
		*pos += len;
		done = len;
	}

out_unlock:
	mutex_unlock(&migf->lock);
	return done;
}

static const struct file_operations nvmevf_save_fops = {
	.owner = THIS_MODULE,
	.read = nvmevf_save_read,
	.release = nvmevf_release_file,
	.llseek = no_llseek,
};

static ssize_t nvmevf_resume_write(struct file *filp, const char __user *buf,
				       size_t len, loff_t *pos)
{
	struct nvmevf_migration_file *migf = filp->private_data;
	loff_t requested_length;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	if (*pos < 0 || check_add_overflow((loff_t)len, *pos, &requested_length))
		return -EINVAL;

	if (requested_length > MAX_MIGRATION_SIZE)
		return -ENOMEM;
	mutex_lock(&migf->lock);
	if (migf->disabled) {
		done = -ENODEV;
		goto out_unlock;
	}

	ret = copy_from_user(migf->vf_data + *pos, buf, len);
	if (ret) {
		done = -EFAULT;
		goto out_unlock;
	}
	*pos += len;
	done = len;
	migf->total_length += len;

out_unlock:
	mutex_unlock(&migf->lock);
	return done;
}

static const struct file_operations nvmevf_resume_fops = {
	.owner = THIS_MODULE,
	.write = nvmevf_resume_write,
	.release = nvmevf_release_file,
	.llseek = no_llseek,
};

static void nvmevf_disable_fds(struct nvmevf_pci_core_device *nvmevf_dev)
{
	if (nvmevf_dev->resuming_migf) {
		nvmevf_disable_fd(nvmevf_dev->resuming_migf);
		fput(nvmevf_dev->resuming_migf->filp);
		nvmevf_dev->resuming_migf = NULL;
	}

	if (nvmevf_dev->saving_migf) {
		nvmevf_disable_fd(nvmevf_dev->saving_migf);
		fput(nvmevf_dev->saving_migf->filp);
		nvmevf_dev->saving_migf = NULL;
	}
}

static struct nvmevf_migration_file *
nvmevf_pci_resume_device_data(struct nvmevf_pci_core_device *nvmevf_dev)
{
	struct nvmevf_migration_file *migf;
	int ret;

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("nvmevf_mig", &nvmevf_resume_fops, migf,
					O_WRONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}
	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);

	/* Allocate buffer to load the device states and the max states is 256K */
	migf->vf_data = kvzalloc(MAX_MIGRATION_SIZE, GFP_KERNEL);
	if (!migf->vf_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	return migf;

out_free:
	fput(migf->filp);
	return ERR_PTR(ret);
}

static struct nvmevf_migration_file *
nvmevf_pci_save_device_data(struct nvmevf_pci_core_device *nvmevf_dev)
{
	struct nvmevf_migration_file *migf;
	int ret;

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("nvmevf_mig", &nvmevf_save_fops, migf,
					O_RDONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}

	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);

	ret = nvmevf_cmd_query_data_size(nvmevf_dev, &migf->total_length);
	if (ret)
		goto out_free;
	/* Allocate buffer and save the device states*/
	migf->vf_data = kvzalloc(migf->total_length, GFP_KERNEL);
	if (!migf->vf_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = nvmevf_cmd_save_data(nvmevf_dev, migf->vf_data, migf->total_length);
	if (ret)
		goto out_free;

	return migf;
out_free:
	fput(migf->filp);
	return ERR_PTR(ret);
}

static struct file *
nvmevf_pci_step_device_state_locked(struct nvmevf_pci_core_device *nvmevf_dev, u32 new)
{
	u32 cur = nvmevf_dev->mig_state;
	int ret;

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_STOP) {
		ret = nvmevf_cmd_suspend_device(nvmevf_dev);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct nvmevf_migration_file *migf;

		migf = nvmevf_pci_save_device_data(nvmevf_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		nvmevf_dev->saving_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY && new == VFIO_DEVICE_STATE_STOP) {
		nvmevf_disable_fds(nvmevf_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RESUMING) {
		struct nvmevf_migration_file *migf;

		migf = nvmevf_pci_resume_device_data(nvmevf_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		nvmevf_dev->resuming_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && new == VFIO_DEVICE_STATE_STOP) {
		ret = nvmevf_cmd_load_data(nvmevf_dev, nvmevf_dev->resuming_migf);
		if (ret)
			return ERR_PTR(ret);
		nvmevf_disable_fds(nvmevf_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
		nvmevf_cmd_resume_device(nvmevf_dev);
		return NULL;
	}

	/* vfio_mig_get_next_state() does not use arcs other than the above */
	WARN_ON(true);
	return ERR_PTR(-EINVAL);
}

static void nvmevf_state_mutex_unlock(struct nvmevf_pci_core_device *nvmevf_dev)
{
again:
	spin_lock(&nvmevf_dev->reset_lock);
	if (nvmevf_dev->deferred_reset) {
		nvmevf_dev->deferred_reset = false;
		spin_unlock(&nvmevf_dev->reset_lock);
		nvmevf_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
		nvmevf_disable_fds(nvmevf_dev);
		goto again;
	}
	mutex_unlock(&nvmevf_dev->state_mutex);
	spin_unlock(&nvmevf_dev->reset_lock);
}

static struct file *
nvmevf_pci_set_device_state(struct vfio_device *vdev, enum vfio_device_mig_state new_state)
{
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(vdev,
			struct nvmevf_pci_core_device, core_device.vdev);
	enum vfio_device_mig_state next_state;
	struct file *res = NULL;
	int ret;

	mutex_lock(&nvmevf_dev->state_mutex);
	while (new_state != nvmevf_dev->mig_state) {
		ret = vfio_mig_get_next_state(vdev, nvmevf_dev->mig_state, new_state, &next_state);
		if (ret) {
			res = ERR_PTR(-EINVAL);
			break;
		}

		res = nvmevf_pci_step_device_state_locked(nvmevf_dev, next_state);
		if (IS_ERR(res))
			break;
		nvmevf_dev->mig_state = next_state;
		if (WARN_ON(res && new_state != nvmevf_dev->mig_state)) {
			fput(res);
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	nvmevf_state_mutex_unlock(nvmevf_dev);
	return res;
}

static int nvmevf_pci_get_device_state(struct vfio_device *vdev,
					   enum vfio_device_mig_state *curr_state)
{
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
			vdev, struct nvmevf_pci_core_device, core_device.vdev);

	mutex_lock(&nvmevf_dev->state_mutex);
	*curr_state = nvmevf_dev->mig_state;
	nvmevf_state_mutex_unlock(nvmevf_dev);
	return 0;
}

static int nvmevf_pci_open_device(struct vfio_device *core_vdev)
{
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
			core_vdev, struct nvmevf_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *vdev = &nvmevf_dev->core_device;
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	if (nvmevf_dev->migrate_cap)
		nvmevf_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
	vfio_pci_core_finish_enable(vdev);
	return 0;
}

static void nvmevf_cmd_close_migratable(struct nvmevf_pci_core_device *nvmevf_dev)
{
	if (!nvmevf_dev->migrate_cap)
		return;

	mutex_lock(&nvmevf_dev->state_mutex);
	nvmevf_disable_fds(nvmevf_dev);
	nvmevf_state_mutex_unlock(nvmevf_dev);
}

static void nvmevf_pci_close_device(struct vfio_device *core_vdev)
{
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
			core_vdev, struct nvmevf_pci_core_device, core_device.vdev);

	nvmevf_cmd_close_migratable(nvmevf_dev);
	vfio_pci_core_close_device(core_vdev);
}

static unsigned int nvmevf_cap_get(struct pci_dev *pdev, struct nvmevf_cap *nvmevf_cap)
{
	struct nvme_command c = { };
	struct nvme_id_ctrl *id;
	int ret;

	c.identify.opcode = nvme_admin_identify;
	c.identify.cns = NVME_ID_CNS_CTRL;

	id = kmalloc(sizeof(struct nvme_id_ctrl), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	ret = nvme_submit_vf_cmd(pdev, &c, NULL, id, sizeof(struct nvme_id_ctrl));
	if (ret) {
		dev_warn(&pdev->dev, "Get identify ctrl failed (ret=0x%x)\n", ret);
		goto out_free;
	}
	nvmevf_cap->migrate_cap = id->vs[0];
	nvmevf_cap->log_ranges_max = id->vs[1];

out_free:
	kfree(id);
	return ret;
}

static int nvmevf_pci_log_start(struct vfio_device *vdev,
						struct rb_root_cached *ranges, u32 nnodes,
						u64 *page_size)
{
	struct nvme_live_mig_command c = { };
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
					vdev, struct nvmevf_pci_core_device, core_device.vdev);
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	struct iova_ranges *iova_ranges;
	struct interval_tree_node *node = NULL;
	u32 range_count, ranges_size, i;
	int ret = 0;

	range_count = nvmevf_dev->log_ranges_max;
	if (range_count < nnodes)
		vfio_combine_ranges(ranges, nnodes, range_count);
	else
		range_count = nnodes;

	ranges_size = offsetofend(struct iova_ranges, page_size)
						+ range_count * sizeof(struct iova_range);
	iova_ranges = kvzalloc(ranges_size, GFP_KERNEL);
	if (iova_ranges == NULL)
		return -ENOMEM;

	iova_ranges->count = cpu_to_le32(range_count);
	iova_ranges->page_size = cpu_to_le64(*page_size);

	node = interval_tree_iter_first(ranges, 0, ULONG_MAX);
	for (i = 0; i < range_count; i++) {
		iova_ranges->ranges[i].iova_start = cpu_to_le64(node->start);
		iova_ranges->ranges[i].length = cpu_to_le64(node->last - node->start + 1);
		node = interval_tree_iter_next(node, 0, ULONG_MAX);
	}

	c.log_start.opcode = nvme_admin_live_mig_log_start;
	c.log_start.vf_index = cpu_to_le16(nvmevf_dev->vf_id);
	c.log_start.size = cpu_to_le32(ranges_size);

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, iova_ranges, ranges_size);
	if (ret) {
		dev_warn(&dev->dev, "DMA logging start failed (ret=0x%x)\n", ret);
		goto out_free;
	}

	nvmevf_dev->log_page_size = *page_size;
	nvmevf_dev->log_active = true;

out_free:
	kvfree(iova_ranges);
	return ret;
}

static void fill_iova_bitmap(struct iova_bitmap *dirty, unsigned char *bitmap,
						u32 bitmap_len, u64 iova, u64 length, u32 page_size)
{
	u64 byte_i, bits_valid, count;
	u64 iova_down, addr;
	u8 bits_offset, bit_i;

	bits_offset = DIV_ROUND_UP((iova - ALIGN_DOWN(iova, page_size * BITS_PER_BYTE)), page_size);
	bits_valid = (ALIGN(iova + length, page_size) - ALIGN_DOWN(iova, page_size))/page_size;
	iova_down = ALIGN_DOWN(iova, page_size);

	for (byte_i = 0, count = 0; byte_i < bitmap_len; byte_i++) {
		for (bit_i = 0; bit_i < BITS_PER_BYTE; bit_i++) {
			if (unlikely(byte_i == 0 && bit_i < bits_offset))
				continue;
			if (unlikely(count >= bits_valid))
				break;
			if (bitmap[byte_i] & BIT(bit_i)) {
				addr = iova_down + count * page_size;
				iova_bitmap_set(dirty, addr, page_size);
			}
			count++;
		}
	}
}

static int nvmevf_pci_log_read_and_clear(struct vfio_device *vdev,
							unsigned long iova, unsigned long length,
							struct iova_bitmap *dirty)
{
	struct nvme_live_mig_command c = { };
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
					vdev, struct nvmevf_pci_core_device, core_device.vdev);
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	unsigned int bitmap_len, buffer_len, offset, times;
	unsigned char *bitmap;
	u64 page_size = nvmevf_dev->log_page_size;
	u64 iova_up, iova_down, iova_curr, len_curr;
	int ret = 0;

	/* Should grab it from nvmevf_dev */
	unsigned int mdts = SZ_128K;

	iova_down = ALIGN_DOWN(iova, page_size * BITS_PER_BYTE);
	iova_up = ALIGN(iova + length, page_size * BITS_PER_BYTE);

	bitmap_len = (iova_up - iova_down) / (page_size * BITS_PER_BYTE);
	bitmap = kvzalloc(bitmap_len, GFP_KERNEL);
	if (bitmap == NULL)
		return -ENOMEM;

	c.log_report.opcode = nvme_admin_live_mig_log_report;
	c.log_report.vf_index = cpu_to_le16(nvmevf_dev->vf_id);

	times = DIV_ROUND_UP(bitmap_len, mdts);
	for (; times > 0; times--, offset += mdts) {
		if (times == 1 && bitmap_len % mdts)
			buffer_len = bitmap_len % mdts;
		else
			buffer_len = mdts;

		iova_curr = iova_down + offset * BITS_PER_BYTE * page_size;
		len_curr = buffer_len * BITS_PER_BYTE * page_size;
		c.log_report.iova = cpu_to_le64(iova_curr);
		c.log_report.length = cpu_to_le64(len_curr);

		ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, bitmap + offset,
								buffer_len);
		if (ret) {
			dev_warn(&dev->dev, "DMA logging report failed (ret=0x%x)\n", ret);
			goto out_free;
		}
	}

	/* Sync dirty bitmap received into iova_bitmap */
	fill_iova_bitmap(dirty, bitmap, bitmap_len, iova, length, page_size);

out_free:
	kvfree(bitmap);
	return ret;
}

static int nvmevf_pci_log_stop(struct vfio_device *vdev)
{
	struct nvme_live_mig_command c = { };
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
					vdev, struct nvmevf_pci_core_device, core_device.vdev);
	struct pci_dev *dev = nvmevf_dev->core_device.pdev;
	int ret = 0;

	c.log_stop.opcode = nvme_admin_live_mig_log_stop;
	c.log_stop.vf_index = cpu_to_le16(nvmevf_dev->vf_id);

	ret = nvme_submit_vf_cmd(dev, (struct nvme_command *)&c, NULL, NULL, 0);
	if (ret) {
		dev_warn(&dev->dev, "DMA logging stop failed (ret=0x%x)\n", ret);
		return ret;
	}

	nvmevf_dev->log_active = false;
	return ret;
}

static int nvmevf_pci_get_data_size(struct vfio_device *core_vdev,unsigned long *stop_copy_length) 
{ 
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(
		core_vdev, struct nvmevf_pci_core_device, core_device.vdev);
	size_t state_size; 
	int ret; 

	mutex_lock(&nvmevf_dev->state_mutex); 
	ret = nvmevf_cmd_query_data_size(nvmevf_dev, &state_size); 
	if (!ret) 
		*stop_copy_length = state_size; 
	nvmevf_state_mutex_unlock(nvmevf_dev); 
	return ret; 
} 

static const struct vfio_migration_ops nvmevf_pci_mig_ops = {
	.migration_set_state = nvmevf_pci_set_device_state,
	.migration_get_state = nvmevf_pci_get_device_state,
	.migration_get_data_size = nvmevf_pci_get_data_size, 
};

static const struct vfio_log_ops nvmevf_pci_log_ops = {
	.log_start = nvmevf_pci_log_start,
	.log_stop = nvmevf_pci_log_stop,
	.log_read_and_clear = nvmevf_pci_log_read_and_clear,
};

static int nvmevf_migration_init_dev(struct vfio_device *core_vdev)
{
	struct nvmevf_pci_core_device *nvmevf_dev = container_of(core_vdev,
					struct nvmevf_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(core_vdev->dev);
	struct nvmevf_cap nvmevf_cap;
	int vf_id, ret = -1;

	if (!pdev->is_virtfn)
		return ret;

	/* Get the identify controller data structure to check the live migration support */
	ret = nvmevf_cap_get(pdev, &nvmevf_cap);
	if (ret)
		return ret;

	ret = -1;
	nvmevf_dev->migrate_cap = nvmevf_cap.migrate_cap ? true : false;
	if (!nvmevf_dev->migrate_cap)
		return ret;

	nvmevf_dev->log_ranges_max = nvmevf_cap.log_ranges_max;

	vf_id = pci_iov_vf_id(pdev);
	if (vf_id < 0)
		return ret;
	nvmevf_dev->vf_id = vf_id + 1;
	core_vdev->migration_flags = VFIO_MIGRATION_STOP_COPY;

	if (nvmevf_dev->migrate_cap)
		core_vdev->mig_ops = &nvmevf_pci_mig_ops;
	if (nvmevf_dev->log_ranges_max)
		core_vdev->log_ops = &nvmevf_pci_log_ops;

	mutex_init(&nvmevf_dev->state_mutex);
	spin_lock_init(&nvmevf_dev->reset_lock);

	return vfio_pci_core_init_dev(core_vdev);
}

static const struct vfio_device_ops nvmevf_pci_ops = {
	.name = "nvme-vfio-pci",
	.init = nvmevf_migration_init_dev,
	.release = vfio_pci_core_release_dev,
	.open_device = nvmevf_pci_open_device,
	.close_device = nvmevf_pci_close_device,
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
	struct nvmevf_pci_core_device *nvmevf_dev;
	int ret;

	nvmevf_dev = vfio_alloc_device(nvmevf_pci_core_device, core_device.vdev,
					&pdev->dev, &nvmevf_pci_ops);
	if (IS_ERR(nvmevf_dev))
		return PTR_ERR(nvmevf_dev);

	dev_set_drvdata(&pdev->dev, &nvmevf_dev->core_device);
	ret = vfio_pci_core_register_device(&nvmevf_dev->core_device);
	if (ret)
		goto out_put_dev;
	return 0;

out_put_dev:
	vfio_put_device(&nvmevf_dev->core_device.vdev);
	return ret;

}

static void nvmevf_pci_remove(struct pci_dev *pdev)
{
	struct nvmevf_pci_core_device *nvmevf_dev = nvmevf_drvdata(pdev);

	vfio_pci_core_unregister_device(&nvmevf_dev->core_device);
	vfio_put_device(&nvmevf_dev->core_device.vdev);
}

static void nvmevf_pci_aer_reset_done(struct pci_dev *pdev)
{
	struct nvmevf_pci_core_device *nvmevf_dev = nvmevf_drvdata(pdev);

	if (!nvmevf_dev->migrate_cap)
		return;

	/*
	 * As the higher VFIO layers are holding locks across reset and using
	 * those same locks with the mm_lock we need to prevent ABBA deadlock
	 * with the state_mutex and mm_lock.
	 * In case the state_mutex was taken already we defer the cleanup work
	 * to the unlock flow of the other running context.
	 */
	spin_lock(&nvmevf_dev->reset_lock);
	nvmevf_dev->deferred_reset = true;
	if (!mutex_trylock(&nvmevf_dev->state_mutex)) {
		spin_unlock(&nvmevf_dev->reset_lock);
		return;
	}
	spin_unlock(&nvmevf_dev->reset_lock);
	nvmevf_state_mutex_unlock(nvmevf_dev);
}

static const struct pci_device_id nvmevf_pci_table[] = {
	/* Intel IPU NVMe Virtual Function */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x1457) },
	{}
};

MODULE_DEVICE_TABLE(pci, nvmevf_pci_table);

static const struct pci_error_handlers nvmevf_err_handlers = {
	.reset_done = nvmevf_pci_aer_reset_done,
	.error_detected = vfio_pci_core_aer_err_detected,
};

static struct pci_driver nvmevf_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = nvmevf_pci_table,
	.probe = nvmevf_pci_probe,
	.remove = nvmevf_pci_remove,
	.err_handler = &nvmevf_err_handlers,
	.driver_managed_dma = true,
};

module_pci_driver(nvmevf_pci_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lei Rao <lei.rao@intel.com>");
MODULE_DESCRIPTION("NVMe VFIO PCI - VFIO PCI driver with live migration support for NVMe");
