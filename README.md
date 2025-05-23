# kjson
内核态cJSON

kernel-4.14

`example`

```c

#include <linux/version.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/cma.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/sched/signal.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <uapi/linux/sched/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/spinlock.h>
#include "kcjson.h"

char *test_cjosn_encode(char *outputs)
{
    cJSON *root, *device1, *device2;
    cJSON *aspace, *vdevs;

    root = cJSON_CreateObject();
    aspace = cJSON_CreateObject();
    vdevs = cJSON_CreateArray();
    device1 = cJSON_CreateObject();
    device2 = cJSON_CreateObject();
    cJSON_AddStringToObject(device1, "name", "virtio_1");
    cJSON_AddStringToObject(device1, "name", "virtio_2");
    cJSON_AddItemToArray(vdevs, device1);
    cJSON_AddItemToArray(vdevs, device2);
    cJSON_AddItemToObject(aspace, "VDEVS", vdevs);
    json_str = cJSON_Print(root);
    if (json_str != NULL) {
        printk(KERN_DEBUG"json_str:\n%s\n", json_str);
    }
    cJSON_Delete(root);

    return json_str;
}

void test_cjosn_decode(char *outputs)
{
	char *json_buf = outputs;
	cJSON *json_root, *json_aspace;
	cJSON *json, *rnode;
	const char *aval;
	int ret;

	json_root = cJSON_Parse(json_buf);
	if(!json_root) {
		printk(KERN_ERR"%s %d cJSON_Parse err!\n", __func__, __LINE__);
		return;
	}

	json_aspace = cJSON_GetObjectItem(json_root, "aspace");
	if(!json_aspace) {
		printk(KERN_ERR"%s %d cJSON_GetObjectItem aspace err!\n", __func__, __LINE__);
		return;
	}

	json = cJSON_GetObjectItem(json_root, "VDEVS");
	if(!json) {
		printk(KERN_ERR"%s %d cJSON_GetObjectItem VDEVS err!\n", __func__, __LINE__);
		return;
	}

	cJSON_ArrayForEach(rnode, json) {
		ret = json_getattr_string(rnode, "name", &aval);
		if(ret == 0)
			printk(KERN_DEBUG"%s %d aval %s\n", __func__, __LINE__, aval);
		else 
			printk(KERN_ERR"%s %d json_getattr_string ret %d\n", __func__, __LINE__, ret);
	}
}
```

