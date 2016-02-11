#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xd46248e6, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x343a1a8, __VMLINUX_SYMBOL_STR(__list_add) },
	{ 0xb2d48a2e, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x4205ad24, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0x1e047854, __VMLINUX_SYMBOL_STR(warn_slowpath_fmt) },
	{ 0xc671e369, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xb742fd7, __VMLINUX_SYMBOL_STR(simple_strtol) },
	{ 0x5152e605, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0x4e4379, __VMLINUX_SYMBOL_STR(crypto_shash_final) },
	{ 0x827d96f6, __VMLINUX_SYMBOL_STR(crypto_shash_update) },
	{ 0x55925520, __VMLINUX_SYMBOL_STR(crypto_alloc_shash) },
	{ 0xb81960ca, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x6118f29, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x89b6a278, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xb5419b40, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x32a06686, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0xb6ed1e53, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x98e259b3, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
	{ 0x781a6c93, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x2bc95bd4, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xf3bbde6a, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xd9665429, __VMLINUX_SYMBOL_STR(crypto_alloc_base) },
	{ 0xffdb82bc, __VMLINUX_SYMBOL_STR(sg_free_table) },
	{ 0xe094ef39, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0xea01a685, __VMLINUX_SYMBOL_STR(mem_map) },
	{ 0xffe5ac28, __VMLINUX_SYMBOL_STR(vmalloc_to_page) },
	{ 0xd2a941d4, __VMLINUX_SYMBOL_STR(sg_init_table) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x9330cb9f, __VMLINUX_SYMBOL_STR(sg_alloc_table) },
	{ 0xa51cdfe8, __VMLINUX_SYMBOL_STR(__FIXADDR_TOP) },
	{ 0x8a7d1c31, __VMLINUX_SYMBOL_STR(high_memory) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xea011e5, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0x62b72b0d, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xe16b893b, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xc19dccc9, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x1da898a7, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xee5a06d1, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x902bd379, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x18d9971, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x521445b, __VMLINUX_SYMBOL_STR(list_del) },
	{ 0x5e3b3ab4, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x42160169, __VMLINUX_SYMBOL_STR(flush_workqueue) },
	{ 0x56cb2648, __VMLINUX_SYMBOL_STR(sysptr) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "659263B6E1959E850E84974");
