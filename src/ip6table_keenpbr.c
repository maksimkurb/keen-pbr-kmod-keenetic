// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/slab.h>
#include <linux/stringify.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "common.h"

/* Table lifecycle follows the Linux 4.9 ip6table_raw per-net pattern. */

struct keenpbr_net {
	struct xt_table *table;
	struct nf_hook_ops *hook_ops;
};

static int keenpbr_net_id;
/* ponytail: global lock serializes rare table creation;
 * per-net locks if contention matters.
 */
static DEFINE_MUTEX(keenpbr_table_init_mutex);

static int keenpbr_priority = KEENPBR_PRIORITY;
static int keenpbr_table_abi = KEENPBR_TABLE_ABI;
static int keenpbr_param_set_readonly(const char *value,
				      const struct kernel_param *param)
{
	(void)value;
	(void)param;
	return -EPERM;
}

static const struct kernel_param_ops keenpbr_readonly_param_ops = {
	.set = keenpbr_param_set_readonly,
	.get = param_get_int,
};
module_param_cb(priority, &keenpbr_readonly_param_ops, &keenpbr_priority, 0444);
module_param_cb(table_abi, &keenpbr_readonly_param_ops, &keenpbr_table_abi, 0444);

static unsigned int keenpbr_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct keenpbr_net *info = priv;

	return ip6t_do_table(skb, state, info->table);
}

static int __net_init keenpbr_table_init(struct net *net)
{
	struct keenpbr_net *info = net_generic(net, keenpbr_net_id);
	static const struct xt_table table = {
		.name = KEENPBR_TABLE_NAME,
		.valid_hooks = KEENPBR_VALID_HOOKS,
		.me = THIS_MODULE,
		.af = NFPROTO_IPV6,
		.priority = KEENPBR_PRIORITY,
		.table_init = keenpbr_table_init,
	};
	struct ip6t_replace *repl;
	struct nf_hook_ops *hook_ops;
	int ret;

	mutex_lock(&keenpbr_table_init_mutex);
	if (info->table) {
		ret = 0;
		goto out_unlock;
	}

	repl = ip6t_alloc_initial_table(&table);
	if (!repl) {
		pr_err("allocating initial table failed: %d\n", -ENOMEM);
		ret = -ENOMEM;
		goto out_unlock;
	}
	hook_ops = xt_hook_ops_alloc(&table, keenpbr_hook);
	if (IS_ERR(hook_ops)) {
		ret = PTR_ERR(hook_ops);
		hook_ops = NULL;
		pr_err("allocating hook ops failed: %d\n", ret);
		goto out_free_repl;
	}
	/* This table has only PREROUTING, so xt_hook_ops_alloc returns one op. */
	hook_ops[0].priv = info;
	ret = ip6t_register_table(net, &table, repl, hook_ops,
				  &info->table);
	if (ret) {
		pr_err("registering table failed: %d\n", ret);
		kfree(hook_ops);
	} else {
		info->hook_ops = hook_ops;
	}
out_free_repl:
	kfree(repl);
out_unlock:
	mutex_unlock(&keenpbr_table_init_mutex);
	return ret;
}

static void __net_exit keenpbr_net_exit(struct net *net)
{
	struct keenpbr_net *info = net_generic(net, keenpbr_net_id);

	mutex_lock(&keenpbr_table_init_mutex);
	if (info->table) {
		ip6t_unregister_table(net, info->table, info->hook_ops);
		info->table = NULL;
	}
	kfree(info->hook_ops);
	info->hook_ops = NULL;
	mutex_unlock(&keenpbr_table_init_mutex);
}

static struct pernet_operations keenpbr_net_ops = {
	.id = &keenpbr_net_id,
	.size = sizeof(struct keenpbr_net),
	.exit = keenpbr_net_exit,
};

static int __init keenpbr_init(void)
{
	int ret;

	ret = register_pernet_subsys(&keenpbr_net_ops);
	if (ret) {
		pr_err("registering pernet subsystem failed: %d\n", ret);
		return ret;
	}

	ret = keenpbr_table_init(&init_net);
	if (ret) {
		unregister_pernet_subsys(&keenpbr_net_ops);
		return ret;
	}
	return 0;
}

static void __exit keenpbr_exit(void)
{
	unregister_pernet_subsys(&keenpbr_net_ops);
}

module_init(keenpbr_init);
module_exit(keenpbr_exit);
MODULE_DESCRIPTION("keenpbr IPv6 PREROUTING xtables table");
MODULE_AUTHOR("keen-pbr contributors");
MODULE_LICENSE("GPL");
MODULE_VERSION(KEENPBR_VERSION);
MODULE_INFO(keenpbr_priority, __stringify(KEENPBR_PRIORITY));
MODULE_INFO(keenpbr_table_abi, __stringify(KEENPBR_TABLE_ABI));
