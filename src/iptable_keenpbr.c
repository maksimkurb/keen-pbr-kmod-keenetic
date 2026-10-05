// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <linux/stringify.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "common.h"

/* Table lifecycle follows the Linux 4.9 iptable_raw per-net pattern. */

struct keenpbr_net {
	struct xt_table *table;
};

static int keenpbr_net_id;
static struct nf_hook_ops *keenpbr_hook_ops;

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
	struct keenpbr_net *info = net_generic(state->net, keenpbr_net_id);

	return ipt_do_table(skb, state, info->table);
}

static int __net_init keenpbr_table_init(struct net *net)
{
	struct keenpbr_net *info = net_generic(net, keenpbr_net_id);
	static const struct xt_table table = {
		.name = KEENPBR_TABLE_NAME,
		.valid_hooks = KEENPBR_VALID_HOOKS,
		.me = THIS_MODULE,
		.af = NFPROTO_IPV4,
		.priority = KEENPBR_PRIORITY,
		.table_init = keenpbr_table_init,
	};
	struct ipt_replace *repl;
	int ret;

	if (info->table)
		return 0;

	repl = ipt_alloc_initial_table(&table);
	if (!repl)
		return -ENOMEM;
	ret = ipt_register_table(net, &table, repl, keenpbr_hook_ops,
				&info->table);
	kfree(repl);
	return ret;
}

static void __net_exit keenpbr_net_exit(struct net *net)
{
	struct keenpbr_net *info = net_generic(net, keenpbr_net_id);

	if (info->table) {
		ipt_unregister_table(net, info->table, keenpbr_hook_ops);
		info->table = NULL;
	}
}

static struct pernet_operations keenpbr_net_ops = {
	.id = &keenpbr_net_id,
	.size = sizeof(struct keenpbr_net),
	.exit = keenpbr_net_exit,
};

static int __init keenpbr_init(void)
{
	static const struct xt_table table = {
		.valid_hooks = KEENPBR_VALID_HOOKS,
		.af = NFPROTO_IPV4,
		.priority = KEENPBR_PRIORITY,
	};
	int ret;

	keenpbr_hook_ops = xt_hook_ops_alloc(&table, keenpbr_hook);
	if (IS_ERR(keenpbr_hook_ops))
		return PTR_ERR(keenpbr_hook_ops);

	ret = register_pernet_subsys(&keenpbr_net_ops);
	if (ret)
		goto free_hooks;

	ret = keenpbr_table_init(&init_net);
	if (ret)
		goto unregister_pernet;
	return 0;

unregister_pernet:
	unregister_pernet_subsys(&keenpbr_net_ops);
free_hooks:
	kfree(keenpbr_hook_ops);
	return ret;
}

static void __exit keenpbr_exit(void)
{
	unregister_pernet_subsys(&keenpbr_net_ops);
	kfree(keenpbr_hook_ops);
}

module_init(keenpbr_init);
module_exit(keenpbr_exit);
MODULE_DESCRIPTION("keenpbr IPv4 PREROUTING xtables table");
MODULE_AUTHOR("keen-pbr contributors");
MODULE_LICENSE("GPL");
MODULE_VERSION(KEENPBR_VERSION);
MODULE_INFO(keenpbr_priority, __stringify(KEENPBR_PRIORITY));
MODULE_INFO(keenpbr_table_abi, __stringify(KEENPBR_TABLE_ABI));
