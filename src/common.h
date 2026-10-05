#ifndef KEENPBR_COMMON_H
#define KEENPBR_COMMON_H

#include <linux/netfilter.h>

#ifndef KEENPBR_PRIORITY
#error "KEENPBR_PRIORITY must be a numeric compile-time value"
#endif

#ifndef KEENPBR_VERSION
#error "KEENPBR_VERSION must be supplied at build time"
#endif

#define KEENPBR_TABLE_ABI 1
#define KEENPBR_TABLE_NAME "keenpbr"
#define KEENPBR_VALID_HOOKS (1 << NF_INET_PRE_ROUTING)

#endif
