include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=keenpbr-table
PKG_VERSION:=$(shell cat $(CURDIR)/VERSION)
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

KEENPBR_PRIORITY_MODE?=after-mangle
ifeq ($(KEENPBR_PRIORITY_MODE),raw)
KEENPBR_PRIORITY:=-300
else ifeq ($(KEENPBR_PRIORITY_MODE),after-raw)
KEENPBR_PRIORITY:=-299
else ifeq ($(KEENPBR_PRIORITY_MODE),before-mangle)
KEENPBR_PRIORITY:=-151
else ifeq ($(KEENPBR_PRIORITY_MODE),after-mangle)
KEENPBR_PRIORITY:=-149
else
$(error Unsupported KEENPBR_PRIORITY_MODE: $(KEENPBR_PRIORITY_MODE))
endif

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) $(CURDIR)/src/* $(PKG_BUILD_DIR)/src/
	$(CP) $(CURDIR)/LICENSE $(PKG_BUILD_DIR)/LICENSE
endef

define Build/Compile
	+$(MAKE) $(KERNEL_MAKEOPTS) M="$(PKG_BUILD_DIR)/src" \
		$(if $(strip $(CFLAGS_MODULE)),CFLAGS_MODULE="$(CFLAGS_MODULE)") \
		KEENPBR_VERSION="$(PKG_VERSION)" \
		KEENPBR_PRIORITY="$(KEENPBR_PRIORITY)" modules
endef

define KernelPackage/keenpbr-table
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Netfilter Extensions
  TITLE:=keenpbr PREROUTING xtables table
  DEPENDS:=+kmod-ipt-core +IPV6:kmod-ip6tables
  FILES:=$(PKG_BUILD_DIR)/src/iptable_keenpbr.ko $(if $(CONFIG_IP6_NF_IPTABLES),$(PKG_BUILD_DIR)/src/ip6table_keenpbr.ko)
endef

define KernelPackage/keenpbr-table/description
  Independent PREROUTING-only keenpbr tables for IPv4 and optional IPv6.
endef

$(eval $(call KernelPackage,keenpbr-table))
