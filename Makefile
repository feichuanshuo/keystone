
#############################
## Configuration variables ##
#############################

export SHELL := /bin/bash

# 设置项目目录
export KEYSTONE                 ?= $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
export KEYSTONE_BUILDROOT       ?= $(KEYSTONE)/buildroot
export KEYSTONE_BR2_EXT         ?= $(KEYSTONE)/overlays

export KEYSTONE_DRIVER          ?= $(KEYSTONE)/linux-keystone-driver
export KEYSTONE_EXAMPLES        ?= $(KEYSTONE)/examples
export KEYSTONE_RUNTIME         ?= $(KEYSTONE)/runtime
export KEYSTONE_SDK             ?= $(KEYSTONE)/sdk
export KEYSTONE_BOOTROM         ?= $(KEYSTONE)/bootrom
export KEYSTONE_SM              ?= $(KEYSTONE)/sm

# 设置构建目录
export BUILDDIR                 ?= $(KEYSTONE)/build-$(KEYSTONE_PLATFORM)$(KEYSTONE_BITS)
export BUILDROOT_OVERLAYDIR     ?= $(BUILDDIR)/overlay
export BUILDROOT_BUILDDIR       ?= $(BUILDDIR)/buildroot.build

# 设置构建参数
export KEYSTONE_PLATFORM        ?= generic
export KEYSTONE_BITS            ?= 64

# 命令行参数解析
include mkutils/args.mk
# 处理日志功能
include mkutils/log.mk

# 设置构建配置文件
BUILDROOT_CONFIGFILE    ?= qemu_riscv$(KEYSTONE_BITS)_virt_defconfig
# 平台为mpfs时
ifeq ($(KEYSTONE_PLATFORM),mpfs)
	EXTERNALS += microchip
endif

# Highest priority external  最高优先级的外部依赖
EXTERNALS += keystone

# 一组Make工具的参数，用于在构建时指定Buildroot的相关配置
# 切换到KEYSTONE_BUILDROOT目录下，输出到BUILDROOT_BUILDDIR目录下
BUILDROOT_MAKEFLAGS     := -C $(KEYSTONE_BUILDROOT) O=$(BUILDROOT_BUILDDIR)
# 设置了Buildroot的外部配置，根据 EXTERNALS 变量的值，添加了外部配置目录
BUILDROOT_MAKEFLAGS     += BR2_EXTERNAL=$(call SEPERATE_LIST,:,$(addprefix $(KEYSTONE_BR2_EXT)/,$(EXTERNALS)))

#####################
## Generic targets ##
#####################

all: buildroot

# 指定的目录不存在则创建
$(BUILDDIR):
	mkdir -p $@

###############
## Buildroot ##
###############

# Build directory

# 指定的目录不存在则创建
$(BUILDROOT_BUILDDIR): $(BUILDDIR)
	mkdir -p $@

$(BUILDROOT_OVERLAYDIR): $(BUILDDIR)
	mkdir -p $@

# Configuration

$(BUILDROOT_BUILDDIR)/.config: $(BUILDROOT_BUILDDIR)
	# 打印信息：正在使用配置文件$(BUILDROOT_CONFIGFILE)配置Buildroot
	$(call log,info,Configuring Buildroot with $(BUILDROOT_CONFIGFILE))
	# 使用指定的配置文件配置Buildroot
	$(MAKE) $(BUILDROOT_MAKEFLAGS) $(BUILDROOT_CONFIGFILE)
	# BR2_ROOTFS_OVERLAY变量的值写入.config文件
	echo "BR2_ROOTFS_OVERLAY=\"$(BUILDROOT_OVERLAYDIR)\"" >> $(BUILDROOT_BUILDDIR)/.config

# Overlay

$(BUILDROOT_OVERLAYDIR)/.done: $(BUILDROOT_OVERLAYDIR)
	# 打印信息：正在配置overlay
	$(call log,info,Setting up overlay)
	# 创建目录 $(BUILDROOT_OVERLAYDIR)/root/.ssh
	mkdir -p $(BUILDROOT_OVERLAYDIR)/root/.ssh
	# 生成ssh密钥对，并将私钥保存在$(BUILDROOT_OVERLAYDIR)/root/.ssh/id-rsa文件中，公钥保存在$(BUILDROOT_OVERLAYDIR)/root/.ssh/id-rsa.pub文件中。
	ssh-keygen -C 'root@keystone' -t rsa -f $(BUILDROOT_OVERLAYDIR)/root/.ssh/id-rsa -N ''
	# 复制公钥到$(BUILDROOT_OVERLAYDIR)/root/.ssh/authorized_keys文件中
	cp $(BUILDROOT_OVERLAYDIR)/root/.ssh/{id-rsa.pub,authorized_keys}
	# 创建一个名为$(BUILDROOT_OVERLAYDIR)/.done的空文件，表示这个目标已经完成。
	touch $@

# Main build target for buildroot. The specific subtarget to build can be overriden
# by setting the BUILDROOT_TARGET environment variable.

BUILDROOT_TARGET        ?= all

.PHONY: buildroot
buildroot: $(BUILDROOT_BUILDDIR)/.config $(BUILDROOT_OVERLAYDIR)/.done
	$(call log,info,Building Buildroot)
	$(MAKE) $(BUILDROOT_MAKEFLAGS) $(BUILDROOT_TARGET) 2>&1 | \
            tee $(BUILDDIR)/build.log | LC_ALL=C grep -of scripts/grep.patterns

# Useful configuration target. This is meant as a development helper to keep
# the repository configuration in sync with what the user is doing. It
# automatically replaces the earlier specified configuration file in the
# BR2_EXTERNAL directory.

.PHONY: buildroot-configure
buildroot-configure: $(BUILDROOT_BUILDDIR)/.config
	$(call log,info,Configuring Buildroot)
	# 打开 Buildroot 的配置菜单，允许用户进行配置。
	$(MAKE) $(BUILDROOT_MAKEFLAGS) menuconfig
	$(call log,debug,Saving new defconfig)
	# 保存新的配置文件为默认配置
	$(MAKE) $(BUILDROOT_MAKEFLAGS) savedefconfig
	# 在 $(KEYSTONE_BR2_EXT)/keystone/configs/$(BUILDROOT_CONFIGFILE) 文件中删除包含 BR2_ROOTFS_OVERLAY 的行
	sed -i '/BR2_ROOTFS_OVERLAY.*/d' $(KEYSTONE_BR2_EXT)/keystone/configs/$(BUILDROOT_CONFIGFILE)

.PHONY: linux-configure
linux-configure: $(BUILDROOT_BUILDDIR)/.config
	$(call log,info,Configuring Linux)
	# 打开 Linux 的配置菜单，允许用户进行配置。
	$(MAKE) $(BUILDROOT_MAKEFLAGS) linux-menuconfig
	$(call log,debug,Saving new defconfig)
	# 保存新的配置文件为默认配置
	$(MAKE) $(BUILDROOT_MAKEFLAGS) linux-savedefconfig
	# 生成一个Linux内核的配置文件, 并将其移动到指定位置, 以供后续使用
	LINUX_BUILDDIR=$$($(MAKE) -s KEYSTONE_LOG_LEVEL=$(LOG_FATAL) $(BUILDROOT_MAKEFLAGS) linux-show-info | jq -r '.linux|.build_dir') ; \
            LINUX_CONFIGFILE=$$(cat $(KEYSTONE_BR2_EXT)/keystone/configs/$(BUILDROOT_CONFIGFILE) | grep BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE | \
                                    awk -F'=' '{ print $$2 }' | sed 's;$$(BR2_EXTERNAL_KEYSTONE_PATH);$(KEYSTONE_BR2_EXT)/keystone;g' | tr -d '"'); \
            mv "$(BUILDROOT_BUILDDIR)/$$LINUX_BUILDDIR/defconfig" "$$LINUX_CONFIGFILE"

#################
## Run targets ##
#################

-include mkutils/plat/$(KEYSTONE_PLATFORM)/run.mk
