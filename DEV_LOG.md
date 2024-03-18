# 开发日志

## 为qemu添加传感器

**~~方案一：尝试使用qemu目录下自带的传感器~~**

` hw/sensor`目录中存在tmp105等传感器，考虑使用该部分传感器。

修改 `keystone/mkutils/plat/generic`下的 `run.mk`文件

```
QEMU_FLAGS := -m $(QEMU_MEM) -smp $(QEMU_SMP) -nographic \
                -machine virt,rom=$(BUILDROOT_BUILDDIR)/images/bootrom.bin \
                -bios $(BUILDROOT_BUILDDIR)/images/fw_jump.elf \
                -kernel $(BUILDROOT_BUILDDIR)/images/Image \
                -drive file=$(BUILDROOT_BUILDDIR)/images/rootfs.ext2,format=raw,id=hd0 \
                -device virtio-blk-device,drive=hd0 \
                -append "console=ttyS0 ro root=/dev/vda" \
                -netdev user,id=net0,net=192.168.100.1/24,dhcpstart=192.168.100.128,hostfwd=tcp::9821-:22 \
                -device virtio-net-device,netdev=net0 \
                -device virtio-rng-pci \
                -device i2c-bus,id=i2c-bus-0 \
                -device i2c-temperature-sensor,bus=i2c-bus-0,address=0x48 \
```

尝试了所用可用传感器，均失败！！！

**问题分析：**

通过在 `build-generic64/buildroot.build/host/bin` 目录下运行

```
./qemu-system-riscv64 -device help
```

查明qemu-riscv并不支持所包含的传感器

**方案二：尝试自己构建传感器外设并接入（ing...）**

通过查看qemu-risc-v支持的设备，可知可以添加一个虚拟的 I2C 设备,使用 `vhost-user-i2c-device` 模型，并指定相应的 `chardev` 来与主机上的某个字符设备通信。
