# KTSensing：一个基于Keystone的可信感知系统

## 说明

项目环境为 Ubuntu 22.04.2 LTS
目前只在qemu中完成相关测试

## 项目进度

- [X] 完成基础环境的搭建
- [ ] 为qemu添加传感器外设
- [ ] 构建可信身份和信任根
- [ ] 实现数据感知功能

## 如何启动

**克隆项目**

```
git clone --recurse-submodules https://github.com/keystone-enclave/keystone.git
```

**安装所需包**

```
sudo apt update
sudo apt install autoconf automake autotools-dev bc \
bison build-essential curl expat jq libexpat1-dev flex gawk gcc git \
gperf libgmp-dev libmpc-dev libmpfr-dev libtool texinfo tmux \
patchutils zlib1g-dev wget bzip2 patch vim-common lbzip2 python3 \
pkg-config libglib2.0-dev libpixman-1-dev libssl-dev screen \
device-tree-compiler expect makeself unzip cpio rsync cmake ninja-build p7zip-full
```

**构建所用组件**

```
cd keystone
make -j$(nproc)
```

**启动qemu**

```
make run
```

**登录**

```
账户：root
密码：sifive
```

**在qemu中启动keystone**

```
modprobe keystone-driver
```

**运行感知程序**

```
cd /usr/share/keystone/examples
./sensing.ko
```
