#!/bin/bash -v
CURDIR=$(cd "$(dirname "${BASH_SOURCE:-$0}")"; pwd)
TOP_DIR=$(cd "${CURDIR}/../..";pwd )
PRODUCT_NAME=${pd}

export MIPS_TOOLS_DIR=/opt/xlp_mipscross/mipscross/linux/bin
export MIPS_CROSS_COMPILE=mips64-nlm-linux-
export KERNDIR=${TOP_DIR}/os/linux
export LINUX_INCLUDE=${TOP_DIR}/os/linux/include
export KERN_BUILDDIR=${TOP_DIR}/os/linux/build.${PRODUCT_NAME}
export SDK=${TOP_DIR}/bcm
export BLDCONFIG=${PRODUCT_NAME}
export DELIVERY=${KERNDIR}/usr/rootfs.xlp.${PRODUCT_NAME}/galaxywind
export NO_LOCAL_TARGETS=1
export kernel_version=2_6
export platform=gtr-${kernel_version}
export ZEBOS=${TOP_DIR}/zeb
