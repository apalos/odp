LIB = $(top_builddir)/lib

AM_CPPFLAGS = \
		-I$(srcdir)/include \
		-I$(top_srcdir)/platform/@with_platform@/include \
		-I$(top_srcdir)/include \
		-I$(top_srcdir)/include/odp/arch/@ARCH_ABI@ \
		-I$(top_builddir)/platform/@with_platform@/include \
		-I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@ \
		-I$(top_builddir)/include \
		-I$(top_srcdir)/frameworks/modular

lib_LTLIBRARIES = \
		$(LIB)/libnet_mdev_r8169.la \
		$(LIB)/libnet_mdev_e1000e.la \
		$(LIB)/libnet_mdev_cxgb4.la

noinst_HEADERS = \
		$(srcdir)/include/mm_api.h \
		$(srcdir)/include/common.h \
		$(srcdir)/include/vfio_api.h \
		$(srcdir)/include/reg_api.h \
		$(srcdir)/include/drivers/r8169.h

__LIB__libnet_mdev_r8169_la_SOURCES = \
		api/mm.c \
		api/vfio_api.c \
		api/sysfs_parse.c \
		api/eth_stats.c \
		drivers/r8169.c

__LIB__libnet_mdev_e1000e_la_SOURCES = \
		api/mm.c \
		api/vfio_api.c \
		api/sysfs_parse.c \
		api/eth_stats.c \
		drivers/e1000e.c

__LIB__libnet_mdev_cxgb4_la_SOURCES = \
		api/mm.c \
		api/vfio_api.c \
		api/sysfs_parse.c \
		api/eth_stats.c \
		drivers/cxgb4.c
