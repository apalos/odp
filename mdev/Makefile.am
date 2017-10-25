pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodp-mdev.pc

LIB   = $(top_builddir)/lib
AM_CPPFLAGS = -I$(srcdir)/include
AM_CPPFLAGS += -I$(top_srcdir)/platform/@with_platform@/include
AM_CPPFLAGS += -I$(top_srcdir)/include
AM_CPPFLAGS += -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
AM_CPPFLAGS += -I$(top_builddir)/platform/@with_platform@/include
AM_CPPFLAGS += -I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@
AM_CPPFLAGS += -I$(top_builddir)/include

AM_LDFLAGS = -version-number '$(ODPHELPER_LIBSO_VERSION)'

mdevincludedir = $(includedir)/mdev/helper/
mdevinclude_HEADERS = \
		  $(srcdir)/include/mm_api.h \
		  $(srcdir)/include/common.h \ 
		  $(srcdir)/include/vfio_api.h \
		  $(srcdir)/include/reg_api.h \
		  $(srcdir)/include/drivers/driver_ops.h \
		  $(srcdir)/include/drivers/r8169.h

noinst_HEADERS =

__LIB__libmdev_la_SOURCES = \
					api/mm.c \
					api/vfio_api.c \
					drivers/e1000e.c \
					drivers/r8169.c

lib_LTLIBRARIES =
