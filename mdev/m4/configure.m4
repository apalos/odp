##########################################################################
# Enable/disable mdev framework
##########################################################################
AC_CONFIG_FILES([mdev/Makefile])
AC_ARG_ENABLE([mdev],
    [AS_HELP_STRING([--enable-mdev], [Enable mediated device support])],
    [mdev=$enableval],
    [mdev=no])
AM_CONDITIONAL([mdev], [test x$mdev = xyes ])
