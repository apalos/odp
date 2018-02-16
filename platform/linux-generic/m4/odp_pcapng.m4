##########################################################################
# Enable PCAPNG support
##########################################################################
have_pcapng=no
AC_ARG_ENABLE([pcapng-support],
	[AS_HELP_STRING([--enable-pcapng-support],
	[enable experimental tcpdump for pktios])],
	have_pcapng=$enableval)

if test x$have_pcapng = xyes
then
    AC_DEFINE([ODP_PCAPNG], [1],
	      [Define to 1 to enable pcapng support])
else
    AC_DEFINE([ODP_PCAPNG], [0],
	      [Define to 0 to disable pcapng support])
fi

AM_CONDITIONAL([have_pcapng], [test x$have_pcapng = xyes])
