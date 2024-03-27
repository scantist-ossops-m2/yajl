# -*- makefile-bsdmake -*-

# N.B.:  ${.CURDIR} here is not needed -- it's already implied because of the
# include done by <bsd.prog.mk> in the subdir's Makefile
.include "../Makefile.inc"

# XXX there's something odd about sjg's Mk-files, and older versions of his BMake.
#
# For some unknown reason <subdir.mk> does .-include <${.CURDIR}/Makefile.inc>.
# No other BSD-based Mk-files does this.
#
# Also until very recently BMake didn't implement .INCLUDEDFROMFILE or
# .INCLUDEDFROMDIR correctly!  This was probably fixed in NetBSD make with the
# following change:
#
# revision 1.281
# date: 2020-09-05 11:18:05 -0700;  author: rillig;  state: Exp;  lines: +60 -66;  commitid: 6IOaNyfoXI226TmC;
# make(1): fix .INCLUDEDFROMDIR/.INCLUDEDFROMFILE
#
# So it is possibly fixed in BMake 20200911, and more likely in 20200927.
#
# xxx so this hack only works with very recent BMake.  Sadly that doesn't
# include the GitHub Ubuntu 22.04 runner with BMake 20200710.
#
.if !defined(.INCLUDEDFROMFILE) || \
	${.INCLUDEDFROMFILE} != "subdir.mk"
bmake_topdir := ${bmake_topdir}/..
#.error "bmake_topdir= ${bmake_topdir}: Included from ${.INCLUDEDFROMDIR}'/'${.INCLUDEDFROMFILE}"
.endif

#.error "bmake_topdir= ${bmake_topdir}: Included from ${.INCLUDEDFROMDIR}'/'${.INCLUDEDFROMFILE}"
