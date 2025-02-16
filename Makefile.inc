# -*- makefile-bsdmake -*-

#	Common/shared setup for BSD Makefiles
#
# N.B.:  Nothing in here should be changed just to build this project.
#
# (Some settings can be overridden on the command-line or from environment
# variables though...)

# XXX see SJG's SSLrsh release for simple portability hacks via Make e.g. in
# particular the use of .-include "$Makefile.${MACHINE}.inc" etc.

# For subdirectories Makefiles this ${bmake_topdir} is provided to help find the
# project's root directory.
#
# N.B.:  the top-level Makefile is not expected to ever have to use it though!
#
bmake_topdir = ..
#
# ${bmake_topdir} is used to allow values in LDADD, DPADD, and CPPFLAGS (or
# CFLAGS) to directly reference both products and sources in other parts of the
# tree, especially if they are set in this file (though use directly in subdir
# makefiles can help them be more readable).  This is particularly useful for a
# project that builds a library used by other programs in the same project,
# and/or which may also build header files shared by several sources in
# different directories in the same project.
#
# For example this file can be used to define the version number(s) for the
# project, and thus sources which use these numbers (header file templates, or
# shared library filenames, etc), can add a dependency on this file as follows:
#
#	version.h: ${.CURDIR}/version.h.in ${.CURDIR}/${bmake_topdir}/Makefile.inc
#
# This file is included by default from any subdirectory makefile by BSD Make's
# standard files, or at least via any of the standard <bsd.*.mk> files which are
# used by makefiles intended to build some actual target.  Normally this happens
# very early on, just before <bsd.own.mk> is included, and it is done by
# sub-directory makes.  For most implementations certain system variables must
# be defined before <bsd.own.mk> is included, and so they can be defined here.
# See below though for why this also includes <bsd.own.mk> itself half-way
# through.  As such we depend on the standard <bsd.*.mk> files protecting
# themselves from multiple inclusions, and though this was not true on the
# original CSRG BSD releases it has been done now in all modern releases.
#
# Note also that this is only included by default by Makefiles using standard
# <bsd.*.mk> files in an immediate subdirectory -- i.e. it is done as follows:
#
#	.include "${.CURDIR}/../Makefile.inc"
#
# Thus the top level Makefile may need to directly include this file, but it
# must only do so after it has defined the default target (i.e. the .MAIN
# target, normally "all").  The top level Makefile should not (need to) use
# ${bmake_topdir}.
#
# This also means that in any project with deeper source trees it may be
# necessary to create a "Makefile.inc" in intermediate sub-directories in order
# for this file to be shared to the deeper sub-directories.  The intermediate
# "Makefile.inc" files should have the following content:
#
#	# -*- makefile-bsdmake -*-
#	#
#	# N.B.:  ${.CURDIR} here is not needed -- it's already implied because of the
#	# include done by <bsd.prog.mk> in the subdir's Makefile
#	.include "../Makefile.inc"
#	bmake_topdir := ${bmake_topdir}/..

.if !target(_GAW_bmake-showenv)

# include any project-specific settings
#
# normally this includes the package name (${PACKAGE}), and include
# sub-directory name (${INCSUBDIR} with a leading slash), project and/or library
# version information (${LIB_MAJOR}, ${LIB_MINOR}, ${LIB_MICRO}), etc.
#
.include "Makefile.project"

# The full version ID for the library
#
LIB_VERSION =	${LIB_MAJOR}.${LIB_MINOR}.${LIB_MICRO}

# note: FreeBSD <bsd.subr.mk> effectively turns off SUBDIR_PARALLEL for installs
#
.if make(install) && \
	defined(MAKE_VERSION) && ${MAKE_VERSION} < 20240414 && \
	(!defined(.FreeBSD) || ${.FreeBSD} != "true") && \
	${.MAKEFLAGS:M-j} == "-j"
. error "Parallel installs are not supported with older BMakes"
.endif

# Installation directories
#
# N.B.:  ${DESTDIR} if set on the 'install' command line, it is also prepended
# to each of these target directories for actual installation targets.
#
# XXX Note that NetBSD's bsd.shlib.mk magic keys off the value of BINDIR (or
# MKDYNAMICROOT) in order to set the location of SHLIBDIR and SHLINKDIR, which
# in turn then determine which dynamic linker is set for the generated binaries
# (when linking non-statically), so don't set PREFIX to an empty value if you
# don't have /libexec/ld.elf_so and you don't have MKDYNAMICROOT=no set
# somewhere (e.g. /etc/mk.conf)!
#
INSTALL_OPTS =	# for specific ownerships
# these will be over-ridden by pkgsrc
PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin
INCSDIR ?= ${PREFIX}/include${INCSUBDIR}
LIBDIR ?= ${PREFIX}/lib
DEBUGDIR ?= ${PREFIX}/libdata/debug
LINTLIBDIR ?= ${PREFIX}/libdata/lint
SHAREDIR ?= ${PREFIX}/share
DOCDIR ?= ${SHAREDIR}/doc
MANDIR ?= ${SHAREDIR}/man

# hmmmm....  This apparently has no precedent in the world of BSD Make.  Base it
# off of LIBDIR....
PKGCONFIGDIR ?= ${LIBDIR}/pkgconfig

# For testing and debugging -- at least on sane systems, or with 'bmake'
#
# (note:  these can also be overridden on the command line)
#
# (note:  sjg's BMake puts optimizer flags in DBG)
#
# (note:  defaults are set in Makefile.compiler, or possibly /etc/mk.conf)
#
#DBG ?= -g3
#OPTIM ?= -O0

# If you are making changes and want to be sure to clean up all warnings....
#
#CWARNFLAGS += -Werror

# N.B.:  testing in the build or 'install' (distribution) directories, or making
# a distribution that can be un-packed on a target system in any arbitrary
# hierarchy (/usr/local, /opt, /usr/pkg, etc.)  is "hard" (i.e. annoyingly more
# difficult than it should be) without dancing with the dynamic linker.  (Or
# suffering the horrors of even worse monstrosities, such as "GNU libtool"!)
#
# Setting LDSTATIC to the linker flag which forces static linking is the easy
# and best fix on most platforms which support full static linking.
#
# This will only have effect on some BSDs, not Darwin/OSX/macOS, nor FreeBSD,
# and it is added to LDFLAGS by the system mk-files (sys.mk in general, but also
# <bsd.prog.mk> sometimes.  Note that some of the sanitizers don't work when
# static-linked.
#
#LDSTATIC =	-static
#
# However, sadly, OS X does not support a command-line way of forcing static
# linking (nor does Solaris?).  As a result on OS X if you want to test programs
# without first installing the library in its final destination directory then
# it is necessary to set the variable DYLD_LIBRARY_PATH in the environment to
# include the location of the library to be tested against.
#
# So, instead of making testing onerous for OS X we use a common trick of giving
# the static library a unique name, such as by appending "_s" or similar to it,
# in order to make it different from the normal name of the dynamic library and
# thus we can trick the linker into thinking there is only a static library
# available.  (This is actually done with a symlink in order to preserve normal
# naming conventions for the actual file.)
#
# Note that the .pc file as-built (for pkgconf, or the older pkg-config, may
# still require adjustments after a "dist" archive is un-packed since it may not
# have been original configured for the final installation directory).
#
# XXX this is, very unfortunately, somewhat ugly and package dependent!
#
# Program and test directories need to reference the static library so that they
# can be run from their build directory without the library having yet been
# installed, so we use "-l${PACKAGE:S/^lib//}_s" to do the linking.  (Note some
# packages include "lib" as the prefix in their package name!)
#
# see src/Makefile for where LIB is set
#
# XXX Handling ${.OBJDIR} both with and without use of ${MAKEOBJDIRPREFIX} is
# tedious.
#
# Note:  In order to avoid problems with parallel builds LDADD and DPADD should
# not be set in src/Makefile, thus this .if:
#
MKOBJ = yes

# yes, always -- we use this because it's safer when using a shared network
# directory for building/testing/etc.  (though it is sometimes somewhat
# annoying)
#
OBJMACHINE ?=	yes

.if !defined(LIB)
. if defined(MAKEOBJDIRPREFIX)
# then .OBJDIR is from MAKEOBJDIRPREFIX
LDADD += -L${.OBJDIR}/${bmake_topdir}/src
DPADD += ${.OBJDIR}/${bmake_topdir}/src/lib${PACKAGE:S/^lib//}.a
. elif defined(MAKEOBJDIR)
LDADD += -L${MAKEOBJDIR}/${bmake_topdir}/src
DPADD += ${MAKEOBJDIR}/${bmake_topdir}/src/lib${PACKAGE:S/^lib//}.a
. else
# assume .OBJDIR is a local directory, so look for bmake_topdir from the parent
LDADD += -L../${bmake_topdir}/src/${.OBJDIR:T}
DPADD += ../${bmake_topdir}/src/${.OBJDIR:T}/lib${PACKAGE:S/^lib//}.a
. endif
LDADD += -l${PACKAGE:S/^lib//}_s
#
# If we're compiling programs to link with lib${PACKAGE}_s.a then on some
# systems we cannot compile or link them with -fPIC or -fPIE, so disable that
# here.
#
# Note this normally only affects <bsd.prog.mk> Makefiles, not libs, even if it
# wasn't wrapped here in ".if !defined(LIB)".
#
# Note however that some of the sanitizers don't work when static-linked.
#
. if (defined(TARGET_OSNAME) && (${TARGET_OSNAME} == "Darwin")) || defined(.FreeBSD)
# for both FreeBSD and Mac OS X....
NO_SHARED = YES
.else
NOSHARED = YES
. endif
.endif # !defined(LIB)

.if defined(MAKEOBJDIRPREFIX)
# .OBJDIR is from MAKEOBJDIRPREFIX
GENHDIR = ${.OBJDIR}/${bmake_topdir}/src
.elif defined(MAKEOBJDIR)
GENHDIR = ${MAKEOBJDIR}/${bmake_topdir}/src
.else
# assume .OBJDIR is a local directory, so look in the parent
GENHDIR += ${.OBJDIR}/../${bmake_topdir}/src/${.OBJDIR:T}
.endif

# xxx Unfortunately most MK files don't provide a "beforecleandir" or
# "beforedistclean".
#
#beforecleandir: cleandir
#	rmdir ${.OBJDIR}

# xxx all this otherwise some systems won't allow unprivileged installs
.if ${USER} != "root"
USER_GRP !=	id -g
BINOWN =	${USER}
BINGRP =	${USER_GRP}
LIBOWN =	${USER}
LIBGRP =	${USER_GRP}
SHAREOWN =	${USER}
SHAREGRP =	${USER_GRP}
FILESOWN =	${USER}
FILESGRP =	${USER_GRP}
NOBINMODE =	644		# else OSX bsdmake can't install!
DEBUGOWN =	${USER}
DEBUGGRP =	${USER_GRP}
MANOWN =	${USER}
MANGRP =	${USER_GRP}
DOCOWN =	${USER}
DOCGRP =	${USER_GRP}
# xxx adapt for typo in mk-20150901 through at least mk-20170418
DOGGRP =	${USER_GRP}
.endif

STRIP =		# empty (needed for OSX bsdmake install)

# more hacks to avoid missing system dependencies with DESTDIR set
DPLIBC =		# empty
LIBC =			# empty
LIBCRT0 =		# empty
LIBCRTI =		# empty
LIBCRTBEGIN =		# empty
LIBCRTEND =		# empty
SHLIB_LDSTARTFILE =	# empty
SHLIB_LDENDFILE =	# empty

# Because we don't do "make includes" in this project, we need to allow other
# program products to be built with reference to the original source header
# files.
#
# The .if here is annoying, but some older systems don't support CPPFLAGS.
#
.if defined(CPPFLAGS)
CPPFLAGS +=	-I${.CURDIR}/${bmake_topdir}/src
.else
CFLAGS +=	-I${.CURDIR}/${bmake_topdir}/src
.endif

# N.B.:  we cannot include <bsd.own.mk> before the default "all" target!!!
#
# I.e. The top-level Makefile must inlcude this file _after_ defining it.
#
.include <bsd.own.mk>

# In NetBSD all TARGETS are candidates for making in the SUBDIR list
#
# (but avoid creating TARGETS if it doesn't exist)
#
.if !empty(TARGETS)
. if empty(TARGETS:Mdocs)
TARGETS +=	docs
. endif
. if empty(TARGETS:Mregress)
TARGETS +=	regress
. endif
. if empty(TARGETS:Mtags)
TARGETS +=	tags
. endif
. if empty(TARGETS:MTAGS)
TARGETS +=	TAGS
. endif
. if empty(TARGETS:Mshowenv)
TARGETS +=	showenv
. endif
.else
#
# In FreeBSD and sjg's Mk-files the list of SUBDIR_TARGETS cannot be appended to
# after including <bsd.subdir.mk>, but most of the interesting targets, such as
# some of these below, are not added to the default value of SUBDIR_TARGETS
# until it is included, so it's pointless to check here if they're already in
# the list.
#
# Note:  In FreeBSD SUBDIR_TARGETS was once reserved for adding custom targets
# that should recurse into subdirs, and the main meat was in ALL_SUBDIR_TARGETS,
# but again that couldn't be seen until after <bsd.subdir.mk> was included.
#
# "regress" was once a default for FreeBSD, but not for some time now.
#
# XXX Dunno why I added obj, depend, and tags.  They've been there in FreeBSD
# for a long time.
#
#SUBDIR_TARGETS +=	obj
#SUBDIR_TARGETS +=	depend
SUBDIR_TARGETS +=	docs
SUBDIR_TARGETS +=	regress
#SUBDIR_TARGETS +=	tags
SUBDIR_TARGETS +=	TAGS
SUBDIR_TARGETS +=	showenv
.endif

# Most implementations do not make 'regress' depend on first building everything
# but we need to build everything before we can do any testing.  This is done
# because 'regress' is an optional target and meant to be called directly, and
# so it should probably try its best to make sure everything is up to date
# before it tries to test those things.
#
# XXX for some reason even NetBSD Make requires the odd trailing .WAIT
#
regress: all .WAIT

#
# some default targets for the extra ones added to TARGETS above
#
# N.B.:  the attempt to use !target() may fail if including <bsd.own.mk> has not
# defined the proper default targets (i.e. if they are defined somewhere later
# after this file is already parsed), but for these this will not likely matter.

.if !target(tags)
# avoid :U for older bmakes
.if !defined(TOOL_CTAGS)
_TOOL_CTAGS = ctags
.else
_TOOL_CTAGS = ${TOOL_CTAGS}
.endif
tags: ${SRCS}
.if defined(SRCS)
	-cd ${.CURDIR} && ${_TOOL_CTAGS} -f /dev/stdout ${.ALLSRC:N*.h} | \
	    ${TOOL_SED} "s;\${.CURDIR}/;;" > ${.TARGET}
.endif
.endif

.if !target(TAGS)
# avoid :U for older bmakes
.if !defined(TOOL_ETAGS)
_TOOL_ETAGS = etags
.else
_TOOL_ETAGS = ${TOOL_ETAGS}
.endif
TAGS: ${SRCS}
.if defined(SRCS)
	-cd ${.CURDIR} && ${_TOOL_ETAGS} -I -l c -o ${.TARGET} ${.ALLSRC:N*.h}
.endif
.endif

.if !target(docs)
docs: .PHONY
.endif

# finally we include Makefile.compiler
#
.include "Makefile.compiler"

# Makefile debugging support
#
showenv: _GAW_bmake-showenv .PHONY

_GAW_bmake-showenv: .PHONY
	@echo "" ; \
	echo "bmake_topdir = '${bmake_topdir}'"; \
	echo "${.OBJDIR}/${bmake_topdir}/src"; \
	if [ -d "${.OBJDIR}/${bmake_topdir}/src" ]; then \
		echo "the directory shown above exists!"; \
	fi; \
	echo "Makefile.inc: ${.CURDIR}/${bmake_topdir}/Makefile.inc"; \
	if [ -f "${.CURDIR}/${bmake_topdir}/Makefile.inc" ]; then \
		echo "the file shown above exists!"; \
	else \
		echo "Where is ${.CURDIR}/${bmake_topdir}/Makefile.inc?"; \
	fi; \
	echo ""; \
	echo "Some Interesting Vars:"; \
	echo "unix = ${unix:Q}"; \
	echo "MAKE_VERSION = ${MAKE_VERSION:Q}"; \
	echo ".FreeBSD = ${.FreeBSD:Q}"; \
	echo ".CURDIR = ${.CURDIR:Q}"; \
	echo ".OBJDIR = ${.OBJDIR:Q}"; \
	echo ".OBJDIR:T = ${.OBJDIR:T:Q}"; \
	echo "_BSD_OWN_MK_ = ${_BSD_OWN_MK_:Q}"; \
	echo "GENHDIR = ${GENHDIR:Q}"; \
	echo "DEBUGDIR = ${DEBUGDIR:Q}"; \
	echo "LINTLIBDIR = ${LINTLIBDIR:Q}"; \
	echo "MAKECONF = ${MAKECONF:Q}"; \
	echo "MKDEBUG = ${MKDEBUG:Q}"; \
	echo "MKDEBUGLIB = ${MKDEBUGLIB:Q}"; \
	echo "MKDYNAMICROOT = ${MKDYNAMICROOT:Q}"; \
	echo "MKLINT = ${MKLINT:Q}"; \
	echo "LDADD = ${LDADD:Q}"; \
	echo "DPADD = ${DPADD:Q}"; \
	echo "MANDIR = ${MANDIR:Q}"; \
	echo "INC_COPY = ${INC_COPY:Q}"; \
	echo "FILES_COPY = ${FILES_COPY:Q}"; \
	echo ""

.endif # !target(_GAW_bmake-showenv)

#
# Local Variables:
# eval: (make-local-variable 'compile-command)
# compile-command: (concat "mkdir -p build; MAKEOBJDIRPREFIX=$(pwd -P)/build " (default-value 'compile-command))
# End:
#
