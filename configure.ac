# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2005-2015 Atheme Project (http://atheme.org/)
# Copyright (C) 2015-2019 Atheme Development Group (https://atheme.github.io/)
# Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)

AC_PREREQ([2.69])

AC_LANG([C])
AC_INIT([Azzurra IRC Services],[2.6.0-alpha1],[https://github.com/azzurra/services/issues/],[services],[https://www.azzurra.chat/])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_FILES([buildsys.mk extra.mk])
AC_CONFIG_HEADERS([inc/sysconf.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_PREFIX_DEFAULT([~/azsvc])
AS_IF([test "x${prefix}" = "xNONE"], [prefix="${ac_default_prefix}"])

AS_IF([test -d ".git" -o -f ".git"], [
    AC_MSG_CHECKING([if you read GIT-Access.txt])
    AS_IF([test -f "libmowgli-2/Makefile"], [
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([please read GIT-Access.txt before trying to build from git])
    ])
], [
    AC_MSG_CHECKING([if you downloaded the correct source code tarball])
    AS_IF([test -f "inc/serno.h"], [
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([please read the Obtaining Services section of README.md])
    ])
])

AH_TOP([
#ifndef AZSVC_INC_SYSCONF_H
#define AZSVC_INC_SYSCONF_H 1

#define AZSVC_API_DIGEST_FRONTEND_INTERNAL     0x00U
#define AZSVC_API_DIGEST_FRONTEND_OPENSSL      0x01U
#define AZSVC_API_DIGEST_FRONTEND_GCRYPT       0x02U

#define AZSVC_API_RANDOM_FRONTEND_INTERNAL     0x00U
#define AZSVC_API_RANDOM_FRONTEND_ARC4RANDOM   0x01U
#define AZSVC_API_RANDOM_FRONTEND_SODIUM       0x02U
#define AZSVC_API_RANDOM_FRONTEND_OPENSSL      0x03U
])

AH_BOTTOM([
#ifndef AZSVC_API_DIGEST_FRONTEND
#  error "No Digest API frontend was selected by the build system"
#endif /* !AZSVC_API_DIGEST_FRONTEND */

#ifndef AZSVC_API_RANDOM_FRONTEND
#  error "No RNG API frontend was selected by the build system"
#endif /* !AZSVC_API_RANDOM_FRONTEND */

#endif /* !AZSVC_INC_SYSCONF_H */
])

# If CFLAGS is empty or unset, explicitly set it to the empty string, so that
# AC_PROG_CC (below) does not add "-O2 -g", as this will conflict with the
# optimisation flags that the compiler sanitizers feature uses, and the
# more advanced debugging flags detection that the CFLAGS feature test uses
AS_IF([test "x${CFLAGS:-}" = "x"], [CFLAGS=""])

# Programs required by the build system
AC_PROG_CC
AC_PROG_CC_C99
AS_IF([test "x${ac_cv_prog_cc_c99}" = "xno"], [
    AC_MSG_FAILURE([This program requires a C99 compiler])
])
AC_CHECK_TOOL([AR], [ar])
AC_PATH_PROG([CP], [cp])
AC_PROG_INSTALL
AC_PATH_PROG([LN], [ln])
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PATH_PROG([MV], [mv])
AC_PROG_RANLIB
AC_PATH_PROG([RM], [rm])
AC_PROG_SED
AC_PATH_PROG([TAR], [tar])
PKG_PROG_PKG_CONFIG
AS_IF([test -z "${PKG_CONFIG}"], [
    AC_MSG_WARN([please consider installing pkg-config])
    AC_MSG_WARN([many of this script's library and feature detection tests rely upon it being available])
    AC_MSG_WARN([if you choose to do so, please re-run this script again])
])

# Does what its name implies. The above block can't be put into this function
# because of autotools black magic voodoo crap that no-one understands ...
AZSVC_CHECK_BUILD_REQUIREMENTS

# Automake compatibility. --nenolod
AC_SUBST([PACKAGE], [AC_PACKAGE_TARNAME])
AC_SUBST([VERSION], [AC_PACKAGE_VERSION])
AC_SUBST([VENDOR_STRING], ["Azzurra IRC Network <https://www.azzurra.chat/>"])
AC_SUBST([PACKAGE_BUGREPORT_I18N], ["https://github.com/azzurra/services/issues/"])
AC_DEFINE_UNQUOTED([PACKAGE], ["${PACKAGE}"], [Name of package])
AC_DEFINE_UNQUOTED([VERSION], ["${VERSION}"], [Version number of package])
AC_DEFINE_UNQUOTED([VENDOR_STRING], ["${VENDOR_STRING}"], [Vendor string for in-tree module headers])
AC_DEFINE_UNQUOTED([PACKAGE_BUGREPORT_I18N], ["${PACKAGE_BUGREPORT_I18N}"], [Where to report translation bugs])

# This should be before any library tests so that insufficient header
# inclusions in those tests are caught before they become a runtime
# problem
AZSVC_TEST_CC_FLAGS([-Werror=implicit])

# Conditional libraries for standard functions (no option to control detection)
AZSVC_LIBTEST_DL
AZSVC_LIBTEST_MATH
AZSVC_LIBTEST_SOCKET

# Libraries that are autodetected (alphabetical)
AZSVC_LIBTEST_ARGON2
AZSVC_LIBTEST_CRYPT
AZSVC_LIBTEST_CRYPTO
AZSVC_LIBTEST_GCRYPT
AZSVC_LIBTEST_MOWGLI
AZSVC_LIBTEST_NETTLE
AZSVC_LIBTEST_SODIUM

# Digest and RNG frontend to use
AZSVC_DECIDE_DIGEST_FRONTEND
AZSVC_DECIDE_RANDOM_FRONTEND

# Optional features
# These must be after library tests, because some of them depend on the
# library detection logic in the tests to set appropriate variables
AZSVC_FEATURETEST_FHSPATHS
AZSVC_FEATURETEST_HEAP_ALLOCATOR
AZSVC_FEATURETEST_LARGENET
dnl AZSVC_FEATURETEST_REPROBUILDS

# These must be here, not above, or they might interfere with library and feature tests
# Explanation is that these modify one or more of CFLAGS, CPPFLAGS, LDFLAGS, and LIBS
# Warnings should be last so that diagnostics don't clutter the contents of config.log
# Sanitizers must be before CFLAGS and LDFLAGS
AZSVC_FEATURETEST_COMPILER_SANITIZERS
AZSVC_FEATURETEST_CPPFLAGS
AZSVC_FEATURETEST_CFLAGS
AZSVC_FEATURETEST_LDFLAGS
AZSVC_FEATURETEST_NLS
AZSVC_FEATURETEST_WARNINGS

# Handle enabling and configuration of submodules
AZSVC_HANDLE_SUBMODULES

# Now add libmowgli and libpcre to CFLAGS and LIBS because the whole codebase uses them
AS_IF([test "x${LIBMOWGLI_CFLAGS}" != "x"], [CFLAGS="${LIBMOWGLI_CFLAGS} ${CFLAGS}"])
AS_IF([test "x${LIBMOWGLI_LIBS}" != "x"], [LIBS="${LIBMOWGLI_LIBS} ${LIBS}"])

AC_OUTPUT
BUILDSYS_TOUCH_DEPS
AZSVC_PRINT_CONFIGURATION
