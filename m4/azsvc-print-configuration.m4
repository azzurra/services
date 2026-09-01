# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2005-2009 Atheme Project (http://atheme.org/)
# Copyright (C) 2018-2019 Aaron Jones <me@aaronmdjones.net>
#
# -*- Atheme IRC Services -*-
# Atheme Build System Component

AC_DEFUN([AZSVC_PRINT_CONFIGURATION], [

    AS_IF([test "${DIGEST_FRONTEND}" = "Internal"], [DIGEST_FRONTEND="None (Internal MD5/SHA/HMAC/PBKDF2 Fallback)"])
    AS_IF([test "${RANDOM_FRONTEND}" = "Internal"], [RANDOM_FRONTEND="None (Internal ChaCha20-based Fallback RNG)"])
    AS_IF([test "${BUILD_WARNINGS}" = "Yes"], [BUILD_WARNINGS="Yes (NOT INTENDED FOR PRODUCTION USAGE)"])
    AS_IF([test "${COMPILER_SANITIZERS}" = "Yes"], [COMPILER_SANITIZERS="Yes (${COMPILER_SANITIZERS_ENABLED})"])
    AS_IF([test "x${USE_NLS}" = "xyes"], [USE_NLS="Yes"], [USE_NLS="No"])

    AS_IF([test "${LIBARGON2}${LIBARGON2_TYPE_ID}" = "YesNo"], [
        LIBARGON2="Partial (Please consider upgrading your Argon2 library)"
    ])

    echo "
Configuration of ${PACKAGE_STRING}:

  Directories:
    Installation Prefix .....: ${prefix}
    Binary Directory ........: ${bindir}
    Config Directory ........: ${sysconfdir}
    Data Directory ..........: ${DATADIR}
    Logfile Directory .......: ${LOGDIR}
    PID File Directory ......: ${RUNDIR}

  Libraries:
    GNU libgcrypt support ...: ${LIBGCRYPT}
    GNU Nettle support ......: ${LIBNETTLE}
    OpenSSL support .........: ${LIBCRYPTO}
    Sodium support ..........: ${LIBSODIUM}

  Password Cryptography:
    Argon2 support ..........: ${LIBARGON2}
    crypt(3) support ........: ${LIBCRYPT}
    scrypt support ..........: ${LIBSODIUM_SCRYPT}

  Program Features:
    Digest Frontend .........: ${DIGEST_FRONTEND}
    Heap Allocator ..........: ${HEAP_ALLOCATOR}
    Internationalization ....: ${USE_NLS}
    Large Network Support ...: ${LARGE_NET}
    RNG Frontend ............: ${RANDOM_FRONTEND}

  Build Features:
    Build Warnings ..........: ${BUILD_WARNINGS}
    Compiler Sanitizers .....: ${COMPILER_SANITIZERS}
    Mowgli Installation .....: ${LIBMOWGLI_SOURCE}

  Build Variables:
    CC ......................: ${CC}
    CFLAGS ..................: ${CFLAGS}
    CPPFLAGS ................: ${CPPFLAGS}
    LDFLAGS .................: ${LDFLAGS}
    LIBS ....................: ${LIBS}

Type 'make' to build ${PACKAGE_TARNAME}, and 'make install' to install it.
"

])
