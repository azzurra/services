# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2005-2009 Atheme Project (http://atheme.org/)
# Copyright (C) 2018-2019 Aaron Jones <me@aaronmdjones.net>
#
# -*- Atheme IRC Services -*-
# Atheme Build System Component

AC_DEFUN([AZSVC_CC_ENABLE_WARNINGS], [

    AZSVC_TEST_CC_FLAGS([-Werror=unknown-warning-option])

    AZSVC_TEST_CC_FLAGS([-Weverything])

    AS_IF([test "${AZSVC_TEST_CC_FLAGS_RESULT}" = "no"], [

        # These two have to be consecutive and first for the most reliable
        # results. Do not alphabetise with the flags below.    -- amdj
        AZSVC_TEST_CC_FLAGS([-Wall])
        AZSVC_TEST_CC_FLAGS([-Wextra])

        AZSVC_TEST_CC_FLAGS([-Waggregate-return])
        AZSVC_TEST_CC_FLAGS([-Waggressive-loop-optimizations])
        AZSVC_TEST_CC_FLAGS([-Walloc-zero])
        AZSVC_TEST_CC_FLAGS([-Walloca])
        AZSVC_TEST_CC_FLAGS([-Warray-bounds])
        AZSVC_TEST_CC_FLAGS([-Wbad-function-cast])
        AZSVC_TEST_CC_FLAGS([-Wc99-c11-compat])
        AZSVC_TEST_CC_FLAGS([-Wcast-qual])
        AZSVC_TEST_CC_FLAGS([-Wdangling-else])
        AZSVC_TEST_CC_FLAGS([-Wdate-time])
        AZSVC_TEST_CC_FLAGS([-Wdisabled-optimization])
        AZSVC_TEST_CC_FLAGS([-Wdouble-promotion])
        AZSVC_TEST_CC_FLAGS([-Wduplicated-branches])
        AZSVC_TEST_CC_FLAGS([-Wduplicated-cond])
        AZSVC_TEST_CC_FLAGS([-Wfatal-errors])
        AZSVC_TEST_CC_FLAGS([-Wfloat-equal])
        AZSVC_TEST_CC_FLAGS([-Wformat-nonliteral])
        AZSVC_TEST_CC_FLAGS([-Wformat-overflow])
        AZSVC_TEST_CC_FLAGS([-Wformat-security])
        AZSVC_TEST_CC_FLAGS([-Wformat-signedness])
        AZSVC_TEST_CC_FLAGS([-Wformat-truncation])
        AZSVC_TEST_CC_FLAGS([-Wformat-y2k])
        AZSVC_TEST_CC_FLAGS([-Winline])
        AZSVC_TEST_CC_FLAGS([-Winit-self])
        AZSVC_TEST_CC_FLAGS([-Winvalid-pch])
        AZSVC_TEST_CC_FLAGS([-Wjump-misses-init])
        AZSVC_TEST_CC_FLAGS([-Wlogical-op])
        AZSVC_TEST_CC_FLAGS([-Wmissing-declarations])
        AZSVC_TEST_CC_FLAGS([-Wmissing-format-attribute])
        AZSVC_TEST_CC_FLAGS([-Wmissing-include-dirs])
        AZSVC_TEST_CC_FLAGS([-Wmissing-prototypes])
        AZSVC_TEST_CC_FLAGS([-Wmissing-variable-declarations])
        AZSVC_TEST_CC_FLAGS([-Wmultistatement-macros])
        AZSVC_TEST_CC_FLAGS([-Wnested-externs])
        AZSVC_TEST_CC_FLAGS([-Wnormalized=nfkc])
        AZSVC_TEST_CC_FLAGS([-Wnull-dereference])
        AZSVC_TEST_CC_FLAGS([-Wold-style-definition])
        AZSVC_TEST_CC_FLAGS([-Woverlength-strings])
        AZSVC_TEST_CC_FLAGS([-Wpointer-arith])
        AZSVC_TEST_CC_FLAGS([-Wpointer-compare])
        AZSVC_TEST_CC_FLAGS([-Wredundant-decls])
        AZSVC_TEST_CC_FLAGS([-Wrestrict])
        AZSVC_TEST_CC_FLAGS([-Wshadow])
        AZSVC_TEST_CC_FLAGS([-Wstack-protector])

        AZSVC_TEST_CC_FLAGS([-Wstrict-overflow=3])
        AS_IF([test "${AZSVC_TEST_CC_FLAGS_RESULT}" = "no"], [
            AZSVC_TEST_CC_FLAGS([-Wstrict-overflow])
        ])

        AZSVC_TEST_CC_FLAGS([-Wstrict-prototypes])
        AZSVC_TEST_CC_FLAGS([-Wstringop-overflow=4])
        AZSVC_TEST_CC_FLAGS([-Wstringop-truncation])
        AZSVC_TEST_CC_FLAGS([-Wtrampolines])
        AZSVC_TEST_CC_FLAGS([-Wundef])
        AZSVC_TEST_CC_FLAGS([-Wunsafe-loop-optimizations])
        AZSVC_TEST_CC_FLAGS([-Wunsuffixed-float-constants])
        AZSVC_TEST_CC_FLAGS([-Wunused])
        AZSVC_TEST_CC_FLAGS([-Wwrite-strings])
    ])

    AZSVC_TEST_CC_FLAGS([-Wno-c++-keyword])
    AZSVC_TEST_CC_FLAGS([-Wno-conversion])
    AZSVC_TEST_CC_FLAGS([-Wno-declaration-after-statement])
    AZSVC_TEST_CC_FLAGS([-Wno-disabled-macro-expansion])
    AZSVC_TEST_CC_FLAGS([-Wno-documentation-deprecated-sync])
    AZSVC_TEST_CC_FLAGS([-Wno-documentation-unknown-command])
    AZSVC_TEST_CC_FLAGS([-Wno-extra-semi-stmt])
    AZSVC_TEST_CC_FLAGS([-Wno-format-pedantic])
    AZSVC_TEST_CC_FLAGS([-Wno-format-zero-length])
    AZSVC_TEST_CC_FLAGS([-Wno-implicit-void-ptr-cast])
    AZSVC_TEST_CC_FLAGS([-Wno-packed])
    AZSVC_TEST_CC_FLAGS([-Wno-padded])
    AZSVC_TEST_CC_FLAGS([-Wno-pedantic])
    AZSVC_TEST_CC_FLAGS([-Wno-reserved-id-macro])
    AZSVC_TEST_CC_FLAGS([-Wno-reserved-identifier])
    AZSVC_TEST_CC_FLAGS([-Wno-sign-conversion])
    AZSVC_TEST_CC_FLAGS([-Wno-unsafe-buffer-usage])
    AZSVC_TEST_CC_FLAGS([-Wno-unused-parameter])
    AZSVC_TEST_CC_FLAGS([-Wno-unused-variable])
    AZSVC_TEST_CC_FLAGS([-Wno-vla])
])

AC_DEFUN([AZSVC_FEATURETEST_WARNINGS], [

    BUILD_WARNINGS="No"

    AC_ARG_ENABLE([warnings],
        [AS_HELP_STRING([--enable-warnings], [Enable compiler warnings])],
        [], [enable_warnings="no"])

    AS_CASE(["x${enable_warnings}"], [xno], [], [xyes], [
        BUILD_WARNINGS="Yes"
        AZSVC_CC_ENABLE_WARNINGS
    ], [
        AC_MSG_ERROR([invalid option for --enable-warnings])
    ])
])
