# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2020-2021 Atheme Development Group (https://atheme.github.io/)
#
# -*- Atheme IRC Services -*-
# Atheme Build System Component

AC_DEFUN([AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER], [

    AZSVC_TEST_CCLD_FLAGS([-fsanitize=$1])
    AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "yes"], [
        COMPILER_SANITIZERS="Yes"
        COMPILER_SANITIZERS_ENABLED="${COMPILER_SANITIZERS_ENABLED:-}${COMPILER_SANITIZERS_ENABLED:+, }$1"
    ])
])

AC_DEFUN([AZSVC_FEATURETEST_COMPILER_SANITIZERS], [

    COMPILER_SANITIZERS="No"
    COMPILER_SANITIZERS_ENABLED=""

    AC_ARG_ENABLE([compiler-sanitizers],
        [AS_HELP_STRING([--enable-compiler-sanitizers], [Enable various compiler run-time-instrumented sanitizers])],
        [], [enable_compiler_sanitizers="no"])

    AS_CASE(["x${enable_compiler_sanitizers}"], [xno], [
        # Enable compiler optimisations (what autoconf would have done if we didn't explicitly overrule it)
        AZSVC_TEST_CC_FLAGS([-O2])
    ], [xyes], [
        AS_IF([test "${HEAP_ALLOCATOR}" = "Yes"], [
            AC_MSG_ERROR([To use --enable-compiler-sanitizers you must pass --disable-heap-allocator])
        ])

        # Disable compiler optimisations for more accurate stack-traces
        AZSVC_TEST_CC_FLAGS([-O0])

        # -fsanitize= benefits from these, but they're not strictly necessary
        AZSVC_TEST_CC_FLAGS([-fno-omit-frame-pointer])
        AZSVC_TEST_CC_FLAGS([-fno-optimize-sibling-calls])

        # Some compilers (like Clang) require LTO to be enabled for some of their sanitizers to function.
        # This test will fail if you are using Clang and not using an LLVM bitcode-parsing-capable linker.
        # Clang in LTO mode compiles to LLVM bitcode, not machine code.
        #
        # The linker is responsible for translating that to machine code. If you want to use Clang, you
        # must set LDFLAGS="-fuse-ld=lld", to use the LLVM linker, or you can use the Gold linker with
        # the LLVM linker plugin (an exercise for the reader).
        AZSVC_TEST_CCLD_FLAGS([-fvisibility=default -flto])

        AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
            AC_MSG_FAILURE([--enable-compiler-sanitizers was given, but LTO (a common pre-requisite) could not be enabled])
        ])

        # Now on to the good stuff ...
        AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([address])
        AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([bounds])
        AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([array-bounds])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([local-bounds])
        ])
        AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([float-divide-by-zero])
        AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([leak])
        AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([undefined])
        AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([alignment])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([bool])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([builtin])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([enum])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([float-cast-overflow])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([function])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([integer])
            AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([implicit-conversion])
                AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
                    AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([implicit-integer-sign-change])
                    AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([implicit-signed-integer-truncation])
                    AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([implicit-unsigned-integer-truncation])
                ])
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([integer-divide-by-zero])
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([shift])
                AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
                    AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([shift-base])
                    AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([shift-exponent])
                ])
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([signed-integer-overflow])
            ])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([nonnull-attribute])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([null])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([nullability])
            AS_IF([test "${AZSVC_TEST_CCLD_FLAGS_RESULT}" = "no"], [
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([nullability-arg])
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([nullability-assign])
                AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([nullability-return])
            ])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([object-size])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([pointer-overflow])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([return])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([returns-nonnull-attribute])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([unreachable])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([unsigned-shift-base])
            AZSVC_FEATURETEST_COMPILER_SANITIZERS_DRIVER([vla-bound])
        ])

        AS_IF([test "${COMPILER_SANITIZERS}" = "No"], [
            AC_MSG_FAILURE([--enable-compiler-sanitizers was given, but no sanitizers could be enabled])
        ])

        # This causes pointless noise, turn it off.
        AZSVC_TEST_CCLD_FLAGS([-fno-sanitize=unsigned-integer-overflow])

        AC_DEFINE([AZSVC_ENABLE_COMPILER_SANITIZERS], [1], [Define to 1 if compiler sanitizers are enabled])
    ], [
        AC_MSG_ERROR([invalid option for --enable-compiler-sanitizers])
    ])
])
