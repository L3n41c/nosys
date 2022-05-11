#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([nosys], m4_esyscmd_s([git describe --tags --always --dirty]), [lenaic.huard@datadoghq.com], [nosys], [https://github.com/L3n41c/nosys])
AC_CONFIG_SRCDIR([src/nosys.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror dist-bzip2 dist-xz subdir-objects])
AM_PROG_AR
LT_INIT
AM_SILENT_RULES([yes])
AX_CFLAGS_WARN_ALL

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([seccomp_load], [seccomp], [], [
  AC_MSG_ERROR([libseccomp not found])
])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
