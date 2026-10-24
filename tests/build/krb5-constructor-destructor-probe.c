/* SPDX-License-Identifier: Apache-2.0 */
/* Reproduces MIT Kerberos 1.22.1's KRB5_AC_GCC_ATTRS runtime probe. */
#include <unistd.h>
void foo1() __attribute__((constructor));
void foo1() { unlink("conftest.1"); }
void foo2() __attribute__((destructor));
void foo2() { unlink("conftest.2"); }
int main () { return 0; }
