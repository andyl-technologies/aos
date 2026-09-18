/* SPDX-License-Identifier: Apache-2.0 */
/* Verifies that the target MIT GSSAPI library advertises SPNEGO. */

#include <gssapi/gssapi.h>
#include <stdio.h>

int main(void) {
    static unsigned char spnego_der[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    gss_OID_desc spnego = {sizeof(spnego_der), spnego_der};
    gss_OID_set mechanisms = GSS_C_NO_OID_SET;
    OM_uint32 minor_status = 0;
    int present = 0;

    if (gss_indicate_mechs(&minor_status, &mechanisms) != GSS_S_COMPLETE) {
        fputs("target GSSAPI mechanism enumeration failed\n", stderr);
        return 1;
    }
    if (gss_test_oid_set_member(&minor_status, &spnego, mechanisms, &present) !=
        GSS_S_COMPLETE) {
        gss_release_oid_set(&minor_status, &mechanisms);
        fputs("target GSSAPI SPNEGO lookup failed\n", stderr);
        return 2;
    }
    gss_release_oid_set(&minor_status, &mechanisms);

    if (!present) {
        fputs("target GSSAPI library does not advertise SPNEGO\n", stderr);
        return 3;
    }

    puts("AOS target GSSAPI SPNEGO probe passed");
    return 0;
}
