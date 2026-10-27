/*
 * Copyright 2026 Andyl, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This exercises the same pure validator used before the real native phase.
 * Root/Owner/cgroup-at-birth/listener SCM_RIGHTS require the actual Guest VM;
 * passing this fixture makes no claim about those privileged native paths. */
#include "includes.h"

#include <assert.h>
#include <string.h>

#include "aos-attach-bootstrap.h"

int
main(void)
{
	unsigned char bytes[192], changed[192];
	unsigned int i;
	static const unsigned int coordinates[] = { 16, 48, 80, 96, 176 };
	static const unsigned int widths[] = { 32, 32, 16, 32, 16 };
	static const unsigned int low_bytes[] = { 135, 139, 143, 147, 151, 159, 167, 169 };

	memset(bytes, 0, sizeof(bytes));
	memcpy(bytes, "AOSSLB01AOSSSH01", 16);
	for (i = 0; i < 5; i++)
		memset(bytes + coordinates[i], 1, widths[i]);
	bytes[135] = 1; /* Financed memory is nonzero. */
	bytes[139] = 4;
	bytes[143] = 3; /* Canonical floor, not a supported-flow sufficiency claim. */
	bytes[147] = 96; /* Copied-reference DATA; not a grant. */
	bytes[151] = 160; /* Parent's inclusive high-FD permit. */
	bytes[159] = 1;
	bytes[167] = 1;
	bytes[169] = 22;
	assert(aos_attach_bootstrap_request_is_canonical_v1(bytes, sizeof(bytes)));
	assert(!aos_attach_bootstrap_request_is_canonical_v1(bytes, sizeof(bytes) - 1));
	assert(!aos_attach_bootstrap_request_is_canonical_v1(bytes, sizeof(bytes) + 1));
	assert(!aos_attach_bootstrap_request_is_canonical_v1(bytes, 184));
	for (i = 0; i < 5; i++) {
		memcpy(changed, bytes, sizeof(bytes));
		memset(changed + coordinates[i], 0, widths[i]);
		assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	}
	for (i = 0; i < sizeof(low_bytes) / sizeof(low_bytes[0]); i++) {
		memcpy(changed, bytes, sizeof(bytes));
		changed[low_bytes[i]] = 0;
		assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	}
	memcpy(changed, bytes, sizeof(bytes));
	changed[0] ^= 1;
	assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	memcpy(changed, bytes, sizeof(bytes));
	changed[8] ^= 1;
	assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	memcpy(changed, bytes, sizeof(bytes));
	changed[160] = 128;
	assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	for (i = 170; i < 176; i++) {
		memcpy(changed, bytes, sizeof(bytes));
		changed[i] = 1;
		assert(!aos_attach_bootstrap_request_is_canonical_v1(changed, sizeof(changed)));
	}
	return 0;
}
