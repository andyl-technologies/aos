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

#ifndef AOS_ATTACH_BOOTSTRAP_H
#define AOS_ATTACH_BOOTSTRAP_H

#include <stddef.h>

/* The default-off recipe uses only the daemon's own inherited stdin channel.
 * It supplies native listener custody, never an execution or resource grant.
 */
void aos_attach_bootstrap_prepare_v1(int, int, int, int);
void aos_attach_bootstrap_current_v1(void);
void aos_attach_bootstrap_listeners_v1(const int *, int);

/* Pure fixed-wire validation is shared by the real entrance and its fixture.
 * A positive return neither enables the bootstrap nor admits a child. */
int aos_attach_bootstrap_request_is_canonical_v1(const unsigned char *, size_t);

#endif
