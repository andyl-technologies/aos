// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Andyl, Inc.
#include "crucible_raw_kernel_call.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>

// This native diagnostic observes the actual installed library after its
// original exec-custody import; it does not link Apache host implementation.
extern "C" int dmtcp_crucible_observe_original_shared_exec(std::uint64_t *, std::size_t)
    __attribute__((weak));

int main()
{
  assert(dmtcp_crucible_observe_original_shared_exec != nullptr);
  std::uint64_t fields[6]{};
  assert(dmtcp_crucible_observe_original_shared_exec(fields, 6) == 0);
  assert(fields[0] == std::uint64_t(dmtcp_crucible::raw_kernel_call::kernelCall(SYS_getpid)));
  assert(fields[1] > 0 && fields[1] % 4096 == 0);
  assert(fields[2] == fields[1] + 1);
  assert(fields[3] == 1 && fields[4] == 2 && fields[5] == 2);
  std::puts("Actual selected launcher/library preserves original shared bank across exec; no native cut authority.");
  // Keep the authenticated final executable and original source channel live
  // until its retained controller retires this test's exact native process.
  unsigned char body[344]{};
  const char marker[] = "ORIGINAL-SHARED-EXEC-OBSERVATION-V1";
  for (std::size_t index = 0; index < sizeof(marker); ++index) body[index] = marker[index];
  using dmtcp_crucible::raw_kernel_call::kernelCall;
  assert(kernelCall(SYS_write, 994, reinterpret_cast<long>(body), sizeof(body)) == sizeof(body));
  char answer = 0;
  kernelCall(SYS_read, 994, reinterpret_cast<long>(&answer), 1);
  return 0;
}
