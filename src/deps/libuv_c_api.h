#ifndef SS_ZIG_LIBUV_C_API_H
#define SS_ZIG_LIBUV_C_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ss_uv_wait_readable(int fd, uint64_t timeout_ms);
int ss_uv_wait_writable(int fd, uint64_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
