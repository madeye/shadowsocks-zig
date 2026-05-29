#include "libuv_c_api.h"

#include <uv.h>

typedef struct ss_uv_wait_context {
    uv_loop_t *loop;
    uv_poll_t *poll;
    uv_timer_t *timer;
    int events;
    int ready;
    int status;
} ss_uv_wait_context;

static void ss_uv_close_callback(uv_handle_t *handle) {
    (void) handle;
}

static void ss_uv_poll_callback(uv_poll_t *handle, int status, int events) {
    ss_uv_wait_context *ctx = (ss_uv_wait_context *) handle->data;
    ctx->status = status;
    ctx->ready = status >= 0 && (events & ctx->events) != 0;
    uv_poll_stop(ctx->poll);
    if (ctx->timer != NULL) uv_timer_stop(ctx->timer);
    uv_stop(ctx->loop);
}

static void ss_uv_timer_callback(uv_timer_t *handle) {
    ss_uv_wait_context *ctx = (ss_uv_wait_context *) handle->data;
    ctx->ready = 0;
    uv_poll_stop(ctx->poll);
    uv_timer_stop(ctx->timer);
    uv_stop(ctx->loop);
}

static int ss_uv_wait(int fd, int events, uint64_t timeout_ms) {
    uv_loop_t loop;
    uv_poll_t poll;
    uv_timer_t timer;
    uv_timer_t *timer_ptr = NULL;
    ss_uv_wait_context ctx;

    if (uv_loop_init(&loop) != 0) return -1;
    if (uv_poll_init_socket(&loop, &poll, (uv_os_sock_t) fd) != 0) {
        uv_loop_close(&loop);
        return -1;
    }
    if (timeout_ms != UINT64_MAX) {
        if (uv_timer_init(&loop, &timer) != 0) {
            uv_close((uv_handle_t *) &poll, ss_uv_close_callback);
            uv_run(&loop, UV_RUN_DEFAULT);
            uv_loop_close(&loop);
            return -1;
        }
        timer_ptr = &timer;
    }

    ctx.loop = &loop;
    ctx.poll = &poll;
    ctx.timer = timer_ptr;
    ctx.events = events;
    ctx.ready = 0;
    ctx.status = 0;
    poll.data = &ctx;
    if (timer_ptr != NULL) timer_ptr->data = &ctx;

    if (uv_poll_start(&poll, events, ss_uv_poll_callback) != 0 ||
        (timer_ptr != NULL && uv_timer_start(timer_ptr, ss_uv_timer_callback, timeout_ms, 0) != 0)) {
        uv_poll_stop(&poll);
        if (timer_ptr != NULL) uv_timer_stop(timer_ptr);
        uv_close((uv_handle_t *) &poll, ss_uv_close_callback);
        if (timer_ptr != NULL) uv_close((uv_handle_t *) timer_ptr, ss_uv_close_callback);
        uv_run(&loop, UV_RUN_DEFAULT);
        uv_loop_close(&loop);
        return -1;
    }

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_close((uv_handle_t *) &poll, ss_uv_close_callback);
    if (timer_ptr != NULL) uv_close((uv_handle_t *) timer_ptr, ss_uv_close_callback);
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    if (ctx.status < 0) return -1;
    return ctx.ready;
}

int ss_uv_wait_readable(int fd, uint64_t timeout_ms) {
    return ss_uv_wait(fd, UV_READABLE, timeout_ms);
}

int ss_uv_wait_writable(int fd, uint64_t timeout_ms) {
    return ss_uv_wait(fd, UV_WRITABLE, timeout_ms);
}
