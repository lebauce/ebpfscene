#ifndef _KERNEL_H__
#define _KERNEL_H__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"
#pragma clang diagnostic ignored "-Wpass-failed"

#include <linux/compiler.h>
#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/ptrace.h>

#include "bpf.h"
#include "bpf_helpers.h"

#define SCREEN_WIDTH 140
#define SCREEN_HEIGHT 55
#define HIDDEN_LINES 2
#define FRAMEBUFFER_SIZE ((unsigned int) (SCREEN_HEIGHT+HIDDEN_LINES+1)*SCREEN_WIDTH*4)

#pragma clang diagnostic pop

#endif

struct bpf_map_def SEC("maps/framebuffer") framebuffer = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(unsigned char[FRAMEBUFFER_SIZE]),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/count") count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

#define RED_OFFSET 1
#define GREEN_OFFSET 2
#define BLUE_OFFSET 3

unsigned int __attribute__((always_inline)) get_color_shift(unsigned int color) {
    switch (color) {
    case 0:
        return 0;
    case 1:
        return 8;
    default:
        return 16;
    }
}

unsigned char __attribute__((always_inline)) get_pixel(unsigned char *buffer, unsigned int x, unsigned int y, unsigned int color) {
    unsigned int offset = (y * SCREEN_WIDTH + x) * 4;
    unsigned int *buffer_int = (unsigned int*) (buffer + offset);

    if (offset < FRAMEBUFFER_SIZE)
         return *buffer_int >> get_color_shift(color);

    return 0;
}

void __attribute__((always_inline)) set_pixel(unsigned char *buffer, unsigned int x, unsigned int y, unsigned char value, unsigned int color) {
    unsigned int offset = (y * SCREEN_WIDTH + x) * 4;
    unsigned int *buffer_int = (int*) (buffer + offset);

    if (offset < FRAMEBUFFER_SIZE)
        *buffer_int = value << get_color_shift(color);
}

SEC("kprobe/do_vfs_ioctl")
int kprobe_do_vfs_ioctl(struct pt_regs *ctx) {
    int cmd = PT_REGS_PARM3(ctx);
    if (cmd != 666)
        return 0;

    u32 key = 0;
    u32 *color_value = bpf_map_lookup_elem(&count, &key);
    if (!color_value)
        return 0;

    char *buffer = bpf_map_lookup_elem(&framebuffer, &key);
    if (buffer) {
        unsigned int x, y;
        int y1 = 0, y2 = 0;
        int value;
        unsigned int color;

        color = *color_value;

#pragma clang loop vectorize(enable)
#pragma unroll
        for (x = 0; x < SCREEN_WIDTH; x++) {
            unsigned char c = 0;
            if (bpf_get_prandom_u32() & 1) {
                c = 255;
            }
            set_pixel(buffer, x, SCREEN_HEIGHT, c, color);
        }

        for (x = 0; x < SCREEN_WIDTH; x++) {
            unsigned char c = 0;
            if (bpf_get_prandom_u32() & 1) {
                c = 255;
            }
            set_pixel(buffer, x, SCREEN_HEIGHT+1, c, color);
        }

        for (y = 0; y < SCREEN_HEIGHT; y++) {
            for (x = 0; x < SCREEN_WIDTH; x++) {
                y1 = (get_pixel(buffer, x - 1, y + 1, color) +
                      get_pixel(buffer, x, y + 1, color)) >> 1;
                y2 = (get_pixel(buffer, x, y + 2, color) +
                      get_pixel(buffer, x + 1, y + 2, color)) >> 1;
                value = ((y1 + y2) >> 1) - 3;
                if (value < 0) {
                    value = 0;
                }
                set_pixel(buffer, x, y, value, color);
            }
        }
    }
    return 0;
}

__u32 _version SEC("version") = 0xFFFFFFFE;

char LICENSE[] SEC("license") = "GPL";
