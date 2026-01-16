#ifndef SYMQEMU_RUNTIME_H
#define SYMQEMU_RUNTIME_H

#include "sym_state.h"

extern SymState *g_sym_state;

void symqemu_init(void);
void symqemu_cleanup(void);
void symqemu_enable(void);
void symqemu_disable(void);

static inline bool symqemu_enabled(void) {
    return g_sym_state && g_sym_state->enabled;
}

void symqemu_set_stdin_symbolic(size_t nbytes);
size_t symqemu_get_stdin_symbolic_bytes(void);
void symqemu_add_symbolic_file(const char *path);
bool symqemu_is_symbolic_file(const char *path);

#endif
void symqemu_taint_read_buffer(int fd, uint64_t buf_addr, size_t count, ssize_t ret);
