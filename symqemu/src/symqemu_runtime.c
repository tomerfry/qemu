/*
 * SymQEMU Runtime Implementation
 */

#include "../include/symqemu_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global state */
SymState *g_sym_state = NULL;

/* Configuration */
static size_t stdin_symbolic_bytes = 16;
static char **symbolic_files = NULL;
static size_t num_symbolic_files = 0;

void symqemu_init(void) {
    if (g_sym_state) return;
    
    g_sym_state = sym_state_new();
    if (!g_sym_state) {
        fprintf(stderr, "[symqemu] Failed to initialize symbolic state\n");
        return;
    }
    
    fprintf(stderr, "[symqemu] Symbolic execution engine initialized\n");
    
    if (stdin_symbolic_bytes > 0) {
        fprintf(stderr, "[symqemu] Will make first %zu bytes of stdin symbolic\n",
                stdin_symbolic_bytes);
    }
}

void symqemu_cleanup(void) {
    if (g_sym_state) {
        fprintf(stderr, "[symqemu] Statistics:\n");
        fprintf(stderr, "  Expressions created: %lu\n", 
                g_sym_state->stats.expressions_created);
        fprintf(stderr, "  Constraints added: %lu\n",
                g_sym_state->stats.constraints_added);
        fprintf(stderr, "  Solver queries: %lu\n",
                g_sym_state->stats.solver_queries);
        fprintf(stderr, "  Symbolic branches: %lu\n",
                g_sym_state->stats.symbolic_branches);
        
        sym_state_free(g_sym_state);
        g_sym_state = NULL;
    }
    
    for (size_t i = 0; i < num_symbolic_files; i++) {
        free(symbolic_files[i]);
    }
    free(symbolic_files);
}

void symqemu_enable(void) {
    if (g_sym_state) g_sym_state->enabled = true;
}

void symqemu_disable(void) {
    if (g_sym_state) g_sym_state->enabled = false;
}

void symqemu_set_stdin_symbolic(size_t nbytes) {
    stdin_symbolic_bytes = nbytes;
}

size_t symqemu_get_stdin_symbolic_bytes(void) {
    return stdin_symbolic_bytes;
}

void symqemu_add_symbolic_file(const char *path) {
    symbolic_files = realloc(symbolic_files, 
                             (num_symbolic_files + 1) * sizeof(char *));
    symbolic_files[num_symbolic_files++] = strdup(path);
}

bool symqemu_is_symbolic_file(const char *path) {
    for (size_t i = 0; i < num_symbolic_files; i++) {
        if (strcmp(symbolic_files[i], path) == 0) return true;
    }
    return false;
}

/* Called after read() syscall to taint buffer with symbolic data */
void symqemu_taint_read_buffer(int fd, uint64_t buf_addr, size_t count, ssize_t ret) {
    if (!g_sym_state || !g_sym_state->enabled) return;
    if (ret <= 0) return;
    
    /* Only taint stdin (fd 0) for now */
    size_t stdin_bytes = symqemu_get_stdin_symbolic_bytes();
    if (fd == 0 && stdin_bytes > 0) {
        static size_t stdin_offset = 0;
        size_t to_taint = 0;
        
        if (stdin_offset < stdin_bytes) {
            to_taint = stdin_bytes - stdin_offset;
            if (to_taint > (size_t)ret) to_taint = ret;
            
            fprintf(stderr, "[symqemu] Tainting %zu bytes at 0x%lx (stdin offset %zu)\n",
                    to_taint, buf_addr, stdin_offset);
            
            sym_mem_make_symbolic(g_sym_state, buf_addr, to_taint, "stdin");
            stdin_offset += ret;
        }
    }
}
