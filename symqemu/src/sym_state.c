/*
 * SymQEMU - Symbolic State Implementation
 * Updated for Bitwuzla 0.8.x API
 */

#include "../include/sym_state.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Simple hash table for memory chunks */
#define MEM_HT_SIZE 4096

typedef struct MemHTEntry {
    uint64_t key;
    SymMemChunk *chunk;
    struct MemHTEntry *next;
} MemHTEntry;

typedef struct MemHT {
    MemHTEntry *buckets[MEM_HT_SIZE];
    size_t count;
} MemHT;

/* Forward declarations for internal functions */
static inline uint32_t mem_ht_hash(uint64_t addr);
static MemHT *mem_ht_new(void);
static void mem_ht_free(MemHT *ht);
SymMemChunk *mem_ht_get(MemHT *ht, uint64_t chunk_addr);
SymMemChunk *mem_ht_get_or_create(MemHT *ht, uint64_t chunk_addr);

static inline uint32_t mem_ht_hash(uint64_t addr) {
    return (uint32_t)((addr >> 12) % MEM_HT_SIZE);
}

static MemHT *mem_ht_new(void) {
    return (MemHT *)calloc(1, sizeof(MemHT));
}

static void mem_ht_free(MemHT *ht) {
    for (int i = 0; i < MEM_HT_SIZE; i++) {
        MemHTEntry *e = ht->buckets[i];
        while (e) {
            MemHTEntry *next = e->next;
            for (int j = 0; j < SYM_MEM_CHUNK_SIZE; j++) {
                if (e->chunk->cells[j].expr) {
                    sym_expr_unref(e->chunk->cells[j].expr);
                }
            }
            free(e->chunk);
            free(e);
            e = next;
        }
    }
    free(ht);
}

SymMemChunk *mem_ht_get(MemHT *ht, uint64_t chunk_addr) {
    uint32_t h = mem_ht_hash(chunk_addr);
    MemHTEntry *e = ht->buckets[h];
    while (e) {
        if (e->key == chunk_addr) return e->chunk;
        e = e->next;
    }
    return NULL;
}

SymMemChunk *mem_ht_get_or_create(MemHT *ht, uint64_t chunk_addr) {
    SymMemChunk *chunk = mem_ht_get(ht, chunk_addr);
    if (chunk) return chunk;
    
    chunk = (SymMemChunk *)calloc(1, sizeof(SymMemChunk));
    chunk->base_addr = chunk_addr;
    
    MemHTEntry *e = (MemHTEntry *)malloc(sizeof(MemHTEntry));
    e->key = chunk_addr;
    e->chunk = chunk;
    
    uint32_t h = mem_ht_hash(chunk_addr);
    e->next = ht->buckets[h];
    ht->buckets[h] = e;
    ht->count++;
    
    return chunk;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

SymState *sym_state_new(void) {
    SymState *s = (SymState *)calloc(1, sizeof(SymState));
    
    /* Initialize bitwuzla - 0.8.x API */
    s->options = bitwuzla_options_new();
    bitwuzla_set_option(s->options, BITWUZLA_OPT_PRODUCE_MODELS, 1);
    
    s->tm = bitwuzla_term_manager_new();
    s->solver = bitwuzla_new(s->tm, s->options);
    
    /* Cache common sorts */
    s->sort_bool = bitwuzla_mk_bool_sort(s->tm);
    s->sort_bv8 = bitwuzla_mk_bv_sort(s->tm, 8);
    s->sort_bv16 = bitwuzla_mk_bv_sort(s->tm, 16);
    s->sort_bv32 = bitwuzla_mk_bv_sort(s->tm, 32);
    s->sort_bv64 = bitwuzla_mk_bv_sort(s->tm, 64);
    
    /* Initialize memory */
    s->memory_ht = mem_ht_new();
    
    /* Initialize constraints array */
    s->constraints_cap = SYM_INITIAL_CONSTRAINTS;
    s->constraints = (SymConstraint *)malloc(
        s->constraints_cap * sizeof(SymConstraint));
    
    /* Initialize push points */
    s->push_points_cap = 32;
    s->push_points = (uint32_t *)malloc(s->push_points_cap * sizeof(uint32_t));
    
    /* Default configuration */
    s->enabled = true;
    s->max_constraints = 10000;
    s->solver_timeout_ms = 30000;
    
    return s;
}

void sym_state_free(SymState *s) {
    if (!s) return;
    
    /* Free register symbolic expressions */
    for (int i = 0; i < SYM_MAX_REGS; i++) {
        if (s->regs[i].expr) {
            sym_expr_unref(s->regs[i].expr);
        }
    }
    
    /* Free memory */
    mem_ht_free((MemHT *)s->memory_ht);
    
    /* Free constraints */
    free(s->constraints);
    free(s->push_points);
    
    /* Free bitwuzla */
    bitwuzla_delete(s->solver);
    bitwuzla_term_manager_delete(s->tm);
    bitwuzla_options_delete(s->options);
    
    free(s);
}

void sym_state_reset(SymState *s) {
    /* Clear registers */
    for (int i = 0; i < SYM_MAX_REGS; i++) {
        sym_value_clear(&s->regs[i]);
    }
    s->reg_taint_bitmap = 0;
    
    /* Clear memory */
    mem_ht_free((MemHT *)s->memory_ht);
    s->memory_ht = mem_ht_new();
    s->num_symbolic_bytes = 0;
    
    /* Clear constraints */
    s->num_constraints = 0;
    s->num_push_points = 0;
    
    /* Reset solver */
    bitwuzla_delete(s->solver);
    s->solver = bitwuzla_new(s->tm, s->options);
    
    /* Reset counters */
    s->current_pc = 0;
    s->insn_count = 0;
    memset(&s->stats, 0, sizeof(s->stats));
}

SymState *sym_state_fork(SymState *s) {
    SymState *copy = (SymState *)malloc(sizeof(SymState));
    memcpy(copy, s, sizeof(SymState));
    
    /* Deep copy bitwuzla state */
    copy->options = bitwuzla_options_new();
    bitwuzla_set_option(copy->options, BITWUZLA_OPT_PRODUCE_MODELS, 1);
    
    copy->tm = bitwuzla_term_manager_new();
    copy->solver = bitwuzla_new(copy->tm, copy->options);
    
    /* Re-cache sorts */
    copy->sort_bool = bitwuzla_mk_bool_sort(copy->tm);
    copy->sort_bv8 = bitwuzla_mk_bv_sort(copy->tm, 8);
    copy->sort_bv16 = bitwuzla_mk_bv_sort(copy->tm, 16);
    copy->sort_bv32 = bitwuzla_mk_bv_sort(copy->tm, 32);
    copy->sort_bv64 = bitwuzla_mk_bv_sort(copy->tm, 64);
    
    /* Ref registers */
    for (int i = 0; i < SYM_MAX_REGS; i++) {
        if (s->regs[i].expr) {
            copy->regs[i].expr = sym_expr_ref(s->regs[i].expr);
        }
    }
    
    /* Simplified: new empty memory */
    copy->memory_ht = mem_ht_new();
    
    /* Copy constraints array */
    copy->constraints = (SymConstraint *)malloc(
        copy->constraints_cap * sizeof(SymConstraint));
    memcpy(copy->constraints, s->constraints,
           s->num_constraints * sizeof(SymConstraint));
    
    /* Copy push points */
    copy->push_points = (uint32_t *)malloc(copy->push_points_cap * sizeof(uint32_t));
    memcpy(copy->push_points, s->push_points,
           s->num_push_points * sizeof(uint32_t));
    
    /* Re-assert constraints */
    for (size_t i = 0; i < copy->num_constraints; i++) {
        bitwuzla_assert(copy->solver, copy->constraints[i].term);
    }
    
    static uint32_t next_path_id = 1;
    copy->path_id = next_path_id++;
    
    return copy;
}

/* ============================================================================
 * Expression Management
 * ============================================================================ */

SymExpr *sym_expr_new(SymState *s, BitwuzlaTerm term, uint32_t width) {
    SymExpr *e = (SymExpr *)malloc(sizeof(SymExpr));
    e->refcount = 1;
    e->term = term;
    e->width = width;
    e->origin_pc = s->current_pc;
    e->name = NULL;
    s->stats.expressions_created++;
    return e;
}

SymExpr *sym_expr_ref(SymExpr *e) {
    if (e) e->refcount++;
    return e;
}

void sym_expr_unref(SymExpr *e) {
    if (!e) return;
    if (--e->refcount == 0) {
        free((void *)e->name);
        free(e);
    }
}

static BitwuzlaSort get_bv_sort(SymState *s, uint32_t width) {
    switch (width) {
        case 8:  return s->sort_bv8;
        case 16: return s->sort_bv16;
        case 32: return s->sort_bv32;
        case 64: return s->sort_bv64;
        default: return bitwuzla_mk_bv_sort(s->tm, width);
    }
}

SymExpr *sym_expr_var(SymState *s, const char *name, uint32_t width) {
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm term = bitwuzla_mk_const(s->tm, sort, name);
    SymExpr *e = sym_expr_new(s, term, width);
    e->name = strdup(name);
    return e;
}

SymExpr *sym_expr_const(SymState *s, uint64_t value, uint32_t width) {
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm term = bitwuzla_mk_bv_value_uint64(s->tm, sort, value);
    return sym_expr_new(s, term, width);
}

/* ============================================================================
 * Register Operations
 * ============================================================================ */

SymValue sym_reg_read(SymState *s, int reg_idx, uint32_t width) {
    (void)width;
    assert(reg_idx >= 0 && reg_idx < SYM_MAX_REGS);
    SymValue v = s->regs[reg_idx];
    if (v.expr) sym_expr_ref(v.expr);
    return v;
}

void sym_reg_write(SymState *s, int reg_idx, SymValue val) {
    assert(reg_idx >= 0 && reg_idx < SYM_MAX_REGS);
    
    if (s->regs[reg_idx].expr) {
        sym_expr_unref(s->regs[reg_idx].expr);
    }
    
    s->regs[reg_idx] = val;
    
    if (val.expr) {
        s->reg_taint_bitmap |= (1ULL << reg_idx);
    } else {
        s->reg_taint_bitmap &= ~(1ULL << reg_idx);
    }
}
