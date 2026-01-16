/*
 * SymQEMU - Symbolic State Management
 * Updated for Bitwuzla 0.8.x API
 */

#ifndef SYM_STATE_H
#define SYM_STATE_H

#include <bitwuzla/c/bitwuzla.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct SymState SymState;
typedef struct SymExpr SymExpr;
typedef struct SymValue SymValue;
typedef struct SymConstraint SymConstraint;
typedef struct SymMemChunk SymMemChunk;

/* Configuration */
#define SYM_MAX_REGS 64
#define SYM_MEM_CHUNK_SIZE 4096
#define SYM_INITIAL_CONSTRAINTS 256

/* ============================================================================
 * Symbolic Expression
 * ============================================================================ */

struct SymExpr {
    uint32_t refcount;
    BitwuzlaTerm term;
    uint32_t width;
    uint64_t origin_pc;
    const char *name;
};

/* ============================================================================
 * Symbolic Value
 * ============================================================================ */

struct SymValue {
    uint64_t concrete;
    SymExpr *expr;
};

/* ============================================================================
 * Constraint
 * ============================================================================ */

struct SymConstraint {
    BitwuzlaTerm term;
    uint64_t pc;
    bool is_branch;
    bool taken;
};

/* ============================================================================
 * Shadow Memory Chunk
 * ============================================================================ */

struct SymMemChunk {
    uint64_t base_addr;
    SymValue cells[SYM_MEM_CHUNK_SIZE];
    uint64_t taint_bitmap[SYM_MEM_CHUNK_SIZE / 64];
};

/* ============================================================================
 * Main Symbolic State
 * ============================================================================ */

struct SymState {
    /* Bitwuzla */
    BitwuzlaOptions *options;
    BitwuzlaTermManager *tm;
    Bitwuzla *solver;
    
    /* Cached sorts */
    BitwuzlaSort sort_bool;
    BitwuzlaSort sort_bv8;
    BitwuzlaSort sort_bv16;
    BitwuzlaSort sort_bv32;
    BitwuzlaSort sort_bv64;
    
    /* Shadow registers */
    SymValue regs[SYM_MAX_REGS];
    uint64_t reg_taint_bitmap;
    
    /* Shadow memory */
    void *memory_ht;
    size_t num_symbolic_bytes;
    
    /* Path constraints */
    SymConstraint *constraints;
    size_t num_constraints;
    size_t constraints_cap;
    
    /* Incremental solving */
    uint32_t *push_points;
    size_t num_push_points;
    size_t push_points_cap;
    
    /* Execution context */
    uint64_t current_pc;
    uint64_t insn_count;
    uint32_t path_id;
    uint32_t next_sym_id;
    
    /* Statistics */
    struct {
        uint64_t solver_queries;
        uint64_t solver_time_us;
        uint64_t expressions_created;
        uint64_t constraints_added;
        uint64_t memory_reads;
        uint64_t memory_writes;
        uint64_t symbolic_branches;
    } stats;
    
    /* Configuration */
    bool enabled;
    bool concretize_on_fork;
    uint32_t max_constraints;
    uint32_t solver_timeout_ms;
};

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

SymState *sym_state_new(void);
void sym_state_free(SymState *s);
SymState *sym_state_fork(SymState *s);
void sym_state_reset(SymState *s);

/* ============================================================================
 * Expression Management
 * ============================================================================ */

SymExpr *sym_expr_new(SymState *s, BitwuzlaTerm term, uint32_t width);
SymExpr *sym_expr_ref(SymExpr *e);
void sym_expr_unref(SymExpr *e);
SymExpr *sym_expr_var(SymState *s, const char *name, uint32_t width);
SymExpr *sym_expr_const(SymState *s, uint64_t value, uint32_t width);

/* ============================================================================
 * SymValue Operations
 * ============================================================================ */

static inline SymValue sym_value_concrete(uint64_t val) {
    return (SymValue){ .concrete = val, .expr = NULL };
}

static inline SymValue sym_value_symbolic(uint64_t concrete, SymExpr *expr) {
    if (expr) sym_expr_ref(expr);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

static inline bool sym_value_is_symbolic(SymValue v) {
    return v.expr != NULL;
}

static inline void sym_value_clear(SymValue *v) {
    if (v->expr) {
        sym_expr_unref(v->expr);
        v->expr = NULL;
    }
}

/* ============================================================================
 * Register Operations
 * ============================================================================ */

SymValue sym_reg_read(SymState *s, int reg_idx, uint32_t width);
void sym_reg_write(SymState *s, int reg_idx, SymValue val);

static inline bool sym_reg_is_symbolic(SymState *s, int reg_idx) {
    return (reg_idx < 64) && (s->reg_taint_bitmap & (1ULL << reg_idx));
}

/* ============================================================================
 * Memory Operations
 * ============================================================================ */

SymValue sym_mem_read(SymState *s, uint64_t addr, uint32_t size);
void sym_mem_write(SymState *s, uint64_t addr, uint32_t size, SymValue val);
void sym_mem_make_symbolic(SymState *s, uint64_t addr, uint64_t size, const char *name_prefix);
bool sym_mem_is_symbolic(SymState *s, uint64_t addr, uint32_t size);

/* ============================================================================
 * ALU Operations
 * ============================================================================ */

SymValue sym_op_add(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sub(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_mul(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_udiv(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sdiv(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_urem(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_srem(SymState *s, SymValue a, SymValue b, uint32_t width);

SymValue sym_op_and(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_or(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_xor(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_not(SymState *s, SymValue a, uint32_t width);
SymValue sym_op_neg(SymState *s, SymValue a, uint32_t width);

SymValue sym_op_shl(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_shr(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sar(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_rol(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_ror(SymState *s, SymValue a, SymValue b, uint32_t width);

SymValue sym_op_eq(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_ne(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_ult(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_ule(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_ugt(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_uge(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_slt(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sle(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sgt(SymState *s, SymValue a, SymValue b, uint32_t width);
SymValue sym_op_sge(SymState *s, SymValue a, SymValue b, uint32_t width);

SymValue sym_op_zext(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width);
SymValue sym_op_sext(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width);
SymValue sym_op_trunc(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width);
SymValue sym_op_extract(SymState *s, SymValue a, uint32_t hi, uint32_t lo);
SymValue sym_op_concat(SymState *s, SymValue hi, SymValue lo, uint32_t hi_width, uint32_t lo_width);
SymValue sym_op_ite(SymState *s, SymValue cond, SymValue t, SymValue f, uint32_t width);

/* ============================================================================
 * Constraint Management
 * ============================================================================ */

void sym_add_constraint(SymState *s, SymValue cond, uint64_t pc, bool is_branch);
void sym_push(SymState *s);
void sym_pop(SymState *s);
BitwuzlaResult sym_check_sat(SymState *s);
uint64_t sym_get_value(SymState *s, SymExpr *expr);

typedef void (*SymModelCallback)(const char *name, uint64_t value, uint32_t width, void *user);
void sym_get_model(SymState *s, SymModelCallback cb, void *user);

/* ============================================================================
 * Debug
 * ============================================================================ */

void sym_state_dump(SymState *s, FILE *out);
void sym_expr_dump(SymExpr *e, FILE *out);
void sym_constraints_dump(SymState *s, FILE *out);
void sym_stats_dump(SymState *s, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* SYM_STATE_H */
