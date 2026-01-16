/*
 * SymQEMU - Constraint Management and Solver Interface
 */

#include "../include/sym_state.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Constraint Management
 * ============================================================================ */

void sym_add_constraint(SymState *s, SymValue cond, uint64_t pc, bool is_branch) {
    if (!cond.expr) {
        /* Purely concrete condition - no constraint to add */
        return;
    }
    
    if (s->num_constraints >= s->max_constraints) {
        /* Too many constraints - could implement pruning here */
        fprintf(stderr, "[symqemu] Warning: max constraints reached (%u)\n",
                s->max_constraints);
        return;
    }
    
    /* Grow array if needed */
    if (s->num_constraints >= s->constraints_cap) {
        s->constraints_cap *= 2;
        s->constraints = (SymConstraint *)realloc(s->constraints,
            s->constraints_cap * sizeof(SymConstraint));
    }
    
    SymConstraint *c = &s->constraints[s->num_constraints++];
    c->term = cond.expr->term;
    c->pc = pc;
    c->is_branch = is_branch;
    c->taken = cond.concrete != 0;
    
    /* Assert to solver */
    bitwuzla_assert(s->solver, c->term);
    
    s->stats.constraints_added++;
}

void sym_push(SymState *s) {
    /* Record current constraint count */
    if (s->num_push_points >= s->push_points_cap) {
        s->push_points_cap *= 2;
        s->push_points = (uint32_t *)realloc(s->push_points,
            s->push_points_cap * sizeof(uint32_t));
    }
    s->push_points[s->num_push_points++] = (uint32_t)s->num_constraints;
    
    /* Push solver context */
    bitwuzla_push(s->solver, 1);
}

void sym_pop(SymState *s) {
    if (s->num_push_points == 0) {
        fprintf(stderr, "[symqemu] Warning: pop with empty stack\n");
        return;
    }
    
    /* Restore constraint count */
    s->num_constraints = s->push_points[--s->num_push_points];
    
    /* Pop solver context */
    bitwuzla_pop(s->solver, 1);
}

BitwuzlaResult sym_check_sat(SymState *s) {
    s->stats.solver_queries++;
    return bitwuzla_check_sat(s->solver);
}

uint64_t sym_get_value(SymState *s, SymExpr *expr) {
    if (!expr) return 0;
    
    BitwuzlaTerm val_term = bitwuzla_get_value(s->solver, expr->term);
    
    /* Extract value from term */
    if (bitwuzla_term_is_value(val_term)) {
        const char *str = bitwuzla_term_value_get_str(val_term);
        /* Parse binary string */
        uint64_t val = 0;
        while (*str) {
            val = (val << 1) | (*str == '1' ? 1 : 0);
            str++;
        }
        return val;
    }
    
    return 0;
}

/* Collect all symbolic variables for model extraction */
typedef struct {
    SymModelCallback cb;
    void *user;
} ModelCollectorCtx;

void sym_get_model(SymState *s, SymModelCallback cb, void *user) {
    /* In a real implementation, we would:
     * 1. Track all symbolic variables created
     * 2. Iterate through them and get their values from the model
     * 
     * For now, we'll scan memory for named symbolic expressions
     */
    (void)s;
    (void)cb;
    (void)user;
    /* TODO: Implement proper variable tracking */
}

/* ============================================================================
 * Debug/Dump Functions
 * ============================================================================ */

void sym_state_dump(SymState *s, FILE *out) {
    fprintf(out, "=== SymState Dump ===\n");
    fprintf(out, "Enabled: %s\n", s->enabled ? "yes" : "no");
    fprintf(out, "Path ID: %u\n", s->path_id);
    fprintf(out, "PC: 0x%lx\n", s->current_pc);
    fprintf(out, "Instruction count: %lu\n", s->insn_count);
    fprintf(out, "\n");
    
    /* Registers */
    fprintf(out, "Symbolic Registers (bitmap: 0x%lx):\n", s->reg_taint_bitmap);
    for (int i = 0; i < SYM_MAX_REGS; i++) {
        if (s->regs[i].expr) {
            fprintf(out, "  R%d: concrete=0x%lx, symbolic=", i, s->regs[i].concrete);
            sym_expr_dump(s->regs[i].expr, out);
            fprintf(out, "\n");
        }
    }
    fprintf(out, "\n");
    
    /* Memory */
    fprintf(out, "Symbolic Memory: %zu bytes\n", s->num_symbolic_bytes);
    fprintf(out, "\n");
    
    /* Constraints */
    fprintf(out, "Constraints: %zu (push depth: %zu)\n", 
            s->num_constraints, s->num_push_points);
    
    /* Stats */
    fprintf(out, "\n");
    sym_stats_dump(s, out);
}

void sym_expr_dump(SymExpr *e, FILE *out) {
    if (!e) {
        fprintf(out, "(null)");
        return;
    }
    
    fprintf(out, "[%ubit", e->width);
    if (e->name) {
        fprintf(out, " %s", e->name);
    }
    fprintf(out, " @0x%lx]", e->origin_pc);
    
    /* Print term */
    bitwuzla_term_print(e->term, out);
}

void sym_constraints_dump(SymState *s, FILE *out) {
    fprintf(out, "=== Constraints (%zu) ===\n", s->num_constraints);
    
    for (size_t i = 0; i < s->num_constraints; i++) {
        SymConstraint *c = &s->constraints[i];
        fprintf(out, "[%zu] PC=0x%lx %s%s: ",
                i, c->pc,
                c->is_branch ? "BRANCH " : "",
                c->taken ? "T" : "F");
        bitwuzla_term_print(c->term, out);
        fprintf(out, "\n");
    }
}

void sym_stats_dump(SymState *s, FILE *out) {
    fprintf(out, "=== Statistics ===\n");
    fprintf(out, "Expressions created: %lu\n", s->stats.expressions_created);
    fprintf(out, "Constraints added: %lu\n", s->stats.constraints_added);
    fprintf(out, "Solver queries: %lu\n", s->stats.solver_queries);
    fprintf(out, "Memory reads: %lu\n", s->stats.memory_reads);
    fprintf(out, "Memory writes: %lu\n", s->stats.memory_writes);
    fprintf(out, "Symbolic branches: %lu\n", s->stats.symbolic_branches);
}
