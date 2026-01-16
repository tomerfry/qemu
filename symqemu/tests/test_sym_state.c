/*
 * SymQEMU - Unit Tests for Symbolic State and Operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sym_state.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        tests_run++; \
        printf("  [TEST] %s ... ", #name); \
        fflush(stdout); \
        test_##name(); \
        tests_passed++; \
        printf("PASS\n"); \
    } \
    static void test_##name(void)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n"); \
        fprintf(stderr, "    Assertion failed: %s\n", #cond); \
        fprintf(stderr, "    At %s:%d\n", __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    uint64_t _a = (a), _b = (b); \
    if (_a != _b) { \
        printf("FAIL\n"); \
        fprintf(stderr, "    Assertion failed: %s == %s\n", #a, #b); \
        fprintf(stderr, "    Got: 0x%lx != 0x%lx\n", _a, _b); \
        fprintf(stderr, "    At %s:%d\n", __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================ */

TEST(state_create_free) {
    SymState *s = sym_state_new();
    ASSERT(s != NULL);
    ASSERT(s->tm != NULL);
    ASSERT(s->solver != NULL);
    ASSERT(s->enabled == true);
    ASSERT(s->num_constraints == 0);
    sym_state_free(s);
}

TEST(state_reset) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_var(s, "test_var", 32);
    SymValue val = sym_value_symbolic(42, e);
    sym_reg_write(s, 0, val);
    ASSERT(s->reg_taint_bitmap != 0);
    
    sym_state_reset(s);
    ASSERT(s->reg_taint_bitmap == 0);
    ASSERT(s->num_constraints == 0);
    ASSERT(s->regs[0].expr == NULL);
    sym_state_free(s);
}

/* ============================================================================
 * Expression Tests
 * ============================================================================ */

TEST(expr_var_creation) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_var(s, "input_0", 8);
    ASSERT(e != NULL);
    ASSERT(e->width == 8);
    ASSERT(e->refcount == 1);
    ASSERT(strcmp(e->name, "input_0") == 0);
    sym_expr_unref(e);
    sym_state_free(s);
}

TEST(expr_const_creation) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_const(s, 0xDEADBEEF, 32);
    ASSERT(e != NULL);
    ASSERT(e->width == 32);
    ASSERT(e->refcount == 1);
    sym_expr_unref(e);
    sym_state_free(s);
}

TEST(expr_refcount) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_var(s, "x", 64);
    ASSERT(e->refcount == 1);
    sym_expr_ref(e);
    ASSERT(e->refcount == 2);
    sym_expr_unref(e);
    ASSERT(e->refcount == 1);
    sym_expr_unref(e);
    sym_state_free(s);
}

/* ============================================================================
 * Register Tests
 * ============================================================================ */

TEST(reg_concrete_write_read) {
    SymState *s = sym_state_new();
    SymValue val = sym_value_concrete(0x12345678);
    sym_reg_write(s, 5, val);
    ASSERT(!sym_reg_is_symbolic(s, 5));
    SymValue read = sym_reg_read(s, 5, 64);
    ASSERT_EQ(read.concrete, 0x12345678);
    ASSERT(read.expr == NULL);
    sym_state_free(s);
}

TEST(reg_symbolic_write_read) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_var(s, "sym_reg", 64);
    SymValue val = sym_value_symbolic(0xAAAA, e);
    sym_reg_write(s, 3, val);
    ASSERT(sym_reg_is_symbolic(s, 3));
    SymValue read = sym_reg_read(s, 3, 64);
    ASSERT_EQ(read.concrete, 0xAAAA);
    ASSERT(read.expr != NULL);
    sym_expr_unref(read.expr);
    sym_state_free(s);
}

TEST(reg_overwrite_clears_symbolic) {
    SymState *s = sym_state_new();
    SymExpr *e = sym_expr_var(s, "old", 64);
    sym_reg_write(s, 7, sym_value_symbolic(100, e));
    ASSERT(sym_reg_is_symbolic(s, 7));
    sym_reg_write(s, 7, sym_value_concrete(200));
    ASSERT(!sym_reg_is_symbolic(s, 7));
    sym_state_free(s);
}

/* ============================================================================
 * Concrete ALU Tests
 * ============================================================================ */

TEST(alu_add_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_add(s, sym_value_concrete(100), 
                                     sym_value_concrete(50), 32);
    ASSERT_EQ(result.concrete, 150);
    ASSERT(result.expr == NULL);
    sym_state_free(s);
}

TEST(alu_sub_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_sub(s, sym_value_concrete(100), 
                                     sym_value_concrete(30), 32);
    ASSERT_EQ(result.concrete, 70);
    sym_state_free(s);
}

TEST(alu_and_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_and(s, sym_value_concrete(0xFF00),
                                     sym_value_concrete(0x0FF0), 16);
    ASSERT_EQ(result.concrete, 0x0F00);
    sym_state_free(s);
}

TEST(alu_overflow_32bit) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_add(s, sym_value_concrete(0xFFFFFFFF),
                                     sym_value_concrete(1), 32);
    ASSERT_EQ(result.concrete, 0);
    sym_state_free(s);
}

TEST(alu_overflow_8bit) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_add(s, sym_value_concrete(0xFF),
                                     sym_value_concrete(1), 8);
    ASSERT_EQ(result.concrete, 0);
    sym_state_free(s);
}

/* ============================================================================
 * Symbolic ALU Tests
 * ============================================================================ */

TEST(alu_add_symbolic) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    SymValue sym_x = sym_value_symbolic(10, x);
    SymValue result = sym_op_add(s, sym_x, sym_value_concrete(5), 32);
    ASSERT_EQ(result.concrete, 15);
    ASSERT(result.expr != NULL);
    ASSERT(result.expr->width == 32);
    sym_expr_unref(result.expr);
    sym_state_free(s);
}

TEST(alu_add_two_symbolic) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 64);
    SymExpr *y = sym_expr_var(s, "y", 64);
    SymValue result = sym_op_add(s, sym_value_symbolic(100, x), 
                                     sym_value_symbolic(200, y), 64);
    ASSERT_EQ(result.concrete, 300);
    ASSERT(result.expr != NULL);
    sym_expr_unref(result.expr);
    sym_state_free(s);
}

TEST(alu_complex_expression) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    SymValue sym_x = sym_value_symbolic(5, x);
    
    SymValue step1 = sym_op_add(s, sym_x, sym_value_concrete(10), 32);
    ASSERT_EQ(step1.concrete, 15);
    
    SymValue step2 = sym_op_mul(s, step1, sym_value_concrete(2), 32);
    ASSERT_EQ(step2.concrete, 30);
    
    SymValue step3 = sym_op_and(s, step2, sym_value_concrete(0xFF), 32);
    ASSERT_EQ(step3.concrete, 30);
    ASSERT(step3.expr != NULL);
    
    sym_expr_unref(step1.expr);
    sym_expr_unref(step2.expr);
    sym_expr_unref(step3.expr);
    sym_state_free(s);
}

/* ============================================================================
 * Comparison Tests
 * ============================================================================ */

TEST(cmp_eq_concrete) {
    SymState *s = sym_state_new();
    SymValue r1 = sym_op_eq(s, sym_value_concrete(5), sym_value_concrete(5), 32);
    ASSERT_EQ(r1.concrete, 1);
    SymValue r2 = sym_op_eq(s, sym_value_concrete(5), sym_value_concrete(6), 32);
    ASSERT_EQ(r2.concrete, 0);
    sym_state_free(s);
}

TEST(cmp_slt_concrete) {
    SymState *s = sym_state_new();
    /* -1 (0xFF in 8 bits) < 1 signed */
    SymValue r1 = sym_op_slt(s, sym_value_concrete(0xFF), sym_value_concrete(1), 8);
    ASSERT_EQ(r1.concrete, 1);
    /* But unsigned 255 > 1 */
    SymValue r2 = sym_op_ult(s, sym_value_concrete(0xFF), sym_value_concrete(1), 8);
    ASSERT_EQ(r2.concrete, 0);
    sym_state_free(s);
}

TEST(cmp_eq_symbolic) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    SymValue result = sym_op_eq(s, sym_value_symbolic(42, x), 
                                    sym_value_concrete(42), 32);
    ASSERT_EQ(result.concrete, 1);
    ASSERT(result.expr != NULL);
    ASSERT(result.expr->width == 1);
    sym_expr_unref(result.expr);
    sym_state_free(s);
}

/* ============================================================================
 * Extension Tests
 * ============================================================================ */

TEST(ext_zext_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_zext(s, sym_value_concrete(0xFF), 8, 32);
    ASSERT_EQ(result.concrete, 0xFF);
    sym_state_free(s);
}

TEST(ext_sext_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_sext(s, sym_value_concrete(0xFF), 8, 32);
    ASSERT_EQ(result.concrete, 0xFFFFFFFF);
    sym_state_free(s);
}

TEST(ext_trunc_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_trunc(s, sym_value_concrete(0x12345678), 32, 8);
    ASSERT_EQ(result.concrete, 0x78);
    sym_state_free(s);
}

TEST(ext_extract_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_extract(s, sym_value_concrete(0x12345678), 15, 8);
    ASSERT_EQ(result.concrete, 0x56);
    sym_state_free(s);
}

TEST(ext_concat_concrete) {
    SymState *s = sym_state_new();
    SymValue result = sym_op_concat(s, sym_value_concrete(0xAB), 
                                        sym_value_concrete(0xCD), 8, 8);
    ASSERT_EQ(result.concrete, 0xABCD);
    sym_state_free(s);
}

/* ============================================================================
 * Constraint Tests
 * ============================================================================ */

TEST(constraint_add) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    SymValue cond = sym_op_eq(s, sym_value_symbolic(10, x), 
                                  sym_value_concrete(10), 32);
    ASSERT(s->num_constraints == 0);
    sym_add_constraint(s, cond, 0x1000, true);
    ASSERT(s->num_constraints == 1);
    ASSERT(s->constraints[0].pc == 0x1000);
    ASSERT(s->constraints[0].is_branch == true);
    sym_expr_unref(cond.expr);
    sym_state_free(s);
}

TEST(constraint_push_pop) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    
    SymValue c1 = sym_op_ult(s, sym_value_symbolic(5, x), 
                                 sym_value_concrete(100), 32);
    sym_add_constraint(s, c1, 0x1000, false);
    ASSERT(s->num_constraints == 1);
    
    sym_push(s);
    
    SymValue c2 = sym_op_ugt(s, sym_value_symbolic(5, x),
                                 sym_value_concrete(10), 32);
    sym_add_constraint(s, c2, 0x1004, false);
    ASSERT(s->num_constraints == 2);
    
    sym_pop(s);
    ASSERT(s->num_constraints == 1);
    
    sym_expr_unref(c1.expr);
    sym_expr_unref(c2.expr);
    sym_state_free(s);
}

TEST(constraint_check_sat) {
    SymState *s = sym_state_new();
    BitwuzlaResult result = sym_check_sat(s);
    ASSERT(result == BITWUZLA_SAT);
    sym_state_free(s);
}

/* ============================================================================
 * Fork Tests
 * ============================================================================ */

TEST(state_fork_basic) {
    SymState *s = sym_state_new();
    SymExpr *x = sym_expr_var(s, "x", 32);
    sym_reg_write(s, 0, sym_value_symbolic(100, x));
    s->current_pc = 0x1000;
    
    SymState *child = sym_state_fork(s);
    ASSERT(child != NULL);
    ASSERT(child != s);
    ASSERT(child->path_id != s->path_id);
    ASSERT(child->current_pc == s->current_pc);
    ASSERT(sym_reg_is_symbolic(child, 0));
    
    sym_reg_write(child, 0, sym_value_concrete(999));
    ASSERT(sym_reg_is_symbolic(s, 0));
    ASSERT(!sym_reg_is_symbolic(child, 0));
    
    sym_state_free(child);
    sym_state_free(s);
}

/* ============================================================================
 * Memory Tests
 * ============================================================================ */

TEST(mem_make_symbolic) {
    SymState *s = sym_state_new();
    sym_mem_make_symbolic(s, 0x2000, 4, "input");
    ASSERT(sym_mem_is_symbolic(s, 0x2000, 4));
    ASSERT(s->num_symbolic_bytes == 4);
    
    SymValue read = sym_mem_read(s, 0x2000, 4);
    ASSERT(read.expr != NULL);
    sym_expr_unref(read.expr);
    sym_state_free(s);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    printf("\n=== SymQEMU Unit Tests ===\n\n");
    
    printf("[Lifecycle]\n");
    run_test_state_create_free();
    run_test_state_reset();
    
    printf("\n[Expressions]\n");
    run_test_expr_var_creation();
    run_test_expr_const_creation();
    run_test_expr_refcount();
    
    printf("\n[Registers]\n");
    run_test_reg_concrete_write_read();
    run_test_reg_symbolic_write_read();
    run_test_reg_overwrite_clears_symbolic();
    
    printf("\n[Concrete ALU]\n");
    run_test_alu_add_concrete();
    run_test_alu_sub_concrete();
    run_test_alu_and_concrete();
    run_test_alu_overflow_32bit();
    run_test_alu_overflow_8bit();
    
    printf("\n[Symbolic ALU]\n");
    run_test_alu_add_symbolic();
    run_test_alu_add_two_symbolic();
    run_test_alu_complex_expression();
    
    printf("\n[Comparisons]\n");
    run_test_cmp_eq_concrete();
    run_test_cmp_slt_concrete();
    run_test_cmp_eq_symbolic();
    
    printf("\n[Extensions]\n");
    run_test_ext_zext_concrete();
    run_test_ext_sext_concrete();
    run_test_ext_trunc_concrete();
    run_test_ext_extract_concrete();
    run_test_ext_concat_concrete();
    
    printf("\n[Constraints]\n");
    run_test_constraint_add();
    run_test_constraint_push_pop();
    run_test_constraint_check_sat();
    
    printf("\n[Forking]\n");
    run_test_state_fork_basic();
    
    printf("\n[Memory]\n");
    run_test_mem_make_symbolic();
    
    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
