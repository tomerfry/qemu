/*
 * SymQEMU - Symbolic ALU Operations
 */

#include "../include/sym_state.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Memory hash table type - defined in sym_state.c */
typedef struct MemHT MemHT;

/* External memory hash table functions from sym_state.c */
extern MemHT *mem_ht_new(void);
extern void mem_ht_free(MemHT *ht);
extern SymMemChunk *mem_ht_get(MemHT *ht, uint64_t chunk_addr);
extern SymMemChunk *mem_ht_get_or_create(MemHT *ht, uint64_t chunk_addr);

/* Helper to get bv sort */
static BitwuzlaSort get_bv_sort(SymState *s, uint32_t width) {
    switch (width) {
        case 8:  return s->sort_bv8;
        case 16: return s->sort_bv16;
        case 32: return s->sort_bv32;
        case 64: return s->sort_bv64;
        default: return bitwuzla_mk_bv_sort(s->tm, width);
    }
}

/* ============================================================================
 * Memory Operations
 * ============================================================================ */

static inline uint64_t chunk_base(uint64_t addr) {
    return addr & ~(uint64_t)(SYM_MEM_CHUNK_SIZE - 1);
}

static inline uint32_t chunk_offset(uint64_t addr) {
    return (uint32_t)(addr & (SYM_MEM_CHUNK_SIZE - 1));
}

SymValue sym_mem_read(SymState *s, uint64_t addr, uint32_t size) {
    s->stats.memory_reads++;
    
    uint64_t base = chunk_base(addr);
    SymMemChunk *chunk = mem_ht_get((MemHT *)s->memory_ht, base);
    
    if (!chunk) {
        return sym_value_concrete(0);
    }
    
    uint32_t off = chunk_offset(addr);
    bool has_symbolic = false;
    
    for (uint32_t i = 0; i < size && (off + i) < SYM_MEM_CHUNK_SIZE; i++) {
        if (chunk->cells[off + i].expr) {
            has_symbolic = true;
            break;
        }
    }
    
    if (!has_symbolic) {
        return sym_value_concrete(0);
    }
    
    /* Build symbolic expression by concatenating bytes (little-endian) */
    SymExpr *result = NULL;
    
    for (uint32_t i = 0; i < size; i++) {
        SymValue byte_val = chunk->cells[off + i];
        SymExpr *byte_expr;
        
        if (byte_val.expr) {
            byte_expr = sym_expr_ref(byte_val.expr);
        } else {
            byte_expr = sym_expr_const(s, byte_val.concrete, 8);
        }
        
        if (result == NULL) {
            result = byte_expr;
        } else {
            BitwuzlaTerm concat = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_CONCAT,
                                                    byte_expr->term, result->term);
            uint32_t new_width = result->width + 8;
            sym_expr_unref(result);
            sym_expr_unref(byte_expr);
            result = sym_expr_new(s, concat, new_width);
        }
    }
    
    return (SymValue){ .concrete = 0, .expr = result };
}

void sym_mem_write(SymState *s, uint64_t addr, uint32_t size, SymValue val) {
    s->stats.memory_writes++;
    
    uint64_t base = chunk_base(addr);
    uint32_t off = chunk_offset(addr);
    
    SymMemChunk *chunk = NULL;
    if (val.expr) {
        chunk = mem_ht_get_or_create((MemHT *)s->memory_ht, base);
    } else {
        chunk = mem_ht_get((MemHT *)s->memory_ht, base);
        if (!chunk) return;
    }
    
    for (uint32_t i = 0; i < size && (off + i) < SYM_MEM_CHUNK_SIZE; i++) {
        if (chunk->cells[off + i].expr) {
            sym_expr_unref(chunk->cells[off + i].expr);
            chunk->cells[off + i].expr = NULL;
            s->num_symbolic_bytes--;
        }
        
        chunk->cells[off + i].concrete = (val.concrete >> (i * 8)) & 0xFF;
        
        if (val.expr) {
            BitwuzlaTerm byte_term = bitwuzla_mk_term1_indexed2(
                s->tm, BITWUZLA_KIND_BV_EXTRACT, val.expr->term,
                i * 8 + 7, i * 8);
            chunk->cells[off + i].expr = sym_expr_new(s, byte_term, 8);
            s->num_symbolic_bytes++;
            chunk->taint_bitmap[(off + i) / 64] |= (1ULL << ((off + i) % 64));
        } else {
            chunk->taint_bitmap[(off + i) / 64] &= ~(1ULL << ((off + i) % 64));
        }
    }
}

void sym_mem_make_symbolic(SymState *s, uint64_t addr, uint64_t size,
                           const char *name_prefix) {
    for (uint64_t i = 0; i < size; i++) {
        char name[64];
        snprintf(name, sizeof(name), "%s_%lu", name_prefix, i);
        SymExpr *byte_sym = sym_expr_var(s, name, 8);
        SymValue val = { .concrete = 0, .expr = byte_sym };
        sym_mem_write(s, addr + i, 1, val);
    }
}

bool sym_mem_is_symbolic(SymState *s, uint64_t addr, uint32_t size) {
    uint64_t base = chunk_base(addr);
    SymMemChunk *chunk = mem_ht_get((MemHT *)s->memory_ht, base);
    if (!chunk) return false;
    
    uint32_t off = chunk_offset(addr);
    for (uint32_t i = 0; i < size; i++) {
        if (chunk->cells[off + i].expr) return true;
    }
    return false;
}

/* ============================================================================
 * Binary ALU Operations
 * ============================================================================ */

SymValue sym_op_add(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete + b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ADD, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sub(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete - b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SUB, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_mul(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete * b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_MUL, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_and(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete & b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_AND, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_or(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete | b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_OR, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_xor(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete ^ b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_XOR, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_shl(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete << b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SHL, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_shr(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) >> b.concrete) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SHR, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sar(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
    }
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((uint64_t)(sa >> b.concrete)) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ASHR, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* Division operations */
SymValue sym_op_udiv(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = b.concrete ? ((a.concrete & mask) / (b.concrete & mask)) : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_UDIV, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sdiv(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = sb ? ((uint64_t)(sa / sb)) & mask : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SDIV, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_urem(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = b.concrete ? ((a.concrete & mask) % (b.concrete & mask)) : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_UREM, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_srem(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = sb ? ((uint64_t)(sa % sb)) & mask : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SREM, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* Rotate operations */
SymValue sym_op_rol(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint32_t shift = b.concrete % width;
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t av = a.concrete & mask;
    uint64_t concrete = ((av << shift) | (av >> (width - shift))) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, av);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ROL, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_ror(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint32_t shift = b.concrete % width;
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t av = a.concrete & mask;
    uint64_t concrete = ((av >> shift) | (av << (width - shift))) & mask;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, av);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ROR, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* ============================================================================
 * Unary Operations
 * ============================================================================ */

SymValue sym_op_not(SymState *s, SymValue a, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (~a.concrete) & mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaTerm result = bitwuzla_mk_term1(s->tm, BITWUZLA_KIND_BV_NOT, a.expr->term);
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_neg(SymState *s, SymValue a, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (-a.concrete) & mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaTerm result = bitwuzla_mk_term1(s->tm, BITWUZLA_KIND_BV_NEG, a.expr->term);
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* ============================================================================
 * Comparison Operations
 * ============================================================================ */

SymValue sym_op_eq(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) == (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_EQUAL, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_ne(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) != (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_DISTINCT, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_ult(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) < (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ULT, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_ule(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) <= (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_ULE, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_ugt(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) > (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_UGT, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_uge(SymState *s, SymValue a, SymValue b, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = ((a.concrete & mask) >= (b.concrete & mask)) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_UGE, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* Signed comparisons */
SymValue sym_op_slt(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t concrete = (sa < sb) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SLT, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sle(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t concrete = (sa <= sb) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SLE, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sgt(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t concrete = (sa > sb) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SGT, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sge(SymState *s, SymValue a, SymValue b, uint32_t width) {
    int64_t sa = (int64_t)a.concrete, sb = (int64_t)b.concrete;
    if (width < 64) {
        int shift = 64 - width;
        sa = (sa << shift) >> shift;
        sb = (sb << shift) >> shift;
    }
    uint64_t concrete = (sa >= sb) ? 1 : 0;
    
    if (!a.expr && !b.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    BitwuzlaSort sort = get_bv_sort(s, width);
    BitwuzlaTerm ta = a.expr ? a.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, a.concrete & mask);
    BitwuzlaTerm tb = b.expr ? b.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, b.concrete & mask);
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_SGE, ta, tb);
    
    SymExpr *expr = sym_expr_new(s, result, 1);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* ============================================================================
 * Extension/Truncation
 * ============================================================================ */

SymValue sym_op_zext(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width) {
    assert(to_width > from_width);
    uint64_t mask = (from_width < 64) ? ((1ULL << from_width) - 1) : UINT64_MAX;
    uint64_t concrete = a.concrete & mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint32_t ext_bits = to_width - from_width;
    BitwuzlaTerm result = bitwuzla_mk_term1_indexed1(
        s->tm, BITWUZLA_KIND_BV_ZERO_EXTEND, a.expr->term, ext_bits);
    
    SymExpr *expr = sym_expr_new(s, result, to_width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_sext(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width) {
    assert(to_width > from_width);
    
    int64_t sa = (int64_t)a.concrete;
    if (from_width < 64) {
        int shift = 64 - from_width;
        sa = (sa << shift) >> shift;
    }
    uint64_t to_mask = (to_width < 64) ? ((1ULL << to_width) - 1) : UINT64_MAX;
    uint64_t concrete = (uint64_t)sa & to_mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    uint32_t ext_bits = to_width - from_width;
    BitwuzlaTerm result = bitwuzla_mk_term1_indexed1(
        s->tm, BITWUZLA_KIND_BV_SIGN_EXTEND, a.expr->term, ext_bits);
    
    SymExpr *expr = sym_expr_new(s, result, to_width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_trunc(SymState *s, SymValue a, uint32_t from_width, uint32_t to_width) {
    (void)from_width;
    assert(to_width < from_width);
    uint64_t mask = (to_width < 64) ? ((1ULL << to_width) - 1) : UINT64_MAX;
    uint64_t concrete = a.concrete & mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaTerm result = bitwuzla_mk_term1_indexed2(
        s->tm, BITWUZLA_KIND_BV_EXTRACT, a.expr->term, to_width - 1, 0);
    
    SymExpr *expr = sym_expr_new(s, result, to_width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_extract(SymState *s, SymValue a, uint32_t hi, uint32_t lo) {
    uint32_t width = hi - lo + 1;
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = (a.concrete >> lo) & mask;
    
    if (!a.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaTerm result = bitwuzla_mk_term1_indexed2(
        s->tm, BITWUZLA_KIND_BV_EXTRACT, a.expr->term, hi, lo);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

SymValue sym_op_concat(SymState *s, SymValue hi, SymValue lo,
                       uint32_t hi_width, uint32_t lo_width) {
    uint32_t result_width = hi_width + lo_width;
    uint64_t hi_mask = (hi_width < 64) ? ((1ULL << hi_width) - 1) : UINT64_MAX;
    uint64_t lo_mask = (lo_width < 64) ? ((1ULL << lo_width) - 1) : UINT64_MAX;
    uint64_t concrete = ((hi.concrete & hi_mask) << lo_width) | (lo.concrete & lo_mask);
    
    if (!hi.expr && !lo.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort hi_sort = get_bv_sort(s, hi_width);
    BitwuzlaSort lo_sort = get_bv_sort(s, lo_width);
    
    BitwuzlaTerm th = hi.expr ? hi.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, hi_sort, hi.concrete & hi_mask);
    BitwuzlaTerm tl = lo.expr ? lo.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, lo_sort, lo.concrete & lo_mask);
    
    BitwuzlaTerm result = bitwuzla_mk_term2(s->tm, BITWUZLA_KIND_BV_CONCAT, th, tl);
    
    SymExpr *expr = sym_expr_new(s, result, result_width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}

/* ITE (if-then-else) */
SymValue sym_op_ite(SymState *s, SymValue cond, SymValue t, SymValue f, uint32_t width) {
    uint64_t mask = (width < 64) ? ((1ULL << width) - 1) : UINT64_MAX;
    uint64_t concrete = cond.concrete ? (t.concrete & mask) : (f.concrete & mask);
    
    if (!cond.expr && !t.expr && !f.expr) {
        return sym_value_concrete(concrete);
    }
    
    BitwuzlaSort sort = get_bv_sort(s, width);
    
    /* Condition must be boolean */
    BitwuzlaTerm tcond = cond.expr ? cond.expr->term :
        (cond.concrete ? bitwuzla_mk_true(s->tm) : bitwuzla_mk_false(s->tm));
    BitwuzlaTerm tt = t.expr ? t.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, t.concrete & mask);
    BitwuzlaTerm tf = f.expr ? f.expr->term :
        bitwuzla_mk_bv_value_uint64(s->tm, sort, f.concrete & mask);
    
    BitwuzlaTerm result = bitwuzla_mk_term3(s->tm, BITWUZLA_KIND_ITE, tcond, tt, tf);
    
    SymExpr *expr = sym_expr_new(s, result, width);
    return (SymValue){ .concrete = concrete, .expr = expr };
}
