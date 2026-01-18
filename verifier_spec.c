/**
 * eBPF Verifier Specification
 *
 * This file defines soundness properties for the verifier's abstract
 * interpretation. It supports multiple verification backends:
 *   - CBMC (default)
 *   - KLEE (via Docker)
 *   - ESBMC
 *
 * Soundness Properties:
 *   ALU:  If v1 in gamma(a1), v2 in gamma(a2), then (v1 OP v2) in gamma(a1 OP_abs a2)
 *   JMP:  If is_scalar_branch_taken() returns 1/0, the condition is true/false
 *
 * Usage:
 *   cbmc verifier_spec.c -DTOOL_CBMC -DVERIFY_ALU64 -DOPCODE=BPF_ADD
 *   cbmc verifier_spec.c -DTOOL_CBMC -DVERIFY_BRANCH64 -DOPCODE=BPF_JEQ
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#if defined(TOOL_KLEE)

#include <klee/klee.h>
#define SYMBOLIC(addr, size, name) klee_make_symbolic(addr, size, name)
#define ASSUME(x) klee_assume(x)
#define ASSERT(x) klee_assert(x)

#elif defined(TOOL_ESBMC)

#include <stdint.h>
#include <limits.h>
void __ESBMC_assume(_Bool);
void __ESBMC_assert(_Bool, const char *);
#define ASSUME(x) __ESBMC_assume(x)
#define ASSERT(x) __ESBMC_assert(x, #x)

/* ESBMC nondet functions */
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);
int nondet_int(void);
struct bpf_reg_state;
struct bpf_reg_state nondet_bpf_reg_state(void);

#define SYMBOLIC(addr, size, name)                             \
	do {                                                   \
		if (size == 8)                                 \
			*(uint64_t *)(addr) = nondet_u64();    \
		else if (size == 4)                            \
			*(uint32_t *)(addr) = nondet_u32();    \
		else if (size == sizeof(struct bpf_reg_state)) \
			*(struct bpf_reg_state *)(addr) =      \
				nondet_bpf_reg_state();        \
		else                                           \
			__ESBMC_assert(0, "unsupported size"); \
	} while (0)

#elif defined(TOOL_CBMC)

#include <stdint.h>
void __CPROVER_assume(_Bool);
#define ASSUME(x) __CPROVER_assume(x)
#define ASSERT(x) assert(x)

/* CBMC nondet functions */
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);
struct bpf_reg_state;
struct bpf_reg_state nondet_bpf_reg_state(void);

#define SYMBOLIC(addr, size, name)                             \
	do {                                                   \
		if (size == 8)                                 \
			*(uint64_t *)(addr) = nondet_u64();    \
		else if (size == 4)                            \
			*(uint32_t *)(addr) = nondet_u32();    \
		else if (size == sizeof(struct bpf_reg_state)) \
			*(struct bpf_reg_state *)(addr) =      \
				nondet_bpf_reg_state();        \
		else                                           \
			assert(0 && "unsupported size");       \
	} while (0)

#else /* Test mode */

#include <stdlib.h>
#define SYMBOLIC(addr, size, name) memset(addr, 0, size)
#define ASSUME(x)                \
	do {                     \
		if (!(x))        \
			exit(0); \
	} while (0)
#define ASSERT(x) assert(x)

#endif

#include "output/range_analysis.c"

/* The specification */

/* Check that abstract state is well-formed */
static void assert_wellformed(const struct bpf_reg_state *r)
{
	ASSERT(r->umin_value <= r->umax_value);
	ASSERT(r->smin_value <= r->smax_value);
	ASSERT(r->u32_min_value <= r->u32_max_value);
	ASSERT(r->s32_min_value <= r->s32_max_value);
	ASSERT((r->var_off.value & r->var_off.mask) == 0);
}

/* Postcondition: concrete value is contained in the abstract state */
static void assert_in_gamma(const struct bpf_reg_state *r, u64 v)
{
	u32 v32 = (u32)v;

	assert_wellformed(r);

	/* Value bounds */
	ASSERT(v >= r->umin_value && v <= r->umax_value);
	ASSERT((s64)v >= r->smin_value && (s64)v <= r->smax_value);
	ASSERT(v32 >= r->u32_min_value && v32 <= r->u32_max_value);
	ASSERT((s32)v32 >= r->s32_min_value && (s32)v32 <= r->s32_max_value);

	/* Tnum: known bits must match */
	ASSERT((v & ~r->var_off.mask) == r->var_off.value);
}

/* Precondition: Created symbolic register containing a concrete value */
static void symbolic_reg_containing(struct bpf_reg_state *r, u64 v)
{
	u32 v32 = (u32)v;

	SYMBOLIC(r, sizeof(*r), "reg");
	r->type = SCALAR_VALUE;

	/* Well-formedness */
	ASSUME((r->var_off.value & r->var_off.mask) == 0);
	ASSUME(r->umin_value <= r->umax_value);
	ASSUME(r->smin_value <= r->smax_value);
	ASSUME(r->u32_min_value <= r->u32_max_value);
	ASSUME(r->s32_min_value <= r->s32_max_value);

	/* Value is in concretization */
	ASSUME(r->umin_value <= v && v <= r->umax_value);
	ASSUME(r->smin_value <= (s64)v && (s64)v <= r->smax_value);
	ASSUME(r->u32_min_value <= v32 && v32 <= r->u32_max_value);
	ASSUME(r->s32_min_value <= (s32)v32 && (s32)v32 <= r->s32_max_value);
	ASSUME((v & ~r->var_off.mask) == r->var_off.value);
}

/* 64-bit concrete binary operations */
static u64 concrete_add64(u64 a, u64 b)
{
	return a + b;
}
static u64 concrete_sub64(u64 a, u64 b)
{
	return a - b;
}
static u64 concrete_mul64(u64 a, u64 b)
{
	return a * b;
}
static u64 concrete_udiv64(u64 a, u64 b)
{
	return (b == 0) ? 0 : (a / b);
}
static u64 concrete_sdiv64(u64 a, u64 b)
{
	s64 sa = a;
	s64 sb = b;

	if (sa == S64_MIN && sb == -1)
		return (u64)sa;

	return (sb == 0) ? 0 : (sa / sb);
}
static u64 concrete_umod64(u64 a, u64 b)
{
	return (b == 0) ? a : (a % b);
}
static u64 concrete_smod64(u64 a, u64 b)
{
	return ((s64)b == 0) ? a : ((s64)a % (s64)b);
}
static u64 concrete_and64(u64 a, u64 b)
{
	return a & b;
}
static u64 concrete_or64(u64 a, u64 b)
{
	return a | b;
}
static u64 concrete_xor64(u64 a, u64 b)
{
	return a ^ b;
}
static u64 concrete_lsh64(u64 a, u64 b)
{
	return a << b;
}
static u64 concrete_rsh64(u64 a, u64 b)
{
	return a >> b;
}
static u64 concrete_arsh64(u64 a, u64 b)
{
	return (u64)((s64)a >> b);
}

/* 32-bit concrete binary operations */
static u32 concrete_add32(u32 a, u32 b)
{
	return a + b;
}
static u32 concrete_sub32(u32 a, u32 b)
{
	return a - b;
}
static u32 concrete_mul32(u32 a, u32 b)
{
	return a * b;
}
static u32 concrete_udiv32(u32 a, u32 b)
{
	return (b == 0) ? 0 : (a / b);
}
static u32 concrete_sdiv32(u32 a, u32 b)
{
	s32 sa = a;
	s32 sb = b;

	if (sa == S32_MIN && sb == -1)
		return (u32)sa;

	return (sb == 0) ? 0 : (sa / sb);
}
static u32 concrete_umod32(u32 a, u32 b)
{
	return (b == 0) ? a : (a % b);
}
static u32 concrete_smod32(u32 a, u32 b)
{
	return ((s32)b == 0) ? a : ((s32)a % (s32)b);
}
static u32 concrete_and32(u32 a, u32 b)
{
	return a & b;
}
static u32 concrete_or32(u32 a, u32 b)
{
	return a | b;
}
static u32 concrete_xor32(u32 a, u32 b)
{
	return a ^ b;
}
static u32 concrete_lsh32(u32 a, u32 b)
{
	return a << b;
}
static u32 concrete_rsh32(u32 a, u32 b)
{
	return a >> b;
}
static u32 concrete_arsh32(u32 a, u32 b)
{
	return (u32)((s32)a >> b);
}

/* Extend bpf op */
#define BPF_SDIV_ 0x08
#define BPF_SMOD_ 0x18

static u64 (*get_op64(u8 op))(u64, u64)
{
	switch (op) {
	case BPF_ADD:
		return concrete_add64;
	case BPF_SUB:
		return concrete_sub64;
	case BPF_MUL:
		return concrete_mul64;
	case BPF_DIV:
		return concrete_udiv64;
	case BPF_SDIV_:
		return concrete_sdiv64;
	case BPF_MOD:
		return concrete_umod64;
	case BPF_SMOD_:
		return concrete_smod64;
	case BPF_AND:
		return concrete_and64;
	case BPF_OR:
		return concrete_or64;
	case BPF_XOR:
		return concrete_xor64;
	case BPF_LSH:
		return concrete_lsh64;
	case BPF_RSH:
		return concrete_rsh64;
	case BPF_ARSH:
		return concrete_arsh64;
	default:
		return NULL;
	}
}

static u32 (*get_op32(u8 op))(u32, u32)
{
	switch (op) {
	case BPF_ADD:
		return concrete_add32;
	case BPF_SUB:
		return concrete_sub32;
	case BPF_MUL:
		return concrete_mul32;
	case BPF_DIV:
		return concrete_udiv32;
	case BPF_SDIV_:
		return concrete_sdiv32;
	case BPF_MOD:
		return concrete_umod32;
	case BPF_SMOD_:
		return concrete_smod32;
	case BPF_AND:
		return concrete_and32;
	case BPF_OR:
		return concrete_or32;
	case BPF_XOR:
		return concrete_xor32;
	case BPF_LSH:
		return concrete_lsh32;
	case BPF_RSH:
		return concrete_rsh32;
	case BPF_ARSH:
		return concrete_arsh32;
	default:
		return NULL;
	}
}

static bool eval_cond64(u8 op, u64 a, u64 b)
{
	switch (op) {
	case BPF_JEQ:
		return a == b;
	case BPF_JNE:
		return a != b;
	case BPF_JGT:
		return a > b;
	case BPF_JGE:
		return a >= b;
	case BPF_JLT:
		return a < b;
	case BPF_JLE:
		return a <= b;
	case BPF_JSGT:
		return (s64)a > (s64)b;
	case BPF_JSGE:
		return (s64)a >= (s64)b;
	case BPF_JSLT:
		return (s64)a < (s64)b;
	case BPF_JSLE:
		return (s64)a <= (s64)b;
	case BPF_JSET:
		return (a & b) != 0;
	default:
		return false;
	}
}

static bool eval_cond32(u8 op, u32 a, u32 b)
{
	switch (op) {
	case BPF_JEQ:
		return a == b;
	case BPF_JNE:
		return a != b;
	case BPF_JGT:
		return a > b;
	case BPF_JGE:
		return a >= b;
	case BPF_JLT:
		return a < b;
	case BPF_JLE:
		return a <= b;
	case BPF_JSGT:
		return (s32)a > (s32)b;
	case BPF_JSGE:
		return (s32)a >= (s32)b;
	case BPF_JSLT:
		return (s32)a < (s32)b;
	case BPF_JSLE:
		return (s32)a <= (s32)b;
	case BPF_JSET:
		return (a & b) != 0;
	default:
		return false;
	}
}

/* Verification Harnesses */

static void verify_alu64(u8 opcode)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state dst, src;
	u64 dv, sv, rv;
	u64 (*op)(u64, u64) = get_op64(opcode);
	u16 off = 0;
	int err;

	SYMBOLIC(&dv, sizeof(dv), "dst_val");
	SYMBOLIC(&sv, sizeof(sv), "src_val");

	/* Bound the shift amount */
	if (opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) {
		ASSUME(sv < 64);
	} else if (opcode == BPF_SDIV_) {
		off = 1;
		opcode = BPF_DIV;
	} else if (opcode == BPF_SMOD_) {
		off = 1;
		opcode = BPF_MOD;
	}

	symbolic_reg_containing(&dst, dv);
	symbolic_reg_containing(&src, sv);

	rv = op(dv, sv);

	struct bpf_insn insn = {
		.code = BPF_ALU64 | opcode | BPF_X,
		.off = off,
	};
	err = adjust_scalar_min_max_vals(&env, &insn, &dst, src);

	if (!err)
		assert_in_gamma(&dst, rv);
}

static void verify_alu32(u8 opcode)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state dst, src;
	u64 dv, sv;
	u32 (*op)(u32, u32) = get_op32(opcode);
	u16 off = 0;
	int err;

	SYMBOLIC(&dv, sizeof(dv), "dst_val");
	SYMBOLIC(&sv, sizeof(sv), "src_val");

	if (opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) {
		ASSUME((u32)sv < 32);
	} else if (opcode == BPF_SDIV_) {
		off = 1;
		opcode = BPF_DIV;
	} else if (opcode == BPF_SMOD_) {
		off = 1;
		opcode = BPF_MOD;
	}

	symbolic_reg_containing(&dst, dv);
	symbolic_reg_containing(&src, sv);

	u64 rv = (u64)op((u32)dv, (u32)sv); /* zero-extended */

	struct bpf_insn insn = {
		.code = BPF_ALU | opcode | BPF_X,
		.off = off,
	};
	err = adjust_scalar_min_max_vals(&env, &insn, &dst, src);

	if (!err)
		assert_in_gamma(&dst, rv);
}

static void verify_alu64_neg(void)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state dst, src = { 0 };
	u64 dv;
	int err;

	SYMBOLIC(&dv, sizeof(dv), "dst_val");
	symbolic_reg_containing(&dst, dv);

	u64 rv = (u64)(-(s64)dv);

	struct bpf_insn insn = { .code = BPF_ALU64 | BPF_NEG };
	src.type = SCALAR_VALUE;
	__mark_reg_known(&src, 0);

	err = adjust_scalar_min_max_vals(&env, &insn, &dst, src);

	if (!err)
		assert_in_gamma(&dst, rv);
}

static void verify_alu32_neg(void)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state dst, src = { 0 };
	u64 dv;
	int err;

	SYMBOLIC(&dv, sizeof(dv), "dst_val");
	symbolic_reg_containing(&dst, dv);

	u64 rv = (u64)(u32)(-(s32)(u32)dv);

	struct bpf_insn insn = { .code = BPF_ALU | BPF_NEG };
	src.type = SCALAR_VALUE;
	__mark_reg_known(&src, 0);

	err = adjust_scalar_min_max_vals(&env, &insn, &dst, src);

	if (!err)
		assert_in_gamma(&dst, rv);
}

static void verify_branch64(u8 opcode)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state tr1, tr2, fr1, fr2;
	struct bpf_reg_state r1, r2;
	u64 v1, v2;

	SYMBOLIC(&v1, sizeof(v1), "v1");
	SYMBOLIC(&v2, sizeof(v2), "v2");

	symbolic_reg_containing(&r1, v1);
	symbolic_reg_containing(&r2, v2);

	int res = is_scalar_branch_taken(&r1, &r2, opcode, false);
	bool taken = eval_cond64(opcode, v1, v2);
	if (res == 1) {
		ASSERT(taken); /* definitely taken => must be true */
		return;
	} else if (res == 0) {
		ASSERT(!taken); /* definitely not taken => must be false */
		return;
	}

	/* res == -1: verify reg_set_min_max */
	memcpy(&tr1, &r1, sizeof(r1));
	memcpy(&tr2, &r2, sizeof(r2));
	memcpy(&fr1, &r1, sizeof(r1));
	memcpy(&fr2, &r2, sizeof(r2));

	int ret = reg_set_min_max(&env, &tr1, &tr2, &fr1, &fr2, opcode, false);
	if (ret)
		return;

	if (taken) {
		assert_in_gamma(&tr1, v1);
		assert_in_gamma(&tr2, v2);
	} else {
		assert_in_gamma(&fr1, v1);
		assert_in_gamma(&fr2, v2);
	}
}

static void verify_branch32(u8 opcode)
{
	struct bpf_verifier_env env = { 0 };
	struct bpf_reg_state tr1, tr2, fr1, fr2;
	struct bpf_reg_state r1, r2;
	u64 v1, v2;

	SYMBOLIC(&v1, sizeof(v1), "v1");
	SYMBOLIC(&v2, sizeof(v2), "v2");

	symbolic_reg_containing(&r1, v1);
	symbolic_reg_containing(&r2, v2);

	int res = is_scalar_branch_taken(&r1, &r2, opcode, true);
	bool taken = eval_cond32(opcode, (u32)v1, (u32)v2);

	if (res == 1) {
		ASSERT(taken);
		return;
	} else if (res == 0) {
		ASSERT(!taken);
		return;
	}

	memcpy(&tr1, &r1, sizeof(r1));
	memcpy(&tr2, &r2, sizeof(r2));
	memcpy(&fr1, &r1, sizeof(r1));
	memcpy(&fr2, &r2, sizeof(r2));

	int ret = reg_set_min_max(&env, &tr1, &tr2, &fr1, &fr2, opcode, true);
	if (ret)
		return;

	if (taken) {
		assert_in_gamma(&tr1, v1);
		assert_in_gamma(&tr2, v2);
	} else {
		assert_in_gamma(&fr1, v1);
		assert_in_gamma(&fr2, v2);
	}
}

#ifndef OPCODE
#define OPCODE BPF_ADD /* default */
#endif

int main(void)
{
#if defined(VERIFY_ALU64)
#if OPCODE == BPF_NEG
	verify_alu64_neg();
#else
	verify_alu64(OPCODE);
#endif

#elif defined(VERIFY_ALU32)
#if OPCODE == BPF_NEG
	verify_alu32_neg();
#else
	verify_alu32(OPCODE);
#endif

#elif defined(VERIFY_BRANCH64)
	verify_branch64(OPCODE);

#elif defined(VERIFY_BRANCH32)
	verify_branch32(OPCODE);

#else
	verify_alu32(BPF_ADD);
#endif

	return 0;
}
