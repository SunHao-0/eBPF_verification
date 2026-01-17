# eBPF Verifier Verification

This tool verifies the soundness of the eBPF verifier's range analysis: if a concrete value is contained in an abstract state *before* an operation, the result must also be *contained* in the abstract result.
For operation `f` with abstract counterpart `f#`:

```
forall c, a: c in gamma(a) => f(c) in gamma(f#(a))
```
Where `gamma(a)` denotes all concrete values satisfying abstract state `a`. See `verifier_spec.c`.


The tool extracts the *unmodified* verifier's code to user space and uses verification tools including `cbmc` to check the specification.
  - One may use this tool to verify their changes to the verifier without compiling any kernel code;
  - or verify the verifier's existing code.

Verified Functions:
  - `adjust_scalar_min_max_vals()`: ALU operations (add, sub, mul, and, or, xor, lsh, rsh, arsh, neg)
  - `is_scalar_branch_taken()`: branch prediction
  - `reg_set_min_max()`: bounds refinement after conditional jumps

Known Limitation:
  - Range analysis only. Extending scope requires: (1) update `extract.py` and (2) update spec in `verifier_spec.c`.
  - Slow for certain operations. Can be improved via modular verification.

## Requirements

- Linux kernel source (bpf-next for the latest code)
- Python 3
- CBMC 6.0+ with bitwuzla solver (recommended)

Download cbmc and bitwuzla:
  - https://github.com/diffblue/cbmc/releases
  - https://github.com/bitwuzla/bitwuzla/releases

Optional: KLEE, ESBMC for alternative backends.

## Quick Start

0. File Structure:
```
extract.py          - Extract functions from kernel source
verifier_spec.c     - Verification harness and soundness spec
output/
  range_analysis.c  - Extracted verifier code (auto-generated)
  cbmc_results/     - CBMC verification output
examples/
  range_analysis_CVE-2020-27194.c  - Vulnerable alu32 or
  range_analysis_CVE-2021-3490.c   - Vulnerable alu32 and/or/xor
```

1. Clone bpf-next:
```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
```
Modify the `Makefile` to update the kernel source path.

2. Extract verifier code:
```bash
make extract
```

3. Run verification:
```bash
make verify-all -j$(nproc)
# To verify a specific op
make verify-alu32-and TOOL=cbmc
```

Most operations verify within five minutes. The following are slow due to large verification conditions:

- alu64-add, alu64-sub

## Expected Results

The latest bpf-next is sound:
```
$ make verify-all -j16
Extracting from:
  verifier.c: bpf-next/kernel/bpf/verifier.c
  tnum.c: bpf-next/kernel/bpf/tnum.c

Extracting from verifier.c:
  [OK] adjust_scalar_min_max_vals (verifier.c:15542-15654)
  ...

Extracted 69 functions to output/range_analysis.c
[cbmc] Verifying alu64 sub...
[cbmc] Verifying alu64 add...
[cbmc] Verifying alu64 and...
[cbmc] Verifying alu64 or...
  PASSED
...
```

For vulnerable code (see `examples/`):
```
$ cp examples/range_analysis_CVE-2021-3490.c output/range_analysis.c
$ make verify-alu32-and
[cbmc] Verifying alu32 and...
  FAILED (see output/cbmc_results/verify-alu32-and.txt)
```

```bash
make verify-all TOOL=cbmc     # Default, fastest with bitwuzla
make verify-all TOOL=esbmc    # Alternative BMC tool
make verify-all TOOL=klee     # Symbolic execution (Docker)
```
