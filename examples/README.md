# Vulnerable Code Examples

This directory contains verifier code with known range analysis bugs.
The verification tool detects them and shows error traces.

## CVE-2020-27194

- Bug: Incorrect 32-bit OR bounds computation

Verify:
```bash
cp examples/range_analysis_CVE-2020-27194.c output/range_analysis.c
make verify-alu32-or
[cbmc] Verifying alu32 or...
  FAILED (see output/cbmc_results/verify-alu32-or.txt)
```

## CVE-2021-3490

- Bug: Missing bounds update for 32-bit AND/OR/XOR

Verify:
```bash
cp examples/range_analysis_CVE-2021-3490.c output/range_analysis.c
make verify-alu32-and
[cbmc] Verifying alu32 and...
  FAILED (see output/cbmc_results/verify-alu32-and.txt)
make verify-alu32-or
[cbmc] Verifying alu32 or...
  FAILED (see output/cbmc_results/verify-alu32-or.txt)
make verify-alu32-xor
[cbmc] Verifying alu32 xor...
  FAILED (see output/cbmc_results/verify-alu32-xor.txt)
```

For comparison, the latest bpf-next code passes all verifications:

```bash
cp examples/range_analysis_bpf-next.c output/range_analysis.c
make verify-alu32-and verify-alu32-or verify-alu32-xor
```

**Expected output:**
```
[cbmc] Verifying alu32 and...
  PASSED
[cbmc] Verifying alu32 or...
  PASSED
[cbmc] Verifying alu32 xor...
  PASSED
```

## Reading Counterexamples

When verification fails, CBMC produces a trace showing:
1. Input values that trigger the bug
2. Abstract state before and after the operation
3. The violated assertion (bounds check)

**Example trace analysis:**
```
$ cat output/cbmc_results/verify-alu32-and.txt
...
Violated property:
  file verifier_spec.c line 125
  assertion v32 >= r->u32_min_value && v32 <= r->u32_max_value
```

This indicates the concrete 32-bit result is outside the computed
abstract bounds - a soundness violation.
