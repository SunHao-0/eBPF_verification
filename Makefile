# Usage:
#   make verify-all -j16         - Verify all with default tool (CBMC)
#   make verify-all TOOL=klee    - Verify all with KLEE (via Docker)
#   make verify-all TOOL=esbmc   - Verify all with ESBMC
#   make verify-alu64-add        - Verify specific operation
#   make extract                 - Extract functions from kernel source

KERNEL_DIR    := bpf-next
VERIFIER_SRC  := $(KERNEL_DIR)/kernel/bpf/verifier.c
TNUM_SRC      := $(KERNEL_DIR)/kernel/bpf/tnum.c

# Tool: cbmc (default), klee, esbmc
TOOL          ?= cbmc
PYTHON        := python3

OUTPUT_DIR    := output
OUTPUT        := $(OUTPUT_DIR)/range_analysis.c
SPEC          := verifier_spec.c
RESULTS_DIR   := $(OUTPUT_DIR)/$(TOOL)_results

# mul is skipped due to semantic mismatch
ALU_OPS       := add sub and or xor neg lsh rsh arsh
JMP_OPS       := eq ne gt ge lt le sgt sge slt sle set
CATEGORIES    := alu64 alu32 branch64 branch32

# Map lowercase op names to BPF opcodes
op_to_bpf = $(strip $(if $(filter add,$1),BPF_ADD,$(if $(filter sub,$1),BPF_SUB,$(if $(filter mul,$1),BPF_MUL,$(if $(filter and,$1),BPF_AND,$(if $(filter or,$1),BPF_OR,$(if $(filter xor,$1),BPF_XOR,$(if $(filter neg,$1),BPF_NEG,$(if $(filter lsh,$1),BPF_LSH,$(if $(filter rsh,$1),BPF_RSH,$(if $(filter arsh,$1),BPF_ARSH,$(if $(filter eq,$1),BPF_JEQ,$(if $(filter ne,$1),BPF_JNE,$(if $(filter gt,$1),BPF_JGT,$(if $(filter ge,$1),BPF_JGE,$(if $(filter lt,$1),BPF_JLT,$(if $(filter le,$1),BPF_JLE,$(if $(filter sgt,$1),BPF_JSGT,$(if $(filter sge,$1),BPF_JSGE,$(if $(filter slt,$1),BPF_JSLT,$(if $(filter sle,$1),BPF_JSLE,$(if $(filter set,$1),BPF_JSET,UNKNOWN))))))))))))))))))))))

# Map category to VERIFY_* define
cat_to_def = $(strip $(if $(filter alu64,$1),VERIFY_ALU64,$(if $(filter alu32,$1),VERIFY_ALU32,$(if $(filter branch64,$1),VERIFY_BRANCH64,$(if $(filter branch32,$1),VERIFY_BRANCH32,$(if $(filter minmax64,$1),VERIFY_MINMAX64,$(if $(filter minmax32,$1),VERIFY_MINMAX32,UNKNOWN)))))))

ALU64_TARGETS    := $(addprefix verify-alu64-,$(ALU_OPS))
ALU32_TARGETS    := $(addprefix verify-alu32-,$(ALU_OPS))
BRANCH64_TARGETS := $(addprefix verify-branch64-,$(JMP_OPS))
BRANCH32_TARGETS := $(addprefix verify-branch32-,$(JMP_OPS))
ALL_TARGETS := $(ALU64_TARGETS) $(ALU32_TARGETS) \
               $(BRANCH64_TARGETS) $(BRANCH32_TARGETS)

# CBMC Configuration
# bitwuzla is the fastest on my test
CBMC_SOLVER := bitwuzla
CBMC_LOOP_BOUNDS := \
	--unwindset tnum_mul.0:65 \
	--unwindset scalar_min_max_mul.0:5,scalar_min_max_mul.1:5 \
	--unwindset scalar32_min_max_mul.0:5,scalar32_min_max_mul.1:5

# Use --trace to produce an error trace
# Use --no-xx-check, as we only care about our spec
CBMC_FLAGS := \
	-DTOOL_CBMC \
	--trace \
	--$(CBMC_SOLVER) \
	--slice-formula \
	$(CBMC_LOOP_BOUNDS) \
	--no-standard-checks \
	--no-bounds-check \
	--no-pointer-check \
	--drop-unused-functions \
	--unwinding-assertions

# ESBMC Configuration
ESBMC_SOLVER := bitwuzla
ESBMC_FLAGS := \
	-DTOOL_ESBMC \
	--default-solver $(ESBMC_SOLVER) \
	--no-bounds-check \
	--no-pointer-check \
	--no-div-by-zero-check \
	--force-malloc-success \
	--unwind 65

# KLEE Configuration (Docker-based)
KLEE_IMAGE    := klee/klee:latest
KLEE_WORKDIR  := /home/klee/verify
DOCKER_RUN    := docker run --rm -v $(CURDIR):$(KLEE_WORKDIR) -w $(KLEE_WORKDIR)

# KLEE needs LLVM bitcode
KLEE_CLANG_FLAGS := -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
                    -DTOOL_KLEE -I$(KLEE_WORKDIR)

KLEE_FLAGS := \
	--libc=uclibc \
	--posix-runtime \
	--only-output-states-covering-new

.PHONY: all extract verify-all verify-alu verify-jmp clean help

all: extract

extract: $(OUTPUT)

$(OUTPUT): extract.py $(VERIFIER_SRC) $(TNUM_SRC) | $(OUTPUT_DIR)
	$(PYTHON) extract.py --verifier $(VERIFIER_SRC) --tnum $(TNUM_SRC) -o $(OUTPUT)

$(OUTPUT_DIR) $(RESULTS_DIR):
	mkdir -p $@

# Verification Dispatch
define make_verify_rule
verify-$(1)-$(2): $(OUTPUT) | $(RESULTS_DIR)
	@echo "[$$(TOOL)] Verifying $(1) $(2)..."
	@$$(MAKE) --no-print-directory _verify-$$(TOOL) \
		CATEGORY=$(1) OP=$(2) \
		DEF=$(call cat_to_def,$(1)) \
		OPCODE=$(call op_to_bpf,$(2))
endef

$(foreach cat,alu64 alu32,$(foreach op,$(ALU_OPS),$(eval $(call make_verify_rule,$(cat),$(op)))))
$(foreach cat,branch64 branch32 minmax64 minmax32,$(foreach op,$(JMP_OPS),$(eval $(call make_verify_rule,$(cat),$(op)))))

# Tool-specific Verification Rules
.PHONY: _verify-cbmc
_verify-cbmc:
	@cbmc $(SPEC) $(CBMC_FLAGS) -D$(DEF) -DOPCODE=$(OPCODE) \
		> $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt 2>&1 && \
		echo "  PASSED" || echo "  FAILED (see $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt)"

.PHONY: _verify-esbmc
_verify-esbmc:
	@esbmc $(SPEC) $(ESBMC_FLAGS) -D$(DEF) -DOPCODE=$(OPCODE) \
		> $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt 2>&1 && \
		echo "  PASSED" || echo "  FAILED (see $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt)"

.PHONY: _verify-klee
_verify-klee:
	@mkdir -p $(RESULTS_DIR)
	@$(DOCKER_RUN) $(KLEE_IMAGE) /bin/bash -c "\
		clang $(KLEE_CLANG_FLAGS) -D$(DEF) -DOPCODE=$(OPCODE) $(SPEC) -o /tmp/spec.bc && \
		klee $(KLEE_FLAGS) /tmp/spec.bc" \
		> $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt 2>&1 && \
		echo "  PASSED" || echo "  FAILED (see $(RESULTS_DIR)/verify-$(CATEGORY)-$(OP).txt)"

verify-all: $(ALL_TARGETS)
	@echo ""
	@echo "======================================"
	@echo "Verification Summary ($(TOOL))"
	@echo "======================================"
	@echo "Total: $(words $(ALL_TARGETS))"
	@passed=$$(grep -l "VERIFICATION SUCCESSFUL\|KLEE: done" $(RESULTS_DIR)/*.txt 2>/dev/null | wc -l); \
	 failed=$$(grep -l "VERIFICATION FAILED\|KLEE: ERROR\|ESBMC.*FALSIFIED" $(RESULTS_DIR)/*.txt 2>/dev/null | wc -l); \
	 echo "Passed: $$passed"; \
	 echo "Failed: $$failed"

verify-alu: $(ALU64_TARGETS) $(ALU32_TARGETS)
	@echo "ALU verification complete ($(TOOL))"

verify-jmp: $(BRANCH64_TARGETS) $(BRANCH32_TARGETS) $(MINMAX64_TARGETS) $(MINMAX32_TARGETS)
	@echo "JMP verification complete ($(TOOL))"

# Docker/KLEE Setup
KLEE_DOCKER_IMAGE := bpf-verify-klee

.PHONY: docker-pull docker-build-klee docker-test

docker-pull:
	docker pull $(KLEE_IMAGE)

docker-build-klee: Dockerfile.klee $(OUTPUT)
	docker build -f Dockerfile.klee -t $(KLEE_DOCKER_IMAGE) .

docker-test:
	@echo "Testing KLEE Docker setup..."
	@$(DOCKER_RUN) $(KLEE_IMAGE) klee --version

.PHONY: esbmc-check

esbmc-check:
	@which esbmc > /dev/null 2>&1 || \
		(echo "ESBMC not found. Install from: http://esbmc.org/" && exit 1)
	@esbmc --version

.PHONY: compile results clean clean-results

compile: $(OUTPUT)
	clang -Wall -Wextra -std=gnu11 -O2 -c $(SPEC) -o $(OUTPUT_DIR)/spec.o

results:
	@if [ -d $(RESULTS_DIR) ]; then \
		echo "Verification Results:"; \
		echo "====================="; \
		for f in $(RESULTS_DIR)/*.txt; do \
			name=$$(basename $$f .txt); \
			if grep -q "VERIFICATION SUCCESSFUL\|KLEE: done" $$f 2>/dev/null; then \
				echo "  $$name: PASSED"; \
			elif grep -q "VERIFICATION FAILED\|KLEE: ERROR\|FALSIFIED" $$f 2>/dev/null; then \
				echo "  $$name: FAILED"; \
			else \
				echo "  $$name: UNKNOWN"; \
			fi; \
		done; \
	else \
		echo "No results. Run 'make verify-all' first."; \
	fi

clean:
	rm -rf $(OUTPUT_DIR) *.o *.bc klee-out-* klee-last

clean-results:
	rm -rf $(RESULTS_DIR)

help:
	@echo "BPF Verifier Soundness Verification"
	@echo "===================================="
	@echo ""
	@echo "Tools: TOOL=cbmc (default), TOOL=klee, TOOL=esbmc"
	@echo ""
	@echo "Main Targets:"
	@echo "  make extract              - Extract functions from kernel"
	@echo "  make verify-all           - Verify all operations"
	@echo "  make verify-alu           - Verify ALU operations only"
	@echo "  make verify-jmp           - Verify JMP operations only"
	@echo "  make results              - Show verification results"
	@echo ""
	@echo "Individual Verification:"
	@echo "  make verify-alu64-add     - Verify 64-bit ADD"
	@echo "  make verify-branch64-eq   - Verify is_scalar_branch_taken for JEQ"
	@echo "  make verify-minmax32-gt   - Verify reg_set_min_max for JGT (32-bit)"
	@echo ""
	@echo "Docker/KLEE:"
	@echo "  make docker-pull          - Pull KLEE Docker image"
	@echo "  make docker-test          - Test KLEE Docker setup"
	@echo "  make verify-all TOOL=klee - Run all with KLEE"
	@echo ""
	@echo "Examples:"
	@echo "  make -j8 verify-all                  # Parallel CBMC"
	@echo "  make verify-all TOOL=esbmc           # Use ESBMC"
	@echo "  make verify-alu64-add TOOL=klee      # Single test with KLEE"
