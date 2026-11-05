# Builds the three libraries and the test programs out of tree.
# Called by run.sh: make -j3 BUILD=... PR=... ZKP=... MOD=... all control
CC ?= gcc
OPT ?= -O2
BUILD ?= build
DEFS = -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -DECMULT_WINDOW_SIZE=15
TESTFLAGS = $(OPT) -std=c89 -pedantic -Wall -Wextra -Wno-long-long -Wno-unused-function -Werror
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
COMMON = $(HERE)ae_common.h $(HERE)anti_exfil_vectors.h

PR_MODS = -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1
ZKP_MODS = -DENABLE_MODULE_ECDSA_S2C=1
MOD_MODS = -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ANTI_EXFIL=1

# $(1) name, $(2) source tree, $(3) module defines
define LIB
$$(BUILD)/$(1)/secp256k1.o: $(2)/src/secp256k1.c
	@mkdir -p $$(@D)
	$$(CC) $$(OPT) -I$(2) -I$(2)/include -I$(2)/src $$(DEFS) $(3) -c $$< -o $$@
$$(BUILD)/$(1)/precomputed_ecmult.o: $(2)/src/precomputed_ecmult.c
	@mkdir -p $$(@D)
	$$(CC) $$(OPT) -I$(2) -I$(2)/include -I$(2)/src $$(DEFS) -c $$< -o $$@
$$(BUILD)/$(1)/precomputed_ecmult_gen.o: $(2)/src/precomputed_ecmult_gen.c
	@mkdir -p $$(@D)
	$$(CC) $$(OPT) -I$(2) -I$(2)/include -I$(2)/src $$(DEFS) -c $$< -o $$@
$$(BUILD)/$(1)/libsecp256k1.a: $$(BUILD)/$(1)/secp256k1.o $$(BUILD)/$(1)/precomputed_ecmult.o $$(BUILD)/$(1)/precomputed_ecmult_gen.o
	rm -f $$@
	ar rcs $$@ $$^
endef
$(eval $(call LIB,pr1140,$(PR),$(PR_MODS)))
$(eval $(call LIB,zkp,$(ZKP),$(ZKP_MODS)))
$(eval $(call LIB,module,$(MOD),$(MOD_MODS)))

# $(1) program, $(2) library name, $(3) source tree
define TEST
$$(BUILD)/test_$(1): $$(HERE)test_$(1).c $$(COMMON) $$(BUILD)/$(2)/libsecp256k1.a
	$$(CC) $$(TESTFLAGS) -I$(3)/include -I$$(HERE) $$< $$(BUILD)/$(2)/libsecp256k1.a -o $$@
$$(BUILD)/control/test_$(1): $$(HERE)test_$(1).c $$(COMMON) $$(BUILD)/$(2)/libsecp256k1.a
	@mkdir -p $$(@D)
	$$(CC) $$(TESTFLAGS) -DAE_CONTROL=1 -I$(3)/include -I$$(HERE) $$< $$(BUILD)/$(2)/libsecp256k1.a -o $$@
endef
$(eval $(call TEST,pr1140,pr1140,$(PR)))
$(eval $(call TEST,zkp,zkp,$(ZKP)))
$(eval $(call TEST,module,module,$(MOD)))

PROGS = $(BUILD)/test_pr1140 $(BUILD)/test_zkp $(BUILD)/test_module
CONTROLS = $(BUILD)/control/test_pr1140 $(BUILD)/control/test_zkp $(BUILD)/control/test_module

all: $(PROGS) $(CONTROLS)
.PHONY: all
