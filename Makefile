INC     = -I./src/inc
CFLAGS  = -g -Wall -std=gnu11 -D_GNU_SOURCE $(INC) -mssse3
LDFLAGS = -T src/base/base.ld -no-pie
LD	= gcc
CC	= gcc
AR	= ar
FLTRACE = fltrace.so

# Path and dir of this makefile
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))

#
# Make options
#

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb
LDFLAGS += -rdynamic
else
CFLAGS += -O3
endif

ifneq ($(SAFEMODE),)
CFLAGS += -DSAFEMODE
endif

ifneq ($(SUPPRESS_LOG),)
CFLAGS += -DSUPPRESS_LOG
endif

# allocate tool cpu/memory from a specific numa node
ifneq ($(NUMA_NODE),)
CFLAGS += -DNUMA_NODE=$(NUMA_NODE)
endif

ifneq ($(EXCLUDE_CORES),)
CFLAGS += -DEXCLUDE_CORES=$(EXCLUDE_CORES)
endif

#
# Dependencies
#

# jemalloc
JEMALLOC_PATH = ${MKFILE_DIR}/jemalloc
JEMALLOC_INC = $(shell cat $(JEMALLOC_PATH)/je_includes)
JEMALLOC_LIBS = $(shell cat $(JEMALLOC_PATH)/je_libs)
JEMALLOC_STATIC_LIBS = $(shell cat $(JEMALLOC_PATH)/je_static_libs)
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(JEMALLOC_STATIC_LIBS),)
$(error JEMALLOC libs not found. Did you run ./deps.sh [-f]?)
endif
endif
CFLAGS += $(JEMALLOC_INC)

#
# Libs
#

# libbase.a - the base library
base_src = $(wildcard src/base/*.c)
base_obj = $(base_src:.c=.o)

# librmem.a - a remote memory library
rmem_src = $(wildcard src/rmem/*.c)
rmem_obj = $(rmem_src:.c=.o)

#
# Tool
#

main_src = $(wildcard src/*.c)
main_obj = $(main_src:.c=.o)
CFLAGS += -fPIC # (fltrace is a shared library)
CFLAGS += -DKEEP_PERTHREAD_DATA
CFLAGS += -DFAULT_SAMPLER

#
# Makefile targets
#

# (must be first target)
all: $(FLTRACE)

libs: libbase.a librmem.a

libbase.a: $(base_obj)
	$(AR) rcs $@ $^

librmem.a: $(rmem_obj)
	$(AR) rcs $@ $^

# fltrace.so has to be built separately as it uses different flags
# use "make fltrace.so"
$(FLTRACE): $(main_obj) libs src/base/base.ld
	$(LD) $(CFLAGS) $(LDFLAGS) -shared $(main_obj) -o $(FLTRACE)	\
		librmem.a libbase.a $(JEMALLOC_STATIC_LIBS) -lpthread -lm -ldl 

## general build rules for all targets
src = $(base_src) $(rmem_src) ${main_src}
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.d: %.S
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) $(dep) libbase.a librmem.a $(FLTRACE)
