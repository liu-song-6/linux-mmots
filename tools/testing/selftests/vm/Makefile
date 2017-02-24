# Makefile for vm selftests

CFLAGS = -Wall -I ../../../../usr/include $(EXTRA_CFLAGS)
<<<<<<< HEAD
BINARIES = compaction_test
BINARIES += hugepage-mmap
BINARIES += hugepage-shm
BINARIES += map_hugetlb
BINARIES += mlock2-tests
BINARIES += on-fault-limit
BINARIES += thuge-gen
BINARIES += transhuge-stress
BINARIES += userfaultfd
BINARIES += userfaultfd_hugetlb
BINARIES += userfaultfd_shmem
BINARIES += mlock-random-test

all: $(BINARIES)
%: %.c
	$(CC) $(CFLAGS) -o $@ $^ -lrt
userfaultfd: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -O2 -o $@ $< -lpthread

userfaultfd_hugetlb: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -DHUGETLB_TEST -O2 -o $@ $< -lpthread

userfaultfd_shmem: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -DSHMEM_TEST -O2 -o $@ $< -lpthread

mlock-random-test: mlock-random-test.c
	$(CC) $(CFLAGS) -o $@ $< -lcap

../../../../usr/include/linux/kernel.h:
	make -C ../../../.. headers_install
=======
LDLIBS = -lrt
TEST_GEN_FILES = compaction_test
TEST_GEN_FILES += hugepage-mmap
TEST_GEN_FILES += hugepage-shm
TEST_GEN_FILES += map_hugetlb
TEST_GEN_FILES += mlock2-tests
TEST_GEN_FILES += on-fault-limit
TEST_GEN_FILES += thuge-gen
TEST_GEN_FILES += transhuge-stress
TEST_GEN_FILES += userfaultfd
TEST_GEN_FILES += mlock-random-test
>>>>>>> linux-next/akpm-base

TEST_PROGS := run_vmtests

include ../lib.mk

$(OUTPUT)/userfaultfd: LDLIBS += -lpthread ../../../../usr/include/linux/kernel.h
$(OUTPUT)/mlock-random-test: LDLIBS += -lcap

../../../../usr/include/linux/kernel.h:
	make -C ../../../.. headers_install
