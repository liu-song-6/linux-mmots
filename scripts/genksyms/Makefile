# SPDX-License-Identifier: GPL-2.0

hostprogs-y	:= genksyms
always		:= $(hostprogs-y)

genksyms-objs	:= genksyms.o parse.tab.o lex.lex.o

# FIXME: fix the ambiguous grammar in parse.y and delete this hack
#
# Suppress shift/reduce, reduce/reduce conflicts warnings
# unless W=1 is specified.
ifeq ($(findstring 1,$(KBUILD_ENABLE_EXTRA_GCC_CHECKS)),)
SUPPRESS_BISON_WARNING := 2>/dev/null
endif

quiet_cmd_bison_no_warn = $(quet_cmd_bison)
      cmd_bison_no_warn = $(cmd_bison) $(SUPPRESS_BISON_WARNING)

$(obj)/parse.tab.c: $(src)/parse.y FORCE
	$(call if_changed,bison_no_warn)

quiet_cmd_bison_h_no_warn = $(quet_cmd_bison_h)
      cmd_bison_h_no_warn = $(cmd_bison_h) $(SUPPRESS_BISON_WARNING)

$(obj)/parse.tab.h: $(src)/parse.y FORCE
	$(call if_changed,bison_h_no_warn)
# FIXME END

# -I needed for generated C source (shipped source)
HOSTCFLAGS_parse.tab.o := -I$(src)
HOSTCFLAGS_lex.lex.o := -I$(src)

# dependencies on generated files need to be listed explicitly
$(obj)/lex.lex.o: $(obj)/parse.tab.h
