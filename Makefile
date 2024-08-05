PG_CONFIG ?= pg_config
PKG_CONFIG ?= pkg-config

MODULE_big = pg_bech32
EXTENSION = pg_bech32
DATA = $(addprefix pg_bech32--,$(addsuffix .sql,2.0))
OBJS = bech32.o module.o
PG_CFLAGS = -Wextra $(addprefix -Werror=,implicit-function-declaration incompatible-pointer-types int-conversion) -Wcast-qual -Wconversion -Wno-declaration-after-statement -Wdisabled-optimization -Wdouble-promotion -Wno-implicit-fallthrough -Wmissing-declarations -Wno-missing-field-initializers -Wpacked -Wno-parentheses -Wno-sign-conversion -Wstrict-aliasing $(addprefix -Wsuggest-attribute=,pure const noreturn malloc) -fstrict-aliasing
SHLIB_LINK =

define PKG_CHECK_MODULES =
  ifeq ($$(sort $(foreach var,$(addprefix $(1)_,CPPFLAGS CFLAGS LDFLAGS LDLIBS),$$(origin $(var)))),undefined)
    ifndef $(1)_CPPFLAGS
      $(1)_CPPFLAGS := $$(shell $$(PKG_CONFIG) --cflags-only-I $(2))
    endif
    ifndef $(1)_CFLAGS
      $(1)_CFLAGS := $$(shell $$(PKG_CONFIG) --cflags-only-other $(2))
    endif
    ifndef $(1)_LDFLAGS
      $(1)_LDFLAGS := $$(shell $$(PKG_CONFIG) --libs-only-L $(2))
    endif
    ifndef $(1)_LDLIBS
      $(1)_LDLIBS := $$(shell $$(PKG_CONFIG) --libs-only-other $(2)) $$(shell $$(PKG_CONFIG) --libs-only-l $(2))
    endif
  endif
endef

$(eval $(call PKG_CHECK_MODULES,LIBBECH32,libbech32))
PG_CPPFLAGS += $(LIBBECH32_CPPFLAGS)
PG_CFLAGS += $(LIBBECH32_CFLAGS)
PG_LDFLAGS += $(LIBBECH32_LDFLAGS)
SHLIB_LINK += $(LIBBECH32_LDLIBS)

ifeq ($(shell command -v $(PG_CONFIG)),)
  $(error $(PG_CONFIG) was not found)
endif
# PostgreSQL 16 moves some definitions into a new varatt.h
ifneq ($(wildcard $(shell $(PG_CONFIG) --includedir-server)/varatt.h),)
  PG_CPPFLAGS += -DHAVE_VARATT_H=1
endif
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

override CPPFLAGS := $(patsubst -I%,-isystem %,$(filter-out -I. -I./,$(CPPFLAGS)))
