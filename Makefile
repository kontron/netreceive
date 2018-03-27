TOPDIR = $(shell pwd)

VERSION := 0.0.2

CROSS_COMPILE ?=
O ?= $(TOPDIR)

o := $(O)/

CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
INSTALL ?= install

# install directories
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib

ALL_TARGETS :=
CLEAN_TARGETS :=

IS_GIT := $(shell if [ -d .git ] ; then echo yes ; else echo no; fi)
ifeq ($(IS_GIT),yes)
VERSION := $(shell git describe --abbrev=8 --dirty --always --tags --long)
endif

cflags_for_lib = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LIBDIR) pkg-config --cflags $(1))
cflags_for_libpcap = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LIBDIR) pcap-config --cflags)

ldflags_for_lib = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LIBDIR) pkg-config --libs $(1))
ldflags_for_libpcap = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LIBDIR) pcap-config --libs)

# let the user override the default CFLAGS/LDFLAGS
CFLAGS ?= -O2
LDFLAGS ?=

MY_CFLAGS := $(CFLAGS)
MY_LDFLAGS := $(LDFLAGS)

MY_CFLAGS += -DVERSION=\"$(VERSION)\"
MY_CFLAGS += $(call cflags_for_lib,glib-2.0)
MY_CFLAGS += $(call cflags_for_libpcap)
MY_CFLAGS += -I/usr/include

LIBS += $(call ldflags_for_lib,glib-2.0)
LIBS += $(call ldflags_for_lib,jansson)
LIBS += $(call ldflags_for_libpcap)
#LIBS += -L/usr/lib/x86_64-linux-gnu -larchive

tests_CFLAGS := -Isrc/ -Wno-missing-field-initializers

define compile_tgt
	@mkdir -p $(dir $@)
	$(CC) -MD -MT $@ -MF $(@:.o=.d) $(CPPFLAGS) $($(1)_CPPFLAGS) $(MY_CFLAGS) $($(1)_CFLAGS) -c -o $@ $<
endef

define link_tgt
	$(CC) $(MY_LDFLAGS) $($(1)_LDFLAGS) -o $@ $(filter-out %.a,$^) -L/ $(addprefix -l:,$(filter %.a,$^)) $(LIBS) $($(1)_LIBS)
endef

MY_CFLAGS += -Wall -Werror -W -O2

ifeq ($(DEBUG),1)
	MY_CFLAGS += -g -O0
endif

ifeq ($(COVERAGE),1)
	MY_CFLAGS += --coverage
	MY_LDFLAGS += --coverage
endif

DEPS := $(shell find $(o) -name '*.d')

ALL_TARGETS += $(o)netreceive $(o)sockstub
CLEAN_TARGETS += clean-netreceive clean-sockstub
INSTALL_TARGETS += install-netreceive

all: real-all

real-all: $(ALL_TARGETS)

$(o)%.o: %.c
	$(call compile_tgt,netreceive)

netreceive_SOURCES := netreceive.c netsock.c
netreceive_OBJECTS := $(addprefix $(o),$(netreceive_SOURCES:.c=.o))

sockstub_SOURCES := sockstub.c
sockstub_OBJECTS := $(addprefix $(o),$(sockstub_SOURCES:.c=.o))

$(o)netreceive: $(netreceive_OBJECTS)
	$(call link_tgt,netreceive)

clean-netreceive:
	rm -f $(netreceive_OBJECTS) $(o)netreceive

install-netreceive: $(o)netreceive
	$(INSTALL) -d -m 0755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(o)netreceive $(DESTDIR)$(BINDIR)/


$(o)sockstub: $(sockstub_OBJECTS)
	$(call link_tgt,sockstub)

clean-sockstub:
	rm -f $(sockstub_OBJECTS) $(o)sockstub

.PHONY: $(CLEAN_TARGETS) clean
clean: $(CLEAN_TARGETS)
	rm -f $(DEPS)

.PHONY: $(INSTALL_TARGETS) install
install: $(INSTALL_TARGETS)

-include $(DEPS)
