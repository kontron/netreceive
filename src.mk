ALL_TARGETS += $(o)netreceive
CLEAN_TARGETS += clean-netreceive

netreceive_SOURCES := $(wildcard *.c)
netreceive_OBJECTS := $(addprefix $(o),$(netreceive_SOURCES:.c=.o))

$(o)%.o: %.c
	$(call compile_tgt,netreceive)

$(o)netreceive: $(netreceive_OBJECTS)
	$(call link_tgt,netreceive)

clean-netreceive:
	rm -f $(netreceive_OBJECTS) $(o)src/libnetreceive.a
