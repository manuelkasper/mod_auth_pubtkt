
include ../Makedefs 

MOD = mod_auth_pubtkt

all: $(TARGET)

$(TARGET): mod_auth_pubtkt.c ap_compat.h
	$(APXS) -c -Wc,"-Wall -ansi $(CFLAGS)" -Wl,"$(LDFLAGS)" -l crypto $(MOD).c

install: $(TARGET)
	$(APXS) -i $(TARGET)

clean:
	-rm -f $(MOD).o $(MOD).so $(MOD).la $(MOD).lo $(MOD).slo
	-rm -rf .libs
