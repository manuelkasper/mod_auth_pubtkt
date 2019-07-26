AUTOMAKE_OPTIONS = foreign
MOD = mod_auth_pubtkt
#WC=-Wc,"-Wall -ansi $(CFLAGS)"
WC=-Wc,"$(CFLAGS)"

all: module

module: $(MOD).c $(TARGET)
	$(APXS) -c $(LIBS) $(WC) $(APXS_LDFLAGS) -Wl,"$(LDFLAGS)" -l crypto $(MOD).c

install-exec-local: module
	$(APXS) -i -a -n modauthpubtkt .libs/$(MOD).so

clean-local:
	-rm -f *.la *.lo *.o *.so *.slo .libs/*

