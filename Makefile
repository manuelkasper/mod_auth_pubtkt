TARGETS = all install clean

$(TARGETS): Makedefs
	cd src && $(MAKE) $@

Makedefs:
	./configure

realclean:
	cd src && make clean
	test -f Makedefs && rm -f Makedefs
