dps: src/* dps-build
	mkdir -p bin
	$(MAKE) -C dps-build && cp dps-build/dps-build bin/
	$(CC) $(CFLAGS) \
		-g -Werror -I. \
		-o bin/$@ $< \
		$(LIBS)

clean:
	$(MAKE) -C dps-build clean
	rm -drf bin/

.DEFAULT_GOAL=dps
.PHONY: clean
