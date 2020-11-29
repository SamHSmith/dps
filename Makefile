dps: src/*
	$(CC) $(CFLAGS) \
		-g -Werror -I. \
		-o $@ $< \
		$(LIBS)

clean:
	rm -f dps

.DEFAULT_GOAL=dps
.PHONY: clean
