
T = trace

srcs = trace.o

.PHONY : clean

$T: $(srcs)
	gcc -g -Wall -Wextra -o $@ $<

clean:
	rm -f $T

