
C = counter
T = trace

cobjs = counter.o
tobjs = trace.o

.PHONY : all clean

all: $T $C

$C: $(cobjs)
	gcc -g -Wall -Wextra -o $@ $< -lpthread

$T: $(tobjs)
	gcc -g -Wall -Wextra -o $@ $<

clean:
	rm -f $T $(tobjs) $C $(cobjs)

