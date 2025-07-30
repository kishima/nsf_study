CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c99 -g -D_GNU_SOURCE -Ilib
CXXFLAGS = -Wall -Wextra -g -D_GNU_SOURCE -Ilib
TARGETS = nsf_reader nsf_player
WAVE_WRITER = lib/Wave_Writer.cpp

.PHONY: all clean

all: $(TARGETS)

nsf_reader: nsf_reader.c
	$(CC) $(CFLAGS) -o nsf_reader nsf_reader.c

nsf_player: nsf_player.c $(WAVE_WRITER)
	$(CXX) $(CXXFLAGS) -o nsf_player nsf_player.c $(WAVE_WRITER)

clean:
	rm -f $(TARGETS)

install: $(TARGETS)
	cp $(TARGETS) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/nsf_reader /usr/local/bin/nsf_player