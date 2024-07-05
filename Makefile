
CC=gcc
CFLAGS=-g -Wall
LDFLAGS=
SRCS=main.c common.c keys.c sv_command.c sv_udata_command.c sv_wm_command.c sv_wm2_command.c sv_auth.c sv_send0_command.c sv_report0_command.c sv_send2_command.c sv_getver_command.c crypto.c
OBJS=$(SRCS:.c=.o)

TARGET=sv_authenticator

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
