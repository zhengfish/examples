# Makefile

E_RED = \e[1;31m
E_GREEN = \e[1;32m
E_YELLOW = \e[1;33m
E_END = \e[0m

CCFLAGS += -Wall -g
CCFLAGS += -I./

LDFLAGS += -Wl,--as-needed
LIBS += -lprotobuf-c

SRCS_1 += amessage_serialize.c \
		  amessage.pb-c.c
OBJS_1 = $(SRCS_1:.c=.o)
APP_1 = amessage_serialize

SRCS_2 += amessage_deserialize.c \
		  amessage.pb-c.c
OBJS_2 = $(SRCS_2:.c=.o)
APP_2 = amessage_deserialize

all: $(APP_1) $(APP_2)

.SUFFIXES: .c
.PHONY: all proto

.c.o:
	@echo -e "compiling : $(E_GREEN)$?$(E_END)"
	@$(CC) $(CCFLAGS) -c $< -o $@

.cpp.o:
	@echo -e "compiling : $(E_GREEN)$?$(E_END)"
	@$(CXX) $(CCFLAGS) -c $< -o $@


$(APP_1): $(OBJS_1)
	@echo -e "link: $(E_YELLOW)$?$(E_END)"
	@echo -e "      $(E_YELLOW)$@$(E_END)"
	@$(CC) $(LDFLAGS) -o $@ $? $(LIBS)

$(APP_2): $(OBJS_2)
	@echo -e "link: $(E_YELLOW)$?$(E_END)"
	@echo -e "      $(E_YELLOW)$@$(E_END)"
	@$(CC) $(LDFLAGS) -o $@ $? $(LIBS)

proto:
	$(RM) *.pb-c.c
	$(RM) *.pb-c.h
	protoc-c --c_out=. ./amessage.proto

clean:
	$(RM) *.pb-c.c
	$(RM) *.pb-c.h
	$(RM) $(APP_1) $(OBJS_1) *.orig
	$(RM) $(APP_2) $(OBJS_2) *.orig

help:
	@echo make help
	@echo make proto
	@echo make all
	@echo Testing:
	@echo "./$(APP_1) 10 2 | ./$(APP_2)"

