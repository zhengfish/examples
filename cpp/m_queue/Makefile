# @file Makefile
# @brief Makefile
# @date 2016-07-21 10:04:06 Thu/29
#

E_RED = \e[1;31m
E_GREEN = \e[1;32m
E_YELLOW = \e[1;33m
E_END = \e[0m

CXXFLAGS += -Wall -g
CXXFLAGS += -Wextra -pedantic-errors
CXXFLAGS += -std=c++11 -pthread
CXXFLAGS += -pthread
LDFLAGS +=
LIBS +=

SRCS += m_queue_test.cpp
OBJS += $(SRCS:.cpp=.o)

all: m_queue_test

m_queue_test: $(OBJS)
	@echo -e "link: $(E_YELLOW)$?$(E_END)"
	@echo -e "      $(E_YELLOW)$@$(E_END)"
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $? $(LIBS)

clean:
	$(RM) m_queue_test
	$(RM) *.o

.c.o:
	@echo -e "compiling : $(E_GREEN)$?$(E_END)"
	@$(CC) $(CCFLAGS) -c $< -o $@

.cpp.o:
	@echo -e "compiling : $(E_GREEN)$?$(E_END)"
	@$(CXX) $(CXXFLAGS) -c $< -o $@
