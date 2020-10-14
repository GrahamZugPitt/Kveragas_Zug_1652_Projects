
CXX      := g++
CC		 := gcc
AR       := ar
RANLIN   := ranlib

CFLAGS  := 	-g -std=gnu11 								\
	 		-m64 										\
			-D_GNU_SOURCE								\
	 		-W -Wall -Werror 							\
	 		-D__STDC_FORMAT_MACROS             			\
	 		-Wno-nonnull -Wno-unused-parameter  		\
			-L../libpetnet								\
			-I../libpetnet								


execs := listen_server      \
		 simple_tcp_client  \
		 select_server		\
		 udp_test_1_server	\
		 udp_test_1_client  \

libs := -lpetnet -lpthread -lrt -lunwind

build = \
	@if [ -z "$V" ]; then \
		echo '	[$1]	$@'; \
		$2; \
	else \
		echo '$2'; \
		$2; \
	fi

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< $(libs) -o $@ $(LFLAGS))

#%.o : %.c 
#	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.o : %.cpp
	$(call build,CXX,$(CXX) $(CFLAGS) -c $<  -o $@)

%.o : %.S 
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)




all: $(execs)




clean: 
	rm -f $(execs)

.PHONY: all clean
