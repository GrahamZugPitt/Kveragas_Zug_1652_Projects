execs := http_client  \
		 http_server1 \
		 http_server2 \
		 http_server3 \



objs := http_client.o  \
		http_server1.o \
		http_server2.o \
		http_server3.o \
		pet_hashtable.o \
		hashtable_example.o \
		list_example.o

CFLAGS := -D_GNU_SOURCE									  \
		  -W -Wall -Werror                                \
          -Wno-nonnull -Wno-unused-parameter              \
		  -Wno-unused-function

build = \
	@if [ -z "$V" ]; then \
		echo '  [$1]    $@'; \
		$2; \
	else \
		echo '$2'; \
		$2; \
	fi

#% : %.o
#	$(call build,LINK,$(CXX) $(CFLAGS) $(objs)  -o $@ $(LFLAGS))

%.o : %.c 
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.o : %.cpp
	$(call build,CXX,$(CXX) $(CFLAGS) -c $< -o $@)

%.o : %.S 
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)


all: $(execs)

http_server3: http_server3.o pet_hashtable.o
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@)

hashtable_example: hashtable_example.o pet_hashtable.o
	$(call build,CC,$(CC) $(CFLAGS) $^ -lreadline -o $@)

list_example: list_example.o
	$(call build,CC,$(CC) $(CFLAGS) $^ -lreadline -o $@)

clean: 
	rm -f $(execs) *.o list_example hashtable_example

.PHONY: all clean