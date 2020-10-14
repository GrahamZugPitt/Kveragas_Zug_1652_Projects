drivers-dir := drivers
util-dir    := util
petlib-dir  := petlib
core-dir    := core


include $(drivers-dir)/Makefile.in
include $(util-dir)/Makefile.in
include $(petlib-dir)/Makefile.in
include $(core-dir)/Makefile.in


CXX      := g++
CC	 := gcc
AR       := ar
RANLIN   := ranlib

CFLAGS  := 	-g -std=gnu11 								\
	 		-m64 										\
			-D_GNU_SOURCE								\
	 		-W -Wall -Werror 							\
	 		-D__STDC_FORMAT_MACROS             			\
			-DPET_ENABLE_DEBUG=1						\
	 		-Wno-nonnull -Wno-unused-parameter  		\
			-I.											\
			-DUSE_LIBUNWIND


drivers-objs :=  $(patsubst %, $(drivers-dir)/%, $(drivers-objs))
util-objs    :=  $(patsubst %, $(util-dir)/%,    $(util-objs))
petlib-objs  :=  $(patsubst %, $(petlib-dir)/%,  $(petlib-objs))
core-objs    :=  $(patsubst %, $(core-dir)/%,    $(core-objs))

objs := petnet.o petnet_socket_api.o


libs := 

build = \
	@if [ -z "$V" ]; then \
		echo '	[$1]	$@'; \
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




all: libpetnet.a

libpetnet.a:  $(petlib-objs) $(util-objs) $(drivers-objs) $(core-objs) $(objs)
	$(call build,AR,$(AR) rcs $@ $^)


clean: 
	rm -f $(objs) $(util-objs) $(drivers-objs) $(petlib-objs) $(core-objs) libpetnet.a

.PHONY: all clean
