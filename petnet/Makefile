
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
	$(call build,CXX,$(CXX) $(CFLAGS) -c $< -o $@)

%.o : %.cpp
	$(call build,CXX,$(CXX) $(CFLAGS) -c $< -o $@)

%.o : %.S 
	$(call build,CXX,$(CXX) $(CFLAGS) -c $< -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)




all: libpetnet apps


apps:
	make -C apps/

libpetnet:
	make -C libpetnet/


clean: 

	make -C apps/ clean
	make -C libpetnet/ clean


.PHONY: all clean apps libpetnet