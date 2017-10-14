OBJ = digger
CC = gcc
DEBUG_CFLAGS = -DDEBUG -g
EXT_CFLAGS += -DUSE_HEURISTICS -DUSE_USER_WHITE_DOMAIN -g

RTE_SDK=$(TOP_DIR)/../../usi_midware/dpdk-stable-16.07.2
RTE_TARGET=build

EXT_CFLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include -msse4
EXT_LDFLAGS += -L/usr/lib/x86_64-linux-gnu -L$(RTE_SDK)/$(RTE_TARGET)/lib -Wl,--start-group -lmysqlclient_r -Wl,--end-group -Wl,--whole-archive,-ldpdk,--no-whole-archive -lrt -ldl -lpthread -lm

SRCS =  main.c  common.h suspicious_ip_domain_url_alert.c ../etc/*.o \
		common.c dbapi.c port_flow_statistics.c attack_success_check.c uthash.h utarray.h \
		utlist.h utringbuffer.h utstring.h

#EXT_CFLAGS=-I../../../shared/usr/include -I$(RTE_SDK)/$(RTE_TARGET)/include -DBUILD_DPDK_MODULE -msse4
#EXT_LDFLAGS=-L/usr/lib/x86_64-linux-gnu -L../../../shared/usr/lib -L$(RTE_SDK)/$(RTE_TARGET)/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive

release:
	$(CC) $(EXT_CFLAGS) $(SRCS) $(INCS) -o $(OBJ) $(INCS) $(LIBS) $(EXT_LDFLAGS)
debug:
	$(CC) $(EXT_CFLAGS) $(DEBUG_CFLAGS) $(SRCS) $(INCS) -o $(OBJ) $(INCS) $(LIBS)
clean:
	-rm -rf *.o $(OBJ)
install:
