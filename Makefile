CC = cc
CFLAGS = -Wall -g
SOURCE_FILES = $(wildcard *.c)
OBJECT_FILES = $(patsubst %.c,%.o,$(src))
OUTPUT_NAME = main

ICP_ROOT = /home/nrgnb/qat
USER_INCLUDES += -I$(ICP_ROOT)/quickassist/include/ \
	-I$(ICP_ROOT)/quickassist/include/lac \
	-I$(ICP_ROOT)/quickassist/lookaside/access_layer/include/ \
	-I$(ICP_ROOT)/quickassist/utilities/libusdm_drv/

# ADDITIONAL_OBJECTS += $(ICP_ROOT)/build/libqat_s.so $(ICP_ROOT)/build/libusdm_drv_s.so
ADDITIONAL_OBJECTS += -lqat_s -lusdm_drv_s

default: $(OBJECT_FILES)
	$(CC) $(CFLAGS) $(USER_INCLUDES) $(SOURCE_FILES) $(ADDITIONAL_OBJECTS) -o $(OUTPUT_NAME)
