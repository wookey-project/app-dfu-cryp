APP_NAME ?= dfucrypto
DIR_NAME = dfucrypto

PROJ_FILES = ../../
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

######### Metadata ##########
ifeq ($(APP_NAME),dfu-cryp)
    IMAGE_TYPE = IMAGE_TYPE0
else
    IMAGE_TYPE = IMAGE_TYPE1
endif

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

CFLAGS += $(DEBUG_CFLAGS)
CFLAGS += -I$(PROJ_FILES)
CFLAGS += -Isrc/ -Iinc/
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -MMD -MP

LDFLAGS += $(AFLAGS) -fno-builtin -nostdlib -nostartfiles

EXTRA_LDFLAGS ?= -Tdfu-cryp.fw1.ld
LDFLAGS += $(EXTRA_LDFLAGS) -L$(APP_BUILD_DIR) -fno-builtin -nostdlib
LD_LIBS += -lcryp -laes -lrng -lstd -L$(APP_BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILES)build

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
OBJ += $(patsubst %.S,$(APP_BUILD_DIR)/%.o,$(ASM))
DEP = $(SRC:.c=.d)

OUT_DIRS = $(dir $(OBJ))

LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(OBJ) $(DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

#############################################################
# build targets (driver, core, SoC, Board... and local)
show:
	@echo
	@echo "\t\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\t\tSRC\t=> " $(SRC)
	@echo "\t\tASM\t=> " $(ASM)
	@echo "\t\tOBJ\t=> " $(OBJ)
	@echo "\t\tDEP\t=> " $(DEP)
	@echo
	@echo "\t\tCFG\t=> " $(CFLAGS)


all: $(APP_BUILD_DIR) $(OUT_DIRS)  app

app: $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

$(OUT_DIRS): $(APP_BUILD_DIR)

# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(OBJ)
	$(call if_changed,link_o_target)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
