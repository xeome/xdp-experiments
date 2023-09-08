# tool macros
CXX := clang
CXXFLAGS := -O2 -g -Wall -target bpf
DBGFLAGS := -g
CCOBJFLAGS := $(CXXFLAGS) -c

OBJ_PATH := obj
SRC_PATH := src

# compile macros
TARGET_NAME := main
TARGET := $(BIN_PATH)/$(TARGET_NAME)

# src files & obj files
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# default rule
default: makedir all

# non-phony targets
$(TARGET): $(OBJ)
	@echo "finished"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CXX) $(CCOBJFLAGS) $< -o $@ 

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(OBJ_PATH)

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(OBJ_PATH)/*.o
