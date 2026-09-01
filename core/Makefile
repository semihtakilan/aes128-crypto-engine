CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?=

BUILD_DIR := build
TEST_BINARY := $(BUILD_DIR)/test_runner
CORE_SOURCES := $(wildcard src/*.c)
TEST_SOURCES := $(wildcard tests/*.c)
CORE_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/src/%.o,$(CORE_SOURCES))
TEST_OBJECTS := $(patsubst tests/%.c,$(BUILD_DIR)/tests/%.o,$(TEST_SOURCES))
DEPENDENCIES := $(CORE_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

.PHONY: all test sanitize clean

all: test

test: CFLAGS += -O2
test: $(TEST_BINARY)
	@$(TEST_BINARY)

sanitize: CFLAGS += -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LDFLAGS += -fsanitize=address,undefined
sanitize: clean $(TEST_BINARY)
	@$(TEST_BINARY)

$(TEST_BINARY): $(CORE_OBJECTS) $(TEST_OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/src/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPENDENCIES)
