# Компилятор и флаги
OS=$(shell uname -s)
CC = gcc
CFLAGS = -Werror -Wall -Wextra -O2 -std=c17 -I./src --coverage
LDFLAGS = -lcheck --coverage

# Директории
SRC_DIR = src
BUILD_DIR = build
TEST_DIR = tests
DEPLOY_DIR = deploy
INPUT_DIR = input_files
CONFIG_DIR = config
COVERAGE_DIR = coverage

# Исходные файлы и файлы тестов
SRC = $(wildcard $(SRC_DIR)/*.c)
TESTS = $(wildcard $(TEST_DIR)/*.c)

# Цели по умолчанию
all: clean build test deploy

# Запуск программы
run: all
	./$(DEPLOY_DIR)/firewall

# Правила сборки
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Сборка всех объектных файлов
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))

# Цель сборки всех объектных файлов и основного исполняемого файла
build: $(BUILD_DIR)/firewall

# Сборка основного исполняемого файла
$(BUILD_DIR)/firewall: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Сборка тестов
$(TEST_DIR)/test_%: $(TEST_DIR)/test_%.c $(filter-out $(BUILD_DIR)/main.o, $(OBJS))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Запуск тестов
test: $(patsubst $(TEST_DIR)/test_%.c,$(TEST_DIR)/test_%,$(TESTS))
	@for test in $^; do \
        echo "Running $$test..."; \
        $$test || exit 1; \
    done
	echo "All tests passed!"
	mv ./*.gcda $(BUILD_DIR)
	mv ./*.gcno $(BUILD_DIR)

# Размещение файлов сборки
deploy: $(BUILD_DIR)/firewall
	@mkdir -p $(DEPLOY_DIR)
	cp $(BUILD_DIR)/firewall $(DEPLOY_DIR)
	echo "Deployment complete. Files are in $(DEPLOY_DIR)"

# Покрытие кода
coverage: clean build test
	@mkdir -p $(COVERAGE_DIR)
	lcov --capture --directory $(BUILD_DIR) --output-file $(COVERAGE_DIR)/coverage.info #--rc branch_coverage=1
	genhtml $(COVERAGE_DIR)/coverage.info --output-directory $(COVERAGE_DIR)/report --branch-coverage
	$(BROWSER_OPEN) $(COVERAGE_DIR)/report/index.html
	echo "Coverage report generated in $(COVERAGE_DIR)/report/"

# Проверка кода
check: all
ifeq ($(OS), Darwin)
	leaks --atExit -- ./$(DEPLOY_DIR)/firewall < $(INPUT_DIR)/input.txt
endif
ifeq ($(OS), Linux)
	valgrind -s ./$(DEPLOY_DIR)/firewall < $(INPUT_DIR)/input.txt
endif
	cp $(CONFIG_DIR)/CPPLINT.cfg .
	cpplint --extension=c src/*.c src/*.h tests/*.c
	rm -rf CPPLINT.cfg
	cppcheck --enable=all --check-level=exhaustive --suppress=missingIncludeSystem src/*.c src/*.h #tests/*.c

# Определение команды открытия браузера в зависимости от ОС
ifeq ($(OS),Windows_NT)
    BROWSER_OPEN = start
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        BROWSER_OPEN = xdg-open
    endif
    ifeq ($(UNAME_S),Darwin)
        BROWSER_OPEN = open
    endif
endif

# Очистка
clean:
	rm -rf $(BUILD_DIR) $(DEPLOY_DIR)
	find $(TEST_DIR) -type f -name 'test_*' ! -name '*.c' -exec rm -f {} +
	rm -rf $(COVERAGE_DIR)
	rm -f ./*.gcda ./*.gcno

.PHONY: all build test deploy clean run coverage check
