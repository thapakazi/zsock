.PHONY: run dev test

SRC_DIR = src
MAIN_FILE = $(SRC_DIR)/main.zig

build:
	@zig build

run:
	@zig run $(MAIN_FILE)

watch:
	@make build
	@echo "Watching changes in $(SRC_DIR)..."
	@fswatch -o $(SRC_DIR) | xargs -n1 -I{} sh -c 'clear && echo "Change detected. Rebuilding..." && make build'

test:
	@zig test $(SRC_DIR)/*.zig

websocat:
	@websocat ws://localhost:8090
