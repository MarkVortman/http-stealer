.DEFAULT_GOAL := build

help:									## Avaliable rules.
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":|##"}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$3}' | sed -e 's/\[32m##/[33m/' | sort

build: 									## Build app.
	gcc -o main main.c -lpcap