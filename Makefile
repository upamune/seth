CLANG_FORMAT=clang-format

.PHONY: fmt
fmt:
	find . -iname *.h -o -iname *.c | xargs $(CLANG_FORMAT) -style=LLVM -i
