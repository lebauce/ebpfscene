fire:
	clang \
		-D__KERNEL__ -DCONFIG_64BIT -D__BPF_TRACING__ \
		-DCC_USING_FENTRY -DKBUILD_MODNAME=\\"ddsysprobe\\" \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
		-Wunused -Wall -emit-llvm \
		-include asm_goto_workaround.h \
		-O2 \
		-fno-stack-protector -fno-color-diagnostics -fno-unwind-tables \
		-fno-asynchronous-unwind-tables -fno-jump-tables \
		-fno-builtin \
		-isystem /usr/src/kernels/`uname -r`/include \
		-isystem /usr/src/kernels/`uname -r`/include/uapi \
		-isystem /usr/src/kernels/`uname -r`/include/generated/uapi \
		-isystem /usr/src/kernels/`uname -r`/arch/x86/include \
		-isystem /usr/src/kernels/`uname -r`/arch/x86/include/uapi \
		-isystem /usr/src/kernels/`uname -r`/arch/x86/include/generated \
		-c fire.c
		llc -march=bpf -filetype=obj -o fire.o fire.bc
	go build main.go
