package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"syscall"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/veandco/go-sdl2/sdl"
	"golang.org/x/sys/unix"
)

//go:embed ioctl.o
var ebpfBytecode []byte

const screenWidth = 800
const screenHeight = 600
const bufferWidth = 140
const bufferHeight = 55
const hiddenLines = 2

func main() {
	if err := sdl.Init(sdl.INIT_EVERYTHING); err != nil {
		panic(err)
	}
	defer sdl.Quit()

	window, err := sdl.CreateWindow("ebpfscene", sdl.WINDOWPOS_UNDEFINED, sdl.WINDOWPOS_UNDEFINED,
		screenWidth, screenHeight, sdl.WINDOW_SHOWN)
	if err != nil {
		panic(err)
	}
	defer window.Destroy()

	renderer, err := sdl.CreateRenderer(window, -1, sdl.RENDERER_ACCELERATED)
	if err != nil {
		panic(err)
	}
	defer renderer.Destroy()

	texture, err := renderer.CreateTexture(sdl.PIXELFORMAT_ABGR8888, sdl.TEXTUREACCESS_STREAMING, bufferWidth, bufferHeight)
	if err != nil {
		panic(fmt.Errorf("failed to create texture: %w", err))
	}

	managerOptions := manager.Options{
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"framebuffer": manager.MapSpecEditor{
				Flags:      unix.BPF_F_MMAPABLE,
				EditorFlag: manager.EditFlags,
			},
		},
	}

	manager := &manager.Manager{
		Probes: []*manager.Probe{{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "ebpfscene",
				EBPFSection:  "kprobe/__x64_sys_ioctl",
				EBPFFuncName: "kprobe_do_vfs_ioctl",
			},
		}},
		Maps: []*manager.Map{{
			Name: "framebuffer",
		}},
	}

	if err := manager.InitWithOptions(bytes.NewReader(ebpfBytecode), managerOptions); err != nil {
		panic(fmt.Errorf("failed to init manager: %w", err))
	}

	_, _, err = manager.GetMapSpec("framebuffer")
	if err != nil {
		panic(err)
	}

	counterMap, _, err := manager.GetMap("count")
	if err != nil {
		panic(err)
	}

	m, _, err := manager.GetMap("framebuffer")
	if err != nil {
		panic(err)
	}

	if err := manager.Start(); err != nil {
		panic(fmt.Errorf("failed to start manager: %w", err))
	}

	framebuffer, err := syscall.Mmap(m.FD(), 0, bufferWidth*(bufferHeight+hiddenLines)*4, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		panic(fmt.Errorf("failed to mmap map: %w", err))
	}

	key := uint32(0)
	i := uint32(0)

	if err := counterMap.Update(&key, &i, ebpf.UpdateAny); err != nil {
		panic(err)
	}

	running := true
	for running {
		for event := sdl.PollEvent(); event != nil; event = sdl.PollEvent() {
			switch event.(type) {
			case *sdl.KeyboardEvent:
				if event.GetType() == sdl.KEYDOWN {
					i = (i + 1) % 3
					if err := counterMap.Update(&key, &i, ebpf.UpdateAny); err != nil {
						panic(err)
					}
				}

			case *sdl.QuitEvent:
				println("Quit")
				running = false
				break
			}
		}

		renderer.Clear()
		src := sdl.Rect{0, 0, bufferWidth, bufferHeight}
		dst := sdl.Rect{0, screenHeight / 4, screenWidth, 3 * screenHeight / 4}

		buffer, _, err := texture.Lock(&src)
		if err != nil {
			panic(err)
		}

		syscall.Syscall(syscall.SYS_IOCTL, uintptr(0), 666, 0)
		copy(buffer, framebuffer)

		renderer.Copy(texture, &src, &dst)
		renderer.Present()

		sdl.Delay(18)

		texture.Unlock()
	}
}
