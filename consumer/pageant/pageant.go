package pageant

import (
	"crypto/sha256"
	"fmt"
	"github.com/fallobst22/ssh-bridge/consumer/pageant/security"
	"io"
	"log"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"encoding/binary"

	"github.com/Microsoft/go-winio"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"encoding/hex"

	"golang.org/x/crypto/ssh/agent"
)

const (
	AgentMaxMessageLength = 1<<14 - 1
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectMemory = crypt32.NewProc("CryptProtectMemory")

	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileMappingA = modkernel32.NewProc("OpenFileMappingA")
)

const (
	// windows consts
	CRYPTPROTECTMEMORY_BLOCK_SIZE    = 16
	CRYPTPROTECTMEMORY_CROSS_PROCESS = 1
	FILE_MAP_ALL_ACCESS              = 0xf001f

	// Pageant consts
	agentPipeName   = `\\.\pipe\pageant.%s.%s`
	agentCopyDataID = 0x804e50ba
	wndClassName    = "Pageant"
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, be careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

var sshAgentRef agent.Agent

func Serve(sshAgent agent.Agent) {
	sshAgentRef = sshAgent

	if runtime.GOOS != "windows" {
		log.Println("Disabling pageant consumer, as platform is not windows")
	}

	go pipeProxy()

	go func() {
		pageantWindow := createPageantWindow()
		if pageantWindow == 0 {
			fmt.Println(fmt.Errorf("CreateWindowEx failed: %v", win.GetLastError()))
			return
		}

		// main message loop
		runtime.LockOSThread()
		hglobal := win.GlobalAlloc(0, unsafe.Sizeof(win.MSG{}))
		msg := (*win.MSG)(unsafe.Pointer(hglobal))
		defer win.GlobalFree(hglobal)
		for win.GetMessage(msg, 0, 0, 0) > 0 {
			win.TranslateMessage(msg)
			win.DispatchMessage(msg)
		}
	}()
}

func openFileMap(dwDesiredAccess uint32, bInheritHandle uint32, mapNamePtr uintptr) (windows.Handle, error) {
	mapPtr, _, err := procOpenFileMappingA.Call(uintptr(dwDesiredAccess), uintptr(bInheritHandle), mapNamePtr)
	if err != nil && err.Error() == "The operation completed successfully." {
		err = nil
	}

	return windows.Handle(mapPtr), err
}

func registerPageantWindow(hInstance win.HINSTANCE) (atom win.ATOM) {
	var wc win.WNDCLASSEX
	wc.Style = 0

	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = syscall.NewCallback(wndProc)
	wc.CbClsExtra = 0
	wc.CbWndExtra = 0
	wc.HInstance = hInstance
	wc.HIcon = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))
	wc.HCursor = win.LoadCursor(0, win.MAKEINTRESOURCE(win.IDC_IBEAM))
	wc.HbrBackground = win.GetSysColorBrush(win.BLACK_BRUSH)
	wc.LpszMenuName = nil
	wc.LpszClassName = syscall.StringToUTF16Ptr(wndClassName)
	wc.HIconSm = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))

	return win.RegisterClassEx(&wc)
}

func createPageantWindow() win.HWND {
	inst := win.GetModuleHandle(nil)
	atom := registerPageantWindow(inst)
	if atom == 0 {
		fmt.Println(fmt.Errorf("RegisterClass failed: %d", win.GetLastError()))
		return 0
	}

	// CreateWindowEx
	pageantWindow := win.CreateWindowEx(win.WS_EX_APPWINDOW,
		syscall.StringToUTF16Ptr(wndClassName),
		syscall.StringToUTF16Ptr(wndClassName),
		0,
		0, 0,
		0, 0,
		0,
		0,
		inst,
		nil)

	return pageantWindow
}

func wndProc(hWnd win.HWND, message uint32, wParam uintptr, lParam uintptr) uintptr {
	switch message {
	case win.WM_COPYDATA:
		{
			copyData := (*copyDataStruct)(unsafe.Pointer(lParam))

			fileMap, err := openFileMap(FILE_MAP_ALL_ACCESS, 0, copyData.lpData)
			defer windows.CloseHandle(fileMap)

			// check security
			ourself, err := security.GetUserSID()
			if err != nil {
				return 0
			}
			ourself2, err := security.GetDefaultSID()
			if err != nil {
				return 0
			}
			mapOwner, err := security.GetHandleSID(fileMap)
			if err != nil {
				return 0
			}
			if !windows.EqualSid(mapOwner, ourself) && !windows.EqualSid(mapOwner, ourself2) {
				return 0
			}

			// Passed security checks, copy data
			sharedMemory, err := windows.MapViewOfFile(fileMap, 2, 0, 0, 0)
			if err != nil {
				return 0
			}
			defer windows.UnmapViewOfFile(sharedMemory)

			sharedMemoryArray := (*[AgentMaxMessageLength]byte)(unsafe.Pointer(sharedMemory))

			size := binary.BigEndian.Uint32(sharedMemoryArray[:4]) + 4
			// size += 4
			if size > AgentMaxMessageLength {
				return 0
			}

			readWriteBuffer := security.NewReadWriteBuffer(sharedMemoryArray[:size])

			err = agent.ServeAgent(
				sshAgentRef,
				&readWriteBuffer,
			)
			if err != nil && err != io.EOF {
				return 0
			}
			copy(sharedMemoryArray[:], readWriteBuffer.WriteBuffer.Bytes())

			// success
			return 1
		}
	}

	return win.DefWindowProc(hWnd, message, wParam, lParam)
}

func capiObfuscateString(realname string) string {
	cryptlen := len(realname) + 1
	cryptlen += CRYPTPROTECTMEMORY_BLOCK_SIZE - 1
	cryptlen /= CRYPTPROTECTMEMORY_BLOCK_SIZE
	cryptlen *= CRYPTPROTECTMEMORY_BLOCK_SIZE

	cryptdata := make([]byte, cryptlen)
	copy(cryptdata, realname)

	pDataIn := uintptr(unsafe.Pointer(&cryptdata[0]))
	cbDataIn := uintptr(cryptlen)
	dwFlags := uintptr(CRYPTPROTECTMEMORY_CROSS_PROCESS)
	// pageant ignores errors
	procCryptProtectMemory.Call(pDataIn, cbDataIn, dwFlags)

	hash := sha256.Sum256(cryptdata)
	return hex.EncodeToString(hash[:])
}

func pipeProxy() {
	currentUser, err := user.Current()
	pipeName := fmt.Sprintf(agentPipeName, strings.Split(currentUser.Username, `\`)[1], capiObfuscateString(wndClassName))
	listener, err := winio.ListenPipe(pipeName, nil)

	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			return
		}

		go func() {
			err := agent.ServeAgent(sshAgentRef, conn)
			if err != nil && err != io.EOF {
				log.Println("Error during communication with pageant named pipe client", err)
			}
		}()
	}
}
