//go:build darwin || linux

package negotiate

// gssapi_unix.go — shared GSSAPI backend for darwin and linux via purego.
//
// purego calls the system GSSAPI shared library (Apple GSS.framework on macOS,
// libgssapi_krb5/libgssapi on Linux) without cgo. The library is dlopen'd at
// runtime; callers that need the pure-Go path (no system library present) fall
// back to gokrb5 on Linux. Delegating to the system library gives curl parity:
// the SPN host is imported as a hostbased name and the mechanism applies its
// own dns_canonicalize_hostname=fallback behaviour.

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// GSSAPI function pointers, bound once by loadGSSAPI before main().
var (
	gssImportName func(minorStatus *uint32, inputName *gssBufferDesc, nameType *gssOIDDesc, outputName *uintptr) uint32

	gssInitSecContext func(
		minorStatus *uint32,
		credHandle uintptr,
		ctxHandle *uintptr,
		targetName uintptr,
		mechType *gssOIDDesc,
		reqFlags uint32,
		timeReq uint32,
		chanBindings uintptr,
		inputToken *gssBufferDesc,
		actualMech *uintptr,
		outputToken *gssBufferDesc,
		retFlags *uint32,
		timeRec *uint32,
	) uint32

	gssReleaseBuffer    func(minorStatus *uint32, buffer *gssBufferDesc) uint32
	gssReleaseName      func(minorStatus *uint32, name *uintptr) uint32
	gssDeleteSecContext func(minorStatus *uint32, ctxHandle *uintptr, outputToken *gssBufferDesc) uint32
	gssDisplayStatus    func(minorStatus *uint32, statusValue uint32, statusType int32, mechType *gssOIDDesc, messageContext *uint32, statusString *gssBufferDesc) uint32
)

const gssCMechCode = int32(2) // GSS_C_MECH_CODE — read the mechanism (krb5) minor status

var (
	gssapiLoadOnce sync.Once
	gssapiLoaded   bool
	gssapiLibPath  string // soname/path of the library that bound successfully
)

// loadGSSAPI dlopens the first library in paths whose symbols bind, once.
func loadGSSAPI(paths []string) bool {
	gssapiLoadOnce.Do(func() {
		for _, p := range paths {
			if tryBindGSSAPI(p) {
				gssapiLoaded = true
				gssapiLibPath = p
				return
			}
		}
	})
	return gssapiLoaded
}

func tryBindGSSAPI(path string) (ok bool) {
	defer func() {
		if recover() != nil { // purego panics on a missing symbol
			// Clear any pointers bound before the panic so a partial bind never
			// leaves callable-but-inconsistent globals.
			gssImportName, gssInitSecContext = nil, nil
			gssReleaseBuffer, gssReleaseName, gssDeleteSecContext = nil, nil, nil
			gssDisplayStatus = nil
			ok = false
		}
	}()
	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil || lib == 0 {
		return false
	}
	purego.RegisterLibFunc(&gssImportName, lib, "gss_import_name")
	purego.RegisterLibFunc(&gssInitSecContext, lib, "gss_init_sec_context")
	purego.RegisterLibFunc(&gssReleaseBuffer, lib, "gss_release_buffer")
	purego.RegisterLibFunc(&gssReleaseName, lib, "gss_release_name")
	purego.RegisterLibFunc(&gssDeleteSecContext, lib, "gss_delete_sec_context")
	func() { // gss_display_status is optional (improves error text only)
		defer func() { _ = recover() }()
		purego.RegisterLibFunc(&gssDisplayStatus, lib, "gss_display_status")
	}()
	return true
}

// gssapiTokenForHost imports HTTP@host as a hostbased name and lets the GSSAPI
// mechanism canonicalize it (curl parity), returning a SPNEGO token.
func gssapiTokenForHost(hostname string) ([]byte, error) {
	// NUL-terminated heap copy kept alive across the call, so no Go string
	// pointer is handed to C.
	spn := append([]byte("HTTP@"+hostname), 0)
	nameStr := gssBufferDesc{length: uintptr(len(spn) - 1), value: unsafe.Pointer(&spn[0])}

	var targetName uintptr
	var minor uint32
	major := gssImportName(&minor, &nameStr, &hostBasedServiceOID, &targetName)
	runtime.KeepAlive(spn)
	if major != gssComplete {
		return nil, fmt.Errorf("negotiate: gss_import_name failed: major=0x%08x minor=0x%08x", major, minor)
	}
	defer gssReleaseName(&minor, &targetName)

	var ctxHandle uintptr
	var outputToken gssBufferDesc
	var retFlags, timeRec uint32
	var actualMech uintptr
	major = gssInitSecContext(&minor, gssNoCredential, &ctxHandle, targetName,
		&spnegoOID, 2|8 /* MUTUAL|SEQUENCE */, gssTimeIndefinite, gssNoChannelBinding,
		gssNoInputToken, &actualMech, &outputToken, &retFlags, &timeRec)

	if ctxHandle != gssNoContext {
		gssDeleteSecContext(&minor, &ctxHandle, nil)
	}
	if major != gssComplete && major != gssContinue {
		return nil, classifyGSSError(major, minor)
	}
	if outputToken.length == 0 || outputToken.value == nil {
		return nil, fmt.Errorf("negotiate: gss_init_sec_context returned empty token")
	}
	tokenBytes := make([]byte, outputToken.length)
	copy(tokenBytes, unsafe.Slice((*byte)(outputToken.value), outputToken.length))
	gssReleaseBuffer(&minor, &outputToken) // copy out, then free the C buffer
	return tokenBytes, nil
}

// classifyGSSError flags unknown-SPN failures as unsupportedMech so Token can
// fall back. Heimdal signals it in the GSS major (GSS_S_BAD_MECH); MIT puts the
// real reason in the mechanism minor status text.
func classifyGSSError(major, minor uint32) error {
	routineErr := (major >> 16) & 0xFF
	unknown := routineErr == 1 // GSS_S_BAD_MECH

	minorText := gssMechErrorText(minor)
	if !unknown && minorText != "" && minorIndicatesUnknownSPN(minorText) {
		unknown = true
	}
	msg := fmt.Sprintf("negotiate: gss_init_sec_context failed: major=0x%08x minor=0x%08x", major, minor)
	if minorText != "" {
		msg += " (" + minorText + ")"
	}
	return &NegotiateError{msg: msg, unsupportedMech: unknown}
}

// gssMechErrorText drains gss_display_status for the mechanism minor code.
func gssMechErrorText(minor uint32) string {
	if gssDisplayStatus == nil || minor == 0 {
		return ""
	}
	var msgCtx uint32
	var parts []string
	for i := 0; i < 8; i++ { // capped to avoid a pathological message chain
		var minor2 uint32
		var buf gssBufferDesc
		gssDisplayStatus(&minor2, minor, gssCMechCode, nil, &msgCtx, &buf)
		if buf.value != nil && buf.length != 0 {
			parts = append(parts, string(unsafe.Slice((*byte)(buf.value), buf.length)))
			gssReleaseBuffer(&minor2, &buf)
		}
		if msgCtx == 0 {
			break
		}
	}
	return strings.Join(parts, "; ")
}
