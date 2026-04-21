//go:build windows

package negotiate

// negotiate_windows.go — SPNEGO token generation on Windows via SSPI.
//
// Uses the Windows Security Support Provider Interface (SSPI) through
// syscall/windows to call secur32.dll. SSPI is the Windows equivalent of
// GSSAPI. The "Negotiate" security package selects SPNEGO automatically.
//
// SSPI uses the currently logged-in user's Kerberos ticket from the Windows
// Credential Manager automatically — no ccache file or path is needed. This
// is the same credential source used by Internet Explorer, Edge, and any other
// browser doing Integrated Windows Authentication.
//
// The C-equivalent calls made here are:
//   1. AcquireCredentialsHandleW("", "Negotiate", SECPKG_CRED_OUTBOUND, ...)
//   2. InitializeSecurityContextW(cred, nil, spn, ISC_REQ_flags, ..., &token)
//   3. FreeCredentialsHandle(cred)
//   4. DeleteSecurityContext(ctx)

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SSPI constants from sspi.h / security.h
const (
	secpkgCredOutbound    = uint32(0x00000002)
	secpkgCredInbound     = uint32(0x00000001) // unused here, for documentation
	iscReqConfidentiality = uint32(0x00000010)
	iscReqIntegrity       = uint32(0x00000010)
	iscReqMutualAuth      = uint32(0x00000002)
	iscReqSequenceDetect  = uint32(0x00000008)
	iscReqConnection      = uint32(0x00000800)
	iscReqFlags           = iscReqMutualAuth | iscReqSequenceDetect | iscReqConnection

	secEOk             = uint32(0x00000000) // SEC_E_OK
	secIContinueNeeded = uint32(0x00090312) // SEC_I_CONTINUE_NEEDED
	maxTokenSize       = 65536              // generous upper bound for the output buffer

	secpkgNegotiate = "Negotiate" // SSPI security package name for SPNEGO
)

// Windows SSPI structures (from sspi.h).
// TimeStamp is a LARGE_INTEGER (int64).
type sspiTimeStamp = int64

// credHandle mirrors CredHandle { ULONG_PTR dwLower; ULONG_PTR dwUpper; }
type credHandle struct {
	Lower uintptr
	Upper uintptr
}

// ctxHandle mirrors SecHandle { ULONG_PTR dwLower; ULONG_PTR dwUpper; }
type ctxHandle struct {
	Lower uintptr
	Upper uintptr
}

// secBuffer mirrors SecBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; }
type secBuffer struct {
	cbBuffer   uint32
	bufferType uint32
	pvBuffer   unsafe.Pointer
}

// secBufferDesc mirrors SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers; }
type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *secBuffer
}

const (
	secbufferVersion = uint32(0) // SECBUFFER_VERSION
	secbufferToken   = uint32(2) // SECBUFFER_TOKEN
	secbufferEmpty   = uint32(0) // SECBUFFER_EMPTY
)

// Loaded SSPI proc pointers.
var (
	modSecur32                     = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCredentialsHandleW  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContextW = modSecur32.NewProc("InitializeSecurityContextW")
	procFreeCredentialsHandle      = modSecur32.NewProc("FreeCredentialsHandle")
	procDeleteSecurityContext      = modSecur32.NewProc("DeleteSecurityContext")
	procFreeContextBuffer          = modSecur32.NewProc("FreeContextBuffer")
)

// Token generates a raw SPNEGO token for use in an HTTP Negotiate
// authentication header targeting the given hostname.
//
// The SPN is "HTTP/hostname" — the standard SPNEGO SPN format for HTTP
// Integrated Windows Authentication. SSPI resolves the actual Kerberos
// service ticket using the logged-in user's credential automatically.
func Token(hostname string) ([]byte, error) {
	spn, err := syscall.UTF16PtrFromString("HTTP/" + hostname)
	if err != nil {
		return nil, fmt.Errorf("negotiate: encoding SPN: %w", err)
	}
	pkg, err := syscall.UTF16PtrFromString(secpkgNegotiate)
	if err != nil {
		return nil, fmt.Errorf("negotiate: encoding package name: %w", err)
	}

	// --- Step 1: Acquire an outbound Negotiate credential handle. ---
	var cred credHandle
	var expiry sspiTimeStamp
	r, _, _ := procAcquireCredentialsHandleW.Call(
		0,                                // pszPrincipal — NULL (current user)
		uintptr(unsafe.Pointer(pkg)),     // pszPackage — "Negotiate"
		uintptr(secpkgCredOutbound),      // fCredentialUse
		0,                                // pvLogonId — NULL
		0,                                // pAuthData — NULL (use default)
		0,                                // pGetKeyFn — NULL
		0,                                // pvGetKeyArgument — NULL
		uintptr(unsafe.Pointer(&cred)),   // phCredential — output
		uintptr(unsafe.Pointer(&expiry)), // ptsExpiry — output
	)
	if r != uintptr(secEOk) {
		return nil, fmt.Errorf("negotiate: AcquireCredentialsHandleW: 0x%08x", r)
	}
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&cred)))

	// --- Step 2: Initialise the security context (generate the SPNEGO token). ---
	// Allocate a generously-sized output buffer; SSPI fills in the actual length.
	outputBuf := make([]byte, maxTokenSize)
	outSecBuf := secBuffer{
		cbBuffer:   uint32(len(outputBuf)),
		bufferType: secbufferToken,
		pvBuffer:   unsafe.Pointer(&outputBuf[0]),
	}
	outSecBufDesc := secBufferDesc{
		ulVersion: secbufferVersion,
		cBuffers:  1,
		pBuffers:  &outSecBuf,
	}

	var ctx ctxHandle
	var ctxAttr uint32
	var ctxExpiry sspiTimeStamp

	r, _, _ = procInitializeSecurityContextW.Call(
		uintptr(unsafe.Pointer(&cred)),          // phCredential
		0,                                       // phContext — NULL (first call)
		uintptr(unsafe.Pointer(spn)),            // pszTargetName — "HTTP/hostname"
		uintptr(iscReqFlags),                    // fContextReq
		0,                                       // Reserved1 — must be 0
		0,                                       // TargetDataRep — 0 = native
		0,                                       // pInput — NULL (first call)
		0,                                       // Reserved2 — must be 0
		uintptr(unsafe.Pointer(&ctx)),           // phNewContext — output
		uintptr(unsafe.Pointer(&outSecBufDesc)), // pOutput — receives token
		uintptr(unsafe.Pointer(&ctxAttr)),       // pfContextAttr — output
		uintptr(unsafe.Pointer(&ctxExpiry)),     // ptsExpiry — output
	)
	defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&ctx)))

	if r != uintptr(secEOk) && r != uintptr(secIContinueNeeded) {
		return nil, fmt.Errorf("negotiate: InitializeSecurityContextW: 0x%08x", r)
	}

	// Copy out only the filled portion of the token.
	tokenLen := binary.LittleEndian.Uint32(outputBuf[0:4])
	_ = tokenLen // outSecBuf.cbBuffer is the actual length SSPI wrote
	tokenBytes := make([]byte, outSecBuf.cbBuffer)
	copy(tokenBytes, outputBuf[:outSecBuf.cbBuffer])

	if len(tokenBytes) == 0 {
		return nil, fmt.Errorf("negotiate: InitializeSecurityContextW returned empty token")
	}
	return tokenBytes, nil
}
