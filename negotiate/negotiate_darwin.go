//go:build darwin

package negotiate

// negotiate_darwin.go — SPNEGO token generation on macOS via GSS.framework.
//
// Uses ebitengine/purego to call GSS.framework without CGo. GSS.framework is
// Apple's Heimdal-based GSSAPI implementation, present on every macOS since
// 10.7. It automatically uses whatever Kerberos credentials are in the macOS
// credential store — both FILE-format ccaches (/tmp/krb5cc_N) and the
// API-type (in-memory CCAPI) ccache populated by corporate SSO or Active
// Directory login. No credential path configuration is needed.
//
// Only the five GSSAPI functions required to generate a one-shot SPNEGO token
// are bound. Everything else (multi-round context establishment, credential
// acquisition, etc.) is handled internally by the framework.

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

const gssFrameworkPath = "/System/Library/Frameworks/GSS.framework/GSS"

// GSSAPI function pointers loaded once at package init.
// The signatures use *gssBufferDesc and *gssOIDDesc (pointer to struct) because
// the C API uses the typedef'd pointer types gss_buffer_t and gss_OID, which are
// already pointer types in C. Opaque handle types (gss_name_t, gss_cred_id_t,
// gss_ctx_id_t) are uintptr because they are C pointer types whose internal
// layout is not relevant to us.
var (
	// gss_import_name converts a string name into an opaque gss_name_t handle.
	// C: OM_uint32 gss_import_name(OM_uint32*, gss_buffer_t, gss_OID, gss_name_t*)
	gssImportName func(
		minorStatus *uint32,
		inputName *gssBufferDesc,
		nameType *gssOIDDesc,
		outputName *uintptr,
	) uint32

	// gss_init_sec_context generates the SPNEGO token bytes.
	// C: OM_uint32 gss_init_sec_context(OM_uint32*, gss_cred_id_t, gss_ctx_id_t*,
	//        gss_name_t, gss_OID, OM_uint32, OM_uint32,
	//        gss_channel_bindings_t, gss_buffer_t, gss_OID*,
	//        gss_buffer_t, OM_uint32*, OM_uint32*)
	gssInitSecContext func(
		minorStatus *uint32,
		credHandle uintptr, // GSS_C_NO_CREDENTIAL = 0
		ctxHandle *uintptr, // in/out: context handle
		targetName uintptr, // from gss_import_name
		mechType *gssOIDDesc, // SPNEGO OID
		reqFlags uint32, // GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG
		timeReq uint32, // 0 = GSS_C_INDEFINITE
		chanBindings uintptr, // GSS_C_NO_CHANNEL_BINDINGS = 0
		inputToken *gssBufferDesc, // GSS_C_NO_BUFFER = nil for first call
		actualMech *uintptr, // ignored output
		outputToken *gssBufferDesc, // receives the token bytes
		retFlags *uint32, // ignored output
		timeRec *uint32, // ignored output
	) uint32

	// gss_release_buffer frees a buffer allocated by the framework.
	// C: OM_uint32 gss_release_buffer(OM_uint32*, gss_buffer_t)
	gssReleaseBuffer func(minorStatus *uint32, buffer *gssBufferDesc) uint32

	// gss_release_name frees a name handle.
	// C: OM_uint32 gss_release_name(OM_uint32*, gss_name_t*)
	gssReleaseName func(minorStatus *uint32, name *uintptr) uint32

	// gss_delete_sec_context destroys a security context.
	// C: OM_uint32 gss_delete_sec_context(OM_uint32*, gss_ctx_id_t*, gss_buffer_t)
	gssDeleteSecContext func(minorStatus *uint32, ctxHandle *uintptr, outputToken *gssBufferDesc) uint32
)

func init() {
	lib, err := purego.Dlopen(gssFrameworkPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		// GSS.framework is guaranteed present on macOS 10.7+. If this panics
		// something is very wrong with the system installation.
		panic(fmt.Sprintf("negotiate: failed to load GSS.framework: %v", err))
	}
	purego.RegisterLibFunc(&gssImportName, lib, "gss_import_name")
	purego.RegisterLibFunc(&gssInitSecContext, lib, "gss_init_sec_context")
	purego.RegisterLibFunc(&gssReleaseBuffer, lib, "gss_release_buffer")
	purego.RegisterLibFunc(&gssReleaseName, lib, "gss_release_name")
	purego.RegisterLibFunc(&gssDeleteSecContext, lib, "gss_delete_sec_context")
}

// Token generates a raw SPNEGO/Kerberos token for use in an HTTP Negotiate
// authentication header targeting the given hostname. The returned bytes are
// the decoded token (not base64 encoded) — callers are responsible for encoding.
//
// The hostname should be the bare hostname (no scheme, no port, no path), e.g.
// "hostname.example.com". The SPN sent to the KDC will be HTTP@hostname
// using the GSS_C_NT_HOSTBASED_SERVICE name type, which the GSSAPI
// implementation internally maps to the canonical SPN "HTTP/hostname".
//
// Credentials are sourced automatically from the macOS Kerberos credential
// store (both API-type/CCAPI and FILE-type ccaches are consulted).
func Token(hostname string) ([]byte, error) {
	// Resolve any CNAME aliases to the canonical A-record hostname.
	// SPNs are registered in Active Directory under the canonical name, not
	// aliases, so gss_import_name must receive the real hostname.
	if resolved, err := resolveCNAME(hostname); err == nil {
		hostname = resolved
	}

	// --- Step 1: Import the target service name. ---
	// Format: "HTTP@hostname" with GSS_C_NT_HOSTBASED_SERVICE.
	// The framework maps "service@host" → "service/host" SPN for the KDC.
	spn := "HTTP@" + hostname
	nameStr := gssBufferDesc{
		length: uintptr(len(spn)),
		value:  unsafe.Pointer(unsafe.StringData(spn)),
	}
	var targetName uintptr
	var minor uint32
	major := gssImportName(&minor, &nameStr, &hostBasedServiceOID, &targetName)
	if major != gssComplete {
		return nil, fmt.Errorf("negotiate: gss_import_name failed: major=0x%08x minor=0x%08x", major, minor)
	}
	defer func() {
		gssReleaseName(&minor, &targetName)
	}()

	// --- Step 2: Initialise the security context and obtain the SPNEGO token. ---
	// For a standard one-shot HTTP Negotiate flow only a single call to
	// gss_init_sec_context is needed (the server accepts the first token).
	// We request mutual authentication (GSS_C_MUTUAL_FLAG = 2) and sequence
	// checking (GSS_C_SEQUENCE_FLAG = 8) to match curl --negotiate behaviour.
	var ctxHandle uintptr
	var outputToken gssBufferDesc
	var retFlags, timeRec uint32
	var actualMech uintptr

	major = gssInitSecContext(
		&minor,
		gssNoCredential,     // use default credential (from credential store)
		&ctxHandle,          // output context handle (we'll delete it after)
		targetName,          // service name imported above
		&spnegoOID,          // request SPNEGO wrapping
		2|8,                 // GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG
		gssTimeIndefinite,   // no time limit
		gssNoChannelBinding, // no channel bindings
		gssNoInputToken,     // no input token on first call
		&actualMech,         // actual mechanism (ignored)
		&outputToken,        // receives the SPNEGO token bytes
		&retFlags,           // returned flags (ignored)
		&timeRec,            // returned time (ignored)
	)

	// Clean up the context handle regardless of outcome.
	if ctxHandle != gssNoContext {
		gssDeleteSecContext(&minor, &ctxHandle, nil)
	}

	if major != gssComplete && major != gssContinue {
		return nil, fmt.Errorf("negotiate: gss_init_sec_context failed: major=0x%08x minor=0x%08x", major, minor)
	}

	// --- Step 3: Copy the token bytes from C memory, then release the buffer. ---
	if outputToken.length == 0 || outputToken.value == nil {
		return nil, fmt.Errorf("negotiate: gss_init_sec_context returned empty token")
	}
	tokenBytes := make([]byte, outputToken.length)
	copy(tokenBytes, unsafe.Slice((*byte)(outputToken.value), outputToken.length))
	gssReleaseBuffer(&minor, &outputToken)

	return tokenBytes, nil
}
