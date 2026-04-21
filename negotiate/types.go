package negotiate

import "unsafe"

// gssBufferDesc mirrors gss_buffer_desc: { size_t length; void *value; }
// Both fields are word-sized on all supported 64-bit platforms.
// For input buffers, value points into Go-managed memory; keep the source
// string alive for the GSSAPI call duration. For output buffers the framework
// allocates the memory; copy the bytes then call gss_release_buffer.
type gssBufferDesc struct {
	length uintptr
	value  unsafe.Pointer
}

// gssOIDDesc mirrors gss_OID_desc: { OM_uint32 length; void *elements; }
type gssOIDDesc struct {
	length   uint32
	elements unsafe.Pointer
}

// spnegoOIDBytes is the DER encoding of the SPNEGO OID 1.3.6.1.5.5.2 (RFC 4178).
// Passed as mech_type to gss_init_sec_context to request SPNEGO wrapping.
var spnegoOIDBytes = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

// hostBasedServiceOIDBytes is the DER encoding of GSS_C_NT_HOSTBASED_SERVICE
// OID 1.3.6.1.5.6.2 (RFC 2744). Used as name_type in gss_import_name to
// indicate "service@host" format; the framework maps this to "service/host".
var hostBasedServiceOIDBytes = []byte{0x2b, 0x06, 0x01, 0x05, 0x06, 0x02}

// spnegoOID and hostBasedServiceOID are ready-to-pass gssOIDDesc values
// pointing into package-level byte slices that will never be GC-collected.
var (
	spnegoOID = gssOIDDesc{
		length:   uint32(len(spnegoOIDBytes)),
		elements: unsafe.Pointer(&spnegoOIDBytes[0]),
	}
	hostBasedServiceOID = gssOIDDesc{
		length:   uint32(len(hostBasedServiceOIDBytes)),
		elements: unsafe.Pointer(&hostBasedServiceOIDBytes[0]),
	}
)

// GSSAPI major status codes.
const (
	gssComplete = uint32(0) // GSS_S_COMPLETE
	gssContinue = uint32(1) // GSS_S_CONTINUE_NEEDED
)

// Sentinel values (GSS_C_NO_xxx constants).
const (
	gssNoCredential     = uintptr(0) // GSS_C_NO_CREDENTIAL
	gssNoContext        = uintptr(0) // GSS_C_NO_CONTEXT
	gssNoChannelBinding = uintptr(0) // GSS_C_NO_CHANNEL_BINDINGS
	gssTimeIndefinite   = uint32(0)  // GSS_C_INDEFINITE
)

// gssNoInputToken is a nil *gssBufferDesc (GSS_C_NO_BUFFER) for the first
// call to gss_init_sec_context.
var gssNoInputToken *gssBufferDesc
