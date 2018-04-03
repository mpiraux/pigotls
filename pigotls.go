package pigotls

/*
#cgo LDFLAGS: ${SRCDIR}/picotls/libpicotls-core.a ${SRCDIR}/picotls/libpicotls-openssl.a -lssl -lcrypto
#include <stdlib.h>
#include <stddef.h>
#include <picotls/include/picotls/openssl.h>
#include <picotls/include/picotls.h>


void init_ctx(ptls_context_t *ctx) {
	ctx->random_bytes = ptls_openssl_random_bytes;
	ctx->key_exchanges = ptls_openssl_key_exchanges;
	ctx->cipher_suites = ptls_openssl_cipher_suites;
	ctx->get_time = &ptls_get_time;
}

void set_handshake_properties(ptls_handshake_properties_t *props, ptls_iovec_t *alpn) {
	props->client.negotiated_protocols.count = 1;
	props->client.negotiated_protocols.list = alpn;
}

void set_extension_data(ptls_handshake_properties_t *props, uint16_t type, ptls_iovec_t data) {
	ptls_raw_extension_t *extensions = (ptls_raw_extension_t*)malloc(sizeof(ptls_raw_extension_t)*2);
	extensions[0].type = type;
	extensions[0].data = data;

	extensions[1].type = 0xffff;
	extensions[1].data.base = NULL;
	extensions[1].data.len = 0;

	props->additional_extensions = extensions;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)
const (
	QuicTransportParametersTLSExtension = 26
)

type Error struct {
	errorCode int
}

func (e Error) Error() string {
	return fmt.Sprintf("picotls error code %d", e.errorCode)
}

type Context struct {
	ctx                 *C.ptls_context_t
	handshakeProperties *C.ptls_handshake_properties_t
}

func NewContext(ALPN string) Context {
	var ctx C.ptls_context_t
	var handshakeProperties C.ptls_handshake_properties_t
	c := Context{&ctx, &handshakeProperties}

	C.init_ctx(&ctx)

	alpnVec := toIOVec([]byte(ALPN))
	C.set_handshake_properties(c.handshakeProperties, &alpnVec)

	return c
}
func (c Context) InitializeCertificateVerifier() {
	var verifier C.ptls_openssl_verify_certificate_t
	C.ptls_openssl_init_verify_certificate(&verifier, nil)
	c.ctx.verify_certificate = (*C.ptls_verify_certificate_t)(unsafe.Pointer(&verifier))
}
func (c Context) SetQUICTransportParameters(extensionData []byte) {
	C.set_extension_data(c.handshakeProperties, QuicTransportParametersTLSExtension, toIOVec(extensionData))
}

type Connection struct {
	Context
	tls *C.ptls_t
}

func NewConnection(serverName string, ALPN string) *Connection {
	c := new(Connection)
	c.Context = NewContext(ALPN)
	c.tls = C.ptls_new(c.Context.ctx, 0)
	C.ptls_set_server_name(c.tls, C.CString(serverName), sizeofString(serverName))
	return c
}
func (c *Connection) InitiateHandshake() ([]byte, bool, error) {
	return c.Handshake(nil)
}
// Uses data received and returns data to be sent to the peer as well as a boolean indicating if the handshake should continue
func (c *Connection) Handshake(data []byte) ([]byte, bool, error) {
	var sendbuf C.ptls_buffer_t
	C.ptls_buffer_init(&sendbuf, unsafe.Pointer(C.CString("")), 0)
	defer C.ptls_buffer_dispose(&sendbuf)

	var ret C.int
	if data == nil {
		ret = C.ptls_handshake(c.tls, &sendbuf, nil, nil, c.Context.handshakeProperties)
	} else {
		recbuf := C.CBytes(data)
		defer C.free(recbuf)
		rec_size := sizeofBytes(data)

		ret = C.ptls_handshake(c.tls, &sendbuf, recbuf, &rec_size, c.Context.handshakeProperties)
	}

	if ret != 0 && ret != C.PTLS_ERROR_IN_PROGRESS {
		return nil, false, Error{int(ret)}
	}

	return toSlice(sendbuf), ret != 0, nil
}
func (c *Connection) Close() {
	C.ptls_free(c.tls)
}

func toSlice(buf C.ptls_buffer_t) []byte {
	return C.GoBytes(unsafe.Pointer(buf.base), C.int(buf.off))
}
func toIOVec(data []byte) C.ptls_iovec_t {
	return C.ptls_iovec_init(C.CBytes(data), sizeofBytes(data))
}
func sizeofString(s string) C.size_t {return (C.size_t)(len(s))}
func sizeofBytes(b []byte) C.size_t {return (C.size_t)(len(b))}