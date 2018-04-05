package pigotls

/*
#cgo LDFLAGS: ${SRCDIR}/picotls/libpicotls-core.a ${SRCDIR}/picotls/libpicotls-openssl.a -lssl -lcrypto
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <picotls/include/picotls/openssl.h>
#include <picotls/include/picotls.h>

#define QUIC_TP_EXTENSION  26

int collect_quic_extension(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type) {
	return type == QUIC_TP_EXTENSION;  // Only collect QUIC extensions
}

int collected_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions) {
	while(extensions->type != 0xffff) {
		if(extensions->type == QUIC_TP_EXTENSION) {
			ptls_raw_extension_t *rec_ext = properties->additional_extensions + 1;
			rec_ext->type = extensions->type;
			rec_ext->data.base = (uint8_t*)malloc(extensions->data.len);
			rec_ext->data.len = extensions->data.len;
			memcpy(rec_ext->data.base, extensions->data.base, extensions->data.len);
			break;
		}
	}
	return 0;
}

void init_ctx(ptls_context_t *ctx) {
	ctx->random_bytes = ptls_openssl_random_bytes;
	ctx->key_exchanges = ptls_openssl_key_exchanges;
	ctx->cipher_suites = ptls_openssl_cipher_suites;
	ctx->get_time = &ptls_get_time;
}

void set_handshake_properties(ptls_handshake_properties_t *props, ptls_iovec_t *alpn, ptls_iovec_t *session_ticket) {
	props->client.negotiated_protocols.count = 1;
	props->client.negotiated_protocols.list = alpn;
	props->collect_extension = collect_quic_extension;
	props->collected_extensions = collected_extensions;
	if (session_ticket != NULL && session_ticket->base != NULL) {
		props->client.session_ticket = *session_ticket;
	}
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

ptls_raw_extension_t get_extension_data(ptls_handshake_properties_t *props, int index) {
	return props->additional_extensions[index];
}

int cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src) {
	ptls_iovec_t *receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_save_ticket_t));
	receiver->base = malloc(src.len);
	memcpy(receiver->base, src.base, src.len);
	receiver->len = src.len;
	return 0;
}

void set_ticket_cb(ptls_context_t *ctx, ptls_iovec_t *receiver) {
	ptls_save_ticket_t* save_ticket = malloc(sizeof(ptls_save_ticket_t) + sizeof(ptls_iovec_t*));
	save_ticket->cb = cb;
	ptls_iovec_t** ppreceiver = (ptls_iovec_t**)(((char*)save_ticket) + sizeof(ptls_save_ticket_t));
	*ppreceiver = receiver;
	ctx->save_ticket = save_ticket;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	QuicTransportParametersTLSExtension = 26
	QuicBaseLabel                       = "QUIC "
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
	savedTicket 		*C.ptls_iovec_t
}

func NewContext(ALPN string, resumptionTicket []byte) Context {
	var ctx C.ptls_context_t
	var handshakeProperties C.ptls_handshake_properties_t
	var savedTicket C.ptls_iovec_t
	c := Context{&ctx, &handshakeProperties, &savedTicket}

	C.init_ctx(&ctx)

	alpnVec := toIOVec([]byte(ALPN))
	resumptionTicketVec := toIOVec(resumptionTicket)
	C.set_handshake_properties(c.handshakeProperties, &alpnVec, &resumptionTicketVec)
	C.set_ticket_cb(c.ctx, c.savedTicket)

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
func (c Context) GetReceivedQUICTransportParameters() []byte {
	extension := C.get_extension_data(c.handshakeProperties, 1)
	if extension._type == QuicTransportParametersTLSExtension {
		return ioVecToSlice(extension.data)
	}
	return nil
}
func (c Context) GetResumptionTicket() []byte {
	return ioVecToSlice(*c.savedTicket)
}
type Connection struct {
	Context
	tls *C.ptls_t
	closed bool
}

func NewConnection(serverName string, ALPN string, resumptionTicket []byte) *Connection {
	c := new(Connection)
	c.Context = NewContext(ALPN, resumptionTicket)
	c.tls = C.ptls_new(c.Context.ctx, 0)
	C.ptls_set_server_name(c.tls, C.CString(serverName), sizeofString(serverName))
	return c
}
func (c *Connection) InitiateHandshake() ([]byte, bool, error) {
	var sendbuf C.ptls_buffer_t
	C.ptls_buffer_init(&sendbuf, unsafe.Pointer(C.CString("")), 0)
	defer C.ptls_buffer_dispose(&sendbuf)

	ret := C.int(0)
	ret = C.ptls_handshake(c.tls, &sendbuf, nil, nil, c.Context.handshakeProperties)
	if ret != 0 && ret != C.PTLS_ERROR_IN_PROGRESS {
		return nil, false, Error{int(ret)}
	}

	return bufToSlice(sendbuf), ret != 0, nil
}

// Uses data received and returns data to be sent to the peer as well as a boolean indicating if the handshake should continue
func (c *Connection) Input(data []byte) ([]byte, bool, error) {
	var sendbuf C.ptls_buffer_t
	C.ptls_buffer_init(&sendbuf, unsafe.Pointer(C.CString("")), 0)
	defer C.ptls_buffer_dispose(&sendbuf)

	roff := (C.size_t)(0)
	inputLen := (C.size_t)(0)
	ret := C.int(0)
	for (roff < (C.size_t)(len(data))) && (ret == 0 || ret == C.PTLS_ERROR_IN_PROGRESS) {
		recbuf := C.CBytes(data[roff:])
		defer C.free(recbuf)
		inputLen = sizeofBytes(data[roff:])

		if C.ptls_handshake_is_complete(c.tls) == 0 {
			ret = C.ptls_handshake(c.tls, &sendbuf, recbuf, &inputLen, c.Context.handshakeProperties)
		} else {
			ret = C.ptls_receive(c.tls, &sendbuf, recbuf, &inputLen)
		}
		roff += inputLen
	}

	if ret != 0 && ret != C.PTLS_ERROR_IN_PROGRESS {
		return nil, false, Error{int(ret)}
	}

	return bufToSlice(sendbuf), ret != 0, nil
}
func (c *Connection) hash() *C.ptls_hash_algorithm_t {
	cipherSuite := C.ptls_get_cipher(c.tls)
	if cipherSuite == nil {
		return &C.ptls_openssl_sha256
	}
	return cipherSuite.hash
}
func (c *Connection) aead() *C.ptls_aead_algorithm_t {
	cipherSuite := C.ptls_get_cipher(c.tls)
	if cipherSuite == nil {
		return &C.ptls_openssl_aes128gcm
	}
	return cipherSuite.aead
}
func (c *Connection) HashDigestSize() int {
	return int(c.hash().digest_size)
}
func (c *Connection) AEADKeySize() int {
	return int(c.aead().key_size)
}
func (c *Connection) AEADIvSize() int {
	return int(c.aead().iv_size)
}
func (c *Connection) HkdfExtract(saltIn, input []byte) []byte {
	var output [256]byte
	C.ptls_hkdf_extract(c.hash(), unsafe.Pointer(&output), toIOVec(saltIn), toIOVec(input))
	return output[:c.hash().digest_size]
}

func (c *Connection) HkdfExpand(prk, info []byte, length int) []byte {
	var output [256]byte
	C.ptls_hkdf_expand(c.hash(), unsafe.Pointer(&output), (C.size_t)(length), toIOVec(prk), toIOVec(info))
	return output[:length]
}

func (c *Connection) HkdfExpandLabel(secret []byte, label string, hashValue []byte, length int) []byte {
	var output [256]byte
	C.ptls_hkdf_expand_label(c.hash(), unsafe.Pointer(&output), (C.size_t)(length), toIOVec(secret),
		C.CString(label), toIOVec(hashValue), C.CString(QuicBaseLabel))
	return output[:length]
}
func (c *Connection) ExportSecret(label string, context []byte, isEarly bool) ([]byte, error) {
	var output [256]byte
	zeroRtt := 0
	if isEarly {
		zeroRtt = 1
	}

	err := C.ptls_export_secret(c.tls, unsafe.Pointer(&output), (C.size_t)(c.HashDigestSize()), C.CString(label), toIOVec(context), C.int(zeroRtt))
	if err != 0 {
		return nil, Error{int(err)}
	}

	return output[:c.HashDigestSize()], nil
}
func (c *Connection) Close() {
	if !c.closed {
		C.ptls_free(c.tls)
		c.closed = true
	}
}

func bufToSlice(buf C.ptls_buffer_t) []byte  { return C.GoBytes(unsafe.Pointer(buf.base), C.int(buf.off)) }
func ioVecToSlice(vec C.ptls_iovec_t) []byte { return C.GoBytes(unsafe.Pointer(vec.base), C.int(vec.len)) }
func toIOVec(data []byte) C.ptls_iovec_t     { if data != nil { return C.ptls_iovec_init(C.CBytes(data), sizeofBytes(data)) }; return C.ptls_iovec_init(nil, 0) }
func sizeofString(s string) C.size_t         { return (C.size_t)(len(s)) }
func sizeofBytes(b []byte) C.size_t          { return (C.size_t)(len(b)) }
