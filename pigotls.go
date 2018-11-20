package pigotls

/*
#cgo LDFLAGS: ${SRCDIR}/picotls/libpicotls-core.a ${SRCDIR}/picotls/libpicotls-openssl.a -lssl -lcrypto
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <picotls/include/picotls.h>
#include <picotls/include/picotls/openssl.h>

#define QUIC_TP_EXTENSION  0xffa5

int collect_quic_extension(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type) {
	return type == QUIC_TP_EXTENSION;  // Only collect QUIC extensions
}

int collected_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions) {
	if(extensions->type == QUIC_TP_EXTENSION) {
		ptls_raw_extension_t *rec_ext = properties->additional_extensions + 1;
		rec_ext->type = extensions->type;
		rec_ext->data.base = (uint8_t*)malloc(extensions->data.len);
		rec_ext->data.len = extensions->data.len;
		memcpy(rec_ext->data.base, extensions->data.base, extensions->data.len);
	}
	return 0;
}

void init_ctx(ptls_context_t *ctx) {
	ctx->hkdf_label_prefix = "quic ";
	ctx->random_bytes = ptls_openssl_random_bytes;
	ctx->key_exchanges = ptls_openssl_key_exchanges;
	ctx->cipher_suites = ptls_openssl_cipher_suites;
	ctx->get_time = &ptls_get_time;
	ctx->omit_end_of_early_data = true;
}

void set_handshake_properties(ptls_handshake_properties_t *props, ptls_iovec_t *alpn, ptls_iovec_t *session_ticket, size_t *max_early_data) {
	props->client.negotiated_protocols.count = 1;
	props->client.negotiated_protocols.list = alpn;
	props->collect_extension = collect_quic_extension;
	props->collected_extensions = collected_extensions;
	if (session_ticket != NULL && session_ticket->base != NULL) {
		props->client.session_ticket = *session_ticket;
		props->client.max_early_data_size = max_early_data;
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

int cb_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src) {
	ptls_iovec_t *receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_save_ticket_t));
	receiver->base = malloc(src.len);
	memcpy(receiver->base, src.base, src.len);
	receiver->len = src.len;
	return 0;
}

void set_ticket_cb(ptls_context_t *ctx, ptls_iovec_t *receiver) {
	ptls_save_ticket_t* save_ticket = malloc(sizeof(ptls_save_ticket_t) + sizeof(ptls_iovec_t*));
	save_ticket->cb = cb_ticket;
	ptls_iovec_t** ppreceiver = (ptls_iovec_t**)(((char*)save_ticket) + sizeof(ptls_save_ticket_t));
	*ppreceiver = receiver;
	ctx->save_ticket = save_ticket;
}

void cb_secret(struct st_ptls_log_secret_t *self, ptls_t *tls, const char *label, ptls_iovec_t secret) {
	ptls_iovec_t *receiver = NULL;
	if (strcmp(label, "EXPORTER_SECRET") == 0) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_log_secret_t));
	} else if (strcmp(label, "EARLY_EXPORTER_SECRET") == 0) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_log_secret_t) + sizeof(ptls_iovec_t*));
	}
	if (receiver != NULL) {
		receiver->base = malloc(secret.len);
		memcpy(receiver->base, secret.base, secret.len);
		receiver->len = secret.len;
	}
}

void set_secret_cb(ptls_context_t *ctx, ptls_iovec_t *exporter_receiver, ptls_iovec_t *early_exporter_receiver) {
	ptls_log_secret_t* save_secret = malloc(sizeof(ptls_log_secret_t) + (sizeof(ptls_iovec_t*) * 2));
	save_secret->cb = cb_secret;
	ptls_iovec_t** ppreceiver = (ptls_iovec_t**)(((char*)save_secret) + sizeof(ptls_log_secret_t));
	*ppreceiver = exporter_receiver;
	ppreceiver = (ptls_iovec_t**)(((char*)save_secret) + sizeof(ptls_log_secret_t) + sizeof(ptls_iovec_t*));
	*ppreceiver = early_exporter_receiver;
	ctx->log_secret = save_secret;
}

int cb_traffic_secret(struct st_ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch, const void *secret) {
	ptls_iovec_t *receiver = NULL;

	ptls_hash_algorithm_t* hash = NULL;
	ptls_cipher_suite_t* cipher = ptls_get_cipher(tls);
	if (cipher == NULL) {
		hash = &ptls_openssl_sha256;
	} else {
		hash = cipher->hash;
	}
	size_t secret_len = hash->digest_size;

	if (epoch == 1 && is_enc == 1) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_update_traffic_key_t));
	} else if (epoch == 2 && is_enc == 0) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_update_traffic_key_t) + sizeof(ptls_iovec_t*));
	} else if (epoch == 2 && is_enc == 1) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*) * 2));
	} else if (epoch == 3 && is_enc == 0) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*) * 3));
	} else if (epoch == 3 && is_enc == 1) {
		receiver = *(ptls_iovec_t**) (((char*)self) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*) * 4));
	}

	if (receiver != NULL) {
		receiver->base = malloc(secret_len);
		memcpy(receiver->base, secret, secret_len);
		receiver->len = secret_len;
	}
	return 0;
}

void set_traffic_secret_cb(ptls_context_t *ctx, ptls_iovec_t *zero_rtt, ptls_iovec_t *hs_dec, ptls_iovec_t *hs_enc, ptls_iovec_t *ap_dec, ptls_iovec_t *ap_enc) {
	ptls_update_traffic_key_t* update_secret = malloc(sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*) * 5));
	update_secret->cb = cb_traffic_secret;
	ptls_iovec_t** ppreceiver = (ptls_iovec_t**)(((char*)update_secret) + sizeof(ptls_update_traffic_key_t));
	*ppreceiver = zero_rtt;
	ppreceiver = (ptls_iovec_t**)(((char*)update_secret) + sizeof(ptls_update_traffic_key_t) + sizeof(ptls_iovec_t*));
	*ppreceiver = hs_dec;
	ppreceiver = (ptls_iovec_t**)(((char*)update_secret) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*)*2));
	*ppreceiver = hs_enc;
	ppreceiver = (ptls_iovec_t**)(((char*)update_secret) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*)*3));
	*ppreceiver = ap_dec;
	ppreceiver = (ptls_iovec_t**)(((char*)update_secret) + sizeof(ptls_update_traffic_key_t) + (sizeof(ptls_iovec_t*)*4));
	*ppreceiver = ap_enc;
	ctx->update_traffic_key = update_secret;
}

ptls_cipher_suite_t *find_cipher_suite(ptls_context_t *ctx, uint16_t id)
{
    ptls_cipher_suite_t **cs;

    for (cs = ctx->cipher_suites; *cs != NULL && (*cs)->id != id; ++cs)
        ;
    return *cs;
}

void restrict_cipher_suite(ptls_context_t *ctx, ptls_cipher_suite_t *cs) {
	*ctx->cipher_suites = cs;
	*(ctx->cipher_suites + 1) = NULL;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	QuicTransportParametersTLSExtension = 0xffa5
	QuicBaseLabel                       = "quic "
	CS_AES_128_GCM_SHA256            = uint16(0x1301)
	CS_AES_256_GCM_SHA384            = uint16(0x1302)
	CS_CHACHA20_POLY1305_SHA256      = uint16(0x1303)
)

var quicBaseLabelC = C.CString(QuicBaseLabel)

type Epoch int

const (
	EpochInitial   Epoch = 0
	Epoch0RTT            = 1
	EpochHandshake       = 2
	Epoch1RTT            = 3
)

var Epochs = []Epoch{EpochInitial, Epoch0RTT, EpochHandshake, Epoch1RTT}

type Error struct {
	errorCode int
}

func (e Error) Error() string {
	return fmt.Sprintf("picotls error code %d", e.errorCode)
}

type Message struct {
	Data  []byte
	Epoch Epoch
}

type Context struct {
	ctx                 *C.ptls_context_t
	handshakeProperties *C.ptls_handshake_properties_t
	savedTicket         *C.ptls_iovec_t
	exporterSecret      *C.ptls_iovec_t
	earlyExporterSecret *C.ptls_iovec_t
	maxEarlyData 		*C.size_t

	zeroRTTSecret *C.ptls_iovec_t
	hsReadSecret  *C.ptls_iovec_t
	hsWriteSecret *C.ptls_iovec_t
	apReadSecret  *C.ptls_iovec_t
	apWriteSecret *C.ptls_iovec_t
}

func NewContext(ALPN string, resumptionTicket []byte) Context {
	var ctx C.ptls_context_t
	var handshakeProperties C.ptls_handshake_properties_t
	var savedTicket C.ptls_iovec_t
	var exporterSecret C.ptls_iovec_t
	var earlyExporterSecret C.ptls_iovec_t
	var maxEarlyData C.size_t

	var zeroRTTSecret C.ptls_iovec_t
	var hsReadSecret  C.ptls_iovec_t
	var hsWriteSecret C.ptls_iovec_t
	var apReadSecret  C.ptls_iovec_t
	var apWriteSecret C.ptls_iovec_t


	c := Context{
		ctx: &ctx,
		handshakeProperties: &handshakeProperties,
		savedTicket: &savedTicket,
		exporterSecret: &exporterSecret,
		earlyExporterSecret: &earlyExporterSecret,
		maxEarlyData: &maxEarlyData,

		zeroRTTSecret: &zeroRTTSecret,
		hsReadSecret: &hsReadSecret,
		hsWriteSecret: &hsWriteSecret,
		apReadSecret: &apReadSecret,
		apWriteSecret: &apWriteSecret,
	}

	C.init_ctx(&ctx)

	alpnVec := toIOVec([]byte(ALPN))
	resumptionTicketVec := toIOVec(resumptionTicket)
	C.set_handshake_properties(c.handshakeProperties, &alpnVec, &resumptionTicketVec, c.maxEarlyData)
	C.set_ticket_cb(c.ctx, c.savedTicket)
	C.set_secret_cb(c.ctx, c.exporterSecret, c.earlyExporterSecret)
	C.set_traffic_secret_cb(c.ctx, c.zeroRTTSecret, c.hsReadSecret, c.hsWriteSecret, c.apReadSecret, c.apWriteSecret)

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
func (c Context) ReceivedQUICTransportParameters() []byte {
	extension := C.get_extension_data(c.handshakeProperties, 1)
	if extension._type == QuicTransportParametersTLSExtension {
		return ioVecToSlice(extension.data)
	}
	return nil
}
func (c Context) RestrictCipherSuite(csID uint16) {
	C.restrict_cipher_suite(c.ctx, C.find_cipher_suite(c.ctx, C.ushort(csID)))
}
func (c Context) ResumptionTicket() []byte {
	return ioVecToSlice(*c.savedTicket)
}
func (c Context) ExporterSecret() []byte {
	return ioVecToSlice(*c.exporterSecret)
}
func (c Context) EarlyExporterSecret() []byte {
	return ioVecToSlice(*c.earlyExporterSecret)
}
func (c Context) ZeroRTTSecret() []byte {
	return ioVecToSlice(*c.zeroRTTSecret)
}
func (c Context) HandshakeReadSecret() []byte {
	return ioVecToSlice(*c.hsReadSecret)
}
func (c Context) HandshakeWriteSecret() []byte {
	return ioVecToSlice(*c.hsWriteSecret)
}
func (c Context) ProtectedReadSecret() []byte {
	return ioVecToSlice(*c.apReadSecret)
}
func (c Context) ProtectedWriteSecret() []byte {
	return ioVecToSlice(*c.apWriteSecret)
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

func (c *Connection) HandleMessage(data []byte, epoch Epoch) ([]Message, bool, error) {
	var sendbuf C.ptls_buffer_t
	C.ptls_buffer_init(&sendbuf, unsafe.Pointer(C.CString("")), 0)
	defer C.ptls_buffer_dispose(&sendbuf)

	var recbuf unsafe.Pointer = nil
	var inputLen C.size_t

	if data != nil {
		recbuf = C.CBytes(data)
		defer C.free(recbuf)
		inputLen = sizeofBytes(data)
	}

	var epoch_offsets [5]C.size_t
	ret := C.ptls_handle_message(c.tls, &sendbuf, (*C.size_t)(unsafe.Pointer(&epoch_offsets)), C.size_t(epoch), recbuf, inputLen, c.Context.handshakeProperties)

	retBuf := bufToSlice(sendbuf)
	var messages []Message

	for i, e := range Epochs {
		if epoch_offsets[i+1] > epoch_offsets[i] {
			messages = append(messages, Message{retBuf[epoch_offsets[i]:epoch_offsets[i+1]], e})
		}
	}

	if ret != 0 && ret != C.PTLS_ERROR_IN_PROGRESS {
		return nil, false, Error{int(ret)}
	}

	return messages, ret != 0, nil
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
func (c *Connection) ClientRandom() []byte {
	return ioVecToSlice(C.ptls_get_client_random(c.tls))
}

type Cipher C.ptls_cipher_context_t
func (c *Connection) NewCipher(key []byte) *Cipher {  // Creates a new symmetric cipher based on the CTR cipher used for AEAD
	return (*Cipher)(C.ptls_cipher_new(c.aead().ctr_cipher, C.int(0), unsafe.Pointer(&key[0])))
}
func (c *Cipher) Encrypt(iv []byte, data []byte) []byte {
	var output [256]byte
	C.ptls_cipher_init((*C.ptls_cipher_context_t)(unsafe.Pointer(c)), unsafe.Pointer(&iv[0]))
	C.ptls_cipher_encrypt((*C.ptls_cipher_context_t)(unsafe.Pointer(c)), unsafe.Pointer(&output),  unsafe.Pointer(&data[0]), sizeofBytes(data))
	return output[:len(data)]
}

type AEAD C.ptls_aead_context_t
func (c *Connection) NewAEAD(key []byte, encryption bool) *AEAD {
	var enc C.int
	if encryption {
		enc = 1
	}
	return (*AEAD)(C.ptls_aead_new(c.aead(), c.hash(), enc, unsafe.Pointer(&key[0]), quicBaseLabelC))
}
func (c *AEAD) Encrypt(cleartext []byte, seq uint64, aad []byte) []byte {
	ciphertext := make([]byte, len(cleartext) + c.Overhead())
	ret := C.ptls_aead_encrypt((*C.ptls_aead_context_t)(unsafe.Pointer(c)), unsafe.Pointer(&ciphertext[0]), unsafe.Pointer(&cleartext[0]), C.size_t(len(cleartext)), C.ulong(seq), unsafe.Pointer(&aad[0]), C.size_t(len(aad)))
	return ciphertext[:ret]
}
func (c *AEAD) Decrypt(ciphertext []byte, seq uint64, aad []byte) []byte {
	cleartext := make([]byte, len(ciphertext) - c.Overhead())
	ret := C.ptls_aead_decrypt((*C.ptls_aead_context_t)(unsafe.Pointer(c)), unsafe.Pointer(&cleartext[0]), unsafe.Pointer(&ciphertext[0]), C.size_t(len(ciphertext)), C.ulong(seq), unsafe.Pointer(&aad[0]), C.size_t(len(aad)))
	if ret == C.SIZE_MAX {
		return nil
	}
	return cleartext[:ret]
}
func (c *AEAD) Overhead() int {
	return int(c.algo.tag_size)
}

func bufToSlice(buf C.ptls_buffer_t) []byte  { return C.GoBytes(unsafe.Pointer(buf.base), C.int(buf.off)) }
func ioVecToSlice(vec C.ptls_iovec_t) []byte { return C.GoBytes(unsafe.Pointer(vec.base), C.int(vec.len)) }
func toIOVec(data []byte) C.ptls_iovec_t     { if data != nil { return C.ptls_iovec_init(C.CBytes(data), sizeofBytes(data)) }; return C.ptls_iovec_init(nil, 0) }
func sizeofString(s string) C.size_t         { return (C.size_t)(len(s)) }
func sizeofBytes(b []byte) C.size_t          { return (C.size_t)(len(b)) }
