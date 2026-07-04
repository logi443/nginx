#!/usr/bin/env bash
#
#  morgon-setup : one installer for the whole stack
#    - Tunnel (morgontun) : install on IRAN (client) and ABROAD (server)
#    - DPI desync (zapret) : Iran side only
#
#  Self-contained: the morgontun source is embedded below and built on the box.
#  Only needs internet for Go + zapret. Run as root.
#
#  BY MEYSAM  (github.com/morgondev)
#
set -euo pipefail

# ---- morgontun paths ----
BIN="/usr/local/bin/morgontun"
CONF_DIR="/etc/morgontun"
CLIENT_ENV="${CONF_DIR}/client.env"
SERVER_ENV="${CONF_DIR}/server.env"
CLIENT_UNIT="/etc/systemd/system/morgontun-client.service"
SERVER_UNIT="/etc/systemd/system/morgontun-server.service"

# ---- zapret paths ----
ZREPO="https://github.com/bol-van/zapret.git"
ZDIR="/opt/zapret"
ZCONF="/etc/zapret-iran.conf"
ZFW="/usr/local/sbin/zapret-iran-fw.sh"
ZUNIT="/etc/systemd/system/zapret-iran.service"
QNUM=200
Z_DEF_OPT="--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=8 --dpi-desync-fooling=badseq,md5sig --dpi-desync-fake-tls=${ZDIR}/files/fake/tls_clienthello_iana_org.bin"

C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_C="\033[1;36m"; C_0="\033[0m"

banner() {
cat <<'EOF'
  __  __  ___  ____   ____  ___  _   _
 |  \/  |/ _ \|  _ \ / ___|/ _ \| \ | |
 | |\/| | | | | |_) | |  _| | | |  \| |
 | |  | | |_| |  _ <| |_| | |_| | |\  |
 |_|  |_|\___/|_| \_\\____|\___/|_| \_|
   tunnel + DPI desync setup  |  BY MEYSAM
EOF
}

msg()  { echo -e "${C_C}[*]${C_0} $*"; }
ok()   { echo -e "${C_G}[+]${C_0} $*"; }
warn() { echo -e "${C_Y}[!]${C_0} $*"; }
err()  { echo -e "${C_R}[-]${C_0} $*" >&2; }

need_root() { [[ "${EUID}" -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }; }

ask() {
  local __v="$1" __p="$2" __d="${3:-}" __i
  if [[ -n "${__d}" ]]; then
    read -rp "$(echo -e "${C_Y}?${C_0} ${__p} [${__d}]: ")" __i; __i="${__i:-${__d}}"
  else
    while :; do read -rp "$(echo -e "${C_Y}?${C_0} ${__p}: ")" __i; [[ -n "${__i}" ]] && break; warn "Required."; done
  fi
  printf -v "${__v}" '%s' "${__i}"
}

# like ask, but allows an empty answer (for optional fields)
ask_opt() {
  local __v="$1" __p="$2" __i
  read -rp "$(echo -e "${C_Y}?${C_0} ${__p}: ")" __i
  printf -v "${__v}" '%s' "${__i}"
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
gen_key() { command -v openssl >/dev/null 2>&1 && openssl rand -hex 16 || head -c16 /dev/urandom | xxd -p; }
detect_wan() { ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}'; }

ensure_go() {
  command -v go >/dev/null 2>&1 && return
  msg "Installing Go toolchain ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq golang-go
}

# build morgontun from the embedded source below
build_morgontun() {
  if [[ -x "${BIN}" ]]; then ok "morgontun already installed at ${BIN}"; return; fi
  ensure_go
  local D; D="$(mktemp -d)"
  cat > "${D}/morgontun.go" <<'GOEOF'
// morgontun - a DPI-evading TCP tunnel.
//
// It combines several proven anti-DPI techniques into one wire protocol:
//   1. TLS-record mimicry     -> on the wire every packet looks like a normal
//                                TLS 1.3 session (ClientHello / ServerHello,
//                                then 0x17 0x03 0x03 application-data records).
//   2. PSK anti-probe auth    -> the fake ClientHello carries an HMAC token
//                                bound to a 1-minute time window, so active
//                                probers cannot trivially replay or fingerprint.
//   3. AEAD encryption        -> AES-256-GCM over an HKDF-derived session key;
//                                no plaintext protocol signature is ever exposed.
//   4. Length padding         -> each record is padded by a random amount so the
//                                underlying protocol's packet-size fingerprint
//                                is destroyed.
//   5. Reality-style fallback -> if a peer fails PSK auth (a probe / stranger),
//                                the server transparently relays it to a real
//                                website, so it looks like an ordinary HTTPS host.
//
// Pure Go standard library only. No external modules, no internet needed to
// build -> ideal for offline / Iran servers. Build once:
//
//   go build -ldflags="-s -w" -o morgontun morgontun.go
//
// BY MEYSAM  (github.com/morgondev)

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"time"
)

const (
	maxChunk  = 16000 // max plaintext bytes per record (keeps record < 16 KiB)
	maxPad    = 255   // max random padding bytes per record
	hsTimeout = 8 * time.Second
	info      = "morgontun/v1"
)

// ---------------------------------------------------------------------------
// crypto helpers (stdlib only)
// ---------------------------------------------------------------------------

// hkdf implements HKDF-SHA256 (RFC 5869) with hmac + sha256 only.
func hkdf(secret, salt, info []byte, length int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(secret)
	prk := h.Sum(nil)

	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// authToken binds clientRandom to a 1-minute window using the pre-shared key.
// Returned value is 32 bytes and is carried inside the fake session_id field.
func authToken(psk, clientRandom []byte, minute int64) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(clientRandom)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(minute))
	m.Write(b[:])
	return m.Sum(nil) // 32 bytes
}

func random32() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("rng: %v", err)
	}
	return b
}

func deriveKey(psk, clientRandom, serverRandom []byte) []byte {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)
	return hkdf(psk, salt, []byte(info), 32)
}

// ---------------------------------------------------------------------------
// secureConn: net.Conn that transparently encrypts + TLS-frames + pads
// ---------------------------------------------------------------------------

type secureConn struct {
	net.Conn
	aead     cipher.AEAD
	wPrefix  uint32
	rPrefix  uint32
	wCounter uint64
	rCounter uint64
	readBuf  []byte
}

func newSecureConn(c net.Conn, key []byte, wPrefix, rPrefix uint32) (*secureConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secureConn{Conn: c, aead: aead, wPrefix: wPrefix, rPrefix: rPrefix}, nil
}

func nonce(prefix uint32, counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], prefix)
	binary.BigEndian.PutUint64(n[4:12], counter)
	return n
}

func (c *secureConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = p[:maxChunk]
		}

		// random padding length
		var pb [1]byte
		rand.Read(pb[:])
		padLen := int(pb[0])

		// plaintext layout: [2-byte real len][real data][random pad]
		plain := make([]byte, 2+len(chunk)+padLen)
		binary.BigEndian.PutUint16(plain[0:2], uint16(len(chunk)))
		copy(plain[2:], chunk)
		rand.Read(plain[2+len(chunk):])

		sealed := c.aead.Seal(nil, nonce(c.wPrefix, c.wCounter), plain, nil)
		c.wCounter++

		// TLS application-data record header
		rec := make([]byte, 5+len(sealed))
		rec[0], rec[1], rec[2] = 0x17, 0x03, 0x03
		rec[3] = byte(len(sealed) >> 8)
		rec[4] = byte(len(sealed))
		copy(rec[5:], sealed)

		if _, err := c.Conn.Write(rec); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *secureConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, hdr); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, errors.New("morgontun: unexpected record type")
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n <= 0 || n > 17000 {
		return 0, errors.New("morgontun: bad record length")
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, sealed); err != nil {
		return 0, err
	}

	plain, err := c.aead.Open(nil, nonce(c.rPrefix, c.rCounter), sealed, nil)
	if err != nil {
		return 0, err
	}
	c.rCounter++

	if len(plain) < 2 {
		return 0, errors.New("morgontun: short plaintext")
	}
	realLen := int(binary.BigEndian.Uint16(plain[0:2]))
	if 2+realLen > len(plain) {
		return 0, errors.New("morgontun: length overflow")
	}
	data := plain[2 : 2+realLen]

	nn := copy(p, data)
	if nn < len(data) {
		c.readBuf = append(c.readBuf, data[nn:]...)
	}
	return nn, nil
}

func (c *secureConn) CloseWrite() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return c.Conn.Close()
}

// ---------------------------------------------------------------------------
// fake TLS handshake builders / parsers
// ---------------------------------------------------------------------------

func buildExtensions(sni string) []byte {
	ext := new(bytes.Buffer)

	// server_name (0x0000)
	name := []byte(sni)
	sn := new(bytes.Buffer)
	sn.Write([]byte{0x00, 0x00})                             // ext type
	body := new(bytes.Buffer)                                // ext body
	list := new(bytes.Buffer)                                // server name list
	list.WriteByte(0x00)                                     // name type host
	list.Write([]byte{byte(len(name) >> 8), byte(len(name))}) // name len
	list.Write(name)
	body.Write([]byte{byte(list.Len() >> 8), byte(list.Len())})
	body.Write(list.Bytes())
	sn.Write([]byte{byte(body.Len() >> 8), byte(body.Len())})
	sn.Write(body.Bytes())
	ext.Write(sn.Bytes())

	// supported_versions (0x002b) -> TLS 1.3 + 1.2
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03})

	// supported_groups (0x000a) -> x25519, secp256r1
	ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})

	return ext.Bytes()
}

func buildClientHello(clientRandom, sessionID []byte, sni string) []byte {
	ext := buildExtensions(sni)

	body := new(bytes.Buffer)
	body.Write([]byte{0x03, 0x03}) // legacy client version = TLS 1.2
	body.Write(clientRandom)       // 32 bytes
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	suites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2f, 0xc0, 0x30}
	body.Write([]byte{byte(len(suites) >> 8), byte(len(suites))})
	body.Write(suites)
	body.Write([]byte{0x01, 0x00}) // 1 compression method: null
	body.Write([]byte{byte(len(ext) >> 8), byte(len(ext))})
	body.Write(ext)

	return wrapHandshake(0x01, 0x0301, body.Bytes())
}

func buildServerHello(serverRandom, sessionID []byte) []byte {
	body := new(bytes.Buffer)
	body.Write([]byte{0x03, 0x03})
	body.Write(serverRandom)
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	body.Write([]byte{0x13, 0x01}) // chosen cipher suite
	body.WriteByte(0x00)           // compression: null
	ext := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04} // supported_versions: TLS 1.3
	body.Write([]byte{byte(len(ext) >> 8), byte(len(ext))})
	body.Write(ext)

	return wrapHandshake(0x02, 0x0303, body.Bytes())
}

// wrapHandshake wraps a handshake body in a handshake header and a TLS record.
func wrapHandshake(hsType byte, recVersion uint16, body []byte) []byte {
	hs := new(bytes.Buffer)
	hs.WriteByte(hsType)
	bl := len(body)
	hs.Write([]byte{byte(bl >> 16), byte(bl >> 8), byte(bl)})
	hs.Write(body)

	rec := new(bytes.Buffer)
	rec.WriteByte(0x16)
	rec.Write([]byte{byte(recVersion >> 8), byte(recVersion)})
	rl := hs.Len()
	rec.Write([]byte{byte(rl >> 8), byte(rl)})
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// readRecord reads exactly one TLS record (header + payload) into a buffer.
func readRecord(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n <= 0 || n > 65535 {
		return nil, errors.New("morgontun: bad handshake record length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// helloRandom returns the 32-byte random field of a ClientHello/ServerHello.
func helloRandom(rec []byte) ([]byte, bool) {
	if len(rec) < 43 {
		return nil, false
	}
	return rec[11:43], true
}

// clientAuth extracts clientRandom + session_id (auth token) from a ClientHello.
func clientAuth(rec []byte) (clientRandom, sessionID []byte, ok bool) {
	if len(rec) < 44 || rec[5] != 0x01 {
		return nil, nil, false
	}
	clientRandom = rec[11:43]
	sidLen := int(rec[43])
	if sidLen == 0 || 44+sidLen > len(rec) {
		return nil, nil, false
	}
	sessionID = rec[44 : 44+sidLen]
	return clientRandom, sessionID, true
}

// ---------------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------------

type halfCloser interface{ CloseWrite() error }

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---------------------------------------------------------------------------
// server / client
// ---------------------------------------------------------------------------

func runServer(listen, target, fallback string, psk []byte) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("server listening on %s -> target %s (fallback: %q)", listen, target, fallback)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleServer(conn, target, fallback, psk)
	}
}

func handleServer(conn net.Conn, target, fallback string, psk []byte) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(hsTimeout))
	rec, err := readRecord(conn)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	cr, sid, ok := clientAuth(rec)
	authed := false
	if ok && len(sid) == 32 {
		now := time.Now().Unix() / 60
		for _, mm := range []int64{now, now - 1, now + 1} {
			if hmac.Equal(sid, authToken(psk, cr, mm)) {
				authed = true
				break
			}
		}
	}

	// Reality-style fallback: a stranger / probe is relayed to a real site.
	if !authed {
		if fallback == "" {
			return
		}
		up, err := net.Dial("tcp", fallback)
		if err != nil {
			return
		}
		up.Write(rec) // replay the exact bytes we already consumed
		relay(conn, up)
		return
	}

	sr := random32()
	if _, err := conn.Write(buildServerHello(sr, sid)); err != nil {
		return
	}

	key := deriveKey(psk, cr, sr)
	sc, err := newSecureConn(conn, key, 2, 1) // server writes prefix 2, reads prefix 1
	if err != nil {
		return
	}

	dst, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	relay(sc, dst)
}

func runClient(listen, remote, sni string, psk []byte) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("client listening on %s -> remote %s (sni: %s)", listen, remote, sni)

	for {
		local, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(local, remote, sni, psk)
	}
}

func handleClient(local net.Conn, remote, sni string, psk []byte) {
	defer local.Close()

	conn, err := net.Dial("tcp", remote)
	if err != nil {
		return
	}

	cr := random32()
	minute := time.Now().Unix() / 60
	sid := authToken(psk, cr, minute)

	if _, err := conn.Write(buildClientHello(cr, sid, sni)); err != nil {
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Now().Add(hsTimeout))
	rec, err := readRecord(conn)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	sr, ok := helloRandom(rec)
	if !ok {
		conn.Close()
		return
	}

	key := deriveKey(psk, cr, sr)
	sc, err := newSecureConn(conn, key, 1, 2) // client writes prefix 1, reads prefix 2
	if err != nil {
		conn.Close()
		return
	}
	relay(local, sc)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func banner() {
	log.Print("morgontun - DPI-evading TCP tunnel  |  BY MEYSAM")
}

func main() {
	log.SetFlags(log.LstdFlags)

	mode := flag.String("mode", "", "server | client")
	listen := flag.String("listen", "", "local listen address (e.g. :443 or 127.0.0.1:1090)")
	remote := flag.String("remote", "", "client mode: server address (e.g. 1.2.3.4:443)")
	target := flag.String("target", "", "server mode: real service to forward to (e.g. 127.0.0.1:10000)")
	fallback := flag.String("fallback", "", "server mode: real site for failed-auth peers (e.g. www.microsoft.com:443)")
	sni := flag.String("sni", "www.microsoft.com", "client mode: SNI to mimic in the fake ClientHello")
	keyStr := flag.String("key", "", "pre-shared key (must match on both sides)")
	flag.Parse()

	if *keyStr == "" {
		log.Fatal("missing -key (pre-shared key must be set on both sides)")
	}
	// Stretch the passphrase to a stable 32-byte PSK.
	sum := sha256.Sum256([]byte("morgontun-psk|" + *keyStr))
	psk := sum[:]

	banner()

	switch *mode {
	case "server":
		if *listen == "" || *target == "" {
			log.Fatal("server mode needs -listen and -target")
		}
		runServer(*listen, *target, *fallback, psk)
	case "client":
		if *listen == "" || *remote == "" {
			log.Fatal("client mode needs -listen and -remote")
		}
		runClient(*listen, *remote, *sni, psk)
	default:
		log.Fatal("set -mode server or -mode client")
	}
}
GOEOF
  msg "Building morgontun ..."
  ( cd "${D}" && go build -ldflags="-s -w" -o "${BIN}" morgontun.go )
  [[ -x "${BIN}" ]] || { err "morgontun build failed"; exit 1; }
  ok "morgontun built -> ${BIN}"
}

# ---------------------------------------------------------------------------
# tunnel: IRAN client
# ---------------------------------------------------------------------------
install_client() {
  need_root
  echo; msg "Install tunnel on IRAN server (client)"; echo
  local REMOTE_IP REMOTE_PORT LISTEN_PORT SNI KEY
  ask REMOTE_IP   "Abroad server IP"                        ""
  ask REMOTE_PORT "Abroad server port"                      "443"
  valid_port "${REMOTE_PORT}" || { err "Invalid port"; exit 1; }
  ask LISTEN_PORT "Local listen port (apps connect here)"   "1090"
  valid_port "${LISTEN_PORT}" || { err "Invalid port"; exit 1; }
  ask SNI         "SNI to mimic"                            "www.microsoft.com"
  ask KEY         "Pre-shared key (blank = auto)"           "$(gen_key)"

  build_morgontun
  mkdir -p "${CONF_DIR}"; chmod 700 "${CONF_DIR}"
  cat > "${CLIENT_ENV}" <<EOF
REMOTE_IP=${REMOTE_IP}
REMOTE_PORT=${REMOTE_PORT}
LISTEN_PORT=${LISTEN_PORT}
SNI=${SNI}
KEY=${KEY}
EOF
  chmod 600 "${CLIENT_ENV}"
  cat > "${CLIENT_UNIT}" <<EOF
[Unit]
Description=morgontun client (Iran)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${CLIENT_ENV}
ExecStart=${BIN} -mode client -listen 0.0.0.0:\${LISTEN_PORT} -remote \${REMOTE_IP}:\${REMOTE_PORT} -sni \${SNI} -key \${KEY}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now morgontun-client.service >/dev/null 2>&1
  systemctl restart morgontun-client.service
  echo; ok "Client started."
  echo -e "   listen : ${C_C}0.0.0.0:${LISTEN_PORT}${C_0}  (point apps here)"
  echo -e "   remote : ${C_C}${REMOTE_IP}:${REMOTE_PORT}${C_0}"
  echo -e "   key    : ${C_C}${KEY}${C_0}  (use SAME key on abroad)"
  echo
  warn "Iran DPI still sees the outer handshake. Add DPI desync with menu option 3."
}

# ---------------------------------------------------------------------------
# tunnel: ABROAD server
# ---------------------------------------------------------------------------
install_server() {
  need_root
  echo; msg "Install tunnel on ABROAD server (server)"; echo
  local LISTEN_PORT TARGET_IP TARGET_PORT FALLBACK KEY
  ask LISTEN_PORT "Listen port (clients connect here)"      "443"
  valid_port "${LISTEN_PORT}" || { err "Invalid port"; exit 1; }
  ask TARGET_IP   "Target IP (real service)"                "127.0.0.1"
  ask TARGET_PORT "Target port (real service)"              "10000"
  valid_port "${TARGET_PORT}" || { err "Invalid port"; exit 1; }
  ask FALLBACK    "Fallback host:port for probes"           "www.microsoft.com:443"
  ask KEY         "Pre-shared key (blank = auto)"           "$(gen_key)"

  build_morgontun
  mkdir -p "${CONF_DIR}"; chmod 700 "${CONF_DIR}"
  cat > "${SERVER_ENV}" <<EOF
LISTEN_PORT=${LISTEN_PORT}
TARGET_IP=${TARGET_IP}
TARGET_PORT=${TARGET_PORT}
FALLBACK=${FALLBACK}
KEY=${KEY}
EOF
  chmod 600 "${SERVER_ENV}"
  cat > "${SERVER_UNIT}" <<EOF
[Unit]
Description=morgontun server (Abroad)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${SERVER_ENV}
ExecStart=${BIN} -mode server -listen :\${LISTEN_PORT} -target \${TARGET_IP}:\${TARGET_PORT} -fallback \${FALLBACK} -key \${KEY}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now morgontun-server.service >/dev/null 2>&1
  systemctl restart morgontun-server.service
  echo; ok "Server started."
  echo -e "   listen : ${C_C}:${LISTEN_PORT}${C_0}  (open in firewall)"
  echo -e "   target : ${C_C}${TARGET_IP}:${TARGET_PORT}${C_0}"
  echo -e "   key    : ${C_C}${KEY}${C_0}  (use SAME key on Iran)"
  echo
}

# ---------------------------------------------------------------------------
# zapret DPI desync (Iran side)
# ---------------------------------------------------------------------------
zapret_build() {
  msg "Installing zapret build deps ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq git make gcc curl ipset iptables \
    libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev zlib1g-dev
  if [[ -d "${ZDIR}/.git" ]]; then
    git -C "${ZDIR}" pull --ff-only || true
  else
    git clone --depth 1 "${ZREPO}" "${ZDIR}"
  fi
  msg "Building nfqws ..."
  make -C "${ZDIR}/nfq" >/dev/null
  [[ -x "${ZDIR}/nfq/nfqws" ]] || { err "nfqws build failed"; exit 1; }
  ok "nfqws built -> ${ZDIR}/nfq/nfqws"
}

zapret_write_fw() {
cat > "${ZFW}" <<'FWEOF'
#!/usr/bin/env bash
set -e
. /etc/zapret-iran.conf
QNUM=200
rule() {
  iptables -t mangle "$1" POSTROUTING -o "${WAN}" -p tcp -m multiport --dports "${PORTS}" \
    ${IPSET_MATCH} -m connbytes --connbytes-dir=original --connbytes-mode=packets \
    --connbytes 1:6 -j NFQUEUE --queue-num ${QNUM} --queue-bypass
}
case "$1" in
  up)
    sysctl -qw net.netfilter.nf_conntrack_checksum=0 || true
    if [[ -n "${TARGET_IPS}" ]]; then
      ipset create zapret_iran hash:ip -exist; ipset flush zapret_iran
      for ip in ${TARGET_IPS//,/ }; do ipset add zapret_iran "$ip" -exist; done
    fi
    rule -C 2>/dev/null || rule -I ;;
  down) rule -D 2>/dev/null || true ;;
esac
FWEOF
chmod 750 "${ZFW}"
}

install_zapret() {
  need_root
  echo; msg "Install DPI desync (zapret) — run this on the IRAN server"; echo
  zapret_build

  local RUNBC
  ask RUNBC "Run blockcheck now to find your ISP's best strategy? (y/N)" "N"
  if [[ "${RUNBC}" =~ ^[Yy]$ ]]; then
    warn "Copy the working 'nfqws --dpi-desync=...' line it prints (without 'nfqws')."
    ( cd "${ZDIR}" && bash blockcheck.sh ) || true
  fi

  local WAN PORTS TARGET_IPS OPT
  WAN="$(detect_wan)"; [[ -z "${WAN}" ]] && WAN="eth0"
  ask WAN        "WAN interface"                                   "${WAN}"
  ask PORTS      "Target TCP ports"                                "80,443"
  ask_opt TARGET_IPS "Abroad server IP(s), comma-sep (blank = all)"
  echo -e "${C_Y}?${C_0} nfqws strategy (Enter = strong default, or paste blockcheck line):"
  read -rp "  OPT: " OPT; OPT="${OPT:-$Z_DEF_OPT}"

  local IPSET_MATCH=""
  [[ -n "${TARGET_IPS}" ]] && IPSET_MATCH="-m set --match-set zapret_iran dst"

  cat > "${ZCONF}" <<EOF
WAN=${WAN}
PORTS=${PORTS}
TARGET_IPS=${TARGET_IPS}
IPSET_MATCH=${IPSET_MATCH}
NFQWS_OPT="${OPT}"
EOF
  chmod 600 "${ZCONF}"
  zapret_write_fw

  cat > "${ZUNIT}" <<EOF
[Unit]
Description=zapret-iran nfqws DPI desync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ZCONF}
ExecStartPre=${ZFW} up
ExecStart=${ZDIR}/nfq/nfqws --qnum=${QNUM} \$NFQWS_OPT
ExecStopPost=${ZFW} down
Restart=always
RestartSec=3
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now zapret-iran.service >/dev/null 2>&1
  systemctl restart zapret-iran.service
  echo; ok "zapret-iran started."
  echo -e "   iface : ${C_C}${WAN}${C_0}   ports: ${C_C}${PORTS}${C_0}"
  [[ -n "${TARGET_IPS}" ]] && echo -e "   scope : ${C_C}${TARGET_IPS}${C_0} (ipset)"
  echo -e "   opt   : ${C_C}${OPT}${C_0}"
  echo
  warn "If sites still blocked, re-run and choose blockcheck to get an ISP-specific line."
}

# ---------------------------------------------------------------------------
# status / stop
# ---------------------------------------------------------------------------
show_svc() {  # show_svc <unit-file> <env> <name>
  [[ -f "$1" ]] || return 1
  local u; u="$(basename "$1")"
  local st; st="$(systemctl is-active "${u}" 2>/dev/null || true)"
  [[ "${st}" == "active" ]] && echo -e "$3: ${C_G}${st}${C_0}" || echo -e "$3: ${C_R}${st:-inactive}${C_0}"
  [[ -f "$2" ]] && { echo "  config:"; sed 's/^KEY=.*/KEY=********/; s/^NFQWS_OPT=/opt=/; s/^/    /' "$2"; }
  echo
}

do_status() {
  echo
  local any=0
  show_svc "${CLIENT_UNIT}" "${CLIENT_ENV}" "IRAN tunnel client"  && any=1
  show_svc "${SERVER_UNIT}" "${SERVER_ENV}" "ABROAD tunnel server" && any=1
  show_svc "${ZUNIT}"       "${ZCONF}"      "IRAN DPI desync"      && any=1
  ss -ltnp 2>/dev/null | grep -iE 'morgontun' | sed 's/^/  listening: /' || true
  pgrep -a nfqws | sed 's/^/  nfqws: /' || true
  [[ "${any}" -eq 0 ]] && warn "Nothing installed yet."
  echo
}

# choose a service -> sets global PICK to client|server|zapret (or empty)
PICK=""
pick_svc() {
  echo
  echo "  1) morgontun client (Iran)"
  echo "  2) morgontun server (Abroad)"
  echo "  3) zapret DPI desync (Iran)"
  local c; read -rp "$(echo -e "${C_Y}Which? [1-3]:${C_0} ")" c
  case "${c}" in 1) PICK=client ;; 2) PICK=server ;; 3) PICK=zapret ;; *) PICK="" ;; esac
}
svc_unit() {
  case "$1" in
    client) echo "morgontun-client.service" ;;
    server) echo "morgontun-server.service" ;;
    zapret) echo "zapret-iran.service" ;;
  esac
}

do_restart() {
  need_root; pick_svc; [[ -z "${PICK}" ]] && { err "Invalid"; return; }
  local u; u="$(svc_unit "${PICK}")"
  if [[ ! -f "/etc/systemd/system/${u}" ]]; then warn "${u} is not installed."; return; fi
  systemctl restart "${u}" && ok "${u} restarted" || err "restart failed (see: journalctl -u ${u})"
  echo
}

do_stop() {
  need_root; pick_svc; [[ -z "${PICK}" ]] && { err "Invalid"; return; }
  local u; u="$(svc_unit "${PICK}")"
  systemctl disable --now "${u}" >/dev/null 2>&1 || true
  [[ "${PICK}" == "zapret" && -x "${ZFW}" ]] && "${ZFW}" down 2>/dev/null || true
  ok "${u} stopped"
  echo
}

do_remove() {
  need_root; pick_svc; [[ -z "${PICK}" ]] && { err "Invalid"; return; }
  local u yn dz db; u="$(svc_unit "${PICK}")"
  read -rp "$(echo -e "${C_Y}Remove ${u} and its config? (y/N):${C_0} ")" yn
  [[ "${yn}" =~ ^[Yy]$ ]] || { warn "cancelled"; echo; return; }

  systemctl disable --now "${u}" >/dev/null 2>&1 || true
  case "${PICK}" in
    client) rm -f "${CLIENT_UNIT}" "${CLIENT_ENV}" ;;
    server) rm -f "${SERVER_UNIT}" "${SERVER_ENV}" ;;
    zapret)
      [[ -x "${ZFW}" ]] && "${ZFW}" down 2>/dev/null || true
      rm -f "${ZUNIT}" "${ZCONF}" "${ZFW}"
      read -rp "$(echo -e "${C_Y}Also delete ${ZDIR} clone? (y/N):${C_0} ")" dz
      [[ "${dz}" =~ ^[Yy]$ ]] && rm -rf "${ZDIR}"
      ;;
  esac
  systemctl daemon-reload

  # drop config dir if empty, and offer to delete the binary when no tunnel is left
  [[ -d "${CONF_DIR}" ]] && rmdir "${CONF_DIR}" 2>/dev/null || true
  if [[ "${PICK}" != "zapret" && ! -f "${CLIENT_UNIT}" && ! -f "${SERVER_UNIT}" && -x "${BIN}" ]]; then
    read -rp "$(echo -e "${C_Y}No tunnel services left. Delete ${BIN}? (y/N):${C_0} ")" db
    [[ "${db}" =~ ^[Yy]$ ]] && rm -f "${BIN}"
  fi
  ok "${u} removed"
  echo
}

# nuke everything: both tunnel roles + zapret, rules, configs, units
do_purge() {
  need_root
  echo
  warn "This removes ALL of it: tunnel client, tunnel server, and zapret desync"
  warn "(services, units, configs, iptables rule, ipset)."
  local yn; read -rp "$(echo -e "${C_Y}Type 'yes' to wipe everything:${C_0} ")" yn
  [[ "${yn}" == "yes" ]] || { warn "cancelled"; echo; return; }

  # stop + disable services
  for u in morgontun-client morgontun-server zapret-iran; do
    systemctl disable --now "${u}.service" >/dev/null 2>&1 || true
    systemctl reset-failed "${u}.service" >/dev/null 2>&1 || true
  done

  # tear down zapret firewall + any stray nfqws
  [[ -x "${ZFW}" ]] && "${ZFW}" down 2>/dev/null || true
  pkill -9 nfqws 2>/dev/null || true
  ipset destroy zapret_iran 2>/dev/null || true

  # remove unit + config files
  rm -f "${CLIENT_UNIT}" "${SERVER_UNIT}" "${ZUNIT}"
  rm -f "${CLIENT_ENV}" "${SERVER_ENV}" "${ZCONF}" "${ZFW}"
  rmdir "${CONF_DIR}" 2>/dev/null || true
  systemctl daemon-reload

  ok "All services, units, configs and rules removed."

  local db dz
  read -rp "$(echo -e "${C_Y}Also delete the morgontun binary (${BIN})? (y/N):${C_0} ")" db
  [[ "${db}" =~ ^[Yy]$ ]] && rm -f "${BIN}" && ok "binary deleted"
  read -rp "$(echo -e "${C_Y}Also delete the zapret clone (${ZDIR})? (y/N):${C_0} ")" dz
  [[ "${dz}" =~ ^[Yy]$ ]] && rm -rf "${ZDIR}" && ok "zapret clone deleted"
  echo
  ok "Clean slate. You can now install fresh from the menu."
  echo
}

# ---------------------------------------------------------------------------
menu() {
  banner
  echo
  echo "  1) Install on IRAN    (tunnel client)"
  echo "  2) Install on ABROAD  (tunnel server)"
  echo "  3) Add DPI desync     (zapret, Iran side)"
  echo "  4) Service status"
  echo "  5) Restart a service"
  echo "  6) Stop a service"
  echo "  7) Remove a service   (delete unit + config)"
  echo "  8) Remove EVERYTHING  (purge all, clean slate)"
  echo "  9) Exit"
  echo
  local c; read -rp "$(echo -e "${C_Y}Select [1-9]:${C_0} ")" c
  case "${c}" in
    1) install_client ;;
    2) install_server ;;
    3) install_zapret ;;
    4) do_status ;;
    5) do_restart ;;
    6) do_stop ;;
    7) do_remove ;;
    8) do_purge ;;
    9) exit 0 ;;
    *) err "Invalid choice"; exit 1 ;;
  esac
}

menu
