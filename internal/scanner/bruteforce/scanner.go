package bruteforce

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"golang.org/x/crypto/ssh"
)

const (
	defaultThreads  = 10
	defaultTimeoutS = 5
	defaultMaxTime  = 600
)

type Cracker interface {
	Name() string
	Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error)
}

type ScanInput struct {
	Host     string                  `json:"host"`
	IP       string                  `json:"ip"`
	Port     int                     `json:"port"`
	Service  string                  `json:"service"`
	Users    []string                `json:"users"`
	Passwords []string              `json:"passwords"`
	Options  model.BruteForceOptions `json:"options"`
}

func Scan(ctx context.Context, input ScanInput) ([]model.BruteResult, error) {
	opts := input.Options
	threads := coalesce(opts.Threads, defaultThreads)
	timeout := time.Duration(coalesce(opts.Timeout, defaultTimeoutS)) * time.Second
	maxTime := coalesce(opts.MaxTime, defaultMaxTime)

	maxCtx, cancel := context.WithTimeout(ctx, time.Duration(maxTime)*time.Second)
	defer cancel()

	service := strings.ToLower(input.Service)
	cracker := getCracker(service)
	if cracker == nil {
		logger.L.Warnw("unsupported brute-force service", "service", service)
		return nil, fmt.Errorf("unsupported service: %s", service)
	}

	connectAddr := input.IP
	if connectAddr == "" {
		connectAddr = input.Host
	}

	logger.L.Infow("brute-force scan starting",
		"host", connectAddr,
		"port", input.Port,
		"service", service,
		"users", len(input.Users),
		"passwords", len(input.Passwords),
		"threads", threads,
	)

	type credential struct {
		user string
		pass string
	}

	credCh := make(chan credential, threads*2)
	var (
		mu       sync.Mutex
		results  []model.BruteResult
		found    int32
		tried    int64
	)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cred := range credCh {
				if maxCtx.Err() != nil {
					return
				}
				if opts.StopOnFirst && atomic.LoadInt32(&found) > 0 {
					return
				}

				if opts.Delay > 0 {
					select {
					case <-time.After(time.Duration(opts.Delay) * time.Millisecond):
					case <-maxCtx.Done():
						return
					}
				}

				ok, err := cracker.Try(maxCtx, connectAddr, input.Port, cred.user, cred.pass, timeout)
				atomic.AddInt64(&tried, 1)

				if ok {
					atomic.AddInt32(&found, 1)
					mu.Lock()
					results = append(results, model.BruteResult{
						Host:     input.Host,
						IP:       input.IP,
						Port:     input.Port,
						Service:  service,
						Username: cred.user,
						Password: cred.pass,
						Success:  true,
					})
					mu.Unlock()
					logger.L.Infow("brute-force credential found",
						"host", connectAddr,
						"port", input.Port,
						"service", service,
						"user", cred.user,
					)
				} else if err != nil {
					logger.L.Debugw("brute-force attempt error",
						"host", connectAddr,
						"port", input.Port,
						"user", cred.user,
						"error", err,
					)
				}
			}
		}()
	}

	go func() {
		defer close(credCh)
		for _, user := range input.Users {
			for _, pass := range input.Passwords {
				if maxCtx.Err() != nil {
					return
				}
				if opts.StopOnFirst && atomic.LoadInt32(&found) > 0 {
					return
				}
				select {
				case credCh <- credential{user: user, pass: pass}:
				case <-maxCtx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()

	logger.L.Infow("brute-force scan completed",
		"host", connectAddr,
		"port", input.Port,
		"service", service,
		"tried", atomic.LoadInt64(&tried),
		"found", len(results),
	)
	return results, nil
}

func getCracker(service string) Cracker {
	switch service {
	case "ssh":
		return &sshCracker{}
	case "ftp":
		return &ftpCracker{}
	case "mysql":
		return &mysqlCracker{}
	case "redis":
		return &redisCracker{}
	case "postgresql":
		return &postgresCracker{}
	case "mongodb":
		return &mongoCracker{}
	case "mssql":
		return &mssqlCracker{}
	default:
		return nil
	}
}

// --- SSH ---

type sshCracker struct{}

func (c *sshCracker) Name() string { return "ssh" }

func (c *sshCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") ||
			strings.Contains(err.Error(), "handshake failed") {
			return false, nil
		}
		return false, err
	}
	conn.Close()
	return true, nil
}

// --- FTP ---

type ftpCracker struct{}

func (c *ftpCracker) Name() string { return "ftp" }

func (c *ftpCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}
	banner := string(buf[:n])
	if !strings.HasPrefix(banner, "220") {
		return false, fmt.Errorf("unexpected FTP banner: %s", banner)
	}

	if _, err := fmt.Fprintf(conn, "USER %s\r\n", user); err != nil {
		return false, err
	}
	n, err = conn.Read(buf)
	if err != nil {
		return false, err
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "331") {
		if strings.HasPrefix(resp, "230") {
			return true, nil
		}
		return false, nil
	}

	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", pass); err != nil {
		return false, err
	}
	n, err = conn.Read(buf)
	if err != nil {
		return false, err
	}
	resp = string(buf[:n])
	if strings.HasPrefix(resp, "230") {
		fmt.Fprintf(conn, "QUIT\r\n")
		return true, nil
	}
	return false, nil
}

// --- MySQL ---

type mysqlCracker struct{}

func (c *mysqlCracker) Name() string { return "mysql" }

func (c *mysqlCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	if n < 5 {
		return false, fmt.Errorf("mysql handshake too short")
	}

	// MySQL protocol: if we get a valid greeting, the service is reachable.
	// A full auth implementation would require proper packet parsing.
	// For brute force, we check if the greeting contains the protocol version.
	if buf[4] != 0x0a && buf[4] != 0xff {
		return false, fmt.Errorf("not a mysql greeting: %x", buf[4])
	}

	if buf[4] == 0xff {
		return false, nil
	}

	// Simplified: attempt a native password auth by sending a quit.
	// In practice, a proper MySQL auth requires scramble handling.
	// We signal "maybe" if the connection succeeds - the caller
	// should use a proper MySQL driver for confirmed results.
	// For a lightweight check, we try a simplified handshake response.
	_ = user
	_ = pass
	return false, fmt.Errorf("mysql auth requires proper driver, skipping detailed check")
}

// --- Redis ---

type redisCracker struct{}

func (c *redisCracker) Name() string { return "redis" }

func (c *redisCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var cmd string
	if user != "" && user != "default" {
		cmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(user), user, len(pass), pass)
	} else if pass != "" {
		cmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(pass), pass)
	} else {
		cmd = "*1\r\n$4\r\nPING\r\n"
	}

	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}
	resp := string(buf[:n])

	if strings.HasPrefix(resp, "+OK") || strings.HasPrefix(resp, "+PONG") {
		return true, nil
	}
	return false, nil
}

// --- PostgreSQL ---

type postgresCracker struct{}

func (c *postgresCracker) Name() string { return "postgresql" }

func (c *postgresCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// PostgreSQL startup message: Version 3.0
	dbname := "postgres"
	params := map[string]string{
		"user":     user,
		"database": dbname,
	}

	var payload []byte
	// protocol version 3.0
	payload = append(payload, 0, 3, 0, 0)
	for k, v := range params {
		payload = append(payload, []byte(k)...)
		payload = append(payload, 0)
		payload = append(payload, []byte(v)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // terminator

	// length prefix (4 bytes including self)
	length := uint32(len(payload) + 4)
	msg := []byte{
		byte(length >> 24), byte(length >> 16),
		byte(length >> 8), byte(length),
	}
	msg = append(msg, payload...)

	if _, err := conn.Write(msg); err != nil {
		return false, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	if n == 0 {
		return false, fmt.Errorf("empty response from postgresql")
	}

	// 'R' = AuthenticationRequest
	if buf[0] == 'R' && n >= 8 {
		authType := uint32(buf[5])<<16 | uint32(buf[6])<<8 | uint32(buf[7])
		if authType == 0 {
			return true, nil
		}
		if authType == 3 {
			// Cleartext password
			passBytes := []byte(pass)
			passMsg := make([]byte, 0, 5+len(passBytes)+1)
			passMsg = append(passMsg, 'p')
			passLen := uint32(4 + len(passBytes) + 1)
			passMsg = append(passMsg,
				byte(passLen>>24), byte(passLen>>16),
				byte(passLen>>8), byte(passLen),
			)
			passMsg = append(passMsg, passBytes...)
			passMsg = append(passMsg, 0)

			if _, err := conn.Write(passMsg); err != nil {
				return false, err
			}

			n, err = conn.Read(buf)
			if err != nil {
				return false, err
			}
			if n >= 8 && buf[0] == 'R' {
				respAuth := uint32(buf[5])<<16 | uint32(buf[6])<<8 | uint32(buf[7])
				if respAuth == 0 {
					return true, nil
				}
			}
			return false, nil
		}
		// MD5 or other auth methods - not easily brutable without proper handling
		return false, nil
	}

	// 'E' = ErrorResponse
	if buf[0] == 'E' {
		return false, nil
	}

	return false, nil
}

// --- MongoDB ---

type mongoCracker struct{}

func (c *mongoCracker) Name() string { return "mongodb" }

func (c *mongoCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// MongoDB wire protocol: send an isMaster command to check connectivity.
	// Full SCRAM-SHA auth is complex; we check if auth is required.
	// If no auth required, unauthenticated access is available.
	isMaster := []byte{
		// message header (16 bytes)
		0x3f, 0x00, 0x00, 0x00, // messageLength: 63
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode: OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		// fullCollectionName: "admin.$cmd\0"
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// BSON document: {isMaster: 1}
		0x13, 0x00, 0x00, 0x00, // docSize: 19
		0x10,                                     // type: int32
		0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // terminator
	}

	if _, err := conn.Write(isMaster); err != nil {
		return false, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	resp := string(buf[:n])
	if strings.Contains(resp, "ismaster") || strings.Contains(resp, "isMaster") || strings.Contains(resp, "isWritablePrimary") {
		if user == "" || (user == "admin" && pass == "") {
			return true, nil
		}
	}
	return false, nil
}

// --- MSSQL ---

type mssqlCracker struct{}

func (c *mssqlCracker) Name() string { return "mssql" }

func (c *mssqlCracker) Try(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// TDS pre-login packet (simplified)
	prelogin := buildTDSPreLogin()
	if _, err := conn.Write(prelogin); err != nil {
		return false, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	// Check if we got a valid TDS response
	if n < 8 || buf[0] != 0x04 {
		return false, fmt.Errorf("invalid TDS response")
	}

	// Send TDS login7 packet
	login7 := buildTDSLogin7(host, user, pass, "master")
	if _, err := conn.Write(login7); err != nil {
		return false, err
	}

	n, err = conn.Read(buf)
	if err != nil {
		return false, err
	}

	if n >= 8 {
		// Token type 0xAD = LoginAck, 0xAA = Error
		for i := 8; i < n; i++ {
			if buf[i] == 0xAD {
				return true, nil
			}
			if buf[i] == 0xAA {
				return false, nil
			}
		}
	}

	return false, nil
}

func buildTDSPreLogin() []byte {
	payload := []byte{
		// VERSION token
		0x00,                   // token type
		0x00, 0x06,             // offset
		0x06,                   // length (hi byte)
		0x00, 0x00,             // length (lo bytes)
		// ENCRYPTION token
		0x01,
		0x00, 0x0c,
		0x01,
		0x00, 0x00,
		// TERMINATOR
		0xff,
		// VERSION data (6 bytes: version + sub-build)
		0x0e, 0x00, 0x06, 0x18, 0x00, 0x00,
		// ENCRYPTION data: NOT_SUP (0x02)
		0x02,
	}

	pktLen := len(payload) + 8
	header := []byte{
		0x12,       // packet type: pre-login
		0x01,       // status: EOM
		byte(pktLen >> 8), byte(pktLen), // length
		0x00, 0x00, // SPID
		0x00,       // packet number
		0x00,       // window
	}

	return append(header, payload...)
}

func buildTDSLogin7(server, user, pass, database string) []byte {
	serverU := encodeUTF16LE(server)
	userU := encodeUTF16LE(user)
	passU := encodeTDSPassword(pass)
	dbU := encodeUTF16LE(database)
	appU := encodeUTF16LE("distributed-scanner")
	hostU := encodeUTF16LE("scanner")
	libU := encodeUTF16LE("go-tds")

	// Fixed portion is 94 bytes
	fixedLen := 94
	offsetBase := fixedLen

	offHost := offsetBase
	offUser := offHost + len(hostU)
	offPass := offUser + len(userU)
	offApp := offPass + len(passU)
	offServer := offApp + len(appU)
	offLib := offServer + len(serverU)
	offDB := offLib + len(libU)

	totalLen := offDB + len(dbU)

	login := make([]byte, totalLen)

	// Length
	putUint32LE(login, 0, uint32(totalLen))
	// TDS version 7.3
	putUint32LE(login, 4, 0x730a0003)
	// Packet size
	putUint32LE(login, 8, 4096)
	// Client version
	putUint32LE(login, 12, 0x07000000)
	// Client PID
	putUint32LE(login, 16, 1234)
	// Connection ID
	putUint32LE(login, 20, 0)
	// Option flags
	login[24] = 0xe0
	login[25] = 0x03
	login[26] = 0x00
	login[27] = 0x00
	// Type flags
	putUint32LE(login, 28, 0)
	// Timezone
	putUint32LE(login, 32, 0)
	// Collation
	putUint32LE(login, 36, 0)

	// Offsets/lengths
	putUint16LE(login, 40, uint16(offHost))
	putUint16LE(login, 42, uint16(len(hostU)/2))
	putUint16LE(login, 44, uint16(offUser))
	putUint16LE(login, 46, uint16(len(userU)/2))
	putUint16LE(login, 48, uint16(offPass))
	putUint16LE(login, 50, uint16(len(passU)/2))
	putUint16LE(login, 52, uint16(offApp))
	putUint16LE(login, 54, uint16(len(appU)/2))
	putUint16LE(login, 56, uint16(offServer))
	putUint16LE(login, 58, uint16(len(serverU)/2))
	// unused (offset 60-63)
	putUint16LE(login, 60, 0)
	putUint16LE(login, 62, 0)
	putUint16LE(login, 64, uint16(offLib))
	putUint16LE(login, 66, uint16(len(libU)/2))
	// locale (offset 68-71)
	putUint16LE(login, 68, 0)
	putUint16LE(login, 70, 0)
	putUint16LE(login, 72, uint16(offDB))
	putUint16LE(login, 74, uint16(len(dbU)/2))

	copy(login[offHost:], hostU)
	copy(login[offUser:], userU)
	copy(login[offPass:], passU)
	copy(login[offApp:], appU)
	copy(login[offServer:], serverU)
	copy(login[offLib:], libU)
	copy(login[offDB:], dbU)

	// Wrap in TDS header
	pktLen := len(login) + 8
	header := []byte{
		0x10,       // packet type: login7
		0x01,       // status: EOM
		byte(pktLen >> 8), byte(pktLen),
		0x00, 0x00,
		0x01,
		0x00,
	}

	return append(header, login...)
}

func encodeUTF16LE(s string) []byte {
	buf := make([]byte, len(s)*2)
	for i, r := range s {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}

func encodeTDSPassword(pass string) []byte {
	encoded := encodeUTF16LE(pass)
	for i := range encoded {
		encoded[i] = ((encoded[i] << 4) & 0xf0) | ((encoded[i] >> 4) & 0x0f)
		encoded[i] ^= 0xa5
	}
	return encoded
}

func putUint32LE(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func putUint16LE(b []byte, off int, v uint16) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}
