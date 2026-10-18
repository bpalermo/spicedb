package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

// testCA is a certificate authority. chain is its own certificate followed
// by those of the CAs above it, up to but not including the root; it is empty
// for a root.
type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	return newCA(t, name, nil)
}

// sub returns a CA signed by ca.
func (ca *testCA) sub(t *testing.T, name string) *testCA {
	t.Helper()
	return newCA(t, name, ca)
}

func newCA(t *testing.T, name string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, issuerKey := template, key
	var chain []*x509.Certificate
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	if parent != nil {
		chain = append([]*x509.Certificate{cert}, parent.chain...)
	}
	return &testCA{cert: cert, key: key, chain: chain}
}

func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	return serial
}

func certPEM(certs ...*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return out.Bytes()
}

// pem returns the CA's own certificate, for a CA bundle.
func (ca *testCA) pem() []byte {
	return certPEM(ca.cert)
}

// issue returns a leaf signed by the CA, followed by the CA's chain, and its
// key. A server certificate is valid for names.
func (ca *testCA) issue(t *testing.T, subject pkix.Name, server bool, names ...string) (chainPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, name := range names {
			if ip := net.ParseIP(name); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, name)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	chain := append([]*x509.Certificate{leaf}, ca.chain...)
	return certPEM(chain...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// writeFile replaces path atomically, the way a certificate writer would,
// and moves its modification time forward so that a rewrite within the
// file system's timestamp granularity is still seen as a change.
func writeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, contents, 0o600))
	next := time.Now()
	if info, err := os.Stat(path); err == nil && !info.ModTime().Before(next) {
		next = info.ModTime().Add(time.Second)
	}
	require.NoError(t, os.Chtimes(tmp, next, next))
	require.NoError(t, os.Rename(tmp, path))
}

var spiffeSubject = pkix.Name{Country: []string{"US"}, Organization: []string{"SPIRE"}, CommonName: "spicedb"}

type tlsFixture struct {
	dir      string
	opts     TLSOptions
	serverCA *testCA
	clientCA *testCA
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	dir := t.TempDir()
	f := &tlsFixture{
		dir:      dir,
		serverCA: newTestCA(t, "server CA"),
		clientCA: newTestCA(t, "client CA"),
		opts: TLSOptions{
			CAPath:   filepath.Join(dir, "ca.pem"),
			CertPath: filepath.Join(dir, "cert.pem"),
			KeyPath:  filepath.Join(dir, "key.pem"),
		},
	}
	writeFile(t, f.opts.CAPath, f.serverCA.pem())
	f.writeClientCert(t, f.clientCA, "spicedb")
	return f
}

func (f *tlsFixture) writeClientCert(t *testing.T, ca *testCA, commonName string) {
	t.Helper()
	subject := spiffeSubject
	subject.CommonName = commonName
	chain, key := ca.issue(t, subject, false)
	writeFile(t, f.opts.CertPath, chain)
	writeFile(t, f.opts.KeyPath, key)
}

// peer is what the server saw of a client.
type peer struct {
	subject string
	chain   int
}

// serve starts a TLS server presenting a certificate from ca for names that
// requires a client certificate verified against clientRoot, and returns
// its address and what it saw of each client that completed a handshake.
func serve(t *testing.T, ca *testCA, clientRoot *testCA, names ...string) (string, <-chan peer) {
	t.Helper()
	if len(names) == 0 {
		names = []string{"localhost", "127.0.0.1"}
	}
	chainPEM, keyPEM := ca.issue(t, pkix.Name{CommonName: "mysql"}, true, names...)
	serverCert, err := tls.X509KeyPair(chainPEM, keyPEM)
	require.NoError(t, err)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientRoot.cert)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	peers := make(chan peer, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn, ok := conn.(*tls.Conn)
			if ok && tlsConn.Handshake() == nil {
				certs := tlsConn.ConnectionState().PeerCertificates
				peers <- peer{subject: certs[0].Subject.String(), chain: len(certs)}
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().String(), peers
}

func configure(t *testing.T, dsn string, opts TLSOptions) (*mysql.Config, *TLSFiles) {
	t.Helper()
	cfg, err := mysql.ParseDSN(dsn)
	require.NoError(t, err)
	files, err := MaybeConfigureTLS(cfg, opts)
	require.NoError(t, err)
	return cfg, files
}

// handshake connects to addr the way a new MySQL connection would.
func handshake(addr string, files *TLSFiles) error {
	conn, err := tls.Dial("tcp", addr, files.clientConfig())
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Handshake()
}

func TestTLSOptionsValidate(t *testing.T) {
	require.NoError(t, TLSOptions{}.Validate())
	require.NoError(t, TLSOptions{CAPath: "ca"}.Validate())
	require.NoError(t, TLSOptions{CertPath: "cert", KeyPath: "key"}.Validate())
	require.ErrorContains(t, TLSOptions{CertPath: "cert"}.Validate(), "must be given together")
	require.ErrorContains(t, TLSOptions{KeyPath: "key"}.Validate(), "must be given together")
}

func TestMaybeConfigureTLSUnset(t *testing.T) {
	for _, dsn := range []string{
		"root@tcp(localhost:3306)/db?parseTime=true",
		"root@tcp(localhost:3306)/db?parseTime=true&tls=skip-verify",
	} {
		cfg, err := mysql.ParseDSN(dsn)
		require.NoError(t, err)
		before := cfg.Clone()
		files, err := MaybeConfigureTLS(cfg, TLSOptions{})
		require.NoError(t, err)
		require.Nil(t, files)
		require.Equal(t, before.TLSConfig, cfg.TLSConfig)
		require.Equal(t, before.TLS, cfg.TLS)

		connector, err := NewConnector(cfg, files)
		require.NoError(t, err)
		_, isReloading := connector.(*reloadingTLSConnector)
		require.False(t, isReloading)
	}
}

func TestMaybeConfigureTLSErrors(t *testing.T) {
	f := newTLSFixture(t)

	for _, tc := range []struct {
		name string
		dsn  string
		opts TLSOptions
		err  string
	}{
		{"conflicting tls parameter", "root@tcp(localhost:3306)/db?tls=skip-verify", f.opts, "sets tls=skip-verify"},
		{"tls disabled in the URI", "root@tcp(localhost:3306)/db?tls=false", f.opts, "sets tls=false"},
		{"preferred tls in the URI", "root@tcp(localhost:3306)/db?tls=preferred", f.opts, "sets tls=preferred"},
		{"certificate without key", "root@tcp(localhost:3306)/db", TLSOptions{CertPath: f.opts.CertPath}, "must be given together"},
		{"no host to verify", "root@unix(/var/run/mysqld.sock)/db", f.opts, "set --datastore-tls-server-name"},
		{"missing CA bundle", "root@tcp(localhost:3306)/db", TLSOptions{CAPath: filepath.Join(f.dir, "missing.pem")}, "unable to read datastore TLS CA bundle"},
		{"CA bundle without certificates", "root@tcp(localhost:3306)/db", TLSOptions{CAPath: f.opts.KeyPath}, "no PEM certificates found"},
		{"certificate and key mismatch", "root@tcp(localhost:3306)/db", TLSOptions{CertPath: f.opts.CertPath, KeyPath: f.opts.CAPath}, "unable to load datastore TLS client certificate and key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := mysql.ParseDSN(tc.dsn)
			require.NoError(t, err)
			_, err = MaybeConfigureTLS(cfg, tc.opts)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestMaybeConfigureTLSConfig(t *testing.T) {
	f := newTLSFixture(t)

	// A user authenticated by its certificate has no password.
	cfg, files := configure(t, "spicedb@tcp(db.example.com:3306)/db?parseTime=true&tls=true", f.opts)
	require.Empty(t, cfg.Passwd)
	require.Empty(t, cfg.TLSConfig)
	require.NotNil(t, cfg.TLS)
	require.Equal(t, uint16(tls.VersionTLS12), cfg.TLS.MinVersion)
	require.Equal(t, "db.example.com", cfg.TLS.ServerName)
	require.False(t, cfg.TLS.InsecureSkipVerify)
	require.NotNil(t, cfg.TLS.RootCAs)
	require.NotNil(t, cfg.TLS.GetClientCertificate)

	connector, err := NewConnector(cfg, files)
	require.NoError(t, err)
	require.IsType(t, &reloadingTLSConnector{}, connector)
	require.IsType(t, &mysql.MySQLDriver{}, connector.Driver())

	opts := f.opts
	opts.ServerName = "mysql.internal"
	cfg, _ = configure(t, "root@unix(/var/run/mysqld.sock)/db", opts)
	require.Equal(t, "mysql.internal", cfg.TLS.ServerName)

	// Without a CA bundle the system roots verify the server; without a
	// client certificate none is offered.
	cfg, _ = configure(t, "root@tcp(db.example.com:3306)/db", TLSOptions{ServerName: "db.internal"})
	require.Nil(t, cfg.TLS.RootCAs)
	require.Nil(t, cfg.TLS.GetClientCertificate)
	require.False(t, cfg.TLS.InsecureSkipVerify)
}

func TestTLSHandshake(t *testing.T) {
	f := newTLSFixture(t)
	addr, peers := serve(t, f.serverCA, f.clientCA)

	_, files := configure(t, "spicedb@tcp("+addr+")/db", f.opts)
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=spicedb,O=SPIRE,C=US", (<-peers).subject)

	// A server certificate from another CA is refused.
	other := newTestCA(t, "other CA")
	otherAddr, _ := serve(t, other, f.clientCA)
	_, files = configure(t, "spicedb@tcp("+otherAddr+")/db", f.opts)
	require.ErrorContains(t, handshake(otherAddr, files), "certificate signed by unknown authority")
}

func TestTLSServerName(t *testing.T) {
	f := newTLSFixture(t)

	// A server certificate from the trusted CA, but for another name, is
	// refused.
	addr, _ := serve(t, f.serverCA, f.clientCA, "other.example.com")
	_, files := configure(t, "spicedb@tcp("+addr+")/db", f.opts)
	require.ErrorContains(t, handshake(addr, files), "cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs")

	opts := f.opts
	opts.ServerName = "mysql.example.com"
	_, files = configure(t, "spicedb@tcp("+addr+")/db", opts)
	require.ErrorContains(t, handshake(addr, files), "certificate is valid for other.example.com, not mysql.example.com")

	// A server reached at its IP address is verified against the configured
	// name instead.
	addr, peers := serve(t, f.serverCA, f.clientCA, "mysql.example.com")
	_, files = configure(t, "spicedb@tcp("+addr+")/db", f.opts)
	require.ErrorContains(t, handshake(addr, files), "cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs")
	_, files = configure(t, "spicedb@tcp("+addr+")/db", opts)
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=spicedb,O=SPIRE,C=US", (<-peers).subject)
}

func TestTLSClientCertificateChain(t *testing.T) {
	f := newTLSFixture(t)

	// The server trusts only a root two levels above the CA that signs the
	// client certificate, so the client must send the whole chain.
	root := newTestCA(t, "root")
	spire := root.sub(t, "intermediate").sub(t, "SPIRE CA")
	f.writeClientCert(t, spire, "spicedb")

	addr, peers := serve(t, f.serverCA, root)
	_, files := configure(t, "spicedb@tcp("+addr+")/db", f.opts)
	require.NoError(t, handshake(addr, files))
	require.Equal(t, peer{subject: "CN=spicedb,O=SPIRE,C=US", chain: 3}, <-peers)

	// A rotated intermediate, with a new SPIRE CA and leaf under it, is
	// picked up by the next connection.
	f.writeClientCert(t, root.sub(t, "next intermediate").sub(t, "next SPIRE CA"), "rotated")
	require.NoError(t, handshake(addr, files))
	require.Equal(t, peer{subject: "CN=rotated,O=SPIRE,C=US", chain: 3}, <-peers)
}

func TestTLSReload(t *testing.T) {
	f := newTLSFixture(t)
	addr, peers := serve(t, f.serverCA, f.clientCA)
	_, files := configure(t, "spicedb@tcp("+addr+")/db", f.opts)

	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=spicedb,O=SPIRE,C=US", (<-peers).subject)

	// A rotated key pair is used by the next connection.
	f.writeClientCert(t, f.clientCA, "rotated")
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=rotated,O=SPIRE,C=US", (<-peers).subject)

	// Half of a rotation (a new certificate with the old key) is not used:
	// the last good pair is.
	chain, _ := f.clientCA.issue(t, pkix.Name{CommonName: "half"}, false)
	writeFile(t, f.opts.CertPath, chain)
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=rotated,O=SPIRE,C=US", (<-peers).subject)

	// Files that disappear keep the last good pair too.
	require.NoError(t, os.Remove(f.opts.CertPath))
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=rotated,O=SPIRE,C=US", (<-peers).subject)

	// Once the rotation completes, the new pair is used.
	f.writeClientCert(t, f.clientCA, "completed")
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=completed,O=SPIRE,C=US", (<-peers).subject)
}

func TestTLSReloadCA(t *testing.T) {
	f := newTLSFixture(t)
	next := newTestCA(t, "next server CA")
	addr, peers := serve(t, next, f.clientCA)
	_, files := configure(t, "spicedb@tcp("+addr+")/db", f.opts)

	require.ErrorContains(t, handshake(addr, files), "certificate signed by unknown authority")

	writeFile(t, f.opts.CAPath, append(f.serverCA.pem(), next.pem()...))
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=spicedb,O=SPIRE,C=US", (<-peers).subject)

	// A CA bundle that no longer parses keeps the last good one.
	writeFile(t, f.opts.CAPath, []byte("not a certificate"))
	require.NoError(t, handshake(addr, files))
	require.Equal(t, "CN=spicedb,O=SPIRE,C=US", (<-peers).subject)
}
