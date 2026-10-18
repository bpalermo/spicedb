package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	log "github.com/authzed/spicedb/internal/logging"
)

// TLSOptions configures the TLS connection to a MySQL server from PEM files
// on disk. The files are watched for changes and reloaded, so a certificate
// and key that are rotated in place (for example a SPIFFE X.509-SVID written
// by spiffe-helper, or a Kubernetes Secret volume) take effect on the next
// connection without a restart.
type TLSOptions struct {
	// CAPath is a PEM bundle of the certificate authorities used to verify the
	// server. When empty, the system roots are used.
	CAPath string

	// CertPath and KeyPath are the PEM client certificate and private key
	// presented to the server. Either both or neither must be set.
	CertPath string
	KeyPath  string

	// ServerName overrides the name the server certificate is verified
	// against, which otherwise is the host of the connection URI.
	ServerName string
}

// IsSet returns whether any TLS option is configured.
func (o TLSOptions) IsSet() bool {
	return o.CAPath != "" || o.CertPath != "" || o.KeyPath != "" || o.ServerName != ""
}

// Validate checks that the options are consistent.
func (o TLSOptions) Validate() error {
	if (o.CertPath == "") != (o.KeyPath == "") {
		return errors.New("a datastore TLS client certificate and key must be given together: set both --datastore-tls-cert-path and --datastore-tls-key-path, or neither")
	}
	return nil
}

// MaybeConfigureTLS configures dbConfig to connect over TLS with the given
// options, and returns the files it reads them from, which NewConnector takes
// to re-read them for each new connection. It is a no-op returning nil when
// no option is set.
//
// The connection URI must not choose a TLS mode of its own other than
// tls=true, since the options would silently replace it.
func MaybeConfigureTLS(dbConfig *mysql.Config, opts TLSOptions) (*TLSFiles, error) {
	if !opts.IsSet() {
		return nil, nil
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	switch dbConfig.TLSConfig {
	case "", "true":
	default:
		return nil, fmt.Errorf("the connection URI sets tls=%s, which conflicts with the datastore TLS options; remove the tls parameter from the URI", dbConfig.TLSConfig)
	}

	serverName := opts.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(dbConfig.Addr)
		if err != nil || host == "" {
			return nil, fmt.Errorf("unable to determine the server name to verify the MySQL server certificate against from address %q; set --datastore-tls-server-name", dbConfig.Addr)
		}
		serverName = host
	}

	files, err := newTLSFiles(opts, serverName)
	if err != nil {
		return nil, err
	}

	dbConfig.TLSConfig = ""
	dbConfig.TLS = files.clientConfig()
	return files, nil
}

// NewConnector returns a connector for dbConfig. With TLS files from
// MaybeConfigureTLS, every new connection is made with a TLS configuration
// built from the files as they are at that moment, so that a rotated CA
// bundle or client certificate is used without a restart; connections that
// are already open keep the one they were made with.
func NewConnector(dbConfig *mysql.Config, files *TLSFiles) (driver.Connector, error) {
	connector, err := mysql.NewConnector(dbConfig)
	if err != nil || files == nil {
		return connector, err
	}
	return &reloadingTLSConnector{config: dbConfig.Clone(), files: files}, nil
}

type reloadingTLSConnector struct {
	config *mysql.Config
	files  *TLSFiles
}

func (c *reloadingTLSConnector) Connect(ctx context.Context) (driver.Conn, error) {
	config := c.config.Clone()
	config.TLS = c.files.clientConfig()
	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, err
	}
	return connector.Connect(ctx)
}

func (c *reloadingTLSConnector) Driver() driver.Driver {
	return &mysql.MySQLDriver{}
}

// fileStamp identifies the version of a file on disk.
type fileStamp struct {
	modTime time.Time
	size    int64
	missing bool
}

// TLSFiles holds the last good CA bundle and key pair loaded from disk and
// reloads them when the files change.
type TLSFiles struct {
	opts       TLSOptions
	serverName string

	mu     sync.Mutex
	stamps []fileStamp      // GUARDED_BY(mu)
	cert   *tls.Certificate // GUARDED_BY(mu)
	roots  *x509.CertPool   // GUARDED_BY(mu)
}

func newTLSFiles(opts TLSOptions, serverName string) (*TLSFiles, error) {
	f := &TLSFiles{opts: opts, serverName: serverName}
	f.stamps = f.stat()
	cert, roots, err := f.load()
	if err != nil {
		return nil, err
	}
	f.cert, f.roots = cert, roots
	return f, nil
}

func (f *TLSFiles) paths() []string {
	return []string{f.opts.CAPath, f.opts.CertPath, f.opts.KeyPath}
}

func (f *TLSFiles) stat() []fileStamp {
	paths := f.paths()
	stamps := make([]fileStamp, len(paths))
	for i, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			stamps[i] = fileStamp{missing: true}
			continue
		}
		stamps[i] = fileStamp{modTime: info.ModTime(), size: info.Size()}
	}
	return stamps
}

// load parses every configured file and returns nothing unless all of them
// parse, so that a half-written pair is never used.
func (f *TLSFiles) load() (*tls.Certificate, *x509.CertPool, error) {
	var roots *x509.CertPool
	if f.opts.CAPath != "" {
		pem, err := os.ReadFile(f.opts.CAPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read datastore TLS CA bundle: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, nil, fmt.Errorf("no PEM certificates found in datastore TLS CA bundle %s", f.opts.CAPath)
		}
	}

	var cert *tls.Certificate
	if f.opts.CertPath != "" {
		pair, err := tls.LoadX509KeyPair(f.opts.CertPath, f.opts.KeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to load datastore TLS client certificate and key: %w", err)
		}
		cert = &pair
	}

	return cert, roots, nil
}

// current returns the CA bundle and key pair to use for a handshake,
// reloading them first if any file changed since the last attempt. A failed
// reload is logged and the previous ones are kept; it is retried when the
// files change again.
func (f *TLSFiles) current() (*tls.Certificate, *x509.CertPool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	stamps := f.stat()
	if !stampsEqual(stamps, f.stamps) {
		f.stamps = stamps
		cert, roots, err := f.load()
		if err != nil {
			log.Warn().Err(err).Msg("unable to reload datastore TLS files; continuing with the previously loaded ones")
		} else {
			f.cert, f.roots = cert, roots
			log.Info().Msg("reloaded datastore TLS files")
		}
	}

	return f.cert, f.roots
}

func stampsEqual(a, b []fileStamp) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].missing != b[i].missing || a[i].size != b[i].size || !a[i].modTime.Equal(b[i].modTime) {
			return false
		}
	}
	return true
}

// clientConfig returns a tls.Config for a new connection with the current
// CA bundle and key pair. The server certificate is verified by crypto/tls
// against the CA bundle (the system roots when none is configured) and the
// server name.
func (f *TLSFiles) clientConfig() *tls.Config {
	cert, roots := f.current()
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: f.serverName,
		RootCAs:    roots,
	}

	if cert != nil {
		// GetClientCertificate rather than Certificates: crypto/tls only sends
		// one of Certificates when its chain names a CA the server lists as
		// acceptable, and the server may list only a root that the chain in
		// the file does not reach. The server is the one to decide.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}

	return config
}
