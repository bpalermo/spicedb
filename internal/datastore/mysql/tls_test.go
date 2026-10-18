//go:build datastore

package mysql

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/authzed/spicedb/internal/datastore/common"
	mysqlCommon "github.com/authzed/spicedb/internal/datastore/mysql/common"
	"github.com/authzed/spicedb/internal/datastore/mysql/migrations"
	"github.com/authzed/spicedb/internal/datastore/mysql/version"
	datastorecfg "github.com/authzed/spicedb/pkg/cmd/datastore/dsconfig"
	"github.com/authzed/spicedb/pkg/datastore"
	"github.com/authzed/spicedb/pkg/datastore/migration"
	"github.com/authzed/spicedb/pkg/datastore/options"
	"github.com/authzed/spicedb/pkg/datastore/queryshape"
	"github.com/authzed/spicedb/pkg/migrate"
	"github.com/authzed/spicedb/pkg/tuple"
)

const (
	tlsTestUser = "spicedb"
	// tlsTestServerName is the only name in the server certificate, so that
	// a connection to the container's address is verified against the
	// configured server name.
	tlsTestServerName = "mysql.test"
)

// certAuthority is a certificate authority. chain is its own certificate
// followed by those of the CAs above it, up to but not including the root;
// it is empty for a root.
type certAuthority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

func newCertAuthority(t *testing.T, name string, parent *certAuthority) *certAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          tlsSerialNumber(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	ca := &certAuthority{cert: cert, key: key}
	if parent != nil {
		ca.chain = append([]*x509.Certificate{cert}, parent.chain...)
	}
	return ca
}

func tlsSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	return serial
}

func certificatesPEM(certs ...*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return out.Bytes()
}

// issue returns a leaf signed by the CA followed by the CA's chain, and the
// leaf's key.
func (ca *certAuthority) issue(t *testing.T, subject pkix.Name, server bool) (chainPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: tlsSerialNumber(t),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{tlsTestServerName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return certificatesPEM(append([]*x509.Certificate{leaf}, ca.chain...)...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func spireSubject(commonName string) pkix.Name {
	return pkix.Name{Country: []string{"US"}, Organization: []string{"SPIRE"}, CommonName: commonName}
}

// runMySQLRequiringClientCertificates starts a MySQL server that accepts only
// TLS connections, trusts only clientRoot for client certificates, and has a
// passwordless user authenticated by its client certificate subject. It
// returns the host:port of the server.
func runMySQLRequiringClientCertificates(t *testing.T, mysqlVersion string, serverCA, clientRoot *certAuthority) string {
	t.Helper()
	serverCert, serverKey := serverCA.issue(t, pkix.Name{CommonName: "mysql"}, true)

	conf := `[mysqld]
require_secure_transport=ON
ssl_ca=/etc/mysql/certs/ca.pem
ssl_cert=/etc/mysql/certs/server-cert.pem
ssl_key=/etc/mysql/certs/server-key.pem
`
	// Init scripts run over the local socket, which require_secure_transport allows.
	initSQL := fmt.Sprintf(`CREATE DATABASE spicedb;
CREATE USER '%[1]s'@'%%' REQUIRE SUBJECT '/C=US/O=SPIRE/CN=spicedb';
GRANT ALL ON spicedb.* TO '%[1]s'@'%%';
`, tlsTestUser)

	file := func(path string, contents []byte) testcontainers.ContainerFile {
		return testcontainers.ContainerFile{ContainerFilePath: path, Reader: bytes.NewReader(contents), FileMode: 0o644}
	}

	container, err := tcmysql.Run(t.Context(),
		"mirror.gcr.io/library/mysql:"+mysqlVersion,
		tcmysql.WithPassword("secret"),
		testcontainers.WithFiles(
			file("/etc/mysql/conf.d/tls.cnf", []byte(conf)),
			file("/etc/mysql/certs/ca.pem", certificatesPEM(clientRoot.cert)),
			file("/etc/mysql/certs/server-cert.pem", serverCert),
			file("/etc/mysql/certs/server-key.pem", serverKey),
			file("/docker-entrypoint-initdb.d/tls.sql", []byte(initSQL)),
		),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)

	endpoint, err := container.PortEndpoint(t.Context(), "3306/tcp", "")
	require.NoError(t, err)
	return endpoint
}

type clientFiles struct {
	opts mysqlCommon.TLSOptions
}

func newClientFiles(t *testing.T, serverCA *certAuthority) *clientFiles {
	t.Helper()
	dir := t.TempDir()
	f := &clientFiles{opts: mysqlCommon.TLSOptions{
		CAPath:     filepath.Join(dir, "ca.pem"),
		CertPath:   filepath.Join(dir, "cert.pem"),
		KeyPath:    filepath.Join(dir, "key.pem"),
		ServerName: tlsTestServerName,
	}}
	require.NoError(t, os.WriteFile(f.opts.CAPath, certificatesPEM(serverCA.cert), 0o600))
	return f
}

// write replaces the client certificate and key the way spiffe-helper does:
// each file atomically, one after the other.
func (f *clientFiles) write(t *testing.T, ca *certAuthority, subject pkix.Name) {
	t.Helper()
	chainPEM, keyPEM := ca.issue(t, subject, false)
	for _, file := range []struct {
		path     string
		contents []byte
	}{{f.opts.CertPath, chainPEM}, {f.opts.KeyPath, keyPEM}} {
		tmp := file.path + ".tmp"
		require.NoError(t, os.WriteFile(tmp, file.contents, 0o600))
		// Move the modification time forward so a rewrite within the file
		// system's timestamp granularity is still seen as a change.
		next := time.Now()
		if info, err := os.Stat(file.path); err == nil && !info.ModTime().Before(next) {
			next = info.ModTime().Add(time.Second)
		}
		require.NoError(t, os.Chtimes(tmp, next, next))
		require.NoError(t, os.Rename(tmp, file.path))
	}
}

func (f *clientFiles) migrationConfig(uri string) *migration.Config {
	return &migration.Config{
		DatastoreURI:  uri,
		TLSCAPath:     f.opts.CAPath,
		TLSCertPath:   f.opts.CertPath,
		TLSKeyPath:    f.opts.KeyPath,
		TLSServerName: f.opts.ServerName,
	}
}

func TestMySQLClientCertificateTLS(t *testing.T) {
	for _, mysqlVersion := range []string{version.MinimumSupportedMySQLVersion, "9"} {
		t.Run("mysql "+mysqlVersion, func(t *testing.T) {
			testMySQLClientCertificateTLS(t, mysqlVersion)
		})
	}
}

func testMySQLClientCertificateTLS(t *testing.T, mysqlVersion string) {
	serverCA := newCertAuthority(t, "server CA", nil)
	// The server trusts only the root, two levels above the CA that issues
	// the client certificate, so the client must send the whole chain.
	root := newCertAuthority(t, "root", nil)
	spireCA := newCertAuthority(t, "SPIRE CA", newCertAuthority(t, "intermediate", root))

	endpoint := runMySQLRequiringClientCertificates(t, mysqlVersion, serverCA, root)
	// No password: the user is authenticated by its certificate subject.
	uri := fmt.Sprintf("%s@tcp(%s)/spicedb?parseTime=true", tlsTestUser, endpoint)

	versionOf := func(t *testing.T, cfg *migration.Config) error {
		driver, err := newMigrationDriverFromConfig(t.Context(), cfg)
		require.NoError(t, err)
		defer driver.Close(t.Context())
		_, err = driver.Version(t.Context())
		return err
	}

	t.Run("without TLS options the connection is refused", func(t *testing.T) {
		// The server refuses either for the insecure transport or for the
		// missing certificate, depending on which it checks first.
		err := versionOf(t, &migration.Config{DatastoreURI: uri})
		require.Error(t, err)
		require.Regexp(t, "insecure transport are prohibited|Access denied", err.Error())
	})

	t.Run("a client certificate with another subject is refused", func(t *testing.T) {
		files := newClientFiles(t, serverCA)
		files.write(t, spireCA, spireSubject("someone-else"))
		require.ErrorContains(t, versionOf(t, files.migrationConfig(uri)), "Access denied")
	})

	t.Run("a server certificate for another name is refused", func(t *testing.T) {
		files := newClientFiles(t, serverCA)
		files.write(t, spireCA, spireSubject("spicedb"))
		cfg := files.migrationConfig(uri)
		cfg.TLSServerName = "other.test"
		require.ErrorContains(t, versionOf(t, cfg), "certificate is valid for mysql.test, not other.test")

		// Without a server name the host of the URI is verified, and the
		// certificate is not valid for it either.
		cfg.TLSServerName = ""
		require.ErrorContains(t, versionOf(t, cfg), "tls: failed to verify certificate")
	})

	t.Run("migrates and serves with the client certificate", func(t *testing.T) {
		files := newClientFiles(t, serverCA)
		files.write(t, spireCA, spireSubject("spicedb"))

		driver, err := newMigrationDriverFromConfig(t.Context(), files.migrationConfig(uri))
		require.NoError(t, err)
		defer driver.Close(t.Context())
		require.NoError(t, migrations.Manager.Run(t.Context(), driver, migrate.Head, migrate.LiveRun))

		cfg := *datastorecfg.DefaultDatastoreConfig()
		cfg.Engine = Engine
		cfg.URI = uri
		cfg.ReadReplicaURIs = []string{uri}
		cfg.TLSCAPath = files.opts.CAPath
		cfg.TLSCertPath = files.opts.CertPath
		cfg.TLSKeyPath = files.opts.KeyPath
		cfg.TLSServerName = files.opts.ServerName
		cfg.EnableDatastoreMetrics = false

		ds, err := newDatastoreFromConfig(t.Context(), cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = ds.Close() })

		ready, err := ds.ReadyState(t.Context())
		require.NoError(t, err)
		require.True(t, ready.IsReady, ready.Message)

		rel := tuple.MustParse("document:readme#viewer@user:tom")
		rev, err := common.WriteRelationships(t.Context(), ds, tuple.UpdateOperationCreate, rel)
		require.NoError(t, err)

		iter, err := ds.SnapshotReader(rev).QueryRelationships(t.Context(), datastore.RelationshipsFilter{
			OptionalResourceType: "document",
		}, options.WithQueryShape(queryshape.Varying))
		require.NoError(t, err)
		var found []string
		for r, err := range iter {
			require.NoError(t, err)
			found = append(found, tuple.MustString(r))
		}
		require.Equal(t, []string{tuple.MustString(rel)}, found)
	})

	t.Run("a rotated certificate is used by new connections", func(t *testing.T) {
		files := newClientFiles(t, serverCA)
		files.write(t, spireCA, spireSubject("spicedb"))

		ds, err := newMySQLDatastore(t.Context(), uri, primaryInstanceID,
			WithTLS(files.opts), WithEnablePrometheusStats(false), GCEnabled(false))
		require.NoError(t, err)
		t.Cleanup(func() { _ = ds.Close() })
		// Close every connection after use, so each ping opens a new one.
		ds.db.SetMaxIdleConns(0)

		ping := func() error { return ds.db.PingContext(t.Context()) }
		require.NoError(t, ping())

		// A certificate the server does not accept shows the files are
		// re-read.
		files.write(t, spireCA, spireSubject("someone-else"))
		require.ErrorContains(t, ping(), "Access denied")

		// A new intermediate and SPIRE CA under the same root, with a new
		// leaf, are picked up too.
		files.write(t, newCertAuthority(t, "next SPIRE CA", newCertAuthority(t, "next intermediate", root)), spireSubject("spicedb"))
		require.NoError(t, ping())
	})
}
