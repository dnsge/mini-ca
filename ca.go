package minica

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path"
	"time"
)

type CertificateData struct {
	Subject   pkix.Name
	NotBefore time.Time
	NotAfter  time.Time
}

type BundlePaths struct {
	KeyPath  string
	CertPath string
}

type CertificateAuthority struct {
	Key    *rsa.PrivateKey
	Cert   *x509.Certificate
	signed []byte
}

func formatCombinedPath(directory, name, extension string) string {
	return path.Join(directory, name+"."+extension)
}

func LoadCertificateAuthority(directory, name string) (*CertificateAuthority, *BundlePaths, error) {
	keyPath := formatCombinedPath(directory, name, "pem")
	certPath := formatCombinedPath(directory, name, "crt")

	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open key file: %w", err)
	}

	key, err := ReadKey(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}

	certFile, err := os.Open(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open cert file: %w", err)
	}

	cert, err := ReadCert(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}

	return &CertificateAuthority{
			Key:    key,
			Cert:   cert,
			signed: nil,
		}, &BundlePaths{
			KeyPath:  keyPath,
			CertPath: certPath,
		}, nil
}

func MakeCertificateAuthority(data *CertificateData) (*CertificateAuthority, error) {
	key := genKey(2048)
	cert := &x509.Certificate{
		SerialNumber:          getNewSerialNumber(),
		Subject:               data.Subject,
		NotBefore:             data.NotBefore,
		NotAfter:              data.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	signedCert, err := signCertificate(cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		Key:    key,
		Cert:   cert,
		signed: signedCert,
	}, nil
}

func MakeIntermediateAuthority(data *CertificateData, parent *CertificateAuthority) (*CertificateAuthority, error) {
	key := genKey(2048)
	cert := &x509.Certificate{
		SerialNumber:          getNewSerialNumber(),
		Subject:               data.Subject,
		NotBefore:             data.NotBefore,
		NotAfter:              data.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	signedCert, err := signCertificate(cert, parent.Cert, &key.PublicKey, parent.Key)
	if err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		Key:    key,
		Cert:   cert,
		signed: signedCert,
	}, nil
}

func MakeLeafCertificate(data *CertificateData, parent *CertificateAuthority, dnsNames []string) (*CertificateAuthority, error) {
	key := genKey(2048)
	cert := &x509.Certificate{
		SerialNumber:   getNewSerialNumber(),
		Subject:        data.Subject,
		NotBefore:      data.NotBefore,
		NotAfter:       data.NotAfter,
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		DNSNames:       dnsNames,
	}

	signedCert, err := signCertificate(cert, parent.Cert, &key.PublicKey, parent.Key)
	if err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		Key:    key,
		Cert:   cert,
		signed: signedCert,
	}, nil
}

func (ca *CertificateAuthority) Save(directory, name string) (*BundlePaths, error) {
	if ca.signed == nil {
		return nil, fmt.Errorf("cannot save imported certificate authority")
	}

	// create directory if it does not already exist
	if !directoryExists(directory) {
		if err := os.Mkdir(directory, 0o777); err != nil {
			return nil, fmt.Errorf("ca directory creation: %w", err)
		}
	}

	keyPath := formatCombinedPath(directory, name, "pem")
	certPath := formatCombinedPath(directory, name, "crt")

	// create Key file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca Key creation: %w", err)
	}
	defer keyFile.Close()

	// chmod Key file
	if err := keyFile.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("ca Key chmod: %w", err)
	}

	// write private Key to Key file
	if err := WriteKey(ca.Key, keyFile); err != nil {
		return nil, fmt.Errorf("ca Key write: %w", err)
	}

	// create certificate file
	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("ca Cert creation: %w", err)
	}
	defer keyFile.Close()

	// chmod certificate file
	if err := certFile.Chmod(0o644); err != nil {
		return nil, fmt.Errorf("ca Cert chmod: %w", err)
	}

	// write signed certificate to certificate file
	if err := WriteCert(ca.signed, certFile); err != nil {
		return nil, fmt.Errorf("ca Cert write: %w", err)
	}

	return &BundlePaths{
		KeyPath:  keyPath,
		CertPath: certPath,
	}, nil
}

func directoryExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return s.IsDir()
}
