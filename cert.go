package minica

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
)

const (
	certificateType = "CERTIFICATE"
	privateKeyType  = "RSA PRIVATE KEY"
)

func genKey(size int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		panic(err)
	}
	return key
}

func ReadKey(in io.Reader) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func WriteKey(key *rsa.PrivateKey, out io.Writer) error {
	return pem.Encode(out, &pem.Block{
		Type:    privateKeyType,
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	})
}

func ReadCert(in io.Reader) (*x509.Certificate, error) {
	b, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	return x509.ParseCertificate(block.Bytes)
}

func WriteCert(b []byte, out io.Writer) error {
	return pem.Encode(out, &pem.Block{
		Type:    certificateType,
		Headers: nil,
		Bytes:   b,
	})
}

func signCertificate(cert, parent *x509.Certificate, certPublicKey *rsa.PublicKey, parentPrivateKey *rsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, cert, parent, certPublicKey, parentPrivateKey)
}

// generate 20 random bytes for serial numbers
func getNewSerialNumber() *big.Int {
	randBytes := make([]byte, 20)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}

	i := big.NewInt(0)
	i.SetBytes(randBytes)
	return i
}
