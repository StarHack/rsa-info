package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: rsa-info <path_to_pem_file>")
		os.Exit(1)
	}

	pemFilePath := os.Args[1]
	err := parsePEMFile(pemFilePath)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func parsePEMFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}

		fmt.Printf("This is an RSA private key (%d-bit).\n", privateKey.N.BitLen())
		fmt.Println("Private Key Modulus:", privateKey.N)
		fmt.Println("Private Key Exponent:", privateKey.D)
		fmt.Println("Primes:", privateKey.Primes)
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return err
			}
		}

		if rsaPublicKey, ok := publicKey.(*rsa.PublicKey); ok {
			fmt.Printf("This is an RSA public key (%d-bit).\n", rsaPublicKey.N.BitLen())
			fmt.Println("Public Key Modulus:", rsaPublicKey.N)
			fmt.Println("Public Key Exponent:", rsaPublicKey.E)
		} else {
			return errors.New("not an RSA public key")
		}
	default:
		fmt.Println("Unsupported PEM type:", block.Type)
	}
	return nil
}
