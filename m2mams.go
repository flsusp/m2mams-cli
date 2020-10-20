package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/flsusp/m2mams-signer-go/m2mams/kprovider"
	"github.com/flsusp/m2mams-signer-go/m2mams/signer"
	"github.com/urfave/cli/v2"
	"os"
	"os/user"
)

func main() {
	var keyProvider string

	usr, err := user.Current()
	panicOnError(err)

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "kprovider",
				Aliases:     []string{"kp"},
				Value:       "file",
				Usage:       "from where retrieve the signing keys (file | env)",
				Destination: &keyProvider,
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "generate",
				Aliases:   []string{"g"},
				Usage:     "generates a key pair for signing JWT tokens",
				UsageText: "m2mams generate <uid> <context> <key pair>",
				Description: "Generates a key pair that can be used to sign tokens using M2MAMS. The output for generating the " +
					"keys is given by the <context> and <key pair> parameters. With these parameters the files generated to" +
					"store the keys would be:\n\n" +
					"   `$HOME/.<context>/<uid>/<key pair>`: with the private key\n" +
					"   `$HOME/.<context>/<uid>/<key pair>.pub.pem`: with the public key in the PEM format\n\n" +
					"   These files are generated as described by https://github.com/flsusp/m2mams.\n\n" +
					"   The default values for <context> and <key pair> are `m2mams` and `id_rsa`, respectively. The value for " +
					"<uid> is used to identify the user at the verifier / server side and usually it is an email address.",
				Action: func(c *cli.Context) error {
					uid := c.Args().Get(0)
					if uid == "" {
						panic(fmt.Errorf("<uid> is required"))
					}

					context := coalesce(c.Args().Get(1), "m2mams")
					keyPair := coalesce(c.Args().Get(2), "id_rsa")

					dir := fmt.Sprintf("%s/.%s/%s", usr.HomeDir, context, uid)
					os.MkdirAll(dir, 0700)

					privateKeyFile := fmt.Sprintf("%s/%s", dir, keyPair)
					publicKeyFile := fmt.Sprintf("%s.pub.pem", privateKeyFile)

					reader := rand.Reader
					bitSize := 4096

					key, err := rsa.GenerateKey(reader, bitSize)
					panicOnError(err)

					savePEMKey(privateKeyFile, key)
					savePublicPEMKey(publicKeyFile, key.PublicKey)

					protectFiles(privateKeyFile, publicKeyFile)

					return nil
				},
			},
			{
				Name:      "sign",
				Aliases:   []string{"s"},
				Usage:     "generates a signed JWT token",
				UsageText: "m2mams sign [--kprovider file|env] <uid> <context> <key pair>",
				Description: "Generates a JWT signed token getting the keys from the given `--kprovider` and identifying the " +
					"key file or environment variable by the <uid>, <context> and <key pair> parameters.\n\n" +
					"   If the `--kprovider file` we expect to get the private key used for generating a signed token at" +
					"`$HOME/.<context>/<uid>/<key pair>`. This file can be generated as described by https://github.com/flsusp/m2mams.\n\n" +
					"   If the `--kprovider env` we expect to have an environment variables named `<context>_<key pair>_PK` " +
					"(all uppercase letters) with the private key to be used in the PEM format.",
				Action: func(c *cli.Context) error {
					uid := c.Args().Get(0)
					if uid == "" {
						panic(fmt.Errorf("<uid> is required"))
					}

					context := coalesce(c.Args().Get(1), "m2mams")
					keyPair := coalesce(c.Args().Get(2), "id_rsa")

					var kp kprovider.KeyProvider
					if keyProvider == "file" {
						kp = kprovider.NewLocalFileSystemKProvider()
					} else if keyProvider == "env" {
						kp = kprovider.NewEnvironmentVariableKProvider()
					} else {
						return cli.Exit("Invalid --kprovider value", 1)
					}

					s := signer.Signer{
						KeyProvider: kp,
						Uid:         uid,
						Context:     context,
						KeyPair:     keyPair,
					}

					tk, err := s.GenerateSignedToken()
					panicOnError(err)

					fmt.Println(tk)

					return nil
				},
			},
		},
		Name:    "M2MAMS CLI",
		Usage:   "CLI that can be used to generate key pairs, generate signed JWT tokens or verify the generated tokens",
		Version: "1.0.0",
	}

	err = app.Run(os.Args)
	panicOnError(err)
}

func coalesce(first string, second string) string {
	if first != "" {
		return first
	}
	return second
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func protectFiles(privateKeyFile string, publicKeyFile string) {
	os.Chmod(privateKeyFile, 0400)
	os.Chmod(publicKeyFile, 0440)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	panicOnError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	panicOnError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	panicOnError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	panicOnError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	panicOnError(err)
}
