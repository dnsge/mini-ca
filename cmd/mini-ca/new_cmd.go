package main

import (
	"fmt"
	minica "github.com/dnsge/mini-ca"
	"github.com/urfave/cli/v2"
)

func runNewCommand(c *cli.Context) error {
	if c.NArg() == 0 {
		fmt.Printf("No certificate type specified\n\n")
		return cli.ShowSubcommandHelp(c)
	}

	certType := c.Args().First()
	switch certType {
	case "root":
		if c.IsSet("parent") {
			fmt.Printf("Warning: \"parent\" flag has no effect for root certificates\n")
		}
	case "mid", "leaf":
		if !c.IsSet("parent") {
			fmt.Printf("Flag \"parent\" must be set for %q certificates\n\n", certType)
			return cli.ShowSubcommandHelp(c)
		}
	default:
		fmt.Printf("Invalid certificate type %q: expected \"root\", \"mid\", or \"leaf\"\n\n", certType)
		return cli.ShowSubcommandHelp(c)
	}

	if certType == "root" {
		return genRoot(c)
	} else if certType == "mid" {
		return genMid(c)
	} else {
		return genLeaf(c)
	}
}

const customTimeFormat = "2006-01-02 15:04:05 MST"

func promptCertData() *minica.CertificateData {
	return &minica.CertificateData{
		Subject:   minica.PromptSubject(),
		NotBefore: minica.PromptDate("Not Before (YYYY-MM-DD hh:mm:ss UTC): ", customTimeFormat),
		NotAfter:  minica.PromptDate("Not After (YYYY-MM-DD hh:mm:ss UTC):  ", customTimeFormat),
	}
}

func genRoot(c *cli.Context) error {
	fmt.Printf("Creating a new root certificate authority\n\n")

	outputName := c.String("name")
	outputDir := c.String("out")
	certData := promptCertData()

	ca, err := minica.MakeCertificateAuthority(certData)
	if err != nil {
		return fmt.Errorf("creating ca: %w", err)
	}

	paths, err := ca.Save(outputDir, outputName)
	if err != nil {
		return err
	}

	fmt.Println("\nSuccessfully created new root certificate authority")
	fmt.Printf("Saved private key to %q\n", paths.KeyPath)
	fmt.Printf("Saved certificate to %q\n", paths.CertPath)

	return nil
}

func genMid(c *cli.Context) error {
	fmt.Printf("Creating a new intermediate certificate authority\n\n")

	outputName := c.String("name")
	outputDir := c.String("out")
	inputName := c.String("parent")
	inputDir := c.String("in")

	parentCa, _, err := minica.LoadCertificateAuthority(inputDir, inputName)
	if err != nil {
		return err
	}

	certData := promptCertData()

	ca, err := minica.MakeIntermediateAuthority(certData, parentCa)
	if err != nil {
		return fmt.Errorf("creating ca: %w", err)
	}

	paths, err := ca.Save(outputDir, outputName)
	if err != nil {
		return err
	}

	fmt.Println("\nSuccessfully created new intermediate certificate authority")
	fmt.Printf("Saved private key to %q\n", paths.KeyPath)
	fmt.Printf("Saved certificate to %q\n", paths.CertPath)

	return nil
}

func promptDNSNames() []string {
	fmt.Println("SAN DNS Names (empty to stop):")
	var names []string
	n := 1
	for {
		answer := minica.PromptString(fmt.Sprintf("DNS.%d = ", n))
		if answer == "" {
			break
		}
		names = append(names, answer)
		n++
	}

	return names
}

func genLeaf(c *cli.Context) error {
	fmt.Printf("Creating a new leaf certificate\n\n")

	outputName := c.String("name")
	outputDir := c.String("out")
	inputName := c.String("parent")
	inputDir := c.String("in")

	parentCa, _, err := minica.LoadCertificateAuthority(inputDir, inputName)
	if err != nil {
		return err
	}

	certData := promptCertData()
	fmt.Println()
	dnsNames := promptDNSNames()

	ca, err := minica.MakeLeafCertificate(certData, parentCa, dnsNames)
	if err != nil {
		return fmt.Errorf("creating ca: %w", err)
	}

	paths, err := ca.Save(outputDir, outputName)
	if err != nil {
		return err
	}

	fmt.Println("\nSuccessfully created new leaf certificate")
	fmt.Printf("Saved private key to %q\n", paths.KeyPath)
	fmt.Printf("Saved certificate to %q\n", paths.CertPath)

	return nil
}
