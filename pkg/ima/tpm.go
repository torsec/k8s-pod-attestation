package ima

import (
	"crypto"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
)

const MaxPCRIndex = 23
const MinPCRIndex = 10

type TPM struct {
	rwc  io.ReadWriteCloser
	Path string
}

func NewTPM(rwc io.ReadWriteCloser, path string) *TPM {
	return &TPM{
		rwc:  rwc,
		Path: path,
	}
}

func (t *TPM) IsOpen() bool {
	return t.rwc != nil
}

func (t *TPM) Open() error {
	var err error
	t.rwc, err = tpmutil.OpenTPM(t.Path)
	if err != nil {
		return fmt.Errorf("unable to open TPM: %v", err)
	}
	return nil
}

func (t *TPM) Close() error {
	err := t.rwc.Close()
	if err != nil {
		return fmt.Errorf("failed to close TPM: %w", err)
	}
	return nil
}

func (t *TPM) ReadPCRs(indexes []int, hashAlgo crypto.Hash) (map[uint32][]byte, error) {
	pcrHashAlgo, err := getPCRHashAlgo(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("unable to get PCR hash algorithm: %w", err)
	}
	pcrSelection := tpm2.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: indexes,
	}
	pcrs, err := client.ReadPCRs(t.rwc, pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("unable to read PCRs: %v", err)
	}

	return pcrs.GetPcrs(), err
}

func getPCRHashAlgo(algo crypto.Hash) (tpm2.Algorithm, error) {
	tpmAlgo, err := tpm2.HashToAlgorithm(algo)
	if err != nil {
		return tpm2.AlgUnknown, fmt.Errorf("unable to determine hash algorithm: %v", err)
	}

	switch tpmAlgo {
	case tpm2.AlgSHA1, tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512:
		return tpmAlgo, nil
	default:
		return tpm2.AlgUnknown, fmt.Errorf("hash algorithm not supported for PCR bank: %v", tpmAlgo)
	}
}
