package ima

import (
	"bytes"
	"crypto"
	"fmt"
)

type Integrity struct {
	attested  int64  // number of attested bytes of IMA measurement list bytes i.e. starting offset for next measurement list verification
	aggregate []byte // cumulative hash of processed IMA measurements
	tpm       *TPM
	PcrIndex  uint32 // index of PCR reserved to store IMA measurements

	TemplateHashAlgo crypto.Hash // hash algorithm used for template hash computation
	FileHashAlgo     crypto.Hash // hash algorithm used for file hash computation
}

func NewIntegrity(pcrIndex uint32, templateHashAlgo, fileHashAlgo crypto.Hash, tpm *TPM, attested int64) (*Integrity, error) {
	i := &Integrity{
		attested:         attested,
		aggregate:        make([]byte, templateHashAlgo.Size()),
		tpm:              tpm,
		PcrIndex:         pcrIndex,
		TemplateHashAlgo: templateHashAlgo,
		FileHashAlgo:     fileHashAlgo,
	}
	if !i.isPCRHashAlgo() {
		return nil, fmt.Errorf("invalid template hash algorithm configuration: %v", templateHashAlgo)
	}
	if !i.isFileHashAlgo() {
		return nil, fmt.Errorf("invalid file hash algorithm configuration: %v", fileHashAlgo)
	}
	if !i.IsValidPCRIndex() {
		return nil, fmt.Errorf("invalid PCR index for IMA measurements: %d", pcrIndex)
	}
	return i, nil
}

func (i *Integrity) isFileHashAlgo() bool {
	switch i.FileHashAlgo {
	case crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func (i *Integrity) IsValidPCRIndex() bool {
	return i.PcrIndex >= MinPCRIndex && i.PcrIndex <= MaxPCRIndex
}

func (i *Integrity) IsValidHashConfig() bool {
	return i.isPCRHashAlgo() && i.isFileHashAlgo()
}

func (i *Integrity) TemplateHashSize() int {
	return i.TemplateHashAlgo.Size()
}

func (i *Integrity) FileHashSize() int {
	return i.FileHashAlgo.Size()
}

func (i *Integrity) Aggregate() []byte {
	return i.aggregate
}

func (i *Integrity) Offset() int64 {
	return i.attested
}

func (i *Integrity) Extend(templateHash []byte) error {
	hash := i.TemplateHashAlgo.New()

	toExtend := append(i.aggregate, templateHash...)
	toHashLen := len(toExtend)
	n, err := hash.Write(toExtend)
	if n != toHashLen {
		return fmt.Errorf("failed to write data to hash buffer: wrote only %d < %d bytes", n, toHashLen)
	}
	if err != nil {
		return fmt.Errorf("failed to write data to hash buffer: %v", err)
	}

	i.aggregate = hash.Sum(nil)
	return nil
}

func (i *Integrity) Check(expectedAggregate []byte) error {
	if !bytes.Equal(i.aggregate, expectedAggregate) {
		return fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match expected value")
	}
	return nil
}

func (i *Integrity) CheckFromPCR() error {
	if i.tpm == nil {
		return fmt.Errorf("TPM is not initialized")
	}
	if !i.tpm.IsOpen() {
		return fmt.Errorf("TPM is not open")
	}
	pcrs, err := i.tpm.ReadPCRs([]int{int(i.PcrIndex)}, i.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to read PCR %d from TPM: %v", i.PcrIndex, err)
	}
	expectedAggregate, ok := pcrs[i.PcrIndex]
	if !ok {
		return fmt.Errorf("PCR %d not found in TPM read result", i.PcrIndex)
	}
	return i.Check(expectedAggregate)
}

func (i *Integrity) IncrementAttested(n int64) {
	i.attested += n
}

func (i *Integrity) isPCRHashAlgo() bool {
	switch i.TemplateHashAlgo {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}
