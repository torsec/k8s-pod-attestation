package ima

import (
	"fmt"
	"github.com/modern-go/reflect2"
)

type Validator struct {
	MeasurementList *MeasurementList
	Entry           Template
	Integrity       *Integrity
	Target          Target
}

func NewValidator(measurementList *MeasurementList, entry Template, integrity *Integrity, target Target) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           entry,
		Integrity:       integrity,
		Target:          target,
	}
}

func NewCgPathValidator(measurementList *MeasurementList, integrity *Integrity, target *CgPathTarget) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &CgPathTemplate{},
		Integrity:       integrity,
		Target:          target,
	}
}

func NewNgValidator(measurementList *MeasurementList, integrity *Integrity, target *NgTarget) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &NgTemplate{},
		Integrity:       integrity,
		Target:          target,
	}
}

func (v *Validator) ValidateTemplateFields(expected int) error {
	err := v.Entry.ValidateFieldsLen(expected)
	if err != nil {
		return fmt.Errorf("failed to validate template fields: %v", err)
	}
	return nil
}

func (v *Validator) SetAttestationOffset() error {
	err := v.MeasurementList.SetOffset(v.Integrity.attested)
	if err != nil {
		return fmt.Errorf("failed to set attestation offset in measurement list: %v", err)
	}
	return nil
}

func (v *Validator) MeasurementListTPMAttestation() error {
	if !v.Integrity.tpm.IsOpen() {
		return fmt.Errorf("TPM is not open")
	}
	// read PCR value from TPM
	pcrs, err := v.Integrity.tpm.ReadPCRs([]int{int(v.Integrity.pcrIndex)}, v.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to read PCR from TPM: %v", err)
	}
	expected := pcrs[v.Integrity.pcrIndex]
	return v.MeasurementListAttestation(expected)
}

func (v *Validator) MeasurementListAttestation(expected []byte) error {
	if len(expected) != v.Integrity.TemplateHashSize() {
		return fmt.Errorf("expected aggregate size does not match template hash size")
	}

	if !v.MeasurementList.IsReady() {
		return fmt.Errorf("IMA measurement list is not ready for attestation")
	}

	var err error
	// process measurement list entries until EOF
	for {
		v.Entry.Clear()

		err = v.Entry.ParseEntry(v.MeasurementList, v.Integrity.pcrIndex, v.Integrity.TemplateHashSize(), v.Integrity.FileHashSize())
		if err != nil {
			return fmt.Errorf("failed to parse entry: %v", err)
		}

		if !reflect2.IsNil(v.Target) {
			_, err = v.Target.CheckMatch(v.Entry)
			if err != nil {
				return fmt.Errorf("failed to match target: %v", err)
			}
		}

		err = v.Integrity.Extend(v.Entry.GetTemplateHash())
		if err != nil {
			return fmt.Errorf("failed to extend entry: %v", err)
		}
		err = v.Integrity.Check(expected)
		if err == nil {
			v.Integrity.IncrementAttested(v.MeasurementList.ptr)
			return nil
		}
	}
}
