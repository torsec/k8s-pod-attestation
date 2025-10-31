package ima

import "fmt"

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

func NewCGPathValidator(measurementList *MeasurementList, integrity *Integrity, target *CGPathTarget) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &CGPathTemplate{},
		Integrity:       integrity,
		Target:          target,
	}
}

func (h *Validator) ValidateTemplateFields(expected int) error {
	err := h.Entry.ValidateFieldsLen(expected)
	if err != nil {
		return fmt.Errorf("failed to validate template fields: %v", err)
	}
	return nil
}

func (h *Validator) SetAttestationOffset() error {
	err := h.MeasurementList.SetOffset(h.Integrity.attested)
	if err != nil {
		return fmt.Errorf("failed to set attestation offset in measurement list: %v", err)
	}
	return nil
}

func (h *Validator) MeasurementListTPMAttestation() error {
	if !h.Integrity.tpm.IsOpen() {
		return fmt.Errorf("TPM is not open")
	}
	// read PCR value from TPM
	pcrs, err := h.Integrity.tpm.ReadPCRs([]int{int(h.Integrity.pcrIndex)}, h.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to read PCR from TPM: %v", err)
	}
	expected := pcrs[h.Integrity.pcrIndex]
	return h.MeasurementListAttestation(expected)
}

func (h *Validator) MeasurementListAttestation(expected []byte) error {
	if len(expected) != h.Integrity.TemplateHashSize() {
		return fmt.Errorf("expected aggregate size does not match template hash size")
	}

	if !h.MeasurementList.IsReady() {
		return fmt.Errorf("IMA measurement list is not ready for attestation")
	}

	var err error
	// process measurement list entries until EOF
	for {
		h.Entry.Clear()

		err = h.Entry.ParseEntry(h.MeasurementList, h.Integrity.pcrIndex, h.Integrity.TemplateHashSize(), h.Integrity.FileHashSize())
		if err != nil {
			return fmt.Errorf("failed to parse entry: %v", err)
		}

		if h.Target != nil {
			_, err = h.Target.CheckMatch(h.Entry)
			if err != nil {
				return fmt.Errorf("failed to match target: %v", err)
			}
		}

		err = h.Integrity.Extend(h.Entry.GetTemplateHash())
		if err != nil {
			return fmt.Errorf("failed to extend entry: %v", err)
		}

		err = h.Integrity.Check(expected)
		if err == nil {
			h.Integrity.IncrementAttested(int64(h.Entry.Size()))
			return nil
		}
	}
}
