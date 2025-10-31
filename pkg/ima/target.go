package ima

type Target interface {
	CheckMatch(t Template) (bool, error)
	GetMatches() Matches
}

type Matches struct {
	Matches map[MeasurementType][]Measurement
}

func NewMatches() *Matches {
	return &Matches{
		Matches: make(map[MeasurementType][]Measurement),
	}
}

func (m *Matches) AddMatch(measurementType MeasurementType, measurement Measurement) {
	m.Matches[measurementType] = append(m.Matches[measurementType], measurement)
}

func (m *Matches) RemoveMatch(measurementType MeasurementType, measurement Measurement) {
	measurements := m.Matches[measurementType]
	for i, msr := range measurements {
		if msr == measurement {
			m.Matches[measurementType] = append(measurements[:i], measurements[i+1:]...)
			break
		}
	}
}

type Measurement struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type MeasurementType int

const (
	ContainerRuntime MeasurementType = iota
	Pod
	Container
	Host
)

func (measurementType MeasurementType) String() string {
	switch measurementType {
	case ContainerRuntime:
		return "containerRuntime"
	case Pod:
		return "pod"
	case Container:
		return "container"
	case Host:
		return "host"
	default:
		return "unknown_measurement_type"
	}
}
