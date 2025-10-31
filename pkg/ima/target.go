package ima

type Target interface {
	CheckMatch(t Template) (bool, error)
	GetMatches() map[MeasurementType][]Measurement
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
