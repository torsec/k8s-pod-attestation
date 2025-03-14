package agent

import (
	"crypto/x509"
)

type Server struct {
	agentHost             string
	agentPort             int
	tlsCertificate        *x509.Certificate
	workerId              string
	TPMPath               string
	IMAMeasurementLogPath string
}

func (s *Server) Init() {

}
