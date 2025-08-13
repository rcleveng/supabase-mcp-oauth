package oauth

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type Code struct {
	ID           string
	Code         string
	ClientID     string
	CodeVerifier string
	ExpiresAt    time.Time
	AccessToken  string
	RefreshToken string
	UserID       string
	Email        string
}

type CodeServer struct {
	driverType       string
	connectionString string
	codes            map[string]Code
	codesMutex       sync.RWMutex
}

func NewCodeServer(driverType string, connectionString string) (*CodeServer, error) {
	switch driverType {
	case "memory":
		return &CodeServer{
			driverType:       driverType,
			connectionString: connectionString,
			codes:            make(map[string]Code),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported driver type: %s", driverType)
	}
}

func (s *CodeServer) RegisterCode(code Code) error {
	switch s.driverType {
	case "memory":
		s.codesMutex.Lock()
		s.codes[code.ID] = code
		s.codesMutex.Unlock()
		slog.Info("registered code", "id", code.ID, "clientID", code.ClientID, "email", code.Email)
		return nil
	default:
		return fmt.Errorf("unsupported driver type: %s", s.driverType)
	}
}

func (s *CodeServer) FindCode(id string, clientID string, codeVerifier string) (Code, error) {
	switch s.driverType {
	case "memory":
		s.codesMutex.RLock()
		code, ok := s.codes[id]
		s.codesMutex.RUnlock()
		if !ok {
			return Code{}, fmt.Errorf("code not found")
		}
		if code.ClientID != clientID {
			return Code{}, fmt.Errorf("client ID mismatch")
		}
		if code.CodeVerifier != codeVerifier {
			// TODO - figure this out.
			slog.Error("code verifier mismatch", "id", id, "clientID", clientID, "codeVerifier", codeVerifier)
		}
		if code.ExpiresAt.Before(time.Now()) {
			// remove from the map too.
			s.codesMutex.Lock()
			delete(s.codes, id)
			s.codesMutex.Unlock()
			return Code{}, fmt.Errorf("code expired")
		}
		return code, nil
	default:
		return Code{}, fmt.Errorf("no database configured for driver type: %s", s.driverType)
	}
}
