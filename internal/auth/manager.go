// Package auth contains the authentication system.
package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/headers"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/google/uuid"
)

const (
	// PauseAfterError is the pause to apply after an authentication failure.
	PauseAfterError = 2 * time.Second

	rtspAuthRealm = "IPCAM"
)

// Protocol is a protocol.
type Protocol string

// protocols.
const (
	ProtocolRTSP   Protocol = "rtsp"
	ProtocolRTMP   Protocol = "rtmp"
	ProtocolHLS    Protocol = "hls"
	ProtocolWebRTC Protocol = "webrtc"
	ProtocolSRT    Protocol = "srt"
)

// Request is an authentication request.
type Request struct {
	User   string
	Pass   string
	IP     net.IP
	Action conf.AuthAction

	// only for ActionPublish and ActionRead
	Path        string
	Protocol    Protocol
	ID          *uuid.UUID
	Query       string
	RTSPRequest *base.Request
	RTSPBaseURL *base.URL
	RTSPNonce   string
}

// Error is a authentication error.
type Error struct {
	Message string
}

// Error implements the error interface.
func (e Error) Error() string {
	return "authentication failed: " + e.Message
}

func userHasPermission(u *conf.AuthInternalUser, req *Request) bool {
	for _, perm := range u.Permissions {
		if perm.Action == req.Action {
			if perm.Action == conf.AuthActionPublish ||
				perm.Action == conf.AuthActionRead ||
				perm.Action == conf.AuthActionPlayback {
				switch {
				case perm.Path == "any":
					return true

				case strings.HasPrefix(perm.Path, "~"):
					regexp, err := regexp.Compile(perm.Path[1:])
					if err == nil && regexp.MatchString(req.Path) {
						return true
					}

				case perm.Path == req.Path:
					return true
				}
			} else {
				return true
			}
		}
	}

	return false
}

// Manager is the authentication manager.
type Manager struct {
	Method          conf.AuthMethod
	InternalUsers   []conf.AuthInternalUser
	HTTPAddress     string
	RTSPAuthMethods []headers.AuthMethod

	mutex sync.RWMutex
}

// ReloadInternalUsers reloads InternalUsers.
func (m *Manager) ReloadInternalUsers(u []conf.AuthInternalUser) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.InternalUsers = u
}

// Authenticate authenticates a request.
func (m *Manager) Authenticate(req *Request) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// if this is a RTSP request, fill username and password
	var rtspAuthHeader headers.Authorization
	if req.RTSPRequest != nil {
		err := rtspAuthHeader.Unmarshal(req.RTSPRequest.Header["Authorization"])
		if err == nil {
			switch rtspAuthHeader.Method {
			case headers.AuthBasic:
				req.User = rtspAuthHeader.BasicUser
				req.Pass = rtspAuthHeader.BasicPass

			case headers.AuthDigestMD5:
				req.User = rtspAuthHeader.Username

			default:
				return Error{Message: "unsupported RTSP authentication method"}
			}
		}
	}

	if m.Method == conf.AuthMethodInternal {
		return m.authenticateInternal(req, &rtspAuthHeader)
	}
	return m.authenticateHTTP(req)
}

func (m *Manager) authenticateInternal(req *Request, rtspAuthHeader *headers.Authorization) error {
	for _, u := range m.InternalUsers {
		if err := m.authenticateWithUser(req, rtspAuthHeader, &u); err == nil {
			return nil
		}
	}

	return Error{Message: "authentication failed"}
}

func (m *Manager) authenticateWithUser(
	req *Request,
	rtspAuthHeader *headers.Authorization,
	u *conf.AuthInternalUser,
) error {
	if u.User != "any" && !u.User.Check(req.User) {
		return Error{Message: "wrong user"}
	}

	if !u.IPs.Contains(req.IP) {
		return Error{Message: "IP not allowed"}
	}

	if !userHasPermission(u, req) {
		return Error{Message: "user doesn't have permission to perform action"}
	}

	if u.User != "any" {
		if req.RTSPRequest != nil && rtspAuthHeader.Method == headers.AuthDigestMD5 {
			err := auth.Validate(
				req.RTSPRequest,
				string(u.User),
				string(u.Pass),
				req.RTSPBaseURL,
				m.RTSPAuthMethods,
				rtspAuthRealm,
				req.RTSPNonce)
			if err != nil {
				return Error{Message: err.Error()}
			}
		} else if !u.Pass.Check(req.Pass) {
			return Error{Message: "invalid credentials"}
		}
	}

	return nil
}

func (m *Manager) authenticateHTTP(req *Request) error {
	enc, _ := json.Marshal(struct {
		IP       string     `json:"ip"`
		User     string     `json:"user"`
		Password string     `json:"password"`
		Action   string     `json:"action"`
		Path     string     `json:"path"`
		Protocol string     `json:"protocol"`
		ID       *uuid.UUID `json:"id"`
		Query    string     `json:"query"`
	}{
		IP:       req.IP.String(),
		User:     req.User,
		Password: req.Pass,
		Action:   string(req.Action),
		Path:     req.Path,
		Protocol: string(req.Protocol),
		ID:       req.ID,
		Query:    req.Query,
	})

	res, err := http.Post(m.HTTPAddress, "application/json", bytes.NewReader(enc))
	if err != nil {
		return Error{Message: fmt.Sprintf("HTTP request failed: %v", err)}
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		if resBody, err := io.ReadAll(res.Body); err == nil && len(resBody) != 0 {
			return Error{Message: fmt.Sprintf("server replied with code %d: %s", res.StatusCode, string(resBody))}
		}

		return Error{Message: fmt.Sprintf("server replied with code %d", res.StatusCode)}
	}

	return nil
}
