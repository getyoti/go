package create

import (
	"github.com/getyoti/yoti-go-sdk/v3/docscan/session/create/check"
	"github.com/getyoti/yoti-go-sdk/v3/docscan/session/create/task"
)

// SessionSpecification is the definition for the Doc Scan Session to be created
type SessionSpecification struct {
	// ClientSessionTokenTTL Client-session-token time-to-live to apply to the created Session
	ClientSessionTokenTTL int `json:"client_session_token_ttl,omitempty"`

	// ResourcesTTL time-to-live used for all Resources created in the course of the session
	ResourcesTTL int `json:"resources_ttl,omitempty"`

	// UserTrackingID the User tracking ID, used to track returning users
	UserTrackingID string `json:"user_tracking_id,omitempty"`

	// Notifications for configuring call-back messages
	Notifications *NotificationConfig `json:"notifications,omitempty"`

	// RequestedChecks is a slice of check.RequestedChecker objects defining the Checks to be performed on each Document
	RequestedChecks []check.RequestedChecker `json:"requested_checks,omitempty"`

	// RequestedTasks is a slice of task.RequestedTask objects defining the Tasks to be performed on each Document
	RequestedTasks []*task.RequestedTask `json:"requested_tasks,omitempty"`

	// SdkConfig retrieves the SDK configuration set of the session specification
	SdkConfig *SDKConfig `json:"sdk_config,omitempty"`
}

// SessionSpecificationBuilder builds the SessionSpecification struct
type SessionSpecificationBuilder struct {
	clientSessionTokenTTL int
	resourcesTTL          int
	userTrackingID        string
	notifications         *NotificationConfig
	requestedChecks       []check.RequestedChecker
	requestedTasks        []*task.RequestedTask
	sdkConfig             *SDKConfig
}

// NewSessionSpecificationBuilder creates a new SessionSpecificationBuilder
func NewSessionSpecificationBuilder() *SessionSpecificationBuilder {
	return &SessionSpecificationBuilder{}
}

// WithClientSessionTokenTTL sets the client session token TTL (time-to-live)
func (b *SessionSpecificationBuilder) WithClientSessionTokenTTL(clientSessionTokenTTL int) *SessionSpecificationBuilder {
	b.clientSessionTokenTTL = clientSessionTokenTTL
	return b
}

// WithResourcesTtl sets the client session token TTL (time-to-live)
func (b *SessionSpecificationBuilder) WithResourcesTtl(resourcesTTL int) *SessionSpecificationBuilder {
	b.resourcesTTL = resourcesTTL
	return b
}

// WithUserTrackingID sets the user tracking ID
func (b *SessionSpecificationBuilder) WithUserTrackingID(userTrackingID string) *SessionSpecificationBuilder {
	b.userTrackingID = userTrackingID
	return b
}

// WithNotifications sets the NotificationConfig
func (b *SessionSpecificationBuilder) WithNotifications(notificationConfig *NotificationConfig) *SessionSpecificationBuilder {
	b.notifications = notificationConfig
	return b
}

// WithRequestedCheck adds a RequestedChecker to the required checks
func (b *SessionSpecificationBuilder) WithRequestedCheck(requestedCheck check.RequestedChecker) *SessionSpecificationBuilder {
	b.requestedChecks = append(b.requestedChecks, requestedCheck)
	return b
}

// WithRequestedTask adds a RequestedTask to the required tasks
func (b *SessionSpecificationBuilder) WithRequestedTask(requestedTask *task.RequestedTask) *SessionSpecificationBuilder {
	b.requestedTasks = append(b.requestedTasks, requestedTask)
	return b
}

// WithSDKConfig sets the SDKConfig
func (b *SessionSpecificationBuilder) WithSDKConfig(SDKConfig *SDKConfig) *SessionSpecificationBuilder {
	b.sdkConfig = SDKConfig
	return b
}

// Build builds the SessionSpecification struct
func (b *SessionSpecificationBuilder) Build() (*SessionSpecification, error) {
	return &SessionSpecification{
		b.clientSessionTokenTTL,
		b.resourcesTTL,
		b.userTrackingID,
		b.notifications,
		b.requestedChecks,
		b.requestedTasks,
		b.sdkConfig,
	}, nil
}