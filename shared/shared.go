package shared

const (
	SocketFd = 3

	// Failure error codes from the sandbox child.
	BadArguments      = 189
	NoNewPrivsFailed  = 190
	NewListenerFailed = 191
	SendmsgFailed     = 192
	ExecCommandFailed = 193
)
