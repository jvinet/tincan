package drop

import "errors"

var (
	ErrNotFound = errors.New("dead-drop: not found")
	ErrReadOnly = errors.New("dead-drop: read-only")
	ErrAuth     = errors.New("dead-drop: auth failed")
	// ErrForbidden is distinct from ErrAuth: the request authenticated (or was
	// anonymous) but is not permitted to read the object — typically a private
	// object or a missing public-read grant rather than a credentials problem.
	ErrForbidden = errors.New("dead-drop: access denied")
)
