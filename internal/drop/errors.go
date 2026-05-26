package drop

import "errors"

var (
	ErrNotFound = errors.New("dead-drop: not found")
	ErrReadOnly = errors.New("dead-drop: read-only")
	ErrAuth     = errors.New("dead-drop: auth failed")
)
