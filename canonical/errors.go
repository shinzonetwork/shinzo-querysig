package canonical

import "errors"

// Sentinel errors wrapped by the dynamic, context-carrying errors this
// package returns, so callers can match on them with errors.Is.
var (
	ErrVariablesNotSingleValue = errors.New("variables must be a single JSON object")
	ErrVariablesNotObject      = errors.New("variables must be a JSON object")
	ErrInvalidNumber           = errors.New("invalid number")
	ErrNumberTooLarge          = errors.New("number magnitude >= 2^53; send large values as strings")
)
