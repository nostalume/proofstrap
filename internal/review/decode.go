package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var ErrMultiple = errors.New("multiple JSON values")

type TrailingError struct{ Err error }

func (err TrailingError) Error() string { return err.Err.Error() }
func (err TrailingError) Unwrap() error { return err.Err }

func DecodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrMultiple
		}
		return TrailingError{Err: err}
	}
	return nil
}
