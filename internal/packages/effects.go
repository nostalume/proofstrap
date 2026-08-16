package packages

import (
	"context"
	"fmt"
	"strings"

	"github.com/nostalume/proofstrap/internal/linux"
)

type effects struct {
	identify func(string) (linux.Identity, error)
	run      func(context.Context, linux.Identity, []string, []byte) (linux.Result, error)
}

func linuxEffects() effects {
	return effects{identify: linux.Identify, run: linux.Run}
}

func nativeDiagnostic(action string, result linux.Result, err error) string {
	if err != nil {
		return fmt.Sprintf("%s: %v", action, err)
	}
	detail := result.Stderr
	if len(detail) == 0 {
		detail = result.Stdout
	}
	if len(detail) > 768 {
		detail = detail[len(detail)-768:]
	}
	text := strings.Join(strings.Fields(strings.ToValidUTF8(string(detail), "�")), " ")
	if text == "" {
		return fmt.Sprintf("%s: native exit %d", action, result.ExitCode)
	}
	return fmt.Sprintf("%s: native exit %d: %s", action, result.ExitCode, text)
}
