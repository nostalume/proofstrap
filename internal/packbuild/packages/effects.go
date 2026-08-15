package packages

import (
	"context"

	"github.com/nostalume/proofstrap/internal/linuxexec"
)

type effects struct {
	identify func(string) (linuxexec.Identity, error)
	run      func(context.Context, linuxexec.Identity, []string, []byte) (linuxexec.Result, error)
}

func linuxEffects() effects {
	return effects{identify: linuxexec.Identify, run: linuxexec.Run}
}
