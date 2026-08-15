package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/nostalume/proofstrap/internal/host"
	"github.com/nostalume/proofstrap/internal/identity"
	"github.com/nostalume/proofstrap/internal/packbuild/packages"
	"github.com/nostalume/proofstrap/internal/services"
)

func prepareOperation(value operation) (preparedOperation, error) {
	switch value.kind {
	case "package":
		return preparePackage(value.review)
	case "identity":
		return prepareIdentity(value.review)
	case "host":
		return prepareHost(value.review)
	case "service":
		return prepareService(value.review)
	default:
		return preparedOperation{}, fmt.Errorf("unknown operation kind %q", value.kind)
	}
}

func preparePackage(data []byte) (preparedOperation, error) {
	review, err := packages.DecodeReview(data)
	if err != nil {
		return preparedOperation{}, err
	}
	return preparedOperation{
		effectLimit: packageTimeout, postLimit: packagePostTimeout,
		admit: func(ctx context.Context) (operationEffect, error) {
			selection := packages.SelectExact(ctx, review.Backend())
			selected, ok := selection.(packages.Selected)
			if !ok {
				if value, indeterminate := selection.(packages.Indeterminate); indeterminate {
					return nil, fmt.Errorf("package selection is indeterminate: %s", value.Detail())
				}
				return nil, fmt.Errorf("%w: reviewed package backend is unavailable or ambiguous", packages.ErrStale)
			}
			operation, err := packages.Reconstruct(review, selected)
			if err != nil {
				return nil, err
			}
			return func(effectCtx context.Context, freshPost postContext) (bool, error) {
				result, err := operation.Apply(effectCtx, freshPost, selected)
				return result.Started(), err
			}, nil
		},
	}, nil
}

func prepareIdentity(data []byte) (preparedOperation, error) {
	review, err := identity.DecodeReview(data)
	if err != nil {
		return preparedOperation{}, err
	}
	capabilities := review.Capabilities()
	return preparedOperation{
		effectLimit: commandTimeout, postLimit: ordinaryTimeout,
		admit: func(ctx context.Context) (operationEffect, error) {
			selected, err := identity.Select(ctx, capabilities)
			if err != nil {
				if errors.Is(err, identity.ErrUnsupported) {
					return nil, fmt.Errorf("%w: %v", identity.ErrStale, err)
				}
				return nil, err
			}
			operation, err := identity.Reconstruct(review, selected)
			if err != nil {
				return nil, err
			}
			return func(effectCtx context.Context, freshPost postContext) (bool, error) {
				result, err := operation.Apply(effectCtx, freshPost, selected)
				return result.Started(), err
			}, nil
		},
	}, nil
}

func prepareHost(data []byte) (preparedOperation, error) {
	review, err := host.DecodeReview(data)
	if err != nil {
		return preparedOperation{}, err
	}
	axis := review.Axis()
	return preparedOperation{
		effectLimit: ordinaryTimeout, postLimit: ordinaryTimeout,
		admit: func(ctx context.Context) (operationEffect, error) {
			var selected *host.Selected
			var err error
			if axis == host.TimezonePersistence {
				selected, err = host.SelectTimezone(ctx)
			} else {
				selected, err = host.SelectHostname(ctx)
			}
			if err != nil {
				if errors.Is(err, host.ErrUnsupported) || errors.Is(err, host.ErrUnauthorized) {
					return nil, fmt.Errorf("%w: %v", host.ErrStale, err)
				}
				return nil, err
			}
			operation, err := host.Reconstruct(review, selected)
			if err != nil {
				return nil, err
			}
			return func(effectCtx context.Context, freshPost postContext) (bool, error) {
				result, err := operation.Apply(effectCtx, freshPost, selected)
				return result.Started(), err
			}, nil
		},
	}, nil
}

func prepareService(data []byte) (preparedOperation, error) {
	review, err := services.DecodeReview(data)
	if err != nil {
		return preparedOperation{}, err
	}
	principal, user := review.Principal()
	return preparedOperation{
		effectLimit: commandTimeout, postLimit: ordinaryTimeout,
		admit: func(ctx context.Context) (operationEffect, error) {
			var selected *services.Selected
			var err error
			if user {
				selected, err = services.SelectUser(ctx, principal)
			} else {
				selected, err = services.SelectSystem(ctx)
			}
			if err != nil {
				if errors.Is(err, services.ErrUnsupported) || errors.Is(err, services.ErrAmbiguous) || errors.Is(err, services.ErrUnauthorized) {
					return nil, fmt.Errorf("%w: %v", services.ErrStale, err)
				}
				return nil, err
			}
			operation, err := services.Reconstruct(review, selected)
			if err != nil {
				return nil, err
			}
			return func(effectCtx context.Context, freshPost postContext) (bool, error) {
				result, err := operation.Apply(effectCtx, freshPost, selected)
				return result.Started(), err
			}, nil
		},
	}, nil
}

func isStale(err error) bool {
	return errors.Is(err, packages.ErrStale) || errors.Is(err, identity.ErrStale) ||
		errors.Is(err, host.ErrStale) || errors.Is(err, services.ErrStale)
}
