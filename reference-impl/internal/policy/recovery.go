// Package policy implements monotonic policy state for rollback defense.
package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// RecoveryConfig defines startup recovery behavior for policy state.
type RecoveryConfig struct {
	Store    StateStore
	Validator *Validator

	// AllowBootstrap permits initializing state when no persisted record exists.
	AllowBootstrap bool

	// BootstrapRecord is required when AllowBootstrap is true and no persisted
	// state exists. It should be a quorum-signed genesis record.
	BootstrapRecord *types.PolicyStateRecord
}

// RecoverPolicyState loads and validates policy state at startup.
//
// Behavior:
// 1. Load latest persisted state.
// 2. If found, enforce monotonic + quorum validation.
// 3. If not found and bootstrap allowed, validate + persist bootstrap record.
// 4. Otherwise fail closed.
func RecoverPolicyState(ctx context.Context, cfg RecoveryConfig) (*types.PolicyStateRecord, error) {
	if cfg.Store == nil {
		return nil, errors.New("policy: recovery store is required")
	}
	if cfg.Validator == nil {
		return nil, errors.New("policy: recovery validator is required")
	}

	record, err := cfg.Store.LoadLatestPolicyState(ctx)
	if err == nil {
		if err := cfg.Validator.AcceptTransition(record); err != nil {
			return nil, fmt.Errorf("policy: persisted record rejected: %w", err)
		}
		return record, nil
	}

	if !errors.Is(err, ErrStateNotFound) {
		return nil, err
	}

	if !cfg.AllowBootstrap {
		return nil, ErrStateNotFound
	}
	if cfg.BootstrapRecord == nil {
		return nil, errors.New("policy: bootstrap mode enabled but bootstrap record is nil")
	}

	if err := cfg.Validator.AcceptTransition(cfg.BootstrapRecord); err != nil {
		return nil, fmt.Errorf("policy: bootstrap record rejected: %w", err)
	}
	if err := cfg.Store.SavePolicyState(ctx, cfg.BootstrapRecord); err != nil {
		return nil, fmt.Errorf("policy: persist bootstrap record: %w", err)
	}

	return cfg.BootstrapRecord, nil
}
