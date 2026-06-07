package prover

import (
	"fmt"
	"strings"
)

type HashMode string

const (
	HashModeV0SHA256 HashMode = "v0-sha256"
	HashModeV1MiMC   HashMode = "v1-mimc"
)

const DefaultHashMode = HashModeV0SHA256

func ParseHashMode(raw string) (HashMode, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DefaultHashMode, nil
	}

	mode := HashMode(value)
	switch mode {
	case HashModeV0SHA256, HashModeV1MiMC:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown hash mode %q", raw)
	}
}

func (m HashMode) String() string {
	if m == "" {
		return string(DefaultHashMode)
	}
	return string(m)
}

func (m HashMode) IsV1() bool {
	return m == HashModeV1MiMC
}
