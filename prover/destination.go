package prover

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/zhenjb/gazk/contract"
)

const DestinationHashDomainTag = "zkdex/withdrawAddr/v0"

func validateDestinationHashBinding(req contract.ProveRequest) error {
	for i, withdrawal := range req.SettlementUpdate.Withdrawals {
		destination := strings.TrimSpace(withdrawal.Destination)
		if destination == "" {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d].destination is required", ErrInvalidProveRequest, i)
		}

		expected, err := DestinationHashFor(destination)
		if err != nil {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d] destinationHash derivation: %v", ErrInvalidProveRequest, i, err)
		}

		if withdrawal.DestinationHash != expected {
			return fmt.Errorf(
				"%w: settlementUpdate.withdrawals[%d].destinationHash mismatch: got %q, expected %q",
				ErrInvalidProveRequest,
				i,
				withdrawal.DestinationHash,
				expected,
			)
		}
	}

	return nil
}

func DestinationHashFor(destination string) (string, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", fmt.Errorf("destination is empty")
	}

	payload := DestinationHashDomainTag + "|" + destination
	sum := sha256.Sum256([]byte(payload))

	return "0x" + hex.EncodeToString(sum[:]), nil
}
