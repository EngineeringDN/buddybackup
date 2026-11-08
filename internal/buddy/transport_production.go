//go:build !integration

package buddy

import (
	"errors"
	"os"
)

func NetworkFromEnvironment(dir string) (Network, error) {
	if os.Getenv("BUDDY_TEST_TRANSPORT") != "" {
		return nil, errors.New("Testtransport ist in Produktions-Builds nicht verfügbar.")
	}
	return NewTSNetwork(dir), nil
}
