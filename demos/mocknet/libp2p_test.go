package mocknet

import (
	"testing"

	"github.com/coinbase/cb-mpc/cb-mpc-go/network"
	"github.com/stretchr/testify/assert"
)

func TestLibRunner(t *testing.T) {
	// Number of players
	n := 3

	// Create mocknet runner
	runner, err := NewMocknetRunner(n)
	assert.NoError(t, err)

	// Connect all nodes
	err = runner.Connect()
	assert.NoError(t, err)

	// Create transports
	transports, err := runner.CreateTransports()
	assert.NoError(t, err)

	// Run dealer protocol
	err = RunDealerProtocol(transports, n, 1, 1024, 10)
	assert.NoError(t, err)

	// Run MTA protocol
	err = RunMTAProtocol(transports, n, 5)
	assert.NoError(t, err)
}
