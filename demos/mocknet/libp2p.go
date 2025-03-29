package mocknet

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/maceip/cb-mpc/pkg/logger"
	"github.com/maceip/cb-mpc/pkg/party"
	"github.com/maceip/cb-mpc/pkg/protocol/dealer"
	"github.com/maceip/cb-mpc/pkg/protocol/player"
	"github.com/maceip/cb-mpc/pkg/protocol/triple/mta"
	"github.com/maceip/cb-mpc/pkg/transport"
)

const (
	protocolID      = "/cb-mpc/1.0.0"
	pubsubTopic     = "cb-mpc-pubsub"
	messageBuffSize = 1 << 20
)

// MocknetRunner manages the mocknet for running the protocol.
type MocknetRunner struct {
	net   mocknet.Mocknet
	hosts []host.Host
	psubs []*pubsub.PubSub
	topics []*pubsub.Topic
}

// NewMocknetRunner creates a new MocknetRunner.
func NewMocknetRunner(n int) (*MocknetRunner, error) {
	net := mocknet.New()
	
	// Create hosts and pubsub instances
	hosts := make([]host.Host, n)
	psubs := make([]*pubsub.PubSub, n)
	topics := make([]*pubsub.Topic, n)
	
	for i := 0; i < n; i++ {
		h, err := net.GenPeer()
		if err != nil {
			return nil, fmt.Errorf("failed to generate peer: %w", err)
		}
		hosts[i] = h
		
		// Create pubsub for each host
		ps, err := pubsub.NewGossipSub(context.Background(), h)
		if err != nil {
			return nil, fmt.Errorf("failed to create pubsub: %w", err)
		}
		psubs[i] = ps
		
		// Join pubsub topic
		topic, err := ps.Join(pubsubTopic)
		if err != nil {
			return nil, fmt.Errorf("failed to join topic: %w", err)
		}
		topics[i] = topic
	}
	
	return &MocknetRunner{
		net:   net,
		hosts: hosts,
		psubs: psubs,
		topics: topics,
	}, nil
}

// Connect connects all hosts in the mocknet.
func (m *MocknetRunner) Connect() error {
	return m.net.LinkAll()
}

// CreateTransports creates transport instances for each host.
func (m *MocknetRunner) CreateTransports() ([]transport.Transport, error) {
	transports := make([]transport.Transport, len(m.hosts))
	
	for i, h := range m.hosts {
		// Create a transport instance for each host using pubsub
		t, err := NewPubSubTransport(h, m.psubs[i], m.topics[i])
		if err != nil {
			return nil, fmt.Errorf("failed to create transport: %w", err)
		}
		transports[i] = t
	}
	
	return transports, nil
}

// PubSubTransport implements the transport.Transport interface using libp2p pubsub.
type PubSubTransport struct {
	host  host.Host
	ps    *pubsub.PubSub
	topic *pubsub.Topic
	sub   *pubsub.Subscription
	
	inbound  chan []byte
	outbound chan []byte
	
	parties map[party.ID]peer.ID
	peerToParty map[peer.ID]party.ID
	
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewPubSubTransport creates a new PubSubTransport.
func NewPubSubTransport(h host.Host, ps *pubsub.PubSub, topic *pubsub.Topic) (*PubSubTransport, error) {
	// Subscribe to the topic
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	t := &PubSubTransport{
		host:      h,
		ps:        ps,
		topic:     topic,
		sub:       sub,
		inbound:   make(chan []byte, messageBuffSize),
		outbound:  make(chan []byte, messageBuffSize),
		parties:   make(map[party.ID]peer.ID),
		peerToParty: make(map[peer.ID]party.ID),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// Start the message handler
	t.wg.Add(1)
	go t.handleMessages()
	
	// Start the message publisher
	t.wg.Add(1)
	go t.publishMessages()
	
	return t, nil
}

// handleMessages processes incoming pubsub messages
func (t *PubSubTransport) handleMessages() {
	defer t.wg.Done()
	
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			msg, err := t.sub.Next(t.ctx)
			if err != nil {
				if t.ctx.Err() == context.Canceled {
					return
				}
				log.Printf("error getting next message: %v", err)
				continue
			}
			
			// Skip messages published by this node
			if msg.ReceivedFrom == t.host.ID() {
				continue
			}
			
			select {
			case t.inbound <- msg.Data:
			default:
				log.Printf("inbound channel full, dropping message")
			}
		}
	}
}

// publishMessages sends outbound messages to the pubsub topic
func (t *PubSubTransport) publishMessages() {
	defer t.wg.Done()
	
	for {
		select {
		case <-t.ctx.Done():
			return
		case msg := <-t.outbound:
			err := t.topic.Publish(t.ctx, msg)
			if err != nil {
				log.Printf("error publishing message: %v", err)
			}
		}
	}
}

// Receive implements transport.Transport.
func (t *PubSubTransport) Receive() ([]byte, error) {
	select {
	case <-t.ctx.Done():
		return nil, fmt.Errorf("transport closed")
	case msg := <-t.inbound:
		return msg, nil
	}
}

// Send implements transport.Transport.
func (t *PubSubTransport) Send(msg []byte) error {
	select {
	case <-t.ctx.Done():
		return fmt.Errorf("transport closed")
	case t.outbound <- msg:
		return nil
	default:
		return fmt.Errorf("outbound channel full")
	}
}

// RegisterParty implements transport.Transport.
func (t *PubSubTransport) RegisterParty(id party.ID, addr string) error {
	// In pubsub transport, we map party IDs to peer IDs
	// Parse the peer ID from the address
	peerID, err := peer.Decode(addr)
	if err != nil {
		return fmt.Errorf("failed to decode peer ID: %w", err)
	}
	
	t.parties[id] = peerID
	t.peerToParty[peerID] = id
	
	return nil
}

// Close implements transport.Transport.
func (t *PubSubTransport) Close() error {
	t.cancel()
	t.wg.Wait()
	return t.sub.Cancel()
}

// RunDealerProtocol runs the dealer protocol with the given parameters.
func RunDealerProtocol(
	transports []transport.Transport,
	nPlayers int,
	t int,
	messageSize int,
	shares int,
) error {
	// Create dealer parameters
	dealers := make([]*dealer.Dealer, nPlayers)
	dids := make([]party.ID, nPlayers)

	// Initialize dealers
	for i := 0; i < nPlayers; i++ {
		dids[i] = party.ID(fmt.Sprintf("dealer-%d", i))
		dealers[i] = dealer.NewDealer(dids[i], transports[i])
	}

	// Run the dealer protocol
	fmt.Printf("Running dealer protocol with %d players, threshold %d, %d shares of size %d bytes\n",
		nPlayers, t, shares, messageSize)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	wg := &sync.WaitGroup{}
	
	// Start dealers
	for i := 0; i < nPlayers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			randomData := make([][]byte, shares)
			for j := 0; j < shares; j++ {
				randomData[j] = make([]byte, messageSize)
				rand.Read(randomData[j])
			}
			
			err := dealers[i].Run(ctx, party.IDSlice(dids), randomData, t)
			if err != nil {
				log.Printf("dealer %d failed: %v", i, err)
			}
		}()
	}
	
	wg.Wait()
	return nil
}

// RunMTAProtocol runs the MTA protocol with the given parameters.
func RunMTAProtocol(
	transports []transport.Transport,
	nPlayers int,
	iterations int,
) error {
	// Create MTA players
	players := make([]*player.Player, nPlayers)
	pids := make([]party.ID, nPlayers)
	
	// Initialize players
	for i := 0; i < nPlayers; i++ {
		pids[i] = party.ID(fmt.Sprintf("player-%d", i))
		players[i] = player.NewPlayer(pids[i], transports[i])
	}
	
	// Run the MTA protocol
	fmt.Printf("Running MTA protocol with %d players for %d iterations\n", nPlayers, iterations)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	wg := &sync.WaitGroup{}
	
	// Start players
	for i := 0; i < nPlayers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			err := players[i].RunProtocol(ctx, party.IDSlice(pids), &mta.Protocol{
				Iterations: iterations,
			})
			if err != nil {
				log.Printf("player %d failed: %v", i, err)
			}
		}()
	}
	
	wg.Wait()
	return nil
}
