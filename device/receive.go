/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/wire"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			// check size of packet

			packet := bufsArrs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4])

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.buffer = bufsArrs[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if !device.acceptsInitiationSize(len(packet)) {
					continue
				}

			case MessageResponseType:
				if !device.acceptsResponseSize(len(packet)) {
					continue
				}

			case MessageCookieReplyType:
				if !device.acceptsCookieReplySize(len(packet)) {
					continue
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	/* See RoutineEncryption: one buffer per worker, sliced to the AEAD's nonce
	 * length, with only the counter field ever written. */
	var nonce [MaxTransportNonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			aead := elem.keypair.receive
			counted := nonce[:aead.NonceSize()]
			binary.LittleEndian.PutUint64(counted[TransportNonceCounterOffset:], elem.counter)

			_, err := aead.Open(content[:0], counted, content, nil)
			if err != nil {
				elem.packet = nil
			} else {
				/* Two different lengths come off the packet, and they were
				 * previously the same constant only because both happen to be
				 * 16: the header at the front, and the AEAD's tag at the
				 * back. */
				elem.packet = elem.packet[MessageTransportOffsetContent:]
				elem.packet = elem.packet[:len(elem.packet)-aead.Overhead()]
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		/* The suite and layout the inbound packet was framed under, resolved
		 * once from its length and then used for every step: mac1, mac2, the
		 * cookie reply and the message itself. Declared here because a goto
		 * cannot jump over a declaration in the same block. */
		var (
			elemSuite  *suite.Suite
			elemLayout wire.Layout
			ok         bool
		)

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			/* The index comes out of the packet before the suite is known,
			 * which is the opposite order from an initiation and is what makes
			 * a cookie reply routable at all. Its length cannot select a suite,
			 * since two suites can frame a reply of the same size, but it does
			 * not have to: the reply names the index its recipient chose, so
			 * the recipient reaches the suite through the peer. */
			receiver, ok := wire.CookieReplyReceiver(elem.packet)
			if !ok {
				device.log.Verbosef("Cookie reply too short to carry an index")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.endpoint.DstToString())
				/* The cookie was encrypted under the suite of the handshake
				 * that provoked it, which is the one this peer has in force.
				 * That suite's layout is also how the reply is framed, so it
				 * decodes the packet as well as decrypting the cookie. */
				s, layout := peer.handshake.suiteInForce()
				if s == nil {
					device.log.Verbosef("Cookie response for a peer with no handshake in flight")
					goto skip
				}
				reply, err := layout.ParseCookieReply(elem.packet)
				if err != nil {
					device.log.Verbosef("Failed to decode cookie reply: %v", err)
					goto skip
				}
				if !peer.cookieGenerator.ConsumeReply(s, reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			/* Which suite framed this packet is settled by its length, before
			 * anything about it is authenticated, because mac1's own length is
			 * a property of that suite. The same suite is then used to parse
			 * and consume the message below, so the packet cannot be MAC'd
			 * under one suite and decoded under another. */
			if elem.msgType == MessageInitiationType {
				elemSuite, elemLayout, ok = device.suiteForInitiationSize(len(elem.packet))
			} else {
				elemSuite, elemLayout, ok = device.suiteForResponseSize(len(elem.packet))
			}
			if !ok {
				device.log.Errorf("No accepted suite frames a %d byte handshake message", len(elem.packet))
				goto skip
			}

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elemSuite, elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elemSuite, elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(elemSuite, elemLayout, &elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			msg, err := elemLayout.ParseInitiation(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message: %v", err)
				goto skip
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(elemSuite, msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			msg, err := elemLayout.ParseResponse(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message: %v", err)
				goto skip
			}

			// consume response

			peer := device.ConsumeMessageResponse(elemSuite, msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.packet == nil {
				// decryption failed
				continue
			}

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}

			validTailPacket = i
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpointFromPacket(elem.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

			if len(elem.packet) == 0 {
				device.log.Verbosef("%v - Receiving keepalive packet", peer)
				continue
			}
			dataPacketReceived = true

			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
					continue
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(elem.packet) {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
					continue
				}

			default:
				device.log.Verbosef("Packet with invalid IP version from %v", peer)
				continue
			}

			bufs = append(bufs, elem.buffer[:MessageTransportOffsetContent+len(elem.packet)])
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)
			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		device.PutInboundElementsContainer(elemsContainer)
	}
}
