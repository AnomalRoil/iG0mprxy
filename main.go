package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

var (
	allowList    *net.IPNet
	upstream     *net.Interface
	downstreams  = make(map[*net.Interface]int)
	mutex        sync.RWMutex
	activeGroups = make(map[string]chan struct{})
	mainConn     net.PacketConn
)

func SetAllowList(cidr string) (err error) {
	_, allowList, err = net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return nil
}

func IsAllowed(ip net.IP) bool {
	if allowList.Contains(ip) {
		return true
	}
	return false
}

func IgmpProcessor(ctx context.Context, ifi *net.Interface) {
	// Create a raw socket
	conn, err := net.ListenPacket("ip4:2", "0.0.0.0") // IGMP is IP protocol number 2
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetConn := ipv4.NewPacketConn(conn)

	// IGMP v3 is 224.0.0.22
	if err := packetConn.JoinGroup(ifi, &net.IPAddr{IP: net.IPv4(224, 0, 0, 22)}); err != nil {
		log.Fatal(err)
	}

	// Loop to receive packets
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		buf := make([]byte, 1500) // size of the largest packet
		n, _, src, err := packetConn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("Processing IGMP from ", src, " on ", ifi.Name)
		queries := processIGMP(buf[:n])
		mutex.Lock()
		for _, q := range queries {
			if q.action {
				if _, ok := activeGroups[q.mcast.String()]; !ok {
					activeGroups[q.mcast.String()] = groupProcessor(ctx, q.mcast)
				} else {
					log.Println("Ignoring request to join group already joined")
				}
			} else {
				if stopChan, ok := activeGroups[q.mcast.String()]; ok {
					// Signal the handler to stop and remove the channel from the map
					close(stopChan)
					delete(activeGroups, q.mcast.String())
				}
			}
		}
		mutex.Unlock()
	}
}

func processIGMP(input []byte) []processedQuery {
	if len(input) < 8 {
		log.Print("Packet too short to be a valid IGMP packet")
		return nil
	}

	// Convert the data to IGMP object
	igmp, err := parseIGMP(input)
	if err != nil {
		log.Print("Error parsing IGMP layer: ", err)
		return nil
	}

	var ret []processedQuery
	for _, groupRecord := range igmp.GroupRecords {
		if query := handleIGMPTypes(groupRecord.Type, groupRecord.MulticastAddress); query != nil {
			ret = append(ret, *query)
		}
	}

	return ret
}

func parseIGMP(input []byte) (*layers.IGMP, error) {
	packet := gopacket.NewPacket(input, layers.LayerTypeIGMP, gopacket.Default)
	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		return nil, fmt.Errorf("empty packet? IGMP Packet cannot be parsed")
	}
	// Convert the layer to IGMP object
	igmp, ok := igmpLayer.(*layers.IGMP)
	if !ok || igmp == nil {
		return nil, fmt.Errorf("unable to cast packet to IGMP type")
	}

	return igmp, nil
}

type processedQuery struct {
	mcast  net.IP
	action bool
}

func handleIGMPTypes(t layers.IGMPv3GroupRecordType, mcast net.IP) *processedQuery {
	fmt.Printf("> mcast addr %s : query=", mcast)
	defer fmt.Print("\n")

	switch t {
	case layers.IGMPIsIn:
		fmt.Print("MODE_IS_INCLUDE")
	case layers.IGMPIsEx:
		fmt.Print("MODE_IS_EXCLUDE")
	case layers.IGMPToIn:
		fmt.Print("CHANGE_TO_INCLUDE_MODE")
		if IsAllowed(mcast) {
			return &processedQuery{mcast, false}
		}
	case layers.IGMPToEx:
		fmt.Print("CHANGE_TO_EXCLUDE_MODE")
		if IsAllowed(mcast) {
			return &processedQuery{mcast, true}
		}
	case layers.IGMPAllow:
		fmt.Print("ALLOW_NEW_SOURCES")
	case layers.IGMPBlock:
		fmt.Print("BLOCK_OLD_SOURCES")
	default:
		fmt.Print(" ")
	}
	return nil
}

func groupProcessor(ctx context.Context, groupIP net.IP) chan struct{} {
	p := ipv4.NewPacketConn(mainConn)

	group := &net.UDPAddr{IP: groupIP}

	if err := p.JoinGroup(upstream, group); err != nil {
		log.Fatal(err)
	}

	for ifi, _ := range downstreams {
		if err := p.JoinGroup(ifi, group); err != nil {
			log.Fatal(err)
		}
	}

	stop := make(chan struct{})
	go func(ctx context.Context) {
		defer func() {
			if err := p.LeaveGroup(upstream, group); err != nil {
				log.Fatal(err)
			}

			for ifi, _ := range downstreams {
				if err := p.LeaveGroup(ifi, group); err != nil {
					log.Fatal(err)
				}
			}
		}()
		p.SetTOS(0x0)
		p.SetTTL(16)
		p.SetMulticastTTL(16)
		p.SetMulticastLoopback(false)

		data := make([]byte, 1500)
		// assume default iptv port for tv7
		dst := &net.UDPAddr{IP: groupIP, Port: 5000}
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
			}
			// src will be the upstream server along with the port and cm is always nil
			n, _, _, err := p.ReadFrom(data)
			if err != nil {
				log.Fatal(err)
			}

			for ifi, _ := range downstreams {
				if err := p.SetMulticastInterface(ifi); err != nil {
					log.Fatal(ifi, err)
				}

				_, err := p.WriteTo(data[:n], nil, dst)
				if err != nil {
					log.Fatal(ifi, err)
				}
			}
		}
	}(ctx)

	return stop
}

func monitorGroups(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		mutex.RLock()
		if len(activeGroups) == 0 {
			continue
		}
		log.Println("Current monitored groups")
		for k, _ := range activeGroups {
			log.Println("- ", k)
		}
		mutex.RUnlock()
	}
}

var usage = "Please specify one upstream interface and one or more downstream downstreams' name, e.g. ./iG0mprxy eth0 eth1 eth2"

func main() {
	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a channel to listen for a SIGTERM signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL, syscall.SIGHUP)

	// Start a goroutine that cancels the context when a SIGTERM is received
	go func() {
		<-sigCh
		log.Println("Received termination signal")
		cancel()
	}()

	go monitorGroups(ctx)

	optionalArgs := 2
	if len(os.Args) < optionalArgs {
		log.Fatal(usage)
	}
	allowStr := os.Args[1]
	err := SetAllowList(allowStr)
	if err != nil {
		log.Fatal("Unable to set allowlist: ", err)
	}
	names := os.Args[optionalArgs:]
	if len(names) < 2 {
		log.Fatal(usage)
	}

	upstream, err = net.InterfaceByName(names[0])
	if err != nil {
		log.Fatal(err)
	}

	// we use the default port of tv7 udp packets
	mainConn, err = net.ListenPacket("udp4", "0.0.0.0:5000")
	if err != nil {
		log.Fatal(err)
	}
	defer mainConn.Close()

	for _, n := range names[1:] {
		ifi, err := net.InterfaceByName(n)
		if err != nil {
			log.Fatal(err)
		}
		go IgmpProcessor(ctx, ifi)
		downstreams[ifi]++
		fmt.Println("Downstream", ifi.Name, "ready, listening")
	}

	select {
	case <-ctx.Done():
	}

	log.Println("Shutting down!")
}
