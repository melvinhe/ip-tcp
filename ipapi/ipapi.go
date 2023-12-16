package ipapi

import (
	"fmt"
	"ip-tcp/ipv4header"
	"ip-tcp/lnxparser"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/google/netstack/tcpip/header"
	"github.com/pkg/errors"
)

type Interface struct {
	Ifname string       // the name of the interface
	IP     netip.Addr   // the IP address of the interface on this host
	Prefix netip.Prefix // the network submask/prefix
	Udp    net.UDPAddr  // the UDP address of the interface on this host
	Down   bool         // whether the interface is down or not
	Listener *net.UDPConn
}

func Start(iface *Interface, ReadChan chan []byte) error {
	// Create listener
	listener, err := net.ListenUDP("udp4", &iface.Udp)
	if err != nil {
		return err
	}
	iface.Listener = listener
	defer listener.Close()

	// Read from the listener and write to the read channel
	for {
		buf := make([]byte, 1400) // Maximum Transfer Unit (MTU) is 1400 bytes
		n, _, err := listener.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		// Only read if the interface is up
		if !iface.Down {
			//fmt.Println("Received packet of length: ", n, " on interface ", iface.Ifname)
			ReadChan <- buf[:n]
		}
	}
	//return nil
}

func Write(iface *Interface, addr net.UDPAddr, packet []byte) error {

	// Cannot send if interface is down
	if iface.Down {
		return errors.New("Interface is down")
	}

	// // Create UDP connection and send
	// conn, err := net.DialUDP("udp4", &iface.Udp, &addr)
	// if err != nil {
	// 	return err
	// }
	// defer conn.Close()
	n, err := iface.Listener.WriteToUDP(packet, &addr)
	if n < len(packet) || err != nil {
		return err
	}
	return nil
}

type Route struct {
	VIP  netip.Addr // the interface to send the packet on
	Cost int        // the cost of sending a packet on that interface (used by RIP)
	T    string     // the type of route (static, RIP, local)
}

type Neighbor struct {
	VIP netip.Addr  // the virtual IP address of the neighbor
	IP  net.UDPAddr // the port of the interface on the neighbor
	If  *Interface  // the interface to send the packet on
}

type HandlerFunc func(*ipv4header.IPv4Header, []byte)

type IP_API struct {
	Forward_table map[netip.Prefix]Route  // maps IP address prefixes (netip) to routes
	Handler_table map[int]HandlerFunc     // maps protocol numbers to handlers
	Neighbors     map[netip.Addr]Neighbor // maps (virtual) IP addresses to UDP ports/interfaces
	Ifaces        map[string]*Interface   // maps interface names to interfaces
	MyIps         []netip.Addr            // the IP addresses of this host
	ReadChan      chan []byte             // channel for reading packets
	Mutex         sync.Mutex              // coarse-grained mutex for updating handler_table
}

func Initialize(api *IP_API, configInfo *lnxparser.IPConfig) error {
	api.Forward_table = make(map[netip.Prefix]Route)
	api.Handler_table = make(map[int]HandlerFunc)
	api.Neighbors = make(map[netip.Addr]Neighbor)
	api.Ifaces = make(map[string]*Interface)
	api.ReadChan = make(chan []byte)
	api.Mutex = sync.Mutex{}

	// Create interfaces
	for _, iface := range configInfo.Interfaces {

		// Create new interface
		udpAddr := *net.UDPAddrFromAddrPort(iface.UDPAddr)
		prefix := iface.AssignedPrefix.Masked()

		new_iface := &Interface{iface.Name, iface.AssignedIP, prefix, udpAddr, false, nil}
		api.Ifaces[iface.Name] = new_iface
		api.MyIps = append(api.MyIps, iface.AssignedIP)

		// Start listening on the interface
		go Start(new_iface, api.ReadChan)
	}

	// Create neighbors
	for _, neighbor := range configInfo.Neighbors {
		udpAddr := *net.UDPAddrFromAddrPort(neighbor.UDPAddr)
		iface := api.Ifaces[neighbor.InterfaceName]
		if iface == nil {
			return errors.New("neighbor interface not found")
		}
		api.Neighbors[neighbor.DestAddr] = Neighbor{neighbor.DestAddr, udpAddr, iface}
	}

	// Create routes
	for prefix, vip := range configInfo.StaticRoutes {
		api.Forward_table[prefix] = Route{vip, 0, "static"}
	}

	return nil
}

func ReceiveAndForward(api *IP_API) error {
	for {
		// Read from the read channel
		buf := <-api.ReadChan
		header_data := buf[:20]
		data := buf[20:]

		// Parse the packet
		ipv4Header, err := ipv4header.ParseHeader(header_data)
		if err != nil {
			return err
		}

		// Check if packet is valid
		valid := ipv4Header.TTL > 0 && uint16(ipv4Header.Checksum) == header.Checksum(header_data, uint16(ipv4Header.Checksum))

		if valid {
			// Update header data
			ipv4Header.TTL -= 1

			// From https://github.com/brown-csci1680/lecture-examples/blob/main/ip-demo/cmd/udp-ip-send/main.go#L113
			ipv4Header.Checksum = 0
			headerBytes, err := ipv4Header.Marshal()
			if err != nil {
				return err
			}
			checksum := header.Checksum(headerBytes, 0)
			// Invert checksum for better validation
			ipv4Header.Checksum = int(checksum ^ 0xffff)

			// Generate packet
			headerBytes, err = ipv4Header.Marshal()
			if err != nil {
				return err
			}
			packet := make([]byte, 0, len(headerBytes)+len(data))
			packet = append(packet, headerBytes...)
			packet = append(packet, []byte(data)...)

			done := false

			// Check if the packet is for this host
			if slices.Contains(api.MyIps, ipv4Header.Dst) {
				go api.Handler_table[ipv4Header.Protocol](ipv4Header, data)
				done = true
			}

			// Check if the packet is for a neighbor
			if !done {
				if neighbor, ok := api.Neighbors[ipv4Header.Dst]; ok && !neighbor.If.Down {
					// Send the packet to the neighbor
					err := Write(neighbor.If, neighbor.IP, packet)
					if err != nil {
						return err
					}
					done = true
				}
			}

			// Check if the packet is for a route
			if !done {

				var neighbor Neighbor
				var iface *Interface
				length := 0

				for prefix, route := range api.Forward_table {
					if prefix.Contains(ipv4Header.Dst) && prefix.Bits() >= length && !api.Neighbors[route.VIP].If.Down {
						// Send the packet to the route
						neighbor = api.Neighbors[route.VIP]
						iface = neighbor.If
						length = prefix.Bits()
					}
				}

				if length == 0 || iface == nil {
					return errors.New("Packet not receivable from any neighbors or routes")
				}
				err := Write(iface, neighbor.IP, packet)
				if err != nil {
					return err
				}
			}
		}
		// Packet is dropped (not processed) if it is invalid or not sendable
	}
}

func SendIP(api *IP_API, dst netip.Addr, protocolNum uint16, data []byte) error {

	src := api.MyIps[0]
	var iface *Interface
	var ip net.UDPAddr

	// Create the header
	hdr := ipv4header.IPv4Header{
		Version:  4,
		Len:      20, // Header length is always 20 when no IP options
		TOS:      0,
		TotalLen: ipv4header.HeaderLen + len(data),
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      16,
		Protocol: int(protocolNum),
		Checksum: 0, // Should be 0 until checksum is computed
		Src:      src,
		Dst:      dst,
		Options:  []byte{},
	}

	// Check if the packet is for this host
	if slices.Contains(api.MyIps, dst) {
		api.Handler_table[int(protocolNum)](&hdr, data)
		return nil
	}

	var neighbor Neighbor
	length := 0

	// Check if the packet is for a route
	for prefix, route := range api.Forward_table {
		// Get the longest prefix match that is not down
		if prefix.Contains(dst) && prefix.Bits() >= length {
			this_neighbor, ok := api.Neighbors[route.VIP]
			if ! ok {
				return errors.New("Neighbor not found")
			}
			if ok && !this_neighbor.If.Down {
				neighbor = api.Neighbors[route.VIP]
				iface = neighbor.If
				ip = neighbor.IP
				length = prefix.Bits()
			}
		}
	}

	// Check if the packet is for a neighbor
	if neighbor, ok := api.Neighbors[dst]; ok {
		if !neighbor.If.Down {
			ip = neighbor.IP
			iface = neighbor.If
		}
	}

	if iface == nil {
		return errors.New("Packet not receiveable from any neighbors or routes")
	}

	// Update header data
	hdr.Src = iface.IP

	// Compute checksum
	headerBytes, err := hdr.Marshal()
	if err != nil {
		return err
	}

	checksum := header.Checksum(headerBytes, 0)
	hdr.Checksum = int(checksum ^ 0xffff)

	// Generate packet
	headerBytes, err = hdr.Marshal()
	if err != nil {
		return err
	}
	packet := make([]byte, 0, len(headerBytes)+len(data))
	packet = append(packet, headerBytes...)
	packet = append(packet, []byte(data)...)
	
	err = Write(iface, ip, packet)
	if err != nil {
		return err
	}
	return nil
}

func RegisterRecvHandler(api *IP_API, protocolNum uint16, callbackFunc HandlerFunc) error {
	api.Mutex.Lock()
	defer api.Mutex.Unlock()
	if _, ok := api.Handler_table[int(protocolNum)]; ok {
		return fmt.Errorf("protocol number %d already registered", protocolNum)
	}
	api.Handler_table[int(protocolNum)] = callbackFunc
	return nil
}

// Functions for printing out the API state

func PrintInterfaces(api *IP_API) {
	fmt.Println("Name\t\tAddr/Prefix\tState")
	for _, iface := range api.Ifaces {
		if iface.Down {
			fmt.Printf("%s\t%s/%d\t%s\n", iface.Ifname, iface.IP.String(), iface.Prefix.Bits(), "down")
		} else {
			fmt.Printf("%s\t%s/%d\t%s\n", iface.Ifname, iface.IP.String(), iface.Prefix.Bits(), "up")
		}
	}
}

func PrintNeighbors(api *IP_API) {
	fmt.Println("Iface\tVIP\t\tUDPAddr")
	for _, neighbor := range api.Neighbors {
		if !neighbor.If.Down {
			fmt.Printf("%s\t%s\t%s\n", neighbor.If.Ifname, neighbor.VIP.String(), neighbor.IP.String())
		}
	}
}

func PrintRoutes(api *IP_API) {
	fmt.Println("T\tPrefix\t\tNext hop\tCost")
	for prefix, route := range api.Forward_table {
		switch route.T {
		case "static":
			fmt.Printf("S\t%s\t%s\t-\n", prefix.String(), route.VIP.String())
		case "RIP":
			fmt.Printf("R\t%s\t%s\t%d\n", prefix.String(), route.VIP.String(), route.Cost)
		case "local":
			neighbor := api.Neighbors[route.VIP]
			iface := neighbor.If.Ifname
			fmt.Printf("L\t%s\tLOCAL:%s\t0\n", prefix.String(), iface)
		}
	}
	// Interfaces are also routes
	for _, iface := range api.Ifaces {
		fmt.Printf("L\t%s\tLOCAL:%s\t0\n", iface.Prefix.String(), iface.Ifname)
	}
}
