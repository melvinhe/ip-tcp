package rip

import (
	"encoding/binary"
	"errors"
	"ip-tcp/ipapi"
	"ip-tcp/ipv4header"
	"ip-tcp/lnxparser"
	"math/bits"
	"net/netip"
	"sync"
	"time"
	//"fmt"
)

// Entry that is stored in our table for Split Horizon with Poisoned Reverse
type RoutingEntry struct {
	Cost int 
	Address netip.Addr
	Time time.Time 
}

const INF = 16
const ROUTE_TIME = 12 // routing refresh time in seconds
const ENTRY_TIME = 5 // periodic updates to all of its interfaces in seconds


// Used in RIPMessage
type RIPEntry struct {
	cost uint32
	address uint32
	mask uint32
}

// What is sent/recieved over the wire
type RIPMessage struct {
	Command uint16 
	Num_entries uint16
	Entries []RIPEntry
}

// API for RIP
type RIP_API struct {
	sendTo []netip.Addr
	recievedFrom map[netip.Prefix]RoutingEntry // maps addresses in forwar table to the time/node/cost they were recieved from
	mutex sync.Mutex
}

func Initialize(rip_api *RIP_API, ip_api * ipapi.IP_API, configInfo *lnxparser.IPConfig) error {
	rip_api.sendTo = configInfo.RipNeighbors
	rip_api.recievedFrom = make(map[netip.Prefix]RoutingEntry)
	rip_api.mutex = sync.Mutex{}
	updateOthers(rip_api, ip_api)
	return nil
}

func HandleMessageSendingAndTimeout(rip_api *RIP_API, ip_api *ipapi.IP_API) error {
	// Being by requesting neighbors
	for _, neighbor := range rip_api.sendTo {
		data := make([]byte, 4)
		binary.BigEndian.PutUint16(data[0:2], uint16(1))
		binary.BigEndian.PutUint16(data[2:4], uint16(0))
		err := ipapi.SendIP(ip_api, neighbor, 200, data)
		if err != nil {
			return errors.New("error sending RIP IP request packet")
		}
	}

	go removeTimedOutConnections(rip_api, ip_api)

	// Update neighbors and remove timed out connections every 5 seconds
	ticker := time.NewTicker(ENTRY_TIME * time.Second)
	for {
        <-ticker.C
        err := updateOthers(rip_api, ip_api)
        if err != nil {
            return err
        }
	}
}

func RIPPacketHandler(rip_api *RIP_API, ip_api *ipapi.IP_API, header *ipv4header.IPv4Header, data []byte) error {
	//fmt.Println("Recieved RIP packet from ", header.Src.String())
	if rip_api == nil {
		return errors.New("RIP API not initialized")
	}
	if len(data) < 4 {
		return errors.New("RIP packet too short")
	}
	command := binary.BigEndian.Uint16(data[0:2])
	// If RIP is response
	if command == 2 {
		// Handle response
		Num_entries := binary.BigEndian.Uint16(data[2:4])
		if len(data) < 4 + int(Num_entries) * 12 {
			return errors.New("RIP packet does not contain enough entries")
		}
		for i := 0; i < int(Num_entries); i++ {
			// Parse RIP packet data
			cost := binary.BigEndian.Uint32(data[4 + i * 12:8 + i * 12])
			address, ok := netip.AddrFromSlice(data[8 + i * 12:12 + i * 12])
			if !ok {
				return errors.New("error parsing RIP packet")
			}
			bits := bits.OnesCount32(binary.BigEndian.Uint32(data[12 + i * 12:16 + i * 12]))
			mask := netip.PrefixFrom(address, bits)
			entry_in_forward, in_forward := ip_api.Forward_table[mask]

			// Don't add local routes
			is_local := false
			for _, iface := range ip_api.Ifaces {
				if iface.Prefix == mask || iface.IP == address {
					is_local = true
				}
			}

			// Add route to forward table & recievedFrom if it doesn't exist or if it's a better route
			//fmt.Println("Recieved RIP packet from ", header.Src.String(), " with route ", mask.String(), " with cost ", int(cost) + 1)
			if !is_local && int(cost) < INF && (!in_forward  || (entry_in_forward.Cost > int(cost) + 1 && entry_in_forward.T == "RIP")){
				ip_api.Forward_table[mask] = ipapi.Route{VIP: header.Src, Cost: int(cost) + 1, T: "RIP"}
				rip_api.recievedFrom[mask] = RoutingEntry{int(cost) + 1, header.Src, time.Now()}
			}
		}
		return nil
	}
	// If RIP is request
	if command == 1 {
		// Handle request
		if updateOne(rip_api, ip_api, header.Src) != nil {
			return errors.New("error updating in response to RIP request")
		}
		return nil
	}
	return errors.New("RIP command not recognized")

}

func removeTimedOutConnections(rip_api *RIP_API, ip_api *ipapi.IP_API) error {
    // Implement the logic to remove timed out connections from the routing table.
    // We iterate through the receivedFrom map and check the Time field to determine if a connection has timed out.
	ticker := time.NewTicker(ROUTE_TIME * time.Second)
	defer rip_api.mutex.Unlock()
	for {
        currentTime := <-ticker.C
		update := false

		rip_api.mutex.Lock()

		new_recievedFrom := make(map[netip.Prefix]RoutingEntry)
		for prefix, entry := range rip_api.recievedFrom {
			if currentTime.Sub(entry.Time) < ROUTE_TIME * time.Second {
				new_recievedFrom[prefix] = entry
			} else {
				update = true
				delete(ip_api.Forward_table, prefix)
			}
		}
		rip_api.recievedFrom = new_recievedFrom

		// Update others if we removed a route
		if update {
			updateOthers(rip_api, ip_api)
		}
		rip_api.mutex.Unlock()
	}
}

func updateOthers(rip_api *RIP_API, ip_api *ipapi.IP_API) error {
    // Implement the logic to update other RIP neighbors with your routing information.
    // We'll need to send RIP messages to your neighbors with your routing information.
	for _, neighbor := range rip_api.sendTo {
		if updateOne(rip_api, ip_api, neighbor) != nil{
			return errors.New("error updating sending update to RIP neighbor")
		}
	}
    return nil
}

func updateOne(rip_api *RIP_API, ip_api *ipapi.IP_API, address netip.Addr) error {
	// Implement the logic to update a specific neighbor with your routing information.
	// We'll send RIP messages to a neighbor, but ensure that we have removed the routes that 
	command := uint16(2)
	var entries []RIPEntry
	var addr []byte

	// Add routes
	for prefix, route := range ip_api.Forward_table {
		// Get data for entry
		mask := (uint32(1) << prefix.Bits()) - 1
		addr = prefix.Addr().AsSlice()
		
		// Add entry to RIP packet ensuring Split Horizon with Poisoned Reverse
		if rip_api.recievedFrom[prefix].Address == address {
			entries = append(entries, RIPEntry{uint32(INF), binary.BigEndian.Uint32(addr), mask})
		} else {
			entries = append(entries, RIPEntry{uint32(route.Cost), binary.BigEndian.Uint32(addr), mask})
		}
	}

	/*
	NO NEED TO ADD NEIGHBORS BECAUSE WE ARE ONLY LOOKING AT NETWORK-LEVEL ROUTING (from looking at the reference)
	// Add neighbors
	for vip, neighbor := range ip_api.Neighbors {
		addr:= vip.AsSlice()
		prefix := neighbor.If.Prefix
		mask := (uint32(1) << prefix.Bits()) - 1
		entries = append(entries, RIPEntry{uint32(1), binary.BigEndian.Uint32(addr), mask})
	}
	*/

	// Add my IPs
	for _, iface := range ip_api.Ifaces{
		if !iface.Down {
			prefix := iface.Prefix
			mask := (uint32(1) << prefix.Bits()) - 1
			addr = prefix.Addr().AsSlice()
			entries = append(entries, RIPEntry{0, binary.BigEndian.Uint32(addr), mask})
		}
	}

	// Serialize data
	Num_entries := uint16(len(entries))
	if Num_entries != 0 {
		data := make([]byte, 4 + Num_entries * 12)
		binary.BigEndian.PutUint16(data[0:2], command)
		binary.BigEndian.PutUint16(data[2:4], Num_entries)
		for i := 0; i < int(Num_entries); i++ {
			binary.BigEndian.PutUint32(data[4 + i * 12:8 + i * 12], entries[i].cost)
			binary.BigEndian.PutUint32(data[8 + i * 12:12 + i * 12], entries[i].address)
			binary.BigEndian.PutUint32(data[12 + i * 12:16 + i * 12], entries[i].mask)
		}
		// Send data
		//fmt.Println("Sending RIP packet of length", len(data), " to ", address.String())
		ipapi.SendIP(ip_api, address, 200, data)
	}
	return nil
	
}