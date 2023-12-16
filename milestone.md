# IP Network

### Interface

**Data**

    type Interface struct {
        Ifname string 				// the name of the interface
        Ip2udp map[string] 			// map mapping the virtual IP address to the UDP socket
        Prefix int 					// the network submask/prefix
        ReadChan chan []byte 		// a channel for reading from the interface
        WriteChan chan []byte 		// a channel for writing to the interface
        Udp : UDPAddr 				// the UDP address of the interface on this host
        Down bool 					// whether the interface is down or not
    }

**Functions**

* Start() (error) - Starts up interface
* Write(vip string, data []byte) - Writes data to a virtual ip address based on the ip2udp table.

**Workflow**

When an interface is created, it will be provided data about itself (ifname, addr, etc.). It will then be run with the start() function in a new goroutine.

The interface will then set up its UDP socket by creating a listener. It will then wait for either data to be recieved via UDP or for data to be written to writeChan. 

If data is recieved via UDP, the start() function will read the data into the readChan channel.

If data is written to writeChan (presumably by the IP_API), the start() function will write the data to the UDP port. 

The primary means of communication between the interface and the IP_API will be the readChan and writeChan channels. 

[comment]: <> (I am not totally sure if we actually need a writeChan variable. It seems like we might be able to just handle this at the IP_API level. I have left it in for now tho)



### IP_API

**Data**

* forward_table : map[Prefix]Route - maps IP address prefixes (netip) to routes

        type Route struct {
            Dest netip.Prefix 			// the destination network
            NextHop netip.Addr 			// the next hop IP address
            If Interface 				// the interface to send the packet on
            Cost int 					// the cost of sending a packet on that interface (used by RIP)
            T string 					// the type of route (static, RIP, local)
        }

* handler_table : map[int]HandlerFunc - maps protocol numbers to handlers
    * type HandlerFunc func([]byte)
* mutex : sync.Mutex - coarse-grained mutex for updating handler_table

**Functions**

* Initialize(configInfo IpConfig) (error) - 
This will instantiate interfaces and create the forward table from the IpConfig. It will also start a new goroutine to handle recieving data from each interface.

* SendIP(dst netip.Addr, protocolNum uint16, data []byte) (error) - 
This will send an IP packet to a certain address. It will look up the next hop in the forwarding table, and then call the interface's Write() function to send an IP packet to that 

* RegisterRecvHandler(protocolNum uint16, callbackFunc HandlerFunc) - 
This will register a new handler function for packets with a certain protocol number.

* PrintInterfaces() (string) - 
This will return a string containing a formatted list of all network interfaces currently managed by the IP_API. It can be useful for users or administrators to quickly check which interfaces are active in the system.

* ListNeighbors() (string) - 
This will return a string containing information about neighboring nodes or devices in the network to help in network troubleshooting and understanding the network's topology.

* ListRoutes(showCosts bool) (string) -
This will return a string containing the routing table of the IP_API, listing the destination prefixes, next-hop addresses, and associated interfaces for routing packets. If showCosts is true, the function should include the cost associated with each route. If showCosts is false, it can provide a simplified view of the routing table without the cost information. 
    

**Workflow**

When the IP_API is instantiated, it will initialize the interfaces and forward table based on the passed in configuration data.

It will also start a new goroutine to handle data recieved by interfaces. This goroutine will either call the associated handler function in a new goroutine to process that packet, or forward the packet to its next hop based on the forwarding table.

New handlers can be registered at any time. This process will involve locking the mutex of the API.

To send data using IP, we will fill in the header data for the packet based on the IP specification, and then append the data. Specifically, we will fill in the following fields in the header:

    type IPv4Header struct {
        Version  int         // protocol version
        Len      int         // header length
        TOS      int         // type-of-service
        TotalLen int         // packet total length
        ID       int         // identification
        Flags    HeaderFlags // flags
        FragOff  int         // fragment offset
        TTL      int         // time-to-live
        Protocol int         // next protocol
        Checksum int         // checksum
        Src      netip.Addr  // source address
        Dst      netip.Addr  // destination address
        Options  []byte      // options, extension headers
    }

We will also have to batch the data in order to ensure that it fits within the Maximum Transfer Unit (MTU) of 1400 bytes (1380 bytes of data). 

The packet will then be forwarded based on the forwarding table. 

[comment]: <> (I am not totally sure about the data structures for the forwarding table. This seems like it should be relatively close. Also, I am not totally sure if batching and sending that data would be okay, as we might need to ensure that the data is sent in the right order. We might also want to have a method to print out all of the interfaces of the IP forwarding table)



### vhost

**Data**

* api : IP_API - the ip api that will be used by this node

**Functions**

REPL() - runs the REPL for the host. The REPL must handle two commands:

* li: List interfaces - calls IP_API's PrintInterfaces() function
* ln: List neighbors - calls IP_API's PrintNeighbors() function
* lr: List routes - calls IP_API's PrintRoutes() function with showCosts set to false
* down: Disable interface - set an interface's down field to true
* up: Enable interface - set an interface's down field to false
* send: Send a test packet - Send a test packet to another node. This will involve calling the IP_API's SendIP() function

**Workflow**

The REPL will run, taking in commands from stdin. The REPL will then preform the corresponding actions.

[comment]: <> ()



### vrouter

**Data**

* api : IP_API - the ip api that will be used by this node

**Functions**

REPL() - runs the REPL for the host. The REPL must handle two commands:

* li: List interfaces - calls IP_API's PrintInterfaces() function
* ln: List neighbors - calls IP_API's PrintNeighbors() function
* lr: List routes - calls IP_API's PrintRoutes() function with showCosts set to true
* down: Disable interface - set an interface's down field to true
* up: Enable interface - set an interface's down field to false
* send: Send a test packet - Send a test packet to another node. This will involve calling the IP_API's SendIP() function

**Workflow**

The REPL will run, taking in commands from stdin. The REPL will then preform the corresponding actions.

[comment]: <> ()




## Questions

**What objects will you use to abstract link layers, and what interface will it have?**

We will encapsulate link layer functionality using Interface structs, effectively serving as wrappers for UDP sockets. These Interface structs allow us to abstract the complexities of low-level networking. Incoming data from UDP sockets is directed to channels, which serve as the communication bridge between the link layer and the IP network layer.

**What fields in the IP packet are read to determine when to forward a packet?**

To make forwarding decisions, we inspect two critical fields within an IP packet:

- TTL (Time to Live): If the TTL field reaches zero or becomes negative, it signifies that the packet has expired in the network. We consequently drop the packet, preventing it from circulating indefinitely.

- Checksum: We verify the checksum to ensure the integrity of the packet. If the checksum calculation indicates that the packet may have been corrupted during transit, we discard it to maintain data integrity.

Upon passing these initial checks, we proceed to examine the destination address. If the destination address matches an entry in our IP forwarding table, we forward the packet. During forwarding, we decrement the TTL by 1 and recalculate the checksum to ensure proper packet handling. If the destination is local, we further inspect the protocol type and route the packet to the corresponding handler function registered within our IP_API for local processing. Packets without a matching destination or protocol are dropped to maintain network efficiency and security.

**What will you do with a packet destined for local delivery (ie, destination IP == your node’s IP)?**

When we receive a packet intended for local delivery, we will reference the packet's protocol number to determine the appropriate callback function. This function is responsible for processing the packet's payload. We pass the packet data to the designated callback function for further handling, allowing the local node to process the data in accordance with the specified protocol.

**What structures will you use to store routing information?**

We will have a lookup table that maps prefixes to their next hops. Specifically, our data structure will look like: 

    forward_table map[Prefix]Route  // maps IP address prefixes (netip) to routes

    type Route struct {
        Dest netip.Prefix 			// the destination network
        NextHop netip.Addr 			// the next hop IP address
        Ifname string 				// the name of the interface
        Cost int 					// the cost of sending a packet on that interface (used by RIP)
        T string 					// the type of route (static, RIP, local)
    }

These structures allow us to efficiently determine the appropriate routing path for outgoing packets based on their destination prefixes as well as fields used by RIP.

**What happens on your node when the topology changes? In other words, when links go up down, how are forwarding and routing affected?**

In response to topology changes, our system dynamically updates the forwarding table and routing information. When links go up or down, the routing protocols (such as RIP) will detect these changes and update the forwarding table accordingly. This ensures that the node's routing decisions are adapted to reflect the current network topology, allowing for efficient and reliable packet forwarding.

We are still in the process of considering network topologies to use:
https://brown-csci1680.github.io/iptcp-docs/sample-networks/

