package tcpapi

import (
	"fmt"
	"ip-tcp/ipapi"
	"ip-tcp/iptcp_utils"
	"ip-tcp/ipv4header"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"io"
	"sync"
	"time"

	"github.com/google/netstack/tcpip/header"
	"github.com/pkg/errors"
)


const (
	MSS = 1000                    // Maximum Segment Size
	alpha = 0.9
	beta = 2.0
	RTO_min = 0.0 				// Minimum Retransmission Timeout (seconds)
	RETRANSMISSION_NUMBER = 5
)
var RTO = 0.05  // Retransmission Timeout (seconds)
var SRTT = 0.05 // Smoothed Round Trip Time (seconds)
var DEFAULT_BUFFER_SIZE = int(math.Pow(2, 16)) - 1
var MAXIMUM_SEQ_NUM = int(math.Pow(2, 32))

// Listener socket
type VTCPListener struct {
	Id int // Socket ID
	Port int // Port number
	Status string // Status of the socket
	TCPStack *TCPAPI // Pointer to TCP stack
	PendingChan chan VTCPConn // Channel for accepting connections
}
// Connection socket ("normal" socket)
type VTCPConn struct {

	// Socket data
	Id int // Socket ID
	LAddr  netip.Addr// Local address
	LPort int // Local port
	RAddr netip.Addr // Remote address
	RPort int // Remote port
	Status string // Status of the socket

	// Lock for socket data
	Lock *sync.Mutex

	// TCP data
	TCPStack *TCPAPI // Pointer to TCP stack
	OtherWindow int // Other window size

	// Recieve buffer data
	RecvBuffer  []byte // Buffer for receiving data
	LBRRead int // Last byte read
	NXTRead int // Next byte expected
	EarlyArrivals [][]int // Array of early arrivals [seqnum, length]

	// Write buffer data
	WriteBuffer []byte // Buffer for writing data
	LBRWrite int // Last byte written
	UNAWrite int // Earliest Unacknowledged sequence number
	NXTWrite int // Next sequence number

	// Channel for signaling that data can be read/written
	ReadChan chan bool // Channel for signaling that data can be read again
	WriteChan chan bool // Channel for signaling that data can be written again
	EmptyChan chan bool // Channel for signaling that the write buffer is empty
	HandshakeChan chan bool // Channel for signaling that the handshake is complete

	// Retransmission data
	RetransmissionsQueue []Retransmission // Retransmissions Queue
	RTOStart             time.Time

	// Connection teardown data
	closing bool // True if connection is closing
}


// Retransmission struct to store retransmission metadata
type Retransmission struct {
	Segment   []byte // Segment to be retransmitted
	Flags     uint8 // TCP flags
	SeqNumber int // Sequence number of the segment
	NumTries  int // Number of times the segment has been sent
	Timestamp time.Time // Time the segment was sent
}

// Add this function to VTCPConn for handling retransmissions
func (conn *VTCPConn) handleRetransmissions() {
	for {
		<-time.After(time.Duration(RTO * float64(time.Second)))
		if conn.Status == "CLOSED" {
			return
		} else {
			conn.Lock.Lock()
			if len(conn.RetransmissionsQueue) > 0 {
				// Retransmit the segments in queue
				newRetransmissionsQueue := make([]Retransmission, 0)
				for len(conn.RetransmissionsQueue) > 0 {
					
					retransmission := conn.RetransmissionsQueue[0]
					conn.RetransmissionsQueue = conn.RetransmissionsQueue[1:]

					// Close the connection after three tries
					if retransmission.NumTries >= RETRANSMISSION_NUMBER {
						//fmt.Println("Closing connection", conn.Id, " due to too many retransmissions")
						conn.Status = "CLOSED"
						conn.TCPStack.Soctable.Sockets[conn.Id] = conn
						conn.Lock.Unlock()
						// Remove connection from socket table
						conn.TCPStack.Lock.Lock()
						delete(conn.TCPStack.Soctable.Sockets, conn.Id)
						conn.TCPStack.Lock.Unlock()
						return
					}

					// Only retransmit if the segment has not been ACKed
					if retransmission.SeqNumber >= conn.UNAWrite {
						conn.sendSegment(&retransmission)
						newRetransmissionsQueue = append(newRetransmissionsQueue, retransmission)
						//fmt.Println("Retransmitting segment with seqnum: ", retransmission.SeqNumber)
					}
				}
				conn.RetransmissionsQueue = newRetransmissionsQueue
				conn.TCPStack.Soctable.Sockets[conn.Id] = conn
			}
			conn.Lock.Unlock()
		}
	}
}

// Add these helper functions to VTCPConn
func (conn *VTCPConn) startRTO() {
	conn.RTOStart = time.Now()
}

func (conn *VTCPConn) resetRTO() {
	conn.RTOStart = time.Time{}
}

func (conn *VTCPConn) isRTOExpired() bool {
	return time.Since(conn.RTOStart).Seconds() >= RTO
}

// LISTENER FUNCTIONS
func VListen(listener_port int, tcpstack *TCPAPI) (*VTCPListener, error) {
	tcpstack.Lock.Lock()
	defer tcpstack.Lock.Unlock()
	// Create listener data structure
	ret := VTCPListener{
		Id: tcpstack.Soctable.NextId, 
		Port: listener_port, 
		Status: "LISTEN", 
		TCPStack: tcpstack,  
		PendingChan: make(chan VTCPConn),
	}
	// Add to socket table
	tcpstack.Soctable.Listeners[ret.Id] = &ret
	tcpstack.Soctable.NextId++
	return &ret, nil
}

func (listener *VTCPListener) VAccept() (*VTCPConn, error) {
	if listener.Status != "LISTEN" {
		return nil, errors.New("Listener not listening")
	}
	// Pull from pending queue
	ret := <- listener.PendingChan
	// Add to socket table
	listener.TCPStack.Lock.Lock()
	defer listener.TCPStack.Lock.Unlock()
	listener.TCPStack.Soctable.Sockets[ret.Id] = &ret
	return &ret, nil
}

func (conn *VTCPConn) sendFin() error {
    // Send FIN segment
    _, err := conn.VWrite([]byte{}, header.TCPFlagFin, conn.NXTWrite, conn.NXTRead)
    if err != nil {
        return err
    }

    // Wait for ACK
    for {
        select {
        case <-time.After(time.Duration(RTO) * time.Second):
            // Handle retransmission or timeout
            // [may need to debug/update retransmission logic here
            fmt.Println("Connection teardown: ACK not received, retransmitting FIN")
            _, err := conn.VWrite([]byte{}, header.TCPFlagFin, conn.NXTWrite, conn.NXTRead)
            if err != nil {
                return err
            }
        case <-conn.ReadChan:
            // ACK received, connection closed
            return nil
        }
    }
}

func (conn *VTCPConn) waitForFin() {
    for {
        select {
        case <-conn.ReadChan:
            // FIN received, send ACK
            _, _ = conn.VWrite([]byte{}, header.TCPFlagAck, conn.NXTWrite, conn.NXTRead)
            // Close the connection
            conn.VClose()
            return
        case <-time.After(time.Duration(RTO) * time.Second):
            // Handle retransmission or timeout
            // TODO: Update Transmission logic
            fmt.Println("Connection teardown: FIN not received, retransmitting ACK")
            _, _ = conn.VWrite([]byte{}, header.TCPFlagAck, conn.NXTWrite, conn.NXTRead)
        }
    }
}

func (conn *VTCPConn) initiateTeardown() {
    // Initiate connection teardown by sending FIN
    conn.sendFin()

    // Wait for FIN from the other end
    conn.waitForFin()
}

// Update VClose function in VTCPConn to initiate connection teardown
// func (conn *VTCPConn) VClose() error {
//     // TODO - COMPLETE CONNECTION TEARDOWN
//     conn.Status = "CLOSED"

//     // Initiate connection teardown
//     conn.initiateTeardown()

//     return nil
// }

// Update VClose function in VTCPListener to handle connection teardown
func (listener *VTCPListener) VClose() error {
    // TODO - COMPLETE CONNECTION TEARDOWN
    listener.Status = "CLOSED"

    // Close all accepted connections
    for _, conn := range listener.TCPStack.Soctable.Sockets {
        if conn.LPort == listener.Port && conn.Status == "ESTABLISHED" {
            conn.VClose()
        }
    }

    return nil
}
// CONNECTION FUNCTIONS
func VConnect(addr netip.Addr, port int, tcpstack *TCPAPI) (VTCPConn, error) {

	// Find an open local port
	done := false
	localport := 0
	for !done {
		done = true
		localport = 20000  + rand.Intn(65535 - 20000)
		for _, socket := range tcpstack.Soctable.Sockets {
			done = done && (socket.LPort != localport)
		}
	}
	tcpstack.Lock.Lock()
	defer tcpstack.Lock.Unlock()
	// Create socket data structure
	seqNum := int(rand.Uint32())
	ret := VTCPConn{
		Id: tcpstack.Soctable.NextId, 
		LAddr: tcpstack.LocalAddr, 
		LPort: localport, 
		RAddr: addr, 
		RPort: port, 
		Status: "SYN_SENT", 
		TCPStack: tcpstack,
		RecvBuffer: make([]byte, DEFAULT_BUFFER_SIZE + 1),
		WriteBuffer: make([]byte, DEFAULT_BUFFER_SIZE + 1),
		UNAWrite: seqNum,
		NXTWrite: seqNum,
		LBRWrite: seqNum,
		ReadChan: make(chan bool),
		WriteChan: make(chan bool),
		EmptyChan: make(chan bool),
		HandshakeChan: make(chan bool),
		Lock: &sync.Mutex{},
		
	}
	// Add to socket table
	tcpstack.Soctable.Sockets[ret.Id] = &ret
	tcpstack.Soctable.NextId++

	// Send SYN
	ret.Status = "SYN_SENT"
	buf := make([]byte, 0)
	retransmission := Retransmission{
		Segment: buf,
		Flags: header.TCPFlagSyn,
		SeqNumber: ret.NXTWrite,
		NumTries: 1,
		Timestamp: time.Now(),
	}
	ret.RetransmissionsQueue = append(ret.RetransmissionsQueue, retransmission)
	err := ret.sendSegment(&retransmission)
	if err != nil {
		panic(err)
	}
	ret.NXTWrite += 1
	ret.LBRWrite += 1
	tcpstack.Soctable.Sockets[ret.Id] = &ret

	// start the retransmission timer
	go ret.handleRetransmissions()
	
	return ret, nil
}

func (conn *VTCPConn) VRead(buf []byte) (int, error) {
	// Block until enough data is available
	//fmt.Println("Buffer Size: ", len(buf))
	//fmt.Println("Written Data Size: ", conn.NXTRead - conn.LBRRead)
	for len(buf) > conn.NXTRead - conn.LBRRead {
		<- conn.ReadChan // Block until enough data is available
	}
	conn.Lock.Lock()
	defer conn.Lock.Unlock()
	if conn.Status != "ESTABLISHED" && conn.Status != "SYN_RCVD" && conn.Status != "SYN_SENT" {
		return 0, io.EOF
	}
	// Read from conns recv buffer
	data := conn.RecvBuffer
	// Copy data into buf
	copy(buf, data[:len(buf)])
	// Shift data in buffer
	new_buffer := make([]byte, DEFAULT_BUFFER_SIZE + 1)
	copy(new_buffer, data[len(buf):])
	conn.RecvBuffer = new_buffer
	// Update pointers
	conn.LBRRead += len(buf)
	return len(buf), nil
}

func (conn *VTCPConn) VWrite(data []byte, flags uint8, seqNum int, ackNum int) (int, error) {
	windowSize := DEFAULT_BUFFER_SIZE - (conn.NXTRead - conn.LBRRead)
	tcpHdr := header.TCPFields{
		SrcPort:       uint16(conn.LPort),
		DstPort:       uint16(conn.RPort),
		SeqNum:        uint32(seqNum),
		AckNum:        uint32(ackNum),
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    uint16(windowSize),
		Checksum:      0,
		UrgentPointer: 0,
	}
	//fmt.Println("Sending Sequence Number: ", seqNum)
	//fmt.Println("Sending Ack Number: ", ackNum)
	//fmt.Println("Sending Data Size: ", len(data))

	checksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, conn.LAddr, conn.RAddr, data)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, iptcp_utils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)

	// Combine the TCP header + payload into one byte array, which
	// becomes the payload of the IP packet
	ipPacketPayload := make([]byte, 0, len(tcpHeaderBytes)+len(data))
	ipPacketPayload = append(ipPacketPayload, tcpHeaderBytes...)
	ipPacketPayload = append(ipPacketPayload, []byte(data)...)

	// Send the IP packet
	err := ipapi.SendIP(conn.TCPStack.IPStack, conn.RAddr, 6, ipPacketPayload)
	if err != nil {
		return 0, err
	}
	return len(ipPacketPayload), nil
}

func (conn *VTCPConn) VClose() error {
	conn.Lock.Lock()
	defer conn.Lock.Unlock()
	if conn.Status == "CLOSED" || conn.Status == "TIME_WAIT" || conn.Status == "CLOSE_WAIT" || conn.Status == "LAST_ACK" || conn.Status == "CLOSING"{
		return nil
	}
	conn.closing = true
	if conn.LBRWrite == conn.UNAWrite {
		// Send FIN
		buf := make([]byte, 0)
		conn.Status = "FIN_WAIT_1"
		retransmission := Retransmission{
			Segment: buf,
			Flags: header.TCPFlagFin | header.TCPFlagAck,
			SeqNumber: conn.NXTWrite,
			NumTries: 1,
			Timestamp: time.Now(),
		}
		conn.RetransmissionsQueue = append(conn.RetransmissionsQueue, retransmission)
		err := conn.sendSegment(&retransmission)
		if err != nil {
			panic(err)
		}
		conn.NXTWrite += 1
		conn.TCPStack.Soctable.Sockets[conn.Id] = conn
	}
	return nil
}

// Helper functions
func (foundSocket *VTCPConn) PrintInfo() {
	fmt.Println("STATUS: ", foundSocket.Status)
	fmt.Println("NXTRead: ", foundSocket.NXTRead)
	fmt.Println("LBRRead: ", foundSocket.LBRRead)
	fmt.Println("NXTWrite: ", foundSocket.NXTWrite)
	fmt.Println("UNAWrite: ", foundSocket.UNAWrite)
	fmt.Println("LBRWrite: ", foundSocket.LBRWrite)
}

func (conn *VTCPConn) sendSegment(segment *Retransmission) error {

	//conn.PrintInfo()

	// Send the segment
	_, err := conn.VWrite(segment.Segment, segment.Flags, segment.SeqNumber, conn.NXTRead)
	if err != nil {
		return err
	}
	segment.Timestamp = time.Now()
	if conn.OtherWindow != 0 || conn.closing{
		segment.NumTries += 1
	}
	return nil
	
}

// TCP API
type SocketTable struct {
	Sockets map[int]*VTCPConn //Maps id to socket
	Listeners map[int]*VTCPListener //Maps id to socket 
	NextId int
	PendingQueue []*VTCPConn //Queue of pending connections
}
type TCPAPI struct {
	Soctable SocketTable
	LocalAddr netip.Addr
	IPStack *ipapi.IP_API
	Lock *sync.Mutex
}

func (api *TCPAPI) Init(localAddr netip.Addr, ipstack *ipapi.IP_API) {
	api.Soctable = SocketTable{
		Sockets: make(map[int]*VTCPConn), 
		Listeners: make(map[int]*VTCPListener), 
		NextId: 0,
	}
	api.LocalAddr = localAddr
	api.IPStack = ipstack
	api.Lock = &sync.Mutex{}
}


func (api *TCPAPI) HandlePacket(ip_header *ipv4header.IPv4Header, raw_data []byte) {
	// Read TCP header
	tcp_header := iptcp_utils.ParseTCPHeader(raw_data)
	data := raw_data[tcp_header.DataOffset:]

	// Check checksum
	tcpChecksumFromHeader := tcp_header.Checksum // Save original
	tcp_header.Checksum = 0
	tcpComputedChecksum := iptcp_utils.ComputeTCPChecksum(&tcp_header, ip_header.Src, ip_header.Dst, data)
	if tcpComputedChecksum != tcpChecksumFromHeader {
		fmt.Println("TCP checksum failed")
		return
	}

	//fmt.Println(iptcp_utils.TCPFlagsAsString(tcp_header.Flags))

	// [SPECIAL CASE] If it is a SYN, route to listener and send SYN ACK
	if tcp_header.Flags == header.TCPFlagSyn {
		for _, listener := range api.Soctable.Listeners {
			if listener.Port == int(tcp_header.DstPort) {
				seqNum := int(rand.Uint32())
				// Create connection socket
				conn := VTCPConn{
					Id: api.Soctable.NextId, 
					LAddr: api.LocalAddr, 
					LPort: int(tcp_header.DstPort), 
					RAddr: ip_header.Src, 
					RPort: int(tcp_header.SrcPort), 
					Status: "SYN_RCVD", 
					TCPStack: api,
					RecvBuffer: make([]byte, DEFAULT_BUFFER_SIZE + 1),
					WriteBuffer: make([]byte, DEFAULT_BUFFER_SIZE + 1),
					UNAWrite: seqNum,
					NXTWrite: seqNum,
					LBRWrite: seqNum,
					OtherWindow: int(tcp_header.WindowSize),
					NXTRead: int(tcp_header.SeqNum) + 1,
					LBRRead: int(tcp_header.SeqNum) + 1,
					ReadChan: make(chan bool),
					WriteChan: make(chan bool),
					EmptyChan: make(chan bool),
					HandshakeChan: make(chan bool),
					Lock: &sync.Mutex{},
				}
				// Add to socket table
				api.Soctable.NextId++
				api.Soctable.Sockets[conn.Id] = &conn
				// Send SYN ACK
				buf := make([]byte, 0)
				retransmission := Retransmission{
					Segment: buf,
					Flags: header.TCPFlagSyn | header.TCPFlagAck,
					SeqNumber: conn.NXTWrite,
					NumTries: 1,
					Timestamp: time.Now(),
				}
				conn.RetransmissionsQueue = append(conn.RetransmissionsQueue, retransmission)
				err := conn.sendSegment(&retransmission)
				if err != nil {
					panic(err)
				}
				conn.NXTWrite += 1
				conn.LBRWrite += 1
				api.Soctable.Sockets[conn.Id] = &conn
				// Send connection to listener
				listener.PendingChan <- conn
				return 
			}
		}
		fmt.Println("Could not find listener")
		return
	}

	// Handle General TCP State changes (based on https://commons.wikimedia.org/wiki/File:Tcp_state_diagram_fixed_new.svg)
	var foundSocket *VTCPConn
	for _, socket := range api.Soctable.Sockets {
		if socket.LPort == int(tcp_header.DstPort) && socket.RPort == int(tcp_header.SrcPort) {
			foundSocket = socket
			break
		}
	}
	if foundSocket == nil {
		fmt.Println("Could not find socket")
		return
	}
	foundSocket.Lock.Lock()
	// Set Window Size
	foundSocket.OtherWindow = int(tcp_header.WindowSize)

	//fmt.Println("Recieved Sequence Number: ", tcp_header.SeqNum)
	//fmt.Println("Recieved Ack Number: ", tcp_header.AckNum)
	//foundSocket.PrintInfo()
	
	// STATE/TRANSITIONS HERE
	switch foundSocket.Status {
		case "SYN_SENT":
			// SYN-ACK
			if header.TCPFlagSyn == (header.TCPFlagSyn &tcp_header.Flags) && header.TCPFlagAck == (header.TCPFlagAck &tcp_header.Flags) {
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved SYN-ACK with incorrect ACK number")
					return
				}
				// Initialize Pointers
				foundSocket.NXTRead = int(tcp_header.SeqNum) + 1
				foundSocket.LBRRead = int(tcp_header.SeqNum) + 1
				foundSocket.UNAWrite += 1
				foundSocket.Status = "ESTABLISHED"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				// Send ACK
				buf := make([]byte, 0)
				_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, foundSocket.NXTRead)
				if err != nil {
					panic(err)
				}
				foundSocket.Lock.Unlock()
				select {
					case foundSocket.HandshakeChan <- true:
					default:
				}
				return
			}
		case "SYN_RCVD":
			// ACK
			if header.TCPFlagAck == (header.TCPFlagAck & tcp_header.Flags) {
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}
				if int(tcp_header.SeqNum) != foundSocket.NXTRead {
					fmt.Println("Recieved ACK with incorrect SEQ number")
					foundSocket.Lock.Unlock()
					return
				}
				foundSocket.Status = "ESTABLISHED"
				foundSocket.UNAWrite += 1
				api.Soctable.Sockets[foundSocket.Id] = foundSocket

				// Start retransmission timer for listener-side
				go foundSocket.handleRetransmissions()

				foundSocket.Lock.Unlock()
				select {
					case foundSocket.HandshakeChan <- true:
					default:
				}
				foundSocket.ReadChan <- true
				return
				
			}
		case "ESTABLISHED":
			// FIN
			if header.TCPFlagFin == (header.TCPFlagFin & tcp_header.Flags) && int(tcp_header.AckNum) == foundSocket.NXTWrite {
				foundSocket.Status = "CLOSE_WAIT"
				foundSocket.closing = true
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.NXTRead += 1
				// Send ACK
				buf := make([]byte, 0)
				_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, foundSocket.NXTRead)
				if err != nil {
					panic(err)
				}

				foundSocket.Status = "LAST_ACK"
				// Send FIN
				buf = make([]byte, 0)
				retransmission := Retransmission{
					Segment: buf,
					Flags: header.TCPFlagFin | header.TCPFlagAck,
					SeqNumber: foundSocket.NXTWrite,
					NumTries: 1,
					Timestamp: time.Now(),
				}
				foundSocket.NXTWrite += 1
				foundSocket.RetransmissionsQueue = append(foundSocket.RetransmissionsQueue, retransmission)
				err = foundSocket.sendSegment(&retransmission)
				if err != nil {
					panic(err)
				}				
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.Lock.Unlock()
				return
			}
			// ACK
			if header.TCPFlagAck == (header.TCPFlagAck & tcp_header.Flags) {

				// Check if ACK is valid
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}

				// RECIEVED DATA
				if len(data) > 0 {

					// Duplicate data
					if int(tcp_header.SeqNum) < foundSocket.NXTRead {
						//fmt.Println("Recieved Duplicate Data")
						
						// Send ACK for data
						buf := make([]byte, 0)
						_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, foundSocket.NXTRead)
						if err != nil {
							panic(err)
						}
						foundSocket.Lock.Unlock()
						return 
					}
					
					// Copy data into buffer
					remainingSpace := DEFAULT_BUFFER_SIZE - (int(tcp_header.SeqNum) - foundSocket.LBRRead)
					if len(data) > remainingSpace {
						fmt.Println("Recieved Data that is too large for window")
					} else {
						
						// Copy data into buffer
						bufferPointer := int(tcp_header.SeqNum) - foundSocket.LBRRead
						copy(foundSocket.RecvBuffer[bufferPointer:bufferPointer+len(data)], data)
						foundSocket.NXTRead += len(data)

						if int(tcp_header.SeqNum) + len(data) == foundSocket.NXTRead {			
							// Add early arrivals to buffer
							done := false
							for !done {
								done = true
								for _, arrival := range foundSocket.EarlyArrivals {
									if arrival[0] == foundSocket.NXTRead {
										done = false
										// Increment NXTRead
										foundSocket.NXTRead += arrival[1]
									}
								}
							}
							// Send ACK for data
							buf := make([]byte, 0)
							_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, foundSocket.NXTRead)
							if err != nil {
								panic(err)
							}

							foundSocket.Lock.Unlock()
							foundSocket.ReadChan <- true
							return

						} else if int(tcp_header.SeqNum) + len(data) > foundSocket.NXTRead {
							// Add to early arrivals
							foundSocket.EarlyArrivals = append(foundSocket.EarlyArrivals, []int{int(tcp_header.SeqNum), len(data)})	
							foundSocket.Lock.Unlock()
							return				
						}
					}

				} else {
					// RECIEVED ACK FOR DATA
					if int(tcp_header.AckNum) > foundSocket.UNAWrite {
						// Increment UNA
						data_size := int(tcp_header.AckNum) - foundSocket.UNAWrite
						foundSocket.UNAWrite = int(tcp_header.AckNum)
						
						// Remove data from buffer
						new_buffer := make([]byte, DEFAULT_BUFFER_SIZE + 1)
						copy(new_buffer, foundSocket.WriteBuffer[data_size:])
						foundSocket.WriteBuffer = new_buffer

						// If there is still data in the write buffer, send it
						if foundSocket.LBRWrite > foundSocket.NXTWrite {
							// Determine how much data to send
							remainingSpace := min(foundSocket.OtherWindow, foundSocket.LBRWrite - foundSocket.NXTWrite)

							// Zero-window probe
							if foundSocket.OtherWindow == 0 {
								remainingSpace = 1
							}

							if remainingSpace > MSS {
								remainingSpace = MSS
							}

							// Send data
							bufferPointer := foundSocket.NXTWrite - foundSocket.UNAWrite
							if bufferPointer < 0 {
								fmt.Println("Buffer Pointer is negative: ", bufferPointer)
							}
							if remainingSpace > 0 && (bufferPointer > 0 || (bufferPointer == 0 && !foundSocket.closing)) {
								send_data := foundSocket.WriteBuffer[bufferPointer:bufferPointer+remainingSpace]
								retransmission := Retransmission{
									Segment: send_data,
									Flags: header.TCPFlagAck,
									SeqNumber: foundSocket.NXTWrite,
									NumTries: 1,
									Timestamp: time.Now(),
								}
								foundSocket.RetransmissionsQueue = append(foundSocket.RetransmissionsQueue, retransmission)
								err := foundSocket.sendSegment(&retransmission)
								if err != nil {
									panic(err)
								}
								foundSocket.NXTWrite += len(send_data)
							}
						} else if foundSocket.LBRWrite == foundSocket.UNAWrite {
							// Check if connection is closing
							if foundSocket.closing {
								// Send FIN
								buf := make([]byte, 0)
								foundSocket.Status = "FIN_WAIT_1"
								retransmission := Retransmission{
									Segment: buf,
									Flags: header.TCPFlagFin | header.TCPFlagAck,
									SeqNumber: foundSocket.NXTWrite,
									NumTries: 1,
									Timestamp: time.Now(),
								}
								foundSocket.NXTWrite += 1
								foundSocket.RetransmissionsQueue = append(foundSocket.RetransmissionsQueue, retransmission)
								err := foundSocket.sendSegment(&retransmission)
								if err != nil {
									panic(err)
								}
								api.Soctable.Sockets[foundSocket.Id] = foundSocket
								foundSocket.Lock.Unlock()
								return
							}
						}

						// Find the retransmission that was ACKed
						retransmission := Retransmission{}
						found := false
						for i, r := range foundSocket.RetransmissionsQueue {
							if r.SeqNumber + data_size == int(tcp_header.AckNum) {
								found = true
								retransmission = r
								foundSocket.RetransmissionsQueue = append(foundSocket.RetransmissionsQueue[:i], foundSocket.RetransmissionsQueue[i+1:]...)
								break
							}
						}

						// Update RTT estimate
						if found {
							estimatedRTT := time.Since(retransmission.Timestamp).Seconds()
							SRTT := alpha * SRTT + (1 - alpha) * estimatedRTT
							RTO = beta * SRTT
							if RTO < RTO_min {
								RTO = float64(RTO_min)
							}
						}

						
						// Send signal that data can be written and possibly that buffer is empty
						if foundSocket.LBRWrite <= foundSocket.UNAWrite {
							foundSocket.Lock.Unlock()
							foundSocket.EmptyChan <- true
							foundSocket.WriteChan <- true
						} else {
							foundSocket.Lock.Unlock()
							foundSocket.WriteChan <- true
						}
						return

					}
				}
			}

		case "LAST_ACK":
			// ACK
			if header.TCPFlagAck == (header.TCPFlagAck & tcp_header.Flags) {
				// Check if ACK is valid
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}
				if int(tcp_header.SeqNum) != foundSocket.NXTRead {
					fmt.Println("Recieved ACK with incorrect SEQ number")
					foundSocket.Lock.Unlock()
					return
				}
				foundSocket.Status = "CLOSED"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.Lock.Unlock()

				// Remove connection from socket table
				api.Lock.Lock()
				delete(api.Soctable.Sockets, foundSocket.Id)
				api.Lock.Unlock()
				return
			}
		case "FIN_WAIT_1":
			// ACK
			if header.TCPFlagAck == (header.TCPFlagAck & tcp_header.Flags) {
				// Check if ACK is valid
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}
				if int(tcp_header.SeqNum) != foundSocket.NXTRead {
					fmt.Println("Recieved ACK with incorrect SEQ number")
					foundSocket.Lock.Unlock()
					return
				}
				foundSocket.UNAWrite = int(tcp_header.AckNum)
				foundSocket.Status = "FIN_WAIT_2"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.Lock.Unlock()
				return
			}
			// FIN
			if header.TCPFlagFin == (header.TCPFlagFin & tcp_header.Flags) && int(tcp_header.AckNum) == foundSocket.NXTWrite {
				foundSocket.Status = "CLOSING"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				// Send ACK
				buf := make([]byte, 0)
				_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, int(tcp_header.SeqNum) + 1)
				if err != nil {
					panic(err)
				}
				foundSocket.Status = "TIME_WAIT"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket

				// Start timer
				foundSocket.Lock.Unlock()
				time.Sleep(2 * time.Second)
				foundSocket.Lock.Lock()

				foundSocket.Status = "CLOSED"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.Lock.Unlock()

				// Remove connection from socket table
				api.Lock.Lock()
				delete(api.Soctable.Sockets, foundSocket.Id)
				api.Lock.Unlock()

				return
			}

		case "FIN_WAIT_2":
			// FIN
			if header.TCPFlagFin == (header.TCPFlagFin & tcp_header.Flags) {
				// Check if ACK is valid
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}
				if int(tcp_header.SeqNum) != foundSocket.NXTRead {
					fmt.Println("Recieved ACK with incorrect SEQ number")
					foundSocket.Lock.Unlock()
					return
				}
				foundSocket.Status = "TIME_WAIT"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				// Send ACK
				buf := make([]byte, 0)
				_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, int(tcp_header.SeqNum) + 1)
				if err != nil {
					panic(err)
				}

				// Start timer
				foundSocket.Lock.Unlock()
				time.Sleep(2 * time.Second)
				foundSocket.Lock.Lock()

				foundSocket.Status = "CLOSED"
				api.Soctable.Sockets[foundSocket.Id] = foundSocket
				foundSocket.Lock.Unlock()

				// Remove connection from socket table
				api.Lock.Lock()
				delete(api.Soctable.Sockets, foundSocket.Id)
				api.Lock.Unlock()

				return
			}
		case "TIME_WAIT":
			// ACK
			if header.TCPFlagAck == (header.TCPFlagAck & tcp_header.Flags) {
				// Check if ACK is valid
				if int(tcp_header.AckNum) != foundSocket.NXTWrite {
					fmt.Println("Recieved ACK with incorrect ACK number")
					foundSocket.Lock.Unlock()
					return
				}
				if int(tcp_header.SeqNum) != foundSocket.NXTRead {
					fmt.Println("Recieved ACK with incorrect SEQ number")
					foundSocket.Lock.Unlock()
					return
				}
				// Send ACK
				buf := make([]byte, 0)
				_, err := foundSocket.VWrite(buf, header.TCPFlagAck, foundSocket.NXTWrite, int(tcp_header.SeqNum) + 1)
				if err != nil {
					panic(err)
				}
			}				
		default:
			fmt.Println("Unknown state: ", foundSocket.Status)
			foundSocket.Lock.Unlock()
			return
	}
	
	foundSocket.Lock.Unlock()

}


// REPL COMMANDS
func (api *TCPAPI) PrintSockets() {
	fmt.Println("SID \t LAddr:LPort \t\t RAddr:RPort \t Status")
	for i := 0; i < api.Soctable.NextId; i++ {
		if socket, ok := api.Soctable.Sockets[i]; ok {
			fmt.Printf("%d \t %s:%d \t %s:%d \t %s\n", socket.Id, socket.LAddr.String(), socket.LPort, socket.RAddr.String(), socket.RPort, socket.Status)
		}
		if listener, ok := api.Soctable.Listeners[i]; ok {
			fmt.Printf("%d \t 0.0.0.0:%d \t 0.0.0.0:0 \t %s\n", listener.Id, listener.Port, listener.Status)
		}
	}	
}


func (api *TCPAPI) Send(socketId int, data [] byte) (int, error){
	socket, ok := api.Soctable.Sockets[socketId]
	if !ok {
		return 0, errors.New("Could not find socket")
	}
	if socket.closing {
		return 0, io.EOF
	}
	// Block until handshake is complete
	if socket.Status == "SYN_SENT" || socket.Status == "SYN_RCVD" {
		socket.HandshakeChan <- true
	}

	ret := len(data)

	// Add data to write buffer in chunks
	for len(data) > 0 {
		socket.Lock.Lock()
		bufferPointer := socket.LBRWrite - socket.UNAWrite
		remainingSpace := DEFAULT_BUFFER_SIZE - bufferPointer
		if bufferPointer < 0 {
			fmt.Println("Buffer Pointer is negative: ", bufferPointer)
		}
		socket.Lock.Unlock()

		// Wait until data can be written using channel
		for remainingSpace <= 0 {
			<- socket.WriteChan
			bufferPointer := socket.LBRWrite - socket.UNAWrite
			remainingSpace = DEFAULT_BUFFER_SIZE - bufferPointer
		}
		dataToAdd := data
		if len(dataToAdd) > remainingSpace {
			dataToAdd = dataToAdd[:remainingSpace]
		}

		if bufferPointer + len(dataToAdd) > DEFAULT_BUFFER_SIZE {
			fmt.Println("Buffer Pointer, remaining space is too large: ", bufferPointer, len(dataToAdd), remainingSpace)
		}

		socket.Lock.Lock()
		// Add data to buffer and remove from front of data
		copy(socket.WriteBuffer[bufferPointer:bufferPointer+len(dataToAdd)], dataToAdd)
		socket.LBRWrite += len(dataToAdd)
		data = data[len(dataToAdd):]
		
		// Send data of window size in MSS-sized chunks
		windowSize := socket.OtherWindow

		// Zero-window probe
		if windowSize == 0 {
			windowSize = 1
		}
		socket.Lock.Unlock()

		for windowSize > 0 && socket.NXTWrite < socket.LBRWrite {

			socket.Lock.Lock()

			// Determine how much data to send
			dataSize := min(socket.LBRWrite - socket.NXTWrite, windowSize)
			if dataSize > MSS {
				dataSize = MSS
			}

			// Send data
			bufferPointer := socket.NXTWrite - socket.UNAWrite
			send_data := socket.WriteBuffer[bufferPointer:bufferPointer+dataSize]
			retransmission := Retransmission{
				Segment: send_data,
				Flags: header.TCPFlagAck,
				SeqNumber: socket.NXTWrite,
				NumTries: 1,
				Timestamp: time.Now(),
			}
			socket.NXTWrite += dataSize
			windowSize -= dataSize
			socket.RetransmissionsQueue = append(socket.RetransmissionsQueue, retransmission)
			err := socket.sendSegment(&retransmission)
			socket.Lock.Unlock()
			if err != nil {
				panic(err)
			}

		}
		<- socket.EmptyChan
	}


	return ret - len(data), nil
	
}

func (api *TCPAPI) Recv(socketId int, numBytes int) (int, []byte, error) {
	socket, ok := api.Soctable.Sockets[socketId]
	if !ok {
		return 0, nil, errors.New("Could not find socket")
	}
	if socket.Status != "ESTABLISHED" {
		return 0, nil, io.EOF
	}

	// Block until handshake is complete
	if socket.Status == "SYN_SENT" || socket.Status == "SYN_RCVD" {
		socket.HandshakeChan <- true
	}

	// Read from conns recv buffer
	ret := make([]byte, numBytes)
	l, err := socket.VRead(ret)
	if err != nil {
		return l, ret, err
	}
	return l, ret, nil
}

func (api *TCPAPI) SendFile(fileName string, ip netip.Addr, port int) {
	// Ensure file exists
	_, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
	}

	// Connect to server
	socket, err := VConnect(ip, port, api)
	if err != nil {
		fmt.Println(err)
	}

	// Open file
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	// Send file in chunks
	total_sent := 0
	for {
		buf := make([]byte, min(MSS, DEFAULT_BUFFER_SIZE - (socket.NXTWrite - socket.UNAWrite)))
		n, err := f.Read(buf)

		if err != nil {
			break
		}
		// Continue until all data has been sent
		if n == 0 {
			break
		} else {
			bytes_sent, err := api.Send(socket.Id, buf[:n])
			total_sent += bytes_sent
			if err != nil  {
				break
			}
		}
	}
	// Close connection
	err = api.Close(socket.Id)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Sent", total_sent, "total bytes")
	
}
func (api *TCPAPI) Close (socketID int) error {
	socket, ok := api.Soctable.Sockets[socketID]

	if ok {
		return socket.VClose()
	}
	listener, ok := api.Soctable.Listeners[socketID]
	if ok {
		return listener.VClose()
	}
	return errors.New("Could not find socket")
	
}

func (api *TCPAPI) RecvFile(outFile string, port int) {
	// Open destination file
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	// Create listener
	listener, err := VListen(port, api)
	if err != nil {
		fmt.Println(err)
	}

	// Accept connection
	reciever, err := listener.VAccept()
	if err != nil {
		fmt.Println(err)
	}

	// Recieve file in chunks
	total_recieved := 0

	// Read data until socket is closed
	for !reciever.closing {
		if reciever.NXTRead - reciever.LBRRead > 0 {
			n, buf, recieve_err := api.Recv(reciever.Id, min(MSS, reciever.NXTRead - reciever.LBRRead))
			if n != 0 {
				bytes_written, write_err := f.Write(buf[:n])
				total_recieved += bytes_written
				if write_err != nil {
					fmt.Println(err)
				}
			}
			if recieve_err != nil && recieve_err != io.EOF{
				fmt.Println(err)
			}
		}
	}
	fmt.Println("Received", total_recieved, "total bytes")

}