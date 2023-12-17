# IP-TCP Network

## How you abstract your link layer and its interfaces

In our implementation, we abstracted the link layer and its interfaces mainly through our use of 'ipapi'. Here are some examples on how the link layer and its interfaces are abstracted:

- Link Layer Abstraction: The ipapi package is designed to manage IP networking functionality, including handling interfaces and routing. Interfaces represent network interfaces, and these interfaces abstract the link layer, representing different network connections, such as Ethernet interfaces or virtual interfaces.

- Interface Struct: The Iface struct represents network interfaces, containing essential information such as the IP address, subnet mask, MAC address, and more. These fields encapsulate the link layer attributes of the network interface.

- Neighbor Information: The ipapi package maintains a list of neighbors, which can be thought of as devices connected to the same network segment. These neighbors are associated with specific interfaces and are crucial for routing decisions.

- Forward Table: The Forward_table data structure manages routing information and can be seen as an abstraction of the link layer's routing table. It contains entries that map network prefixes to the next-hop IP addresses and the corresponding outgoing interfaces. This is updated by RIP if RIP is being used.

## The thread model for your RIP implementation

Our RIP implementation in the provided code follows a simple thread model. Key elements of the thread model include:

- RIP Packet Handling: The handling of RIP packets, both requests and responses, is initiated in the 'HandleMessageSendingAndTimeout' function, which runs as a separate goroutine. This function periodically sends RIP requests to neighbors and processes RIP packets received from neighbors. It's responsible for managing the RIP protocol.

- Timed-Out Connections: A separate goroutine, 'removeTimedOutConnections', runs periodically to remove timed-out connections from the routing table. It checks the timestamps of routes and removes entries that haven't been updated within a specified time frame (e.g., 'ROUTE_TIME' seconds). This ensures that stale routes are removed in a timely manner.

- Updating Neighbors: The 'updateOthers' function is responsible for updating neighbors with routing information. It sends RIP responses to neighbors, providing them with information about the local network topology.

- Thread Safety: To ensure thread safety, the code uses a mutex (sync.Mutex) to protect the shared data structures, particularly the routing table and the 'recievedFrom' map.

Our thread model essentially allows for concurrent handling of RIP packets and periodic maintenance tasks while ensuring proper synchronization to avoid race conditions when modifying shared data structures.

## The steps you will need to process IP packets

The processing of IP packets involves several steps:

- Receiving Packets: The 'ReceiveAndForward' function in the 'ipapi' package listens for incoming IP packets on all network interfaces. It collects incoming packets and forwards them to the appropriate destination based on routing information (or sends them to a handler).

- Packet Handling: When an IP packet is received, the code extracts the destination IP address from the packet header. It then looks up the routing table (Forward_table) to determine the next-hop IP address and the outgoing interface for the packet. If this hop is local, the packet is sent to a designated handler function.

- Forwarding: The code forwards the packet to the next-hop IP address using the specified network interface.

- Local Delivery: If the destination IP address is one of the local network interfaces, the packet is locally delivered to the corresponding network interface, which can handle higher-level protocol processing.

These steps ensure that incoming IP packets are correctly routed and delivered based on the routing information stored in the routing table. The code abstracts the low-level link layer details, making it easy to process IP packets without the need for manual management of the underlying network interfaces and routing.


# TCP

For this project we implemented TCP in using our IP project. Our implementation allows for creating connection, sending and recieving packets over lossy/nonlossy links, and closing connections.

## Socket Abstraction

Much of our code relies on a socket abstraction that we created. There are two types of sockets, listeners and connections. 

Listeners do not require much logic, they are only used to listen for clients and then generate a connection socket once a client has connected. 

Connection sockets are more complex and are used in our implementation of TCP. They consist of general socket data (ports, addresses, id, status), buffers/associated pointers for sending and recieving, a retransmission queue, channels/mutexes for thread synchronization, and closing data. 

## TCP API

Our TCP API, similar to our IP API, is what allows us to use TCP to send/recieve packets. It has four main parts: handshake, sending data, recieving data, and closing the connection.

### Handshake

The handshake begins when a client calls VConnect() to connect to a listener. When this happens, the client sends a SYN packet to the listener. This SYN packet contains the client's window size and sequence number, which are saved by the listener. Upon recieving a SYN packet, the listener creates a connection socket, storing the client's window size and sequence number, as well as its own sequence number. Both the client's and the listner's initial sequence numbers are chosen randomly. 

The listener then sends a SYN-ACK packet, incrementing the sequence number of the client and sending its own window size. This is acknowledged by the client with an ACK in which the client increments the sequence number of the listener.

By this point, both sides know each other's sequence numbers and window sizes. In our implementation, we have a channel which will block sending until we complete the handshake. We send on this channel after we recieve a SYN-ACK (on the client side) or we recieve an ACK (on the listener side). This prevents data from being sent before the handshake is completed, as this would cause issues establishing the connection.

### Sending Data

When sending data, we wait until the connection has been fully established, as described above. We then add our data in chunks to a sending buffer and send the data in MSS-sized packets. We send multiple packets at the same time, but only so much that they do not exceed the other side's window size.

If we ever recieve a window size of zero, we begin zero window probing. This means that we will send packets of size 1 in order to probe to see whether the size of the window has increased.

Whenever we recieve an ACK for sent data, we will then be able to send more data. We handle this in our HandlePacket() function. It uses similar logic to our Send() function.

We will also resend data if it has not been ACKed within a certain amount of time. This is done using our handleRetransmissions() function. This is a seperate goroutine which will look through the retransmission queue, and resend packets that have not been ACKed after the timeout period.

When we recieve ACKs for sent data, we update our retransmission timeout. This is based on Smoothed Round Trip Time (SRTT) which is calculated for each ACKed segment. We look up the segment in our retransmission queue, see when we sent the segment, and then calculate a measure of the round trip time from the difference between the time we sent the segment and the time we recieved the ACK.

### Recieving Data

When recieving data, the TCP API checks to ensure that the sequence numbers for both sides are correct. In this case, there are two types of packets, the next expected packet and early arrivals.

When an early arrival is recieved, it's information is added to an early arrival queue. This information includes the sequence number and the length of the data. The data itself is written into the recieving buffer. The information from the early arrivals will be used when we recieve the next expected packet. 

When we recieve the next expected packet, that data is added to the recieve buffer and read pointers are updated accordingly. We then check the early arrivals queue. While the next packet that we expect is in the queue, we update our read pointers accordingly. This implementation means that we do not need to have early arrivals retransmitted by the client, improving efficiency.

### Closing Connection

When one side decides to close the connection, it will wait until it has sent all of the data that it wants to send. Once it recieves an ACK for the bit of data in the send buffer, it will send a FIN packet. Like normal data, FIN packets are added to the retransmission queue. 

Whenever the other side recieves the FIN packet, it will ACK the packet and send a FIN. As was posted on EdStem, once a connection sends a FIN packet, it will no longer add information to its recieve buffer. Therefore, we do not send any more data from our send buffer after recieving a FIN, even if our send buffer is not empty. Instead, we go straight to terminating the connection by sending a FIN. This FIN is also added to the retransmission queue.

We then proceed based on the TCP state transitions in diagram below. Generally, the side that sends the FIN initially will go through the states FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT and then finally become CLOSED. The other side will go from CLOSE_WAIT to LAST_ACK to CLOSED.

When a connection is closed, it is removed from the TCP API and will no longer be shown when the command *ls* is entered into the terminal.

![TCP state transitions](https://github.com/melvinhe/ip-tcp/assets/64095665/8864fb2d-a156-41f7-ba8a-b36aef26cf2e)

### Wireshark Capture

We have captured a Wireshark capture of sending a ~1MB file using our TCP implementation and the reference router. The reference router was set to have a drop rate of 0.02. Annotations for the Wireshark capture are below.

**The 3-way handshake**

Packets: 1, 3, 5

Description: The handshake is begun with Packet 1, which is a SYN packet. In response, the other side sends Packet 3, a SYN-ACK packet with the acknowledgement number increased by 1. This packet is ACKed with Packet 5, at which point the relative sequence numbers of both sides are 1. 

This is working as expected.

**One example segment sent and acknowledged**

Packets: 7, 9

Description: Packet 7 is a data packet of size 1000, which is the maximum send size in our implementation. This packet is ACKed with Packet 9. Packet 9 has the correctly incremented acknowledgement number (increased by 1000). Neither packet is dropped.

This is working as expected.

**One segment that is retransmitted**

Packets: 59, 60, 62

Description: Here, Packet 59 is a data packet, however it is dropped by the router. Because of this, it is not ACKed within the timeout time. Therefore, Packet 60 is sent. Packet 60 is a retransmission of Packet 59 and contains the same data. Packet 62 is an ACK for Packet 60.

This is working as expected.

**Connection teardown**

Packets: 4275, 4277, 4278, 4281, 4283

Description: The connection teardown is begun with Packet 4275, which is a FIN packet. This packet is ACKed with Packet 4277. Packet 4278 is the FIN packet from the other side, however, this packet appears to have been dropped. This leads to a retransmission of the FIN packet, which is Packet 4281. This packet is ACKed with Packet 4283, ending the connection teardown. 

This is working as expected.

### Comparison to Reference

Below is a comparison of our implementation and the reference. To test the efficiency, we had both implementations send the same ~1MB file and measured the time to send it using Wireshark. Both sides used the reference router with a drop rate set to 0.02.

| Implementation     | Time |
| ------------------ | ---- |
| Our TCP            | 6.84s |
| Reference          | 2.21s |

As you can see, while our implementation is slightly slower, it is within an order of magnitude of the reference. With some more fine tuning of our timeout parameters we might have been able to decrease the time even further. We are happy with our results.
