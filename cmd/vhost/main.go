package main

import (
	"bufio"
	"flag"
	"fmt"
	"ip-tcp/ipapi"
	"ip-tcp/ipv4header"
	"ip-tcp/lnxparser"
	"ip-tcp/tcpapi"
	"net/netip"
	"os"
	"strings"
	"strconv"
)

var host_api *ipapi.IP_API
var tcp_api *tcpapi.TCPAPI

func REPL(){
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		line_split := strings.Split(line, " ")
		switch line_split[0] {
		case "li":
			if len(line_split) != 1 {
				fmt.Println("Usage: li")
			} else {
				//fmt.Println("Listing interfaces...")
				ipapi.PrintInterfaces(host_api)
			}
		case "ln":
			if len(line_split) != 1 {
				fmt.Println("Usage: ln")
			} else {
				//fmt.Println("Listing neighbors...")
				ipapi.PrintNeighbors(host_api)
			}
		case "lr":
			if len(line_split) != 1 {
				fmt.Println("Usage: lr")
			} else {
				//fmt.Println("Listing routes...")
				ipapi.PrintRoutes(host_api)
			}
		case "down":
			if len(line_split) != 2 {
				fmt.Println("Usage: down <ifname>")
			} else {
				iface, ok := host_api.Ifaces[line_split[1]]
				if !ok {
					fmt.Println("Interface not found:", line_split[1])
				} else {
					//fmt.Println("Bringing down interface ", line_split[1])
					iface.Down = true
				}
			}
		case "up":
			if len(line_split) != 2 {
				fmt.Println("Usage: up <ifname>[TEST5]")
			} else {
				iface, ok := host_api.Ifaces[line_split[1]]
				if !ok {
					fmt.Println("Interface not found:", line_split[1])
				} else {
					fmt.Println("Bringing up interface ", line_split[1])
					iface.Down = false
				}
			}
		case "send":
			if len(line_split) < 3 {
				fmt.Println("Usage: send <addr> <message ...>")
			} else {
				message := strings.Join(line_split[2:], " ")
				//fmt.Println("Sending message", message, " to ", line_split[1])
				addr, err := netip.ParseAddr(line_split[1])
				if err != nil {
					fmt.Println(err)
				}
				err = ipapi.SendIP(host_api, addr, 0, []byte(message))
				if err != nil {
					fmt.Println(err)
				}
			}
		case "a":
			if len(line_split) != 2 {
				fmt.Println("Usage: a <port>")
			} else {
				port, err := strconv.Atoi(line_split[1])
				if err != nil {
					fmt.Println(err)
				} else {
				fmt.Println("Listening on port", port)
				listen_conn, err := tcpapi.VListen(port, tcp_api)
				if err != nil {
					fmt.Println(err)
				} else {
					go func ()  {
						for {
							_, err := listen_conn.VAccept()
							if err != nil {
								fmt.Println(err)
								break
							}
						}
					}()
				}
				}
			}
		case "c":
			if len(line_split) != 3 {
				fmt.Println("Usage: c <vip> <port>")
				break
			}
			vip, err := netip.ParseAddr(line_split[1])
			if err != nil {
				fmt.Println(err)
				break
			}
			port, err := strconv.Atoi(line_split[2])
			if err != nil {
				fmt.Println(err)
				break
			}
			fmt.Println("Connecting to", vip, "on port", port)
			_, err = tcpapi.VConnect(vip, port, tcp_api)
			if err != nil {
				fmt.Println(err)
			}
		case "ls":
			if len(line_split) != 1 {
				fmt.Println("Usage: ls")
				break
			}
			fmt.Println("Listing sockets...")
			tcp_api.PrintSockets()
		case "s":
			if len(line_split) != 3 {
				fmt.Println("Usage: s <socket> <message ...>")
				break
			}
			socketId, err := strconv.Atoi(line_split[1])
			if err != nil {
				fmt.Println(err)
				break
			}
			message := strings.Join(line_split[2:], " ")
			ret, err := tcp_api.Send(socketId, []byte(message))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Sent", ret, "bytes")
		case "r":
			if len(line_split) != 3 {
				fmt.Println("Usage: r <socket> <bytes>")
				break
			}
			socketId, err := strconv.Atoi(line_split[1])
			if err != nil {
				fmt.Println(err)
				break
			}
			numBytes, err := strconv.Atoi(line_split[2])
			if err != nil {
				fmt.Println(err)
				break
			}
			l, ret, err := tcp_api.Recv(socketId, numBytes)
			if err != nil {
				fmt.Println(err)
				break
			}
			fmt.Println("Read", l, "bytes:", string(ret))
		case "sf":
			if len(line_split) != 4 {
				fmt.Println("Usage: sf <file> <ip> <port>")
				break
			}
			fileName := line_split[1]
			ip, err := netip.ParseAddr(line_split[2])
			if err != nil {
				fmt.Println(err)
				break
			}
			port, err := strconv.Atoi(line_split[3])
			if err != nil {
				fmt.Println(err)
				break
			}
			go tcp_api.SendFile(fileName, ip, port)
		case "rf":
			if len(line_split) != 3 {
				fmt.Println("Usage: rf <dest file> <port>")
				break
			}
			fileName := line_split[1]
			port, err := strconv.Atoi(line_split[2])
			if err != nil {
				fmt.Println(err)
				break
			}
			go tcp_api.RecvFile(fileName, port)
		case "cl":
			if len(line_split) != 2 {
				fmt.Println("Usage: cl <socket>")
				break
			}
			socketId, err := strconv.Atoi(line_split[1])
			if err != nil {
				fmt.Println(err)
				break
			}
			err = tcp_api.Close(socketId)
			if err != nil {
				fmt.Println(err)
			}
		
		default:
			fmt.Println("Invalid command")
		}
	}
}

func handlePacket(header *ipv4header.IPv4Header, data []byte) {
	fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n", header.Src.String(), header.Dst.String(), header.TTL, string(data))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage:  %s -config <configFile>\n", os.Args[0])
		os.Exit(1)
	}
	
	fileName := flag.String("config", "", "<configFile>")
	flag.Parse()
	if *fileName == "" {
		fmt.Println(*fileName)
		fmt.Printf("Usage:  %s -config <configFile>\n", os.Args[0])
		os.Exit(1)
	}

	// Parse the file
	lnxConfig, err := lnxparser.ParseConfig(*fileName)
	if err != nil {
		panic(err)
	}

	// Initialize the IP_API with the parsed configuration
	host_api = &ipapi.IP_API{}
	err = ipapi.Initialize(host_api, lnxConfig)
	if err != nil {
		panic(err)
	}

	ipapi.RegisterRecvHandler(host_api, 0, handlePacket)

	go ipapi.ReceiveAndForward(host_api)

	// Initialize the TCP_API
	tcp_api = &tcpapi.TCPAPI{}
	tcp_api.Init(host_api.MyIps[0], host_api)

	ipapi.RegisterRecvHandler(host_api, 6, tcp_api.HandlePacket)

	REPL()
}