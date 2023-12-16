package main

import (
	"bufio"
	"flag"
	"fmt"
	"ip-tcp/ipapi"
	"ip-tcp/ipv4header"
	"ip-tcp/lnxparser"
	"ip-tcp/rip"
	"net/netip"
	"os"
	"strings"
)

var router_api *ipapi.IP_API
var rip_api *rip.RIP_API

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
				ipapi.PrintInterfaces(router_api)
			}
		case "ln":
			if len(line_split) != 1 {
				fmt.Println("Usage: ln")
			} else {
				//fmt.Println("Listing neighbors...")
				ipapi.PrintNeighbors(router_api)
			}
		case "lr":
			if len(line_split) != 1 {
				fmt.Println("Usage: lr")
			} else {
				//fmt.Println("Listing routes...")
				ipapi.PrintRoutes(router_api)
			}
		case "down":
			if len(line_split) != 2 {
				fmt.Println("Usage: down <ifname>")
			} else {
				iface, ok := router_api.Ifaces[line_split[1]]
				if !ok {
					fmt.Println("Interface not found:", line_split[1])
				} else {
					//fmt.Println("Bringing down interface ", line_split[1])
					iface.Down = true
				}
			}
		case "up":
			if len(line_split) != 2 {
				fmt.Println("Usage: up <ifname>")
			} else {
				iface, ok := router_api.Ifaces[line_split[1]]
				if !ok {
					fmt.Println("Interface not found:", line_split[1])
				} else {
					//fmt.Println("Bringing up interface ", line_split[1])
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
				err = ipapi.SendIP(router_api, addr, 0, []byte(message))
				if err != nil {
					fmt.Println(err)
				}
			}
		default:
			fmt.Println("Invalid command")
		}
	}
}

func handleTestPacket(header *ipv4header.IPv4Header, data []byte) {
	fmt.Printf("Received test packet: Src: %s, Dst: %s, TTL: %d, Data: %s\n", header.Src.String(), header.Dst.String(), header.TTL, string(data))
}

func handleRIPPacket(header *ipv4header.IPv4Header, data []byte) {
	err := rip.RIPPacketHandler(rip_api, router_api, header, data)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage:  %s -config <configFile>\n", os.Args[0])
		os.Exit(1)
	}
	
	fileName := flag.String("config", "", "<configFile>")
	flag.Parse()
	if *fileName == "" {
		fmt.Printf("Usage:  %s -config <configFile>\n", os.Args[0])
		os.Exit(1)
	}

	// Parse the file
	lnxConfig, err := lnxparser.ParseConfig(*fileName)
	if err != nil {
		panic(err)
	}

	// Initialize the IP_API with the parsed configuration
	router_api = &ipapi.IP_API{}
	err = ipapi.Initialize(router_api, lnxConfig)
	if err != nil {
		panic(err)
	}

	// Initialize RIP_API with the parsed configuration, if necessary 
	if lnxConfig.RoutingMode == lnxparser.RoutingTypeRIP{
		rip_api = &rip.RIP_API{}
		err = rip.Initialize(rip_api, router_api, lnxConfig)
		if err != nil {
			panic(err)
		}
		go rip.HandleMessageSendingAndTimeout(rip_api, router_api)
		ipapi.RegisterRecvHandler(router_api, 200, handleRIPPacket)

	}

	ipapi.RegisterRecvHandler(router_api, 0, handleTestPacket)

	go ipapi.ReceiveAndForward(router_api)
	REPL()
}