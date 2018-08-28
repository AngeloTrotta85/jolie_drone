//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


package inet.applications.udpapp;

import inet.applications.contract.IApp;


//
// Sends UDP packets to the given IP address at the given interval.
// Compatible with both ~Ipv4 and ~Ipv6.
//
// The sending interval can be a constant or a random value (e.g. exponential(1)).
// If the destAddresses parameter contains more than one address, one
// of them is randomly chosen for each packet. An address may be given in the
// dotted decimal notation, or with the module name. (The L3AddressResolver
// class is used to resolve the address.) To disable the model, set
// destAddresses to "".
//
// Received packets are discarded.
//
// The peer can be a ~UdpSink, another ~UdpBasicApp (it handles received packets
// like ~UdpSink), or a ~UdpEchoApp. When used with ~UdpEchoApp, the rcvdPkLifetime
// statistic will contain the round-trip times.
//
simple UdpBasicAppJolie like IApp
{
    parameters:
        string interfaceTableModule;   // The path to the InterfaceTable module
        int localPort = default(-1);  // local port (-1: use ephemeral port)
        string destAddresses = default(""); // list of IP addresses, separated by spaces ("": don't send)
        string localAddress = default("");
        string packetName = default("UdpBasicAppData");
        int destPort;
        volatile int messageLength @unit(B); // length of messages to generate, in bytes
        double startTime @unit(s) = default(this.sendInterval); // application start time (start of the first packet)
        double stopTime @unit(s) = default(-1s);  // time of finishing sending, -1s means forever
        volatile double sendInterval @unit(s); // should usually be a random value, e.g. exponential(1)
        int timeToLive = default(-1); // if not -1, set the TTL (Ipv4) or Hop Limit (Ipv6) field of sent packets to this value
        int typeOfService = default(-1); // if not -1, set the ToS (Ipv4) or Traffic Class (Ipv6) field of sent packets to this value
        string multicastInterface = default("");  // if not empty, set the multicast output interface option on the socket (interface name expected)
        bool receiveBroadcast = default(false); // if true, makes the socket receive broadcast packets
        bool joinLocalMulticastGroups = default(false); // if true, makes the socket receive packets from all multicast groups set on local interfaces
        
        double coapServerLoopTimer = default(0.05); // time to check message from the server-thread
        string jolieAddress = default("192.168.1.177"); // address of the orchestrator
        int jolieAddressPort = default(5683); // address port of the orchestrator
        string gatewayRealAddress = default("192.168.1.176"); // address of the gateway
        int gatewayRealAddressPort = default(5683); // address port of the gateway
        string droneRegisterStringTemplate = default("{\"address\":\"%s:%d\",\"id\":%d}"); 									// template for the drone-register template message; 	example: {"address":"192.168.1.176:5683","id":0}                     
        string dronePositionStringTemplate = default("{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}"); 	// template for the drone-position template message; 	example: {"drone":{"id":0},"position":{"x":20.05,"y":42.65}}
        string droneAlertStringTemplate = default("{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}"); 		// template for the drone-alert template message;   	example: {"drone":{"id":0},"position":{"x":20.05,"y":42.65}}
        
        double neigh_timeout = default(10);	// neighors timeout                                      
        
        @display("i=block/app");
        @signal[packetSent](type=Packet);
        @signal[packetReceived](type=Packet);
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[throughput](title="throughput"; unit=bps; source="throughput(packetReceived)"; record=vector);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[rcvdPkLifetime](title="received packet lifetime"; source="dataAge(packetReceived)"; unit=s; record=stats,vector; interpolationmode=none);
        @statistic[rcvdPkSeqNo](title="received packet sequence number"; source="appPkSeqNo(packetReceived)"; record=vector; interpolationmode=none);
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}