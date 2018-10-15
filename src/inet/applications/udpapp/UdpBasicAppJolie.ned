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
        
        bool implementLocalJolie = default(false);
        string policyType @enum("DETECT_ALONE", "DETECT_FOCUS", "IMAGE_ALONE", "IMAGE_FOCUS", "STIMULUS") = default("DETECT_ALONE");
        
        double coapServerLoopTimer = default(0.05); // time to check message from the server-thread
        string jolieAddress = default("192.168.1.177"); // address of the orchestrator
        int jolieAddressPort = default(5683); // address port of the orchestrator
        string gatewayRealAddress = default("192.168.1.176"); // address of the gateway
        int gatewayRealAddressPort = default(5683); // address port of the gateway
        string droneRegisterStringTemplate = default("{\"address\":\"%s:%d\",\"id\":%d}"); 										// template for the drone-register template message; 	example: {"address":"192.168.1.176:5683","id":0}                     
        string dronePositionStringTemplate = default("{\"uav\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}"); 		// template for the drone-position template message; 	example: {"uav":{"id":0},"position":{"x":20.05,"y":42.65}}
        string droneEnergyStringTemplate = default("{\"uav\":{\"id\":%d},\"energy\":{\"percentage\":%.02lf}}"); 				// template for the drone-position template message; 	example: {"uav":{"id":0},"position":{"residual":2.5}}
        string droneAlertStringTemplate = default("{\"uav\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf},\"result\":{\"accuracy\":%.02lf,\"class\":\"%s\"}}"); 			// template for the drone-alert template message;   	example: {"uav":{"id":0},"position":{"x":20.05,"y":42.65}}
        string droneImageStringTemplateP1 = default("{\"uav\":{\"id\":%d},\"image\":{\"base64\":\""); 							// template for the drone-image part1 template message; example: {"uav":{"id":0},"image":{"base64":"
        string droneImageStringTemplateP2 = default("\"}}"); 																	// template for the drone-image part2 template message; example: "}}
        string droneStatsStringTemplate = default("{\"alarm\":{\"start\":%ld}}"); 		
        
        double neigh_timeout = default(10);	// neighors timeout     
        double finalAlarmDelayTime @unit(s) = default(1s);  
        
        double detectThreshold = default(50);
        double focusActivationThreshold = default(40);
        double googleImageTime @unit(s) = default(1s);
        
        double uavRadiusSensor @unit(m) = default(50m);
        double uavFocusRadius = default(1.2);
        
        double detectPeriodShort @unit(s) = default(3s);
        double imagePeriodShort @unit(s) = default(3s);
        double detectPeriodLong @unit(s) = default(10s);
        double imagePeriodLong @unit(s) = default(10s);
        
        double focusTime @unit(s) = default(15s);
        double limitFocusOffset @unit(s) = default(10s);
        
        double coverStiffness = default(1);
        double focusStiffness = default(3);
        double stopStiffness = default(5);
        
        double alarmTime @unit(s) = default(100s);
        double alarmPositionX = default(100);
        double alarmPositionY = default(100);
        double alarmGaussDeviationDistance = default(50);
        double alarmMaxAccuracyCloud = default(80);
        double alarmMaxAccuracyDrone = default(60);
        double alarmGaussDeviationMax = default(10);    
        
        string logFilePositions = default("logFilePositions.txt");    
        bool saveVectorCoverage = default(false); 
        
        double avgPDRTime @unit(s) = default(30s);                      
        
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
