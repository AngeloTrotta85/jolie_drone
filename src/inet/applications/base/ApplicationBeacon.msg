//
// Copyright (C) 2016 Andras Varga
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

import inet.common.INETDefs;
import inet.common.geometry.Geometry;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;


struct node_info_msg_t {
	int src_appAddr;
	Ipv4Address src_ipAddr;
	
	// MOBILITY
	Coord mob_position;
	Coord mob_velocity;
    
    //// MAC
    //double queuesizePerc;  
    //double sendRetryPerc;

    //// IP-MAC
    //double generatedByteIP;
    //double receivedByteIP;
    //double genVStransmIpByte;
    
	//// APPLICATION 
    //double nodeDegree;
};


class ApplicationBeacon extends FieldsChunk
{
    uint32_t sequenceNumber;
    node_info_msg_t src_info;
    
    int uavReferee;
    bool isGW;
    
    
    //Ipv4Address nhAddr[];
    //int nhByteGen[];
    //double nhMBsecGen[];
}
