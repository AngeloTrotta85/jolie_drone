//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

import inet.common.INETDefs;
import inet.common.geometry.Geometry;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;

namespace inet;

struct SpringForce
{
    int s_id;
    //char s_name[32];
    string s_name;
    
    double distance;
    Coord position;
    double stiffness;
};

//
// TODO generated message class
//
class ApplicationPolicy extends FieldsChunk {
	int dest_appAddr;
	Ipv4Address dest_ipAddr;
	
	int p_id;
	//char p_name[32];
	string p_name;
	
	int drone_id;
	
	int a_id;
	//char a_name[32]; 
	string a_name;   
	string a_class;   
    double a_period;
	
	SpringForce springs[3];
	
}
