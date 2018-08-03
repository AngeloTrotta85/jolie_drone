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

package inet.mobility.single;

import inet.mobility.base.MovingMobilityBase;

//
// This is a linear mobility model with speed, angle and acceleration parameters.
// Angle only changes when the mobile node hits a wall: then it reflects
// off the wall at the same angle.
//
// @author Angelo Trotta - trotta@cs.unibo.it
//
simple VirtualSpringMobility extends MovingMobilityBase
{
    parameters:
        double initialX @unit(m) = default(uniform(this.constraintAreaMinX, this.constraintAreaMaxX));
        double initialY @unit(m) = default(uniform(this.constraintAreaMinY, this.constraintAreaMaxY));
        double initialZ @unit(m) = default(uniform(this.constraintAreaMinZ, this.constraintAreaMaxZ));
        bool initFromDisplayString = default(true);
        //double speed @unit(mps) = default(0mps); // speed of the host
        //double angle @unit(deg) = default(uniform(0deg, 360deg)); // angle of linear motion
        //double acceleration = default(0); // acceleration of linear motion (m/s2)
        double maxacceleration = default(1); // acceleration of linear motion (m/s2)
        double maxspeed @unit(mps) = default(1 mps); // speed of the host (in m/s)
        
        
        double staticFrictionCoefficient = default(0.5); //  static friction coefficient
        double kineticFrictionCoefficient = default(0.3); //  dynamic friction coefficient
        double frictionForce = default(10); //  friction force - define the force applied with the previuos coefficient
        double dragCoefficient = default(0.04); //  Aerodynamic friction (streamlined body)
        double defaultStiffness = default(2);	// default spring stiffness
        @class(VirtualSpringMobility);
}
