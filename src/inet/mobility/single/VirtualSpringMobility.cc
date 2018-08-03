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

#include <list>

#include "VirtualSpringMobility.h"

#include "inet/common/INETMath.h"

namespace inet {

Define_Module(VirtualSpringMobility);

VirtualSpringMobility::VirtualSpringMobility() {}

void VirtualSpringMobility::initialize(int stage)
{
    MovingMobilityBase::initialize(stage);

    EV_TRACE << "initializing VirtualSpringMobility stage " << stage << endl;
    if (stage == INITSTAGE_LOCAL) {
        maxspeed = par("maxspeed");
        maxacceleration = par("maxacceleration");

        staticFrictionCoefficient = par("staticFrictionCoefficient");
        kineticFrictionCoefficient = par("kineticFrictionCoefficient");
        frictionForce = par("frictionForce");
        dragCoefficient = par("dragCoefficient");
        defaultStiffness = par("defaultStiffness");

        speed = Coord::ZERO;
        acceleration = Coord::ZERO;
        virtualSpringTotalForce = Coord::ZERO;
        counterIdx = 0;

        WATCH_RW(virtualSpringTotalForce.x);
        WATCH_RW(virtualSpringTotalForce.y);
    }
    else if (stage == INITSTAGE_PHYSICAL_ENVIRONMENT) {
        /*for (int i = 0 ; i < 4; i++) {
            Coord dir = Coord (dblrand()-0.5, dblrand()-0.5);
            dir.normalize();
            addVirtualSpring(dir, dblrand() * 15);
        }*/
    }
}

void VirtualSpringMobility::move()
{
    lastVelocity = speed;
    double elapsedTime = (simTime() - lastUpdate).dbl();
    lastPosition += lastVelocity * elapsedTime;

    // do something if we reach the wall
    if (lastPosition.x < constraintAreaMin.x) lastPosition.x = constraintAreaMin.x;
    if (lastPosition.x > constraintAreaMax.x) lastPosition.x = constraintAreaMax.x;
    if (lastPosition.y < constraintAreaMin.y) lastPosition.y = constraintAreaMin.y;
    if (lastPosition.y > constraintAreaMax.y) lastPosition.y = constraintAreaMax.y;

    Coord radentFrictionForces = getRadentFrictionTotalForces(virtualSpringTotalForce);

    if (speed.length() == 0) {
        if (virtualSpringTotalForce.length() > radentFrictionForces.length()) {
            acceleration = virtualSpringTotalForce + radentFrictionForces;
            speed = acceleration * elapsedTime;
        }
        else {
            acceleration = Coord::ZERO;
            speed = Coord::ZERO;
        }
    }
    else {
        // add aerodynamic friction force
        speed += speed * (-dragCoefficient);

        if (virtualSpringTotalForce.length() > radentFrictionForces.length()) {
            acceleration = virtualSpringTotalForce + radentFrictionForces;
            speed += acceleration * elapsedTime;
        }
        else {
            Coord oppositSpeed = speed * (-1);
            oppositSpeed.normalize();
            acceleration = oppositSpeed * (radentFrictionForces.length() - virtualSpringTotalForce.length());

            Coord diffSpeed = acceleration * elapsedTime;
            if (diffSpeed.length() > speed.length()) {
                acceleration = Coord::ZERO;
                speed = Coord::ZERO;
            }
            else {
                speed += acceleration * elapsedTime;
            }
        }
    }

    // accelerate
    // TODO ! is wrong!!!!
    //double speedLength = speed.length() + (acceleration.length() * elapsedTime);
    //speed += acceleration * elapsedTime;
    //if (speed.length() <= 0) {
    //    speed = Coord::ZERO;
    //}

}

Coord VirtualSpringMobility::getRadentFrictionTotalForces(Coord acc) {
    Coord ris = Coord::ZERO;
    Coord dirFF = acc * (-1);
    dirFF.normalize();

    if (acc.length() > 0) {
        if (lastVelocity == Coord::ZERO) {
            // add static friction force
            ris += dirFF * (staticFrictionCoefficient * frictionForce);
        }
        else {
            // add dynamic friction force
            ris += dirFF * (kineticFrictionCoefficient * frictionForce);
        }
    }

    //if (lastSpeed > 0) {
    //    // add aerodynamic friction force
    //    ris += (-dragCoefficient) * lastSpeed;
    //}

    return ris;
}

unsigned int VirtualSpringMobility::addVirtualSpring(Coord unityDirectionVector, double l0, double springDisplacement){
    return addVirtualSpring(unityDirectionVector, defaultStiffness, l0, springDisplacement);
}

unsigned int VirtualSpringMobility::addVirtualSpring(Coord unityDirectionVector, double stiffness, double l0, double springDisplacement){
    unsigned int ris = ++counterIdx;
    ForceInfo newForce;

    newForce.l0 = l0;
    newForce.displacement = springDisplacement;
    newForce.stiffness = stiffness;
    newForce.unitDirection = unityDirectionVector;
    newForce.force = calculateSpringForce(unityDirectionVector, stiffness, springDisplacement);

    activeForces[ris] = newForce;

    //activeForces[ris] = calculateSpringForce(unityDirectionVector, stiffness, springDisplacement);

   // EV << "VirtualSpringMobility - adding force of " << activeForces[ris].force
   //    << " from stiffness: " << stiffness  << " and displacement: " << springDisplacement << endl;

    // update the force
    updateTotalForce();

    return ris;
}

unsigned int VirtualSpringMobility::updateVirtualSpring(unsigned int idx, Coord unityDirectionVector, double l0, double springDisplacement){
    return updateVirtualSpring(idx, unityDirectionVector, defaultStiffness, l0, springDisplacement);
}

unsigned int VirtualSpringMobility::updateVirtualSpring(unsigned int idx, Coord unityDirectionVector, double stiffness, double l0, double springDisplacement){
    unsigned int ris = 0;

    if (activeForces.count(idx) > 0) {
        ForceInfo newForce;

        newForce.displacement = springDisplacement;
        newForce.l0 = l0;
        newForce.stiffness = stiffness;
        newForce.unitDirection = unityDirectionVector;
        newForce.force = calculateSpringForce(unityDirectionVector, stiffness, springDisplacement);

        activeForces[idx] = newForce;

        //activeForces[idx] = calculateSpringForce(unityDirectionVector, stiffness, springDisplacement);
        ris = idx;
    }

    // update the force
    updateTotalForce();

    return ris;
}

unsigned int VirtualSpringMobility::deleteVirtualSpring(unsigned int idx){
    unsigned int ris = 0;

    if (activeForces.count(idx) > 0) {
        activeForces.erase(idx);
        ris = idx;
    }

    // update the force
    updateTotalForce();

    return ris;

}

void VirtualSpringMobility::clearVirtualSprings(void) {
    activeForces.clear();

    // update the force
    virtualSpringTotalForce = Coord::ZERO;
}

void VirtualSpringMobility::clearVirtualSpringsAndsetPosition(Coord newPos) {
    clearVirtualSprings();

    lastPosition = newPos;
    lastVelocity = speed = acceleration = Coord::ZERO;
}

Coord VirtualSpringMobility::calculateSpringForce(Coord unityDirectionVector, double stiffness, double springDisplacement) {
    Coord u = unityDirectionVector;
    u.normalize();
    return ( u * ((-stiffness) * springDisplacement));
}

void VirtualSpringMobility::filterNodeListAcuteAngleTest(std::list<NodeBasicInfo> &original, std::list<NodeBasicInfo> &filtered) {
    Coord myPos = getCurrentPosition();

    filtered.clear();

    for (auto it = original.begin(); it != original.end(); it++) {
        bool acute_angle_result = true;

        Coord itPos = it->position;

        for (auto check = original.begin(); check != original.end(); check++) {
            if (check != it) {
                Coord checkPos = check->position;

                /****************************************/
                double angle = calculateAngle( myPos, checkPos, itPos );

                if (angle == 0) {
                    if(     (myPos.distance(checkPos) < myPos.distance(itPos)    ) &&
                            (itPos.distance(checkPos) < itPos.distance(myPos)    )){
                        acute_angle_result = false;
                        break;
                    }
                }
                else if((angle > (M_PI / 2)) || (angle < (-(M_PI / 2)))) {
                    acute_angle_result = false;
                    break;
                }
                /****************************************/
            }
        }

        if (acute_angle_result) {
            filtered.push_back(*it);
        }
    }
}

void VirtualSpringMobility::updateTotalForce(void) {
    Coord tot = Coord::ZERO;
    std::list <Coord> passActiveForces;
    std::map <unsigned int, ForceInfo>::iterator it, check;
    Coord myPos = getCurrentPosition();

    // the active forces are the ones that pass the "acute angle test"
    // check for each force the "acute angle test"
    for (it = activeForces.begin(); it != activeForces.end(); it++) {
        bool acute_angle_result = true;
        Coord itPos = myPos + (it->second.unitDirection * (it->second.l0 - it->second.displacement));

        for (check = activeForces.begin(); check != activeForces.end(); check++) {
            if (check != it) {
                Coord checkPos = myPos + (check->second.unitDirection * (check->second.l0 - check->second.displacement));

                /****************************************/
                double angle = calculateAngle( myPos, checkPos, itPos );

                if (angle == 0) {
                    if(     (myPos.distance(checkPos) < myPos.distance(itPos)    ) &&
                            (itPos.distance(checkPos) < itPos.distance(myPos)    )){
                        acute_angle_result = false;
                        break;
                    }
                }
                else if((angle > (M_PI / 2)) || (angle < (-(M_PI / 2)))) {
                    acute_angle_result = false;
                    break;
                }
                /****************************************/

                /*
                double angle = calculateAngle( myPos, checkPos, itPos );

                if (angle == 0) {
                    if ((it->second.unitDirection - check->second.unitDirection).length() > 1){
                        // they are in opposite direction
                        acute_angle_result = false;
                        break;
                    }
                    else if (checkPos.length() < itPos.length()) {
                        // the 'it' is behind 'check'
                        acute_angle_result = false;
                        break;
                    }
                }
                else if((angle > (PI / 2)) || (angle < (-(PI / 2)))) {
                    acute_angle_result = false;
                    break;
                }
                */
            }
        }

        if (acute_angle_result) {
            passActiveForces.push_back(it->second.force);
        }
    }

    for (std::list <Coord>::iterator itAct = passActiveForces.begin(); itAct != passActiveForces.end(); itAct++) {
        tot += *itAct;
    }
    virtualSpringTotalForce = tot;
}

double VirtualSpringMobility::calculateAngle(Coord a, Coord b, Coord c) {
        double vABx, vABy, vABz, vCBx, vCBy, vCBz, tmp1,tmp2;

        vABx = a.x - b.x;
        vABy = a.y - b.y;
        vABz = a.z - b.z;
        vCBx = c.x - b.x;
        vCBy = c.y - b.y;
        vCBz = c.z - b.z;

        tmp1 = vABx*vCBx + vABy*vCBy + vABz*vCBz;
        tmp2 = sqrt(((vABx*vABx) + (vABy*vABy) + (vABz*vABz)) * ((vCBx*vCBx) + (vCBy*vCBy) + (vCBz*vCBz)));

        if(tmp2 != 0) {
            return acos(tmp1/tmp2);
        }
        else {
            return 0;
        }
    }

} /* namespace inet */
