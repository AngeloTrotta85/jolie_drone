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

#ifndef INET_MOBILITY_SINGLE_VIRTUALSPRINGMOBILITY_H_
#define INET_MOBILITY_SINGLE_VIRTUALSPRINGMOBILITY_H_

#include <stdlib.h>
#include "inet/common/INETDefs.h"

#include "inet/mobility/base/MovingMobilityBase.h"
#include "inet/power/contract/IEpEnergyConsumer.h"
#include "inet/power/contract/IEpEnergySource.h"

namespace inet {

class VirtualSpringMobility : public MovingMobilityBase, public power::IEpEnergyConsumer {

public:
    typedef struct {
        Coord force;
        Coord unitDirection;
        double l0;
        double stiffness;
        double displacement;
    } ForceInfo;

    typedef struct {
        int id;
        Coord position;
    } NodeBasicInfo;

public:
    VirtualSpringMobility();

    /** @brief Add a new force
     *  @param unityDirectionVector direction of the spring
     *  @param l0 the natural spring length
     *  @param springDisplacement the displacement of the spring (l0 - l) [l0 is the natural spring length]
     *  @return the univocal index
     */
    unsigned int addVirtualSpring(Coord unityDirectionVector, double l0, double springDisplacement);
    unsigned int addVirtualSpring(Coord unityDirectionVector, double stiffness, double l0, double springDisplacement);
    unsigned int addVirtualSpring(Coord unityDirectionVector, double stiffness, double l0, double springDisplacement, bool acuteTest);

    /** @brief Update an existing virtual spring
     *  @param idx the spring to modify
     *  @param unityDirectionVector direction of the spring
     *  @param l0 the natural spring length
     *  @param springDisplacement the displacement of the spring (l0 - l) [l0 is the natural spring length]
     *  @return the univocal index "idx";  0 if an error occurred
     */
    unsigned int updateVirtualSpring(unsigned int idx, Coord unityDirectionVector, double l0, double springDisplacement);
    unsigned int updateVirtualSpring(unsigned int idx, Coord unityDirectionVector, double stiffness, double l0, double springDisplacement);

    /** @brief Delete an existing virtual spring
     *  @param idx the spring to delete
     *  @return the univocal index "idx";  0 if an error occurred
     */
    unsigned int deleteVirtualSpring(unsigned int idx);


    /** @brief Clear all the virtual springs */
    void clearVirtualSprings(void);

    /** @brief Set statically a new position */
    void clearVirtualSpringsAndsetPosition(Coord newPos);

    /** @brief Filter the node list by doing the acute angle test */
    void filterNodeListAcuteAngleTest(std::list<NodeBasicInfo> &original, std::list<NodeBasicInfo> &filtered);


    virtual power::IEnergySource *getEnergySource() const override { return energySource; }
    virtual W getPowerConsumption() const override { return powerConsumption; }

protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

    /** @brief Initializes mobility model parameters.*/
    virtual void initialize(int stage) override;

    /** @brief Move the host*/
    virtual void move() override;

    virtual void drainEnergyByAllMotors(void);

private:
    /** @brief Calculate the force */
    Coord calculateSpringForce(Coord unityDirectionVector, double stiffness, double springDisplacement);

    /** @brief Update the total force */
    void updateTotalForce(void);

    /** @brief Calculate the total friction force on the node */
    Coord getRadentFrictionTotalForces(Coord acc);

    /** @brief Calculate the angle BAC */
    double calculateAngle(Coord a, Coord b, Coord c);

    /** @brief Calculate total motors consumption */
    W calculateTotalMotorConsumption(void);


protected:
    /** @brief Maximum speed of the host */
    double maxspeed;

    /** @brief Maximum acceleration of the host */
    double maxacceleration;

    /** @brief Static friction coefficient */
    double staticFrictionCoefficient;

    /** @brief Kinetic friction coefficient */
    double kineticFrictionCoefficient;

    /** @brief Friction force */
    double frictionForce;

    /** @brief Aerodynamic friction */
    double dragCoefficient;

    /** @brief Default stiffness */
    double defaultStiffness;

    /** @brief Force on the node*/
    Coord virtualSpringTotalForce;

    /** @brief Actual speed of the node */
    Coord speed;

    /** @brief Actual acceleration of the node */
    Coord acceleration;

    /** @brief Single motor consumption */
    W motorConsumption;

private:
    std::map <unsigned int, ForceInfo> activeForces;
    std::map <unsigned int, ForceInfo> activeForces_noAcuteTest;
    unsigned int counterIdx;

    power::IEpEnergySource *energySource = nullptr;
    W powerConsumption = W(NaN);
};

} /* namespace inet */

#endif /* INET_MOBILITY_SINGLE_VIRTUALSPRINGMOBILITY_H_ */
