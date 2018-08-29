//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2004,2011 Andras Varga
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

#ifndef __INET_UDPBASICAPPDRONE_H
#define __INET_UDPBASICAPPDRONE_H

#include <inet/common/INETDefs.h>

#include <coap.h>
#include <vector>
#include <thread>         // std::thread

#include <inet/applications/base/ApplicationPacket_m.h>
#include <inet/applications/base/ApplicationBase.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>

#include "../base/ApplicationBeacon_m.h"
#include "../base/ApplicationPolicy_m.h"
#include "../base/ApplicationDroneAlert_m.h"
#include "../base/ApplicationDronePosition_m.h"
#include "../base/ApplicationDroneRegister_m.h"

#include "inet/mobility/single/VirtualSpringMobility.h"

#include "UdpBasicAppJolie.h"

namespace inet {

/**
 * UDP application. See NED for more info.
 */
class INET_API UdpBasicAppDrone : public ApplicationBase
{
public:
    enum DroneState {
        DS_COVER = 1,
        DS_STOP = 2,
        DS_FOCUS = 3
    };

  protected:
    enum SelfMsgKinds { START = 1, SEND, STOP };

    // parameters
    std::vector<L3Address> destAddresses;
    std::vector<std::string> destAddressStr;
    int localPort = -1, destPort = -1;
    simtime_t startTime;
    simtime_t stopTime;
    const char *packetName = nullptr;
    double neigh_timeout;
    double mobility_timeout;

    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;
    DroneState myState;

    int myAppAddr;
    Ipv4Address myIPAddr;
    std::vector<Ipv4Address> addressTable;
    Ipv4Address gatewayIpAddress;


    // statistics
    int numSent = 0;
    int numReceived = 0;

    //internal variables
    cMessage *self1Sec_selfMsg = nullptr;
    cMessage *selfMobility_selfMsg = nullptr;
    IMobility *mob;
    VirtualSpringMobility *vmob;

    double actual_spring_stiffness;
    double actual_spring_distance;

    Coord focus_point;
    double focus_spring_stiffness;
    double focus_spring_distance;

    Coord stop_point;
    double stop_spring_stiffness;
    double stop_spring_distance;

    Coord lastSentPosition;
    double thresholdPositionUpdate;

    std::map<Ipv4Address, std::list<UdpBasicAppJolie::neigh_info_t>> neighMap;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    // chooses random destination address
    virtual L3Address chooseDestAddr();
    virtual void sendPacket();
    virtual void processPacket(Packet *msg);
    virtual void setSocketOptions();

    virtual void processStart();
    virtual void processSend();
    virtual void processStop();

    virtual bool handleNodeStart(IDoneCallback *doneCallback) override;
    virtual bool handleNodeShutdown(IDoneCallback *doneCallback) override;
    virtual void handleNodeCrash() override;

    virtual void manageReceivedBeacon(Packet *msg);
    virtual Packet *createBeaconPacket();

    virtual void manageNewPolicy(Packet *pk);

    virtual void registerUAV_init(void);
    virtual void positionUAV_update(void);
    virtual void alertUAV_send(void);

    void msg1sec_call(void);
    void updateMobility(void);
    void addVirtualSpringToMobility(Coord destPos, double spring_l0, double spring_stiffness);


  public:
    UdpBasicAppDrone() {}
    ~UdpBasicAppDrone();

    DroneState getMyState() const { return myState; }
    void setMyState(DroneState myState) { this->myState = myState; }
};

} // namespace inet

#endif // ifndef __INET_UDPBASICAPPDRONE_H

