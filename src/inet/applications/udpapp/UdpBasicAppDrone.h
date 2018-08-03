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

#include "inet/mobility/single/VirtualSpringMobility.h"

#include "UdpBasicAppJolie.h"

namespace inet {

/**
 * UDP application. See NED for more info.
 */
class INET_API UdpBasicAppDrone : public ApplicationBase
{
  protected:
    enum SelfMsgKinds { START = 1, SEND, STOP };

    // parameters
    std::vector<L3Address> destAddresses;
    std::vector<std::string> destAddressStr;
    int localPort = -1, destPort = -1;
    simtime_t startTime;
    simtime_t stopTime;
    const char *packetName = nullptr;

    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;

    int myAppAddr;
    Ipv4Address myIPAddr;
    std::vector<Ipv4Address> addressTable;
    Ipv4Address gatewayIpAddress;


    // statistics
    int numSent = 0;
    int numReceived = 0;

    //internal variables
    IMobility *mob;

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


  public:
    UdpBasicAppDrone() {}
    ~UdpBasicAppDrone();
};

} // namespace inet

#endif // ifndef __INET_UDPBASICAPPDRONE_H

