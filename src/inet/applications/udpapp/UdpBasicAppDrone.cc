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


#include "UdpBasicAppDrone.h"

#include <arpa/inet.h>

#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

namespace inet {

Define_Module(UdpBasicAppDrone);

UdpBasicAppDrone::~UdpBasicAppDrone()
{
    cancelAndDelete(selfMsg);
}

void UdpBasicAppDrone::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    //std::cout << "UdpBasicAppDrone::initialize BEGIN - Stage " << stage << std::flush << endl;

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");

        neigh_timeout = par("neigh_timeout");
        mobility_timeout = par("mobility_timeout");

        actual_spring_stiffness = 1;
        actual_spring_distance = 80;

        myAppAddr = this->getParentModule()->getIndex();
        myIPAddr = Ipv4Address::UNSPECIFIED_ADDRESS;

        setMyState(DS_STOP);

        mob = check_and_cast<IMobility *>(this->getParentModule()->getSubmodule("mobility"));
        vmob = dynamic_cast<VirtualSpringMobility *>(this->getParentModule()->getSubmodule("mobility"));

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

        self1Sec_selfMsg = new cMessage("1sec_self");
        scheduleAt(simTime() + 1, self1Sec_selfMsg);

        selfMobility_selfMsg = new cMessage("mobility_self");
        scheduleAt(simTime() + mobility_timeout, selfMobility_selfMsg);
    }
    else if (stage == INITSTAGE_LAST) {
        addressTable.resize(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize(), Ipv4Address::UNSPECIFIED_ADDRESS);
        gatewayIpAddress = Ipv4Address::UNSPECIFIED_ADDRESS;
    }

    //std::cout << "UdpBasicAppDrone::initialize END - Stage " << stage << std::flush << endl;
}

void UdpBasicAppDrone::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void UdpBasicAppDrone::setSocketOptions()
{
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int typeOfService = par("typeOfService");
    if (typeOfService != -1)
        socket.setTypeOfService(typeOfService);

    const char *multicastInterface = par("multicastInterface");
    if (multicastInterface[0]) {
        IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        InterfaceEntry *ie = ift->getInterfaceByName(multicastInterface);
        if (!ie)
            throw cRuntimeError("Wrong multicastInterface setting: no interface named \"%s\"", multicastInterface);
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    bool receiveBroadcast = par("receiveBroadcast");
    if (receiveBroadcast)
        socket.setBroadcast(true);

    bool joinLocalMulticastGroups = par("joinLocalMulticastGroups");
    if (joinLocalMulticastGroups) {
        MulticastGroupList mgl = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        socket.joinLocalMulticastGroups(mgl);
    }
}

L3Address UdpBasicAppDrone::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

Packet *UdpBasicAppDrone::createBeaconPacket() {

    char msgName[64];
    node_info_msg_t mineInfo;
    sprintf(msgName, "UDPBasicAppBeacon-%d-%d", myAppAddr, numSent);

    long msgByteLength = (sizeof(struct node_info_msg_t)) + sizeof(uint32_t);
    Packet *pk = new Packet(msgName);
    const auto& payload = makeShared<ApplicationBeacon>();
    payload->setChunkLength(B(msgByteLength));
    payload->setSequenceNumber(numSent);
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    //std::cout << "(" << myIPAddr << ") createBeaconPacket() mob " << mob << endl << std::flush;

    mineInfo.mob_position = mob->getCurrentPosition();
    mineInfo.mob_velocity = mob->getCurrentVelocity();

    mineInfo.src_appAddr = myAppAddr;
    mineInfo.src_ipAddr = myIPAddr;

    payload->setSrc_info(mineInfo);

    pk->insertAtBack(payload);
    pk->addPar("sourceId") = getId();
    pk->addPar("msgId") = numSent;

    return pk;
}

void UdpBasicAppDrone::sendPacket() {
    Packet *packet;

    //std::cout << "(" << myIPAddr << ") sendPacket() BEGIN " << endl << std::flush;

    packet = createBeaconPacket();

    //std::cout << "(" << myIPAddr << ") sendPacket() packet created " << endl << std::flush;

    /*std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());
    packet->insertAtBack(payload);*/


    L3Address destAddr = chooseDestAddr();

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending a beacon " << endl << std::flush;

    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void UdpBasicAppDrone::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
    setSocketOptions();

    /*const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;

    while ((token = tokenizer.nextToken()) != nullptr) {
        destAddressStr.push_back(token);
        L3Address result;
        L3AddressResolver().tryResolve(token, result);
        if (result.isUnspecified())
            EV_ERROR << "cannot resolve destination address: " << token << endl;
        destAddresses.push_back(result);
    }*/

    destAddresses.push_back(Ipv4Address::ALLONES_ADDRESS);

    IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
    if (ift) {
        char buf[64];
        for (int i = 0; i < (int)addressTable.size(); i++) {

            //snprintf(buf, sizeof(buf), "UDPBurstML.host[%d]", i);
            snprintf(buf, sizeof(buf), "%s.host[%d]",this->getParentModule()->getParentModule()->getName(), i);
            //EV << "Looking for " << buf << endl;
            L3Address addr = L3AddressResolver().resolve(buf);
            addressTable[i] = addr.toIpv4();
        }

        if (myIPAddr == Ipv4Address::UNSPECIFIED_ADDRESS) {
            InterfaceEntry *wlan = ift->getInterfaceByName("wlan0");
            if (wlan) {
                myIPAddr = wlan->getIpv4Address();
                addressTable[myAppAddr] = myIPAddr;
            }
        }

        snprintf(buf, sizeof(buf), "%s.gateway",this->getParentModule()->getParentModule()->getName());
        L3Address addr = L3AddressResolver().resolve(buf);
        gatewayIpAddress = addr.toIpv4();
    }


    if (!destAddresses.empty()) {
        selfMsg->setKind(SEND);
        processSend();
    }
    else {
        if (stopTime >= SIMTIME_ZERO) {
            selfMsg->setKind(STOP);
            scheduleAt(stopTime, selfMsg);
        }
    }
}

void UdpBasicAppDrone::processSend()
{
    sendPacket();
    simtime_t d = simTime() + par("sendInterval");
    if (stopTime < SIMTIME_ZERO || d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleAt(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleAt(stopTime, selfMsg);
    }
}

void UdpBasicAppDrone::processStop()
{
    socket.close();
}

void UdpBasicAppDrone::handleMessageWhenUp(cMessage *msg)
{
    if (msg == self1Sec_selfMsg) {
            msg1sec_call();
            scheduleAt(simTime() + 1, self1Sec_selfMsg);
        }
    else if (msg == selfMobility_selfMsg) {
        updateMobility();
        scheduleAt(simTime() + mobility_timeout, selfMobility_selfMsg);
    }
    else if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
        }
    }
    else if (msg->getKind() == UDP_I_DATA) {
        // process incoming packet
        if (strncmp(msg->getName(), "UDPBasicAppPolicy", 17) == 0) {
            manageNewPolicy(check_and_cast<Packet *>(msg));
        }
        else if (strncmp(msg->getName(), "UDPBasicAppBeacon", 17) == 0){
            processPacket(check_and_cast<Packet *>(msg));
        }
        else {
            throw cRuntimeError("Unrecognized data message (%s)%s", msg->getClassName(), msg->getName());
        }

    }
    else if (msg->getKind() == UDP_I_ERROR) {
        EV_WARN << "Ignoring UDP error report\n";
        delete msg;
    }
    else {
        throw cRuntimeError("Unrecognized message (%s)%s", msg->getClassName(), msg->getName());
    }
}

void UdpBasicAppDrone::refreshDisplay() const
{
    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);


    sprintf(buf, "IP: %s", myIPAddr.str().c_str());
    this->getParentModule()->getDisplayString().setTagArg("t", 0, buf);
}

void UdpBasicAppDrone::msg1sec_call(void) {
    for (auto& n : neighMap) {
        auto it = n.second.begin();
        while (it != n.second.end()) {
            if (it->timestamp_lastSeen > neigh_timeout) {
                it = n.second.erase(it);
            }
            else {
                it++;
            }
        }
    }
}

void UdpBasicAppDrone::addVirtualSpringToMobility(Coord destPos, double spring_l0, double spring_stiffness) {
    if (vmob) {
        Coord myPos = mob->getCurrentPosition();

        double springDispl = spring_l0 - destPos.distance(myPos);

        Coord uVec = destPos - myPos;
        uVec.normalize();

        vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl);
    }
}

void UdpBasicAppDrone::updateMobility(void) {
    if (vmob) {
        //Coord myPos = mob->getCurrentPosition();

        // clear everything
        vmob->clearVirtualSprings();

        for (auto& n : neighMap) {
            if (n.second.size() > 0) {
                UdpBasicAppJolie::neigh_info_t *ni = &(*(n.second.begin()));
                //Coord neighPos = ni->info.mob_position + (ni->info.mob_velocity * (simTime() - ni->timestamp_lastSeen));  //TODO see if it is ok
                Coord neighPos = ni->info.mob_position;

                addVirtualSpringToMobility(neighPos, actual_spring_distance, actual_spring_stiffness);

                /*double distance = neighPos.distance(myPos);

                double springDispl = actual_spring_distance - distance;

                Coord uVec = neighPos - myPos;
                uVec.normalize();

                vmob->addVirtualSpring(uVec, actual_spring_stiffness, actual_spring_distance, springDispl);*/
            }
        }

        if (getMyState() == DS_FOCUS) {
            addVirtualSpringToMobility(focus_point, focus_spring_distance, focus_spring_stiffness);
        }
        else if (getMyState() == DS_STOP) {
            addVirtualSpringToMobility(stop_point, stop_spring_distance, stop_spring_stiffness);
        }
    }
}

void UdpBasicAppDrone::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    manageReceivedBeacon(pk);

    delete pk;
    numReceived++;
}

void UdpBasicAppDrone::manageReceivedBeacon(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationBeacon>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationBeacon -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());

    Ipv4Address rcvIPAddr = appmsg->getSrc_info().src_ipAddr;
    if (rcvIPAddr != myIPAddr){
        if (neighMap.count(rcvIPAddr) == 0) {
            neighMap[rcvIPAddr] = std::list<UdpBasicAppJolie::neigh_info_t>();
        }
        UdpBasicAppJolie::neigh_info_t rcvInfo;
        rcvInfo.timestamp_lastSeen = simTime();
        rcvInfo.info = appmsg->getSrc_info();

        neighMap[rcvIPAddr].push_front(rcvInfo);

        //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Received a beacon from (" << rcvInfo.info.src_ipAddr << ")" << endl << std::flush;
    }
}

void UdpBasicAppDrone::manageNewPolicy(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationPolicy>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationPolicy -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());

    EV_INFO << "Received policy: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    int policy_id = appmsg->getP_id();
    switch (policy_id) {
    case P_COVER:
        setMyState(DS_COVER);
        actual_spring_stiffness = appmsg->getStiffness();
        actual_spring_distance = appmsg->getDistance();
        break;

    case P_STOP:
        setMyState(DS_STOP);
        stop_point = appmsg->getPosition();
        stop_spring_stiffness = appmsg->getStiffness();
        stop_spring_distance = appmsg->getDistance();
        break;

    case P_FOCUS:
        setMyState(DS_FOCUS);
        focus_point = appmsg->getPosition();
        focus_spring_stiffness = appmsg->getStiffness();
        focus_spring_distance = appmsg->getDistance();
        break;

    default:
        throw cRuntimeError("Unknown received policy. ID: %d", policy_id);
        break;
    }

    delete pk;
}

bool UdpBasicAppDrone::handleNodeStart(IDoneCallback *doneCallback)
{
    simtime_t start = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(start, selfMsg);
    }
    return true;
}

bool UdpBasicAppDrone::handleNodeShutdown(IDoneCallback *doneCallback)
{
    if (selfMsg)
        cancelEvent(selfMsg);
    return true;
}

void UdpBasicAppDrone::handleNodeCrash()
{
    if (selfMsg)
        cancelEvent(selfMsg);
}


} // namespace inet

