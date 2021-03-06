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

//#include "inet/power/storage/SimpleEpEnergyStorage.h"

namespace inet {

//using namespace inet::power;

Define_Module(UdpBasicAppDrone);

UdpBasicAppDrone::~UdpBasicAppDrone()
{
    cancelAndDelete(selfMsg);
    cancelAndDelete(periodicExecutionMsg);
    cancelAndDelete(periodicMsg);
    cancelAndDelete(selfPosition_selfMsg);
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
        thresholdPositionUpdate = par("thresholdPositionUpdate");
        thresholdEnergyUpdate = par("thresholdEnergyUpdate");
        uavImageSize = par("uavImageSize");
        uavImageFragment = par("uavImageFragment");
        detectionTime = par("detectionTime");

        uavRadiusSensor = par("uavRadiusSensor");

        UdpBasicAppJolie *jiot = check_and_cast<UdpBasicAppJolie *>(this->getParentModule()->getParentModule()->getSubmodule("gateway")->getSubmodule("app", 0));

        alarmTime = jiot->par("alarmTime");
        double alarmPositionX = jiot->par("alarmPositionX");
        double alarmPositionY = jiot->par("alarmPositionY");
        alarmPosition = Coord(alarmPositionX, alarmPositionY);
        alarmGaussDeviationDistance = jiot->par("alarmGaussDeviationDistance");
        alarmMaxAccuracy = jiot->par("alarmMaxAccuracyDrone");
        alarmGaussDeviationMax = jiot->par("alarmGaussDeviationMax");

        first_policy_received = -1;
        imageId2send = 0;
        uniqueIDmsg = 0;

        actual_spring_stiffness = 1;
        actual_spring_distance = 80;
        lastSentPosition = Coord::ZERO;
        lastSentEnergy = -1;
        WATCH(lastSentEnergy);
        WATCH(lastSentPosition);

        myAppAddr = this->getParentModule()->getIndex();
        myIPAddr = Ipv4Address::UNSPECIFIED_ADDRESS;

        setMyState(DS_STOP);

        mob = check_and_cast<IMobility *>(this->getParentModule()->getSubmodule("mobility"));
        vmob = dynamic_cast<VirtualSpringMobility *>(this->getParentModule()->getSubmodule("mobility"));

        //energySource = getModuleFromPar<IEpEnergySource>(par("energySourceModule"), this);
        //powerConsumption = W(0);

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

        selfPosition_selfMsg = new cMessage("selfPosition_selfMsg");

        periodicMsg = new cMessage("periodicMsg_selfMsg");
        periodicExecutionMsg = new cMessage("periodicExecutionMsg_selfMsg");

        self1Sec_selfMsg = new cMessage("1sec_self");
        scheduleAt(simTime() + 1, self1Sec_selfMsg);

        selfMobility_selfMsg = new cMessage("mobility_self");
        scheduleAt(simTime() + mobility_timeout, selfMobility_selfMsg);
    }
    else if (stage == INITSTAGE_PHYSICAL_ENVIRONMENT) {
        //energySource->addEnergyConsumer(this);
    }
    else if (stage == INITSTAGE_LAST) {
        addressTable.resize(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize(), Ipv4Address::UNSPECIFIED_ADDRESS);
        gatewayIpAddress = Ipv4Address::UNSPECIFIED_ADDRESS;

        //for (int i = 0; i < 20; i++) {
            //std::cout << "Parameter detectionTime: " << truncnormal(detectionTime, 0.1) << endl;
            //sleep(1);
        //}
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
    payload->setUavReferee(-1);

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

    registerUAV_init();

    first_policy_received = 0;

    stop_point = mob->getCurrentPosition();
    stop_spring_distance = 0;
    stop_spring_stiffness = 100;
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
    else if (msg == selfPosition_selfMsg) {
        sendUpdatePosition();
        //sendUpdateEnergy();
        //checkAlert();
        scheduleAt(simTime() + 1, selfPosition_selfMsg);
    }
    else if (msg == periodicMsg) {
        //if (!periodicExecutionMsg->isScheduled()) {
            //cancelEvent(periodicMsg);
            //periodicExecutionMsg->ge
            //scheduleAt(simTime() + time + 0.01, periodicMsg);

        //    periodicPolicy();
        //    scheduleAt(simTime() + action_period, periodicMsg);
        //}

        if (!periodicExecutionMsg->isScheduled()) {
            periodicPolicy();
        }
        scheduleAt(simTime() + truncnormal(action_period, action_period/20.0), periodicMsg);
    }
    else if (msg == periodicExecutionMsg) {
        endImageRecognition();
    }
    else if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                scheduleAt(simTime() + 1, selfPosition_selfMsg);
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
    /*for (auto& n : neighMap) {
        auto it = n.second.begin();
        while (it != n.second.end()) {
            if (it->timestamp_lastSeen > neigh_timeout) {
                it = n.second.erase(it);
            }
            else {
                it++;
            }
        }
    }*/

    if (first_policy_received == 0) {
        if (dblrand() < 0.2) {
            registerUAV_init();
        }
    }

    simtime_t nowT = simTime();

    auto it = neighMap.begin();
    while(it != neighMap.end()) {
        if ((nowT - it->second.timestamp_lastSeen) > neigh_timeout) {
            it = neighMap.erase(it);
        }
        else {
            it++;
        }
    }
}

void UdpBasicAppDrone::addVirtualSpringToMobility(Coord destPos, double spring_l0, double spring_stiffness, spring_type st, bool make_acute_test) {
    if (vmob) {
        Coord myPos = mob->getCurrentPosition();

        double springDispl = spring_l0 - destPos.distance(myPos);

        Coord uVec = destPos - myPos;
        uVec.normalize();

        switch (st) {
        case NORMAL_SPRING:
        default:
            vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl, make_acute_test);
            break;

        case ONLY_REPULSIVE_SPRING:
            if (springDispl > 0) {
                vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl, make_acute_test);
            }
            break;

        case ONLY_ATTRACTIVE_SPRING:
            if (springDispl < 0) {
                vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl, make_acute_test);
            }
            break;

        }

        //vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl, make_acute_test);
        //vmob->addVirtualSpring(uVec, spring_stiffness, spring_l0, springDispl, st);
    }
}

void UdpBasicAppDrone::periodicPolicy(void) {
    if (action_type == A_IMAGE) {
        takeSnapshot();
        imageUAV_send();
        //imageUAV_send_useFragments();
    }
    else if (action_type == A_DETECT) {
        executeImageRecognition();
        //alertUAV_send(99, "zingaro");
    }
}

void UdpBasicAppDrone::sendUpdatePosition(void) {
    //check to send the position

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Check position"
    //        << " - lastSentPosition = " << lastSentPosition
    //        << " - mob->getCurrentPosition(): " << mob->getCurrentPosition()
    //        << " - distance: " << mob->getCurrentPosition().distance(lastSentPosition)
    //        << " - thresholdPositionUpdate: " << thresholdPositionUpdate
    //        << endl << std::flush;

    if (    (lastSentPosition == Coord::ZERO) ||
            (mob->getCurrentPosition().distance(lastSentPosition) > thresholdPositionUpdate) ) {
        positionUAV_update();
        lastSentPosition = mob->getCurrentPosition();
    }
    //positionUAV_update();
}

void UdpBasicAppDrone::sendUpdateEnergy(void) {
    //check to send the energy
    //SimpleEpEnergyStorage *es = getModuleFromPar<SimpleEpEnergyStorage>(par("energySourceModule"), this);
    //double actEnergy = es->getResidualEnergyCapacity().get(); //static_cast<SimpleEpEnergyStorage *>(energySource)->getResidualEnergyCapacity().get();
    //double actEnergy = getResidualEnergy().get();
    double actEnergy = getResidualEnergyPercentage();


    if (    (lastSentEnergy < 0) ||
            (fabs(actEnergy - lastSentEnergy) > thresholdEnergyUpdate) ) {
        energyUAV_update();
        lastSentEnergy = actEnergy;
    }
    //positionUAV_update();
}

void UdpBasicAppDrone::updateMobility(void) {
    if (vmob) {
        //Coord myPos = mob->getCurrentPosition();

        // clear everything
        vmob->clearVirtualSprings();

        if (actual_spring_isActive) {

            for (auto& n : neighMap) {

                UdpBasicAppJolie::neigh_info_t *ni = &(n.second);

                if (ni->isGW) continue; // remove the gateway

                //Coord neighPos = ni->info.mob_position + (ni->info.mob_velocity * (simTime() - ni->timestamp_lastSeen));  //TODO see if it is ok
                Coord neighPos = ni->info.mob_position;

                addVirtualSpringToMobility(neighPos, actual_spring_distance, actual_spring_stiffness, NORMAL_SPRING, true);

                //if (n.second.size() > 0) {
                //    UdpBasicAppJolie::neigh_info_t *ni = &(*(n.second.begin()));

                    //if ((ni->isGW) && (ni->uavReferee != myAppAddr)) continue; // remove the gateway
                //    if (ni->isGW) continue; // remove the gateway

                    //Coord neighPos = ni->info.mob_position + (ni->info.mob_velocity * (simTime() - ni->timestamp_lastSeen));  //TODO see if it is ok
                //    Coord neighPos = ni->info.mob_position;

                //    addVirtualSpringToMobility(neighPos, actual_spring_distance, actual_spring_stiffness);

                    /*double distance = neighPos.distance(myPos);

                double springDispl = actual_spring_distance - distance;

                Coord uVec = neighPos - myPos;
                uVec.normalize();

                vmob->addVirtualSpring(uVec, actual_spring_stiffness, actual_spring_distance, springDispl);*/
                //}
            }

            for (auto& n : neighMap) {
                //if (n.second.size() > 0) {
                //UdpBasicAppJolie::neigh_info_t *ni = &(*(n.second.begin()));
                UdpBasicAppJolie::neigh_info_t *ni = &(n.second);
                if (ni->isGW) {
                    if (ni->uavReferee == myAppAddr) {
                        Coord neighPos = ni->info.mob_position;
                        //double distance = neighPos.distance(mob->getCurrentPosition());
                        //if (distance > actual_spring_distance) {
                            //addVirtualSpringToMobility(neighPos, actual_spring_distance, actual_spring_stiffness);
                        //}
                        addVirtualSpringToMobility(neighPos, actual_spring_distance, actual_spring_stiffness, ONLY_ATTRACTIVE_SPRING, false);
                    }
                    break;
                }
                //}
            }
        }

        if (focus_spring_isActive) {
            addVirtualSpringToMobility(focus_point, focus_spring_distance, focus_spring_stiffness, ONLY_ATTRACTIVE_SPRING, false);
        }

        if (stop_spring_isActive) {
            addVirtualSpringToMobility(stop_point, stop_spring_distance, stop_spring_stiffness, ONLY_ATTRACTIVE_SPRING, false);
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
        //if (neighMap.count(rcvIPAddr) == 0) {
        //    neighMap[rcvIPAddr] = std::list<UdpBasicAppJolie::neigh_info_t>();
        //}
        UdpBasicAppJolie::neigh_info_t rcvInfo;
        rcvInfo.timestamp_lastSeen = simTime();
        rcvInfo.info = appmsg->getSrc_info();
        rcvInfo.uavReferee = appmsg->getUavReferee();
        rcvInfo.isGW = appmsg->isGW();

        //neighMap[rcvIPAddr].push_front(rcvInfo);
        neighMap[rcvIPAddr] = rcvInfo;

        //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Received a beacon from (" << rcvInfo.info.src_ipAddr << ")" << endl << std::flush;
    }
}

void UdpBasicAppDrone::manageNewPolicy(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationPolicy>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationPolicy -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());

    first_policy_received = 1;

    EV_INFO << "Received policy: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] received a new policy. Policy ID: "<< appmsg->getP_id() << ". Action ID: " << appmsg->getA_id() << endl << std::flush;

    initPolicyVariables();

    if ((appmsg->getA_id() == A_DETECT) || (appmsg->getA_id() == A_IMAGE)) {
        action_period = appmsg->getA_period();
        action_type = appmsg->getA_id();
        action_class = std::string(appmsg->getA_class());
        scheduleAt(simTime(), periodicMsg);
    }

    if (appmsg->getSprings(SPRING_COVER_IDX).s_id == P_COVER) {
        actual_spring_isActive = true;
        actual_spring_stiffness = appmsg->getSprings(SPRING_COVER_IDX).stiffness;
        actual_spring_distance = appmsg->getSprings(SPRING_COVER_IDX).distance;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Cover active. Stiff : " << actual_spring_stiffness <<
                "; distance: " << actual_spring_distance << endl << std::flush;
    }

    if (appmsg->getSprings(SPRING_FOCUS_IDX).s_id == P_FOCUS) {
        focus_spring_isActive = true;
        focus_point = appmsg->getSprings(SPRING_FOCUS_IDX).position;
        focus_spring_stiffness = appmsg->getSprings(SPRING_FOCUS_IDX).stiffness;
        focus_spring_distance = appmsg->getSprings(SPRING_FOCUS_IDX).distance;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Focus active. Point: "
                << focus_point << "; stiff : " << focus_spring_stiffness <<
                        "; distance: " << focus_spring_distance << endl << std::flush;
    }

    if (appmsg->getSprings(SPRING_STOP_IDX).s_id == P_STOP) {
        stop_spring_isActive = true;
        stop_point = appmsg->getSprings(SPRING_STOP_IDX).position;
        stop_spring_stiffness = appmsg->getSprings(SPRING_STOP_IDX).stiffness;
        stop_spring_distance = appmsg->getSprings(SPRING_STOP_IDX).distance;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Stop active. Point: "
                        << stop_point << "; stiff : " << stop_spring_stiffness <<
                                "; distance: " << stop_spring_distance << endl << std::flush;
    }

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Policy name: " << appmsg->getP_name()
            << "; Action name: " << appmsg->getA_name() << "(" << ((appmsg->getA_id() == A_IMAGE) ? "A_IMAGE" : "A_DETECT") << ")"
            << "; Cover Spring: " << appmsg->getSprings(SPRING_COVER_IDX).s_name << "(dist:" << appmsg->getSprings(SPRING_COVER_IDX).s_name << ")"
            << "; Stop Spring: " << appmsg->getSprings(SPRING_FOCUS_IDX).s_name << "(dist:" << appmsg->getSprings(SPRING_FOCUS_IDX).s_name << ")"
            << "; Stop Spring: " << appmsg->getSprings(SPRING_STOP_IDX).s_name << "(dist:" << appmsg->getSprings(SPRING_STOP_IDX).s_name << ")"
            << endl;

    /*int policy_id = appmsg->getP_id();
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

    case P_DETECT:
        setMyState(DS_DETECT);
        extra_point = appmsg->getPosition();
        extra_spring_stiffness = appmsg->getStiffness();
        extra_spring_distance = appmsg->getDistance();
        extra_period = appmsg->getPeriod();
        scheduleAt(simTime(), periodicMsg);
        break;

    case P_IMAGE:
        setMyState(DS_IMAGE);
        extra_point = appmsg->getPosition();
        extra_spring_stiffness = appmsg->getStiffness();
        extra_spring_distance = appmsg->getDistance();
        extra_period = appmsg->getPeriod();
        scheduleAt(simTime(), periodicMsg);
        break;

    default:
        throw cRuntimeError("Unknown received policy. ID: %d", policy_id);
        break;
    }*/

    delete pk;
}

void UdpBasicAppDrone::initPolicyVariables(void){

    cancelEvent(periodicMsg);
    cancelEvent(periodicExecutionMsg);

    actual_spring_stiffness = 0;
    actual_spring_distance = 0;
    actual_spring_isActive = false;

    focus_point = Coord::ZERO;
    focus_spring_stiffness = 0;
    focus_spring_distance = 0;
    focus_spring_isActive = false;

    stop_point = Coord::ZERO;
    stop_spring_stiffness = 0;
    stop_spring_distance = 0;
    stop_spring_isActive = false;

    action_period = 0;
    action_type = A_NONE;
}

void UdpBasicAppDrone::registerUAV_init(void) {
    char msgName[64];
    sprintf(msgName, "UDPBasicAppDroneReg-%d", myAppAddr);

    long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t);

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDroneRegister>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the registration" << endl << std::flush;

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);
}

void UdpBasicAppDrone::positionUAV_update(void) {
    char msgName[64];
    sprintf(msgName, "UDPBasicAppDronePos-%d", myAppAddr);

    long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + (2.0 * sizeof(double));

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDronePosition>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);
    payload->setPosition(mob->getCurrentPosition());

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the position: " << mob->getCurrentPosition() << endl << std::flush;

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);
}

J UdpBasicAppDrone::getResidualEnergy(void) {
    //SimpleEpEnergyStorage *es = getModuleFromPar<SimpleEpEnergyStorage>(par("energySourceModule"), this);
    //return es->getResidualEnergyCapacity();
    return J(0);
}

double UdpBasicAppDrone::getResidualEnergyPercentage(void){
    //SimpleEpEnergyStorage *es = getModuleFromPar<SimpleEpEnergyStorage>(par("energySourceModule"), this);
    //return ((es->getResidualEnergyCapacity().get() / es->getNominalEnergyCapacity().get()) * 100.0);
    return 0;
}

void UdpBasicAppDrone::energyUAV_update(void) {
    char msgName[64];
    sprintf(msgName, "UDPBasicAppDroneEnergy-%d", myAppAddr);

    long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + (2.0 * sizeof(double));
    //long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + uavImageSize;

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDroneEnergy>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);
    //payload->setResidual(getResidualEnergy().get());
    payload->setResidual(getResidualEnergyPercentage());

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the energy: " << payload->getResidual() << endl << std::flush;

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);
}

void UdpBasicAppDrone::alertUAV_send(double acc, const char *classe) {
    char msgName[64];
    sprintf(msgName, "UDPBasicAppDroneAlert-%d-%d", myAppAddr, uniqueIDmsg);

    long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + (2.0 * sizeof(double));

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDroneAlert>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);
    payload->setPosition(mob->getCurrentPosition());
    payload->setAccuracy(acc);
    payload->setClasse(classe);

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the alert: "
            << mob->getCurrentPosition()
            << " - Class: " << classe << " - Accuracy: " << acc
            << endl << std::flush;

    publicPacketSent[uniqueIDmsg] = simTime();
    //publicPacketSent[packet->getId()] = simTime();
    ++uniqueIDmsg;

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);
}

void UdpBasicAppDrone::imageUAV_send(void) {
    //char msgName[64];
    //sprintf(msgName, "UDPBasicAppDroneImage-%d", myAppAddr);
    char msgName[128];
    sprintf(msgName, "UDPBasicAppDroneImage-%d-%d-%lf-%lf", myAppAddr, uniqueIDmsg, mob->getCurrentPosition().x, mob->getCurrentPosition().y);

    long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + uavImageSize;
    //long msgByteLength = sizeof(uint32_t) + sizeof(uint32_t) + 4;

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDroneImage>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);
    payload->setPosition(mob->getCurrentPosition());

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the image: " << mob->getCurrentPosition() << endl << std::flush;

    publicPacketSent[uniqueIDmsg] = simTime();
    //publicPacketSent[packet->getId()] = simTime();
    ++uniqueIDmsg;

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);

}



void UdpBasicAppDrone::imageUAV_send_singleFragment(int image_id, int fragment_size, int fragment_number, int fragment_total, Coord myPos) {
    char msgName[128];
    sprintf(msgName, "UDPBasicAppDroneFragImage-%d-%d-%d-%d-%lf-%lf", myAppAddr, image_id, fragment_number, fragment_total,
            myPos.x, myPos.y);
    //sprintf(msgName, "UDPBasicAppDroneFragImage-%d", myAppAddr);

    long msgByteLength = fragment_size;

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationDroneFragmentOfImage>();
    //const auto& payload = makeShared<ApplicationDroneAlert>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setDrone_appAddr(myAppAddr);
    payload->setDrone_ipAddr(myIPAddr);
    payload->setPosition(mob->getCurrentPosition());
    payload->setFn(fragment_number);
    payload->setFt(fragment_total);
    payload->setImageID(image_id);
    //payload->setAccuracy(1);
    //payload->setClasse("pippo");

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    /*std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the image fragment from " << mob->getCurrentPosition()
                    << "; frag size: " << msgByteLength
                    << "; frag number: " << fragment_number
                    << "; frag total: " << fragment_total
                    << "; img ID: " << image_id
                    << endl << std::flush;*/

    L3Address destAddr = L3Address(gatewayIpAddress);
    socket.sendTo(packet, destAddr, destPort);
}


void UdpBasicAppDrone::imageUAV_send_useFragments(void) {
    //int nFragments = ceil(((double) uavImageSize) / ((double) uavImageFragment));
    int nFragments = ceil(((double) truncnormal(uavImageSize, uavImageSize/10.0)) / ((double) uavImageFragment));

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[UAV] Sending the image using "
            << nFragments << " fragments of size " << uavImageFragment << endl << std::flush;

    for (int i = 0; i < nFragments; i++) {
        imageUAV_send_singleFragment(imageId2send, uavImageFragment, i+1, nFragments, mob->getCurrentPosition());
    }
    ++imageId2send;
    //alertUAV_send(10, "ciao");
    //imageUAV_send_singleFragment(32, 1, 1);
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

void UdpBasicAppDrone::takeSnapshot(void) {
    //powerConsumption = W(1); // = computePowerConsumption();


    //emit(powerConsumptionChangedSignal, powerConsumption.get());
}

void UdpBasicAppDrone::executeImageRecognition(void) {
    double time = truncnormal(detectionTime, 0.2);

    //if (!periodicMsg->isScheduled()) {
        //cancelEvent(periodicMsg);
    //    scheduleAt(simTime() + 0.01, periodicMsg);
    //}

    scheduleAt(simTime() + time, periodicExecutionMsg);
    //periodicExecutionMsg

    //powerConsumption = W(1); // = computePowerConsumption();

    //emit(powerConsumptionChangedSignal, powerConsumption.get());
}

void UdpBasicAppDrone::endImageRecognition(void) {
    double confidence;
    char classe[64];
    //scheduleAt(simTime() + truncnormal(detectionTime, 0.1), periodicExecutionMsg);

    //powerConsumption = W(0); // = computePowerConsumption();

    memset(classe, 0, sizeof(classe));
    detectAlarm(mob->getCurrentPosition(), confidence, classe, sizeof(classe));

    alertUAV_send(confidence, classe);

    //emit(powerConsumptionChangedSignal, powerConsumption.get());
}

void UdpBasicAppDrone::detectAlarm(Coord actPos, double &conf, char *buff, int buffSize) {
    snprintf(buff, buffSize, "%s", action_class.c_str());

    if (simTime() >= alarmTime) {
        //double maxconf = alarmMaxAccuracy - truncnormal(0, alarmGaussDeviationMax);
        //if (maxconf < 0) maxconf = 0;
        double maxconf = alarmMaxAccuracy;

        conf = maxconf / exp( pow(mob->getCurrentPosition().distance(alarmPosition), 2.0) / (2 * pow(alarmGaussDeviationDistance, 2.0) ) );
    }
    else {
        conf = 0;
    }
}

} // namespace inet

