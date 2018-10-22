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

//std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a beacon from (" << rcvInfo.info.src_ipAddr << ")" << endl << std::flush;

#include <chrono>
#include <fstream>      // std::ofstream
#include <vector>

#include "UdpBasicAppJolie.h"
#include "UdpBasicAppDrone.h"

#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

using namespace rapidjson;

namespace inet {

std::list<UdpBasicAppJolie::policy> UdpBasicAppJolie::policy_queue;
std::mutex UdpBasicAppJolie::policy_queue_mtx;

Define_Module(UdpBasicAppJolie);

UdpBasicAppJolie::~UdpBasicAppJolie()
{
    cancelAndDelete(selfMsg);
    cancelAndDelete(coapServer_selfMsg);
    cancelAndDelete(alertStart_selfMsg);
    cancelAndDelete(focusTime_selfMsg);
}

void UdpBasicAppJolie::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    //std::cout << "UdpBasicAppJolie::initialize BEGIN - Stage " << stage << std::flush << endl;

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

        droneRegisterStringTemplate = par("droneRegisterStringTemplate");
        dronePositionStringTemplate = par("dronePositionStringTemplate");
        droneEnergyStringTemplate = par("droneEnergyStringTemplate");
        droneAlertStringTemplate = par("droneAlertStringTemplate");
        droneImageStringTemplateP1 = par("droneImageStringTemplateP1");
        droneImageStringTemplateP2 = par("droneImageStringTemplateP2");
        droneStatsStringTemplate = par("droneStatsStringTemplate");

        jolieAddress = par("jolieAddress");
        jolieAddressPort = par("jolieAddressPort");
        gatewayRealAddress = par("gatewayRealAddress");
        gatewayRealAddressPort = par("gatewayRealAddressPort");
        logFilePositions = par("logFilePositions");

        uavRadiusSensor = par("uavRadiusSensor");
        detectThreshold = par("detectThreshold");
        focusActivationThreshold = par("focusActivationThreshold");
        googleImageTime = par("googleImageTime");
        uavFocusRadius = par("uavFocusRadius");

        detectPeriodShort = par("detectPeriodShort");
        imagePeriodShort = par("imagePeriodShort");
        detectPeriodLong = par("detectPeriodLong");
        imagePeriodLong = par("imagePeriodLong");

        saveVectorCoverage = par("saveVectorCoverage");

        avgPDRTime = par("avgPDRTime");

        if (focusActivationThreshold > detectThreshold)
            throw cRuntimeError("Invalid focusActivationThreshold/detectThreshold parameters");

        coverStiffness = par("coverStiffness");
        focusStiffness = par("focusStiffness");
        stopStiffness = par("stopStiffness");

        implementLocalJolie = par("implementLocalJolie");

        finalAlarmDelayTime = par("finalAlarmDelayTime");
        focusTime = par("focusTime");
        limitFocusOffset = par("limitFocusOffset");

        coapServer_loopTimer = par("coapServerLoopTimer");
        neigh_timeout = par("neigh_timeout");

        std::string policyType = par("policyType");
        if (policyType.compare("DETECT_ALONE") == 0) {
            isAlone = true;
            isDetect = true;
            isStimulus = false;
            isAOB = false;
        }
        else if (policyType.compare("DETECT_FOCUS") == 0) {
            isAlone = false;
            isDetect = true;
            isStimulus = false;
            isAOB = false;
        }
        else if (policyType.compare("IMAGE_ALONE") == 0) {
            isAlone = true;
            isDetect = false;
            isStimulus = false;
            isAOB = false;
        }
        else if (policyType.compare("IMAGE_FOCUS") == 0) {
            isAlone = false;
            isDetect = false;
            isStimulus = false;
            isAOB = false;
        }
        else if (policyType.compare("STIMULUS") == 0) {
            isAlone = false;
            isDetect = true;
            isStimulus = true;
            isAOB = false;
        }
        else if (policyType.compare("AOB") == 0) {
            isAlone = false;
            isDetect = true;
            isStimulus = false;
            isAOB = true;
        }
        else {
            throw cRuntimeError("Invalid policyType parameter");
        }

        myAppAddr = this->getParentModule()->getIndex();
        myIPAddr = Ipv4Address::UNSPECIFIED_ADDRESS;

        imageIdx= 0;
        jstate = JIOT_COVER;
        bestDetectValue = 0;
        lastBestDetectValue = 0;

        mob = check_and_cast<IMobility *>(this->getParentModule()->getSubmodule("mobility"));

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

        end_msg = new cMessage("endMessage_selfMsg");
        focusTime_selfMsg = new cMessage("focusTime_selfMsg");

        coapServer_selfMsg = new cMessage("coapServer_loop");
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);

        self1Sec_selfMsg = new cMessage("1sec_self");
        scheduleAt(simTime() + 1, self1Sec_selfMsg);

        self5Sec_selfMsg = new cMessage("5sec_self");
        scheduleAt(simTime() + 5, self5Sec_selfMsg);

        alarmTime = par("alarmTime");
        double alarmPositionX = par("alarmPositionX");
        double alarmPositionY = par("alarmPositionY");
        alarmPosition = Coord(alarmPositionX, alarmPositionY);
        alarmGaussDeviationDistance = par("alarmGaussDeviationDistance");
        alarmMaxAccuracy = par("alarmMaxAccuracyCloud");
        alarmGaussDeviationMax = par("alarmGaussDeviationMax");

        alertStart_selfMsg = new cMessage("alert_self");
        scheduleAt(simTime() + alarmTime, alertStart_selfMsg);

        coverageStatsAbs.setName("Coverage Absolute");
        coverageStatsRelAll.setName("Coverage Relative All Scenario");
        coverageStatsRelHex.setName("Coverage Relative Hexagons");
        coverageStatsRelCircle.setName("Coverage relative Circle");

        detectRatio.setName("DetectRatio");
        detect2imageRis.setName("detect2imageRis");
        image2detectRis.setName("image2detectRis");
        avgPDR_vec.setName("avgPDR");
    }
    else if (stage == INITSTAGE_LAST) {
        int droneNumber = this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize();

        addressTable.resize(droneNumber, Ipv4Address::UNSPECIFIED_ADDRESS);

        fragmentsLog.resize(droneNumber);

        std::cout << "UdpBasicAppJolie::initialize found " << addressTable.size() << " drones" << endl << std::flush;

        std::ofstream ofs;
        ofs.open (logFilePositions, std::ofstream::out);
        if (ofs.is_open()) {
            ofs.close();
        }

        if (!implementLocalJolie){
            serverCoAP_init();
        }

        // coverage stats
        int nnodes = this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize();
        Coord maxArea = check_and_cast<IMobility *>(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getSubmodule("mobility"))->getConstraintAreaMax();
        coverageMax = nnodes * pow(uavRadiusSensor, 2.0) * 1.5 * SQRT_3;
        coverageMaxCircle = nnodes * uavRadiusSensor * uavRadiusSensor * M_PI;
        coverageAll = maxArea.x * maxArea.y;
    }
    //std::cout << "UdpBasicAppJolie::initialize END - Stage " << stage << std::flush << endl;
}

void UdpBasicAppJolie::finish()
{
    double cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle;
    calculateCoverage(cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle);

    if (jstate == JIOT_ALARM) {
        simtime_t alarmDetectTime = simTime() - alarmTime;
        recordScalar("alarm detect delay", alarmDetectTime.dbl());
        recordScalar("alarm detect max confidence", bestDetectValue);

        recordScalar("coverage end absolute", cov_abs);
        recordScalar("coverage end relative all scenario", cov_rel_all);
        recordScalar("coverage end relative hexagon", cov_rel_hex);
        recordScalar("coverage end relative circle", cov_rel_circle);

        recordScalar("detection result", 1);
    }
    else {

        recordScalar("coverage alarm absolute", cov_abs);
        recordScalar("coverage alarm relative all scenario", cov_rel_all);
        recordScalar("coverage alarm relative hexagon", cov_rel_hex);
        recordScalar("coverage alarm relative circle", cov_rel_circle);

        recordScalar("detection result", 0);

    }

    //std::cout << "UdpBasicAppJolie::finish BEGIN" << std::flush << endl;
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
    //std::cout << "UdpBasicAppJolie::finish END" << std::flush << endl;

    // waiting for the thread
    //t_coap.join();
}

void UdpBasicAppJolie::setSocketOptions()
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

L3Address UdpBasicAppJolie::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    return destAddresses[k];
}

int UdpBasicAppJolie::getCloserUAV(void) {
    int closer = -1;
    double minDistance = std::numeric_limits<double>::max();

    for (auto& n : neighMap) {
        //double d = mob->getCurrentPosition().distance(n.second.begin()->info.mob_position);
        double d = mob->getCurrentPosition().distance(n.second.info.mob_position);
        if (d < minDistance) {
            d = minDistance;
            //closer = n.second.begin()->info.src_appAddr;
            closer = n.second.info.src_appAddr;
        }
    }

    return closer;
}

Packet *UdpBasicAppJolie::createBeaconPacket() {

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

    mineInfo.mob_position = mob->getCurrentPosition();
    mineInfo.mob_velocity = mob->getCurrentVelocity();

    mineInfo.src_appAddr = myAppAddr;
    mineInfo.src_ipAddr = myIPAddr;

    payload->setSrc_info(mineInfo);
    payload->setUavReferee(getCloserUAV());
    payload->setIsGW(true);

    pk->insertAtBack(payload);
    pk->addPar("sourceId") = getId();
    pk->addPar("msgId") = numSent;

    return pk;
}

void UdpBasicAppJolie::sendPacket()
{
    Packet *packet;

    //std::cout << "(" << myIPAddr << ") sendPacket() BEGIN " << endl << std::flush;

    packet = createBeaconPacket();

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

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending a beacon " << endl << std::flush;

    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void UdpBasicAppJolie::send_policy_to_drone(policy *p) {
    char msgName[64];
    sprintf(msgName, "UDPBasicAppPolicy-%d-%d", myAppAddr, p->drone_id);

    long msgByteLength = (sizeof(policy)) + sizeof(uint32_t) + sizeof(uint32_t);

    Packet *packet = new Packet(msgName);

    const auto& payload = makeShared<ApplicationPolicy>();
    payload->setChunkLength(B(msgByteLength));
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());

    payload->setP_id(p->p_id);
    payload->setP_name(p->p_name);
    payload->setDrone_id(p->drone_id);

    payload->setA_id(p->a_id);
    payload->setA_name(p->a_name);
    payload->setA_class(p->a_class);
    payload->setA_period(p->a_period);

    for (unsigned int jj = 0; jj < payload->getSpringsArraySize(); jj++) {
        struct SpringForce newsp;

        if (jj < 3) {
            newsp.distance = p->springs[jj].distance;
            newsp.position = p->springs[jj].position;
            newsp.s_id = p->springs[jj].s_id;
            newsp.s_name = p->springs[jj].s_name;
            newsp.stiffness = p->springs[jj].stiffness;
        }
        else {
            std::stringstream ss;
            ss << p;
            throw cRuntimeError("Error in sending the policy:\n %s", ss.str().c_str());
        }

        payload->setSprings(jj, newsp);
    }

    payload->setDest_appAddr(p->drone_id);
    payload->setDest_ipAddr(addressTable[p->drone_id]);

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

    if (droneMap.count(p->drone_id) != 0) {
        //droneMap[p->drone_id].lastSentPolicy = *p;
        drone_info_t *dr = &droneMap[p->drone_id];

        dr->lastSentPolicy = *p;

        intevalmsg_time_t itt;
        itt.timestamp = simTime();
        itt.intervalmsg = p->a_period;

        dr->activeAction = p->a_id;
        dr->pol_time_list.push_front(itt);
    }

    L3Address destAddr = L3Address(addressTable[p->drone_id]);
    socket.sendTo(packet, destAddr, destPort);
}


void UdpBasicAppJolie::processStart()
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
        for (int i = 0; i < (int)addressTable.size(); i++) {

            char buf[32];
            //snprintf(buf, sizeof(buf), "UDPBurstML.host[%d]", i);
            snprintf(buf, sizeof(buf), "%s.host[%d]",this->getParentModule()->getParentModule()->getName(), i);
            //EV << "Looking for " << buf << endl;
            L3Address addr = L3AddressResolver().resolve(buf);
            addressTable[i] = addr.toIpv4();

            std::cout << "Setting node "<< i << " with IP address: " << addressTable[i] << endl << std::flush;
        }

        if (myIPAddr == Ipv4Address::UNSPECIFIED_ADDRESS) {
            InterfaceEntry *wlan = ift->getInterfaceByName("wlan0");
            if (wlan) {
                myIPAddr = wlan->getIpv4Address();
                //addressTable[myAppAddr] = myIPAddr;

                std::cout << "Setting my IP address: " << myIPAddr << endl << std::flush;
            }
        }
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

    //registerUAVs_CoAP_init();
}

void UdpBasicAppJolie::processSend()
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

void UdpBasicAppJolie::processStop()
{
    socket.close();
}

void UdpBasicAppJolie::handleMessageWhenUp(cMessage *msg)
{
    if (msg == alertStart_selfMsg) {
        auto nowT = std::chrono::system_clock::now();
        //auto nowT = std::chrono::steady_clock::now();

        unsigned long int timeEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(nowT.time_since_epoch()).count();

        //std::time_t now_time = std::chrono::system_clock::to_time_t(nowT);
        //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Real time clock: "
        //        << std::ctime(&now_time) << "; -> millis: " << timeEpoch << endl << std::flush;

        if (!implementLocalJolie) {
            stats_CoAP(timeEpoch);
        }

        recordScalar("AlarmStart", timeEpoch);


        double cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle;
        calculateCoverage(cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle);
        recordScalar("coverage alarm absolute", cov_abs);
        recordScalar("coverage alarm relative all scenario", cov_rel_all);
        recordScalar("coverage alarm relative hexagon", cov_rel_hex);
        recordScalar("coverage alarm relative circle", cov_rel_circle);
    }
    else if (msg == coapServer_selfMsg) {
        serverCoAP_checkLoop();
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);
    }
    else if (msg == self1Sec_selfMsg) {
        msg1sec_call();
        scheduleAt(simTime() + 1, self1Sec_selfMsg);
    }
    else if (msg == self5Sec_selfMsg) {
        msg5sec_call();
        scheduleAt(simTime() + 5, self5Sec_selfMsg);
    }
    else if (msg == focusTime_selfMsg) {
        if (bestDetectValue > detectThreshold){
            jstate = JIOT_ALARM;
        }
        startFinalAlarmPublishing();
    }
    else if (msg == end_msg) {
        endSimulation();
    }
    else if (msg->isSelfMessage()) {
        if ( strncmp(msg->getName(), "imageSelf_", 10) == 0 ) {
            unsigned int idx;
            int droneID;
            Coord dronePosition;

            sscanf(msg->getName(), "imageSelf_%u", &idx);

            if (imageChecking.count(idx) > 0) {
                droneID = imageChecking[idx].dID;
                dronePosition = imageChecking[idx].pos;
                imageChecking.erase(idx);

                checkReceivedGoogleResult(droneID, dronePosition);
            }

            delete msg;
        }
        else if(strncmp(msg->getName(), "stimSelf_", 9) == 0) {
            int dID;
            sscanf(msg->getName(), "stimSelf_%d", &dID);
            checkChangeRule(dID);
            scheduleAt(simTime() + 4.0 + (dblrand() * 2.0), msg);
        }
        else {
            ASSERT(msg == selfMsg);
            switch (selfMsg->getKind()) {
            case START:
                processStart();
                //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] " << "started the process" << endl << std::flush;
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] " << " stopped the process" << endl << std::flush;
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
            }
        }
    }
    else if (msg->getKind() == UDP_I_DATA) {

       /* std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: " << msg->getName()
                << "; Class name: " << msg->getClassName()
                << "; Class full name: " << msg->getFullName()
                << "; Class full path: " << msg->getFullPath()
                << "; Class display string: " << msg->getDisplayString()
                << endl << std::flush;*/

        // process incoming packet
        if (strncmp(msg->getName(), "UDPBasicAppDroneReg", 19) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDroneReg" << endl;
            if (implementLocalJolie){
                manageNewRegistration_local(check_and_cast<Packet *>(msg));
            }
            else {
                manageNewRegistration(check_and_cast<Packet *>(msg));
            }
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDronePos", 19) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDronePos" << endl;
            if (implementLocalJolie){
                manageNewPosition_local(check_and_cast<Packet *>(msg));
            }
            else {
                manageNewPosition(check_and_cast<Packet *>(msg));
            }
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneEnergy", 22) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDroneEnergy" << endl;
            if (implementLocalJolie){
                manageNewEnergy_local(check_and_cast<Packet *>(msg));
            }
            else {
                manageNewEnergy(check_and_cast<Packet *>(msg));
            }
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneAlert", 21) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDroneAlert" << endl;
            if (implementLocalJolie){
                manageNewAlert_local(check_and_cast<Packet *>(msg));
            }
            else {
                manageNewAlert(check_and_cast<Packet *>(msg));
            }
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneImage", 21) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDroneImage" << endl;
            if (implementLocalJolie){
                manageNewImage_local(check_and_cast<Packet *>(msg));
            }
            else {
                manageNewImage(check_and_cast<Packet *>(msg));
            }
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneFragImage", 25) == 0) {
            //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a message: UDPBasicAppDroneFragImage" << endl;
            manageNewImageFragment(check_and_cast<Packet *>(msg));
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

void UdpBasicAppJolie::refreshDisplay() const
{
    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);


    sprintf(buf, "IP: %s", myIPAddr.str().c_str());
    this->getParentModule()->getDisplayString().setTagArg("t", 0, buf);
}

void UdpBasicAppJolie::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a beacon" << endl << std::flush;

    manageReceivedBeacon(pk);

    delete pk;
    numReceived++;
}

void UdpBasicAppJolie::calculateCoverage(double &cov_abs, double &cov_rel_all, double &cov_rel_hex, double &cov_rel_circle) {
    int nnodes = this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize();
    Coord maxArea = check_and_cast<IMobility *>(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getSubmodule("mobility"))->getConstraintAreaMax();
    std::vector<std::vector<int>> covMatrix;
    double areaAbsCovered = 0;

    cov_abs = cov_rel_all = cov_rel_hex = cov_rel_circle = 0;

    covMatrix.resize(maxArea.x);
    for (auto& v : covMatrix) {
        v = std::vector<int>();
        v.resize(maxArea.y, 0);
    }

    for (int i = 0; i < nnodes; i++) {
        //UdpBasicAppDrone *d = check_and_cast<UdpBasicAppDrone *>(this->getParentModule()->getParentModule()->getSubmodule("host", i));
        IMobility *dmob = check_and_cast<IMobility *>(this->getParentModule()->getParentModule()->getSubmodule("host", i)->getSubmodule("mobility"));
        Coord dPos = dmob->getCurrentPosition();

        int minX = 0;
        int minY = 0;
        int maxX = maxArea.x;
        int maxY = maxArea.y;

        if ((dPos.x - uavRadiusSensor) > 0) minX = (dPos.x - uavRadiusSensor);
        if ((dPos.y - uavRadiusSensor) > 0) minY = (dPos.y - uavRadiusSensor);
        if ((dPos.x + uavRadiusSensor) < maxArea.x) maxX = (dPos.x + uavRadiusSensor);
        if ((dPos.y + uavRadiusSensor) < maxArea.y) maxY = (dPos.y + uavRadiusSensor);

        for (int ii = minX; ii < maxX; ii++) {
            for (int jj = minY; jj < maxY; jj++) {
                if (covMatrix[ii][jj] == 0) {
                    if (Coord(ii, jj).distance(dPos) <= uavRadiusSensor) {
                        covMatrix[ii][jj] = 1;
                        ++areaAbsCovered;
                    }
                }
            }
        }
    }

    cov_abs = areaAbsCovered;
    cov_rel_all = areaAbsCovered / coverageAll;
    cov_rel_hex = areaAbsCovered / coverageMax;
    cov_rel_circle = areaAbsCovered / coverageMaxCircle;

    if (cov_rel_all > 1) cov_rel_all = 1;
    if (cov_rel_hex > 1) cov_rel_hex = 1;
    if (cov_rel_circle > 1) cov_rel_circle = 1;
}

double UdpBasicAppJolie::calculatePDR_singleUAV_GOD(int droneID) {
    double ris = 0;
    UdpBasicAppDrone *dd = check_and_cast<UdpBasicAppDrone *>(this->getParentModule()->getParentModule()->getSubmodule("host", droneID)->getSubmodule("app", 0));

    if (receivedPktMap.count(droneID) != 0) {
        int receivedOK = 0;
        int sentTotal = 0;

        std::map<long int, simtime_t> *mm = &(receivedPktMap[droneID]);

        for (auto& pd : dd->publicPacketSent) {
            if ((simTime() - pd.second) <= avgPDRTime) {
                ++sentTotal;

                if (mm->count(pd.first) != 0) {
                    ++receivedOK;
                }
            }
        }

        if (sentTotal > 0) {
            ris = ((double) receivedOK) / ((double) sentTotal);
        }
    }
    return ris;
}

double UdpBasicAppJolie::calculatePDR_singleUAV(int droneID) {
    double ris = 0;

    if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        if ((dr->pol_time_list.size() > 0) && (dr->msgRcv_timestamp_list.size() > 0)) {

            auto itPolicy = dr->pol_time_list.begin();
            auto itMsg = dr->msgRcv_timestamp_list.begin();

            //simtime_t lastMsg = itMsg->timestamp;
            //simtime_t lastPolicy = itPeriod->timestamp;
            //simtime_t lastCheck = simTime();

            simtime_t lastPolicy = simTime();

            simtime_t timeLimit = simtime_t::ZERO;
            if (simTime() > avgPDRTime) {
                timeLimit = simTime() - avgPDRTime;
            }

            double sumTime = 0;
            double numPktInPolicy = 0;
            double sumPDR = 0;

            //while ( ((simTime() - lastCheck) < avgPDRTime) && (itPeriod != dr->pol_time_list.end()) ) {
            //while ((simTime() - itPolicy->timestamp) < avgPDRTime) {
            while ( (itPolicy != dr->pol_time_list.end()) && ((simTime() - itPolicy->timestamp) < avgPDRTime) ) {

                while ( (itMsg != dr->msgRcv_timestamp_list.end()) && (itPolicy->timestamp <= itMsg->timestamp) ) {
                    ++numPktInPolicy;
                    itMsg++;
                }

                double timePolicy = (lastPolicy - itPolicy->timestamp).dbl();
                double theorPktReceived = timePolicy / itPolicy->intervalmsg;

                double thisPolicyPDR = numPktInPolicy / theorPktReceived;
                if (thisPolicyPDR > 1) thisPolicyPDR = 1;

                sumPDR += thisPolicyPDR * timePolicy;
                sumTime += timePolicy;

                numPktInPolicy = 0;
                lastPolicy = itPolicy->timestamp;
                itPolicy++;
            }

            if ( (itPolicy != dr->pol_time_list.end()) && (itPolicy->timestamp <= timeLimit) ) {
                double timePolicy = (lastPolicy - timeLimit).dbl();
                double theorPktReceived = timePolicy / itPolicy->intervalmsg;

                double thisPolicyPDR = numPktInPolicy / theorPktReceived;
                if (thisPolicyPDR > 1) thisPolicyPDR = 1;

                sumPDR += thisPolicyPDR * timePolicy;
                sumTime += timePolicy;
            }


            /*while ((simTime() - lastCheck) < avgPDRTime) {

                while ((itPeriod->timestamp > itMsg->timestamp) && (itPeriod != dr->pol_time_list.end())) {
                    double timePolicy = (lastPolicy - itPeriod->timestamp).dbl();
                    double theorPktReceived = timePolicy / itPeriod->intervalmsg;

                    double thisPolicyPDR = numPktInPolicy / theorPktReceived;
                    if (thisPolicyPDR > 1) thisPolicyPDR = 1;

                    sumPDR += thisPolicyPDR * timePolicy;
                    sumTime += timePolicy;

                    numPktInPolicy = 0;
                    lastPolicy = itPeriod->timestamp;


                    if (itPeriod != dr->pol_time_list.end()) itPeriod++;
                }

                ++numPktInPolicy;
                lastCheck = itMsg->timestamp;
                if ((itMsg != dr->msgRcv_timestamp_list.end())) {
                    itMsg++;
                }
                else {
                    break;
                }
            }

            //while ( ((simTime() - lastCheck) < avgPDRTime) && (itMsg != dr->msgRcv_timestamp_list.end()) ) {
            while ((simTime() - lastCheck) < avgPDRTime) {

                if (itPeriod->timestamp > itMsg->timestamp) {
                    double timePolicy = (lastPolicy - itPeriod->timestamp).dbl();
                    double theorPktReceived = timePolicy / itPeriod->intervalmsg;

                    double thisPolicyPDR = numPktInPolicy / theorPktReceived;
                    if (thisPolicyPDR > 1) thisPolicyPDR = 1;

                    sumPDR += thisPolicyPDR * timePolicy;
                    sumTime += timePolicy;

                    numPktInPolicy = 0;
                    lastPolicy = itPeriod->timestamp;
                    itPeriod++;

                    if (itPeriod == dr->pol_time_list.end()) break;
                }

                if ((itMsg != dr->msgRcv_timestamp_list.end())) {
                    ++numPktInPolicy;
                    lastCheck = itMsg->timestamp;
                    itMsg++;
                }
            }*/

            if (sumTime > 0) {
                ris = sumPDR / sumTime;
            }

        }
    }

    return ris;
}

double UdpBasicAppJolie::calculatePDR_allUAV(void) {
    double ris = 0;

    for (auto& d : droneMap) {
        //ris += calculatePDR_singleUAV(d.first);
        ris += calculatePDR_singleUAV_GOD(d.first);
    }

    if (droneMap.size() > 0) {
        ris = ris / ((double) droneMap.size());
    }

    return ris;
}

void UdpBasicAppJolie::manageNewRegistration(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDroneRegister>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDroneRegister", pk->getClassName(), pk->getName());

    EV_INFO << "Received Registration: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a registration" << endl << std::flush;

    registerSingleUAV_CoAP(appmsg->getDrone_appAddr());

    delete pk;
}

void UdpBasicAppJolie::manageNewPosition(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDronePosition>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDronePosition", pk->getClassName(), pk->getName());

    EV_INFO << "Received Position: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a position" << endl << std::flush;

    sendPositionSingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getPosition().x, appmsg->getPosition().y);

    delete pk;
}

void UdpBasicAppJolie::manageNewEnergy(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDroneEnergy>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDronePosition", pk->getClassName(), pk->getName());

    EV_INFO << "Received Energy: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a energy" << endl << std::flush;

    sendEnergySingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getResidual());
    //sendImageSingleUAV_CoAP(appmsg->getDrone_appAddr(), 1, 1);

    delete pk;
}

void UdpBasicAppJolie::manageNewAlert(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDroneAlert>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDroneAlert", pk->getClassName(), pk->getName());

    EV_INFO << "Received Alert: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an alert" << endl << std::flush;

    sendAlertSingleUAV_CoAP(appmsg->getDrone_appAddr(),
            appmsg->getPosition().x, appmsg->getPosition().y,
            appmsg->getAccuracy(), appmsg->getClasse());

    delete pk;
}

void UdpBasicAppJolie::manageNewImage(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDroneImage>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDroneImage", pk->getClassName(), pk->getName());

    EV_INFO << "Received Alert: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an image" << endl << std::flush;

    sendImageSingleUAV_CoAP(appmsg->getDrone_appAddr(),
            appmsg->getPosition().x, appmsg->getPosition().y);

    delete pk;
}

void UdpBasicAppJolie::manageNewRegistration_local(Packet *pk) {
    try {
        const auto& appmsg = pk->peekDataAt<ApplicationDroneRegister>(B(0), B(pk->getByteLength()));
        if (!appmsg)
            throw cRuntimeError("Message (%s)%s is not a ApplicationDroneRegister", pk->getClassName(), pk->getName());

        EV_INFO << "Received Registration: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a registration" << endl << std::flush;

        //registerSingleUAV_CoAP(appmsg->getDrone_appAddr());
        drone_info_t newDI;

        newDI.src_appAddr = appmsg->getDrone_appAddr();
        newDI.src_ipAddr = addressTable[appmsg->getDrone_appAddr()];
        newDI.mob_position = Coord(-1, -1);
        newDI.energy = -1;

        if ((isStimulus) || (isAOB)) {
            newDI.activeAction = A_DETECT;
        }
        else {
            if (isDetect) {
                newDI.activeAction = A_DETECT;
            }
            else {
                newDI.activeAction = A_IMAGE;
            }
        }

        if ((isStimulus || isAOB) && (droneMap.count(newDI.src_appAddr) == 0)) {
            char buff[32];
            snprintf(buff, sizeof(buff), "stimSelf_%d", newDI.src_appAddr);

            cMessage *self_message = new cMessage(buff);
            scheduleAt(simTime() + 10.0 + (dblrand() * 5.0), self_message);
        }

        droneMap[newDI.src_appAddr] = newDI;

        // sending first policy
        sendPolicyCover(newDI.src_appAddr);

    }
    catch(const cRuntimeError& e) {
        std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] manageNewRegistration_local threw an exception: " << e.what() << endl;
    }

    delete pk;
}

void UdpBasicAppJolie::manageNewPosition_local(Packet *pk) {
    try {
        const auto& appmsg = pk->peekDataAt<ApplicationDronePosition>(B(0), B(pk->getByteLength()));
        if (!appmsg)
            throw cRuntimeError("Message (%s)%s is not a ApplicationDronePosition", pk->getClassName(), pk->getName());

        EV_INFO << "Received Position: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a position" << endl << std::flush;

        //sendPositionSingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getPosition().x, appmsg->getPosition().y);
        if (droneMap.count(appmsg->getDrone_appAddr()) != 0) {
            droneMap[appmsg->getDrone_appAddr()].mob_position = Coord(appmsg->getPosition().x, appmsg->getPosition().y);
        }
        else {
            EV_INFO << "Received position from an unregistered drone " << appmsg->getDrone_appAddr() << endl;
        }

    }
    catch(const cRuntimeError& e) {
        std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] manageNewPosition_local threw an exception: " << e.what() << endl;
    }

    delete pk;
}

void UdpBasicAppJolie::manageNewEnergy_local(Packet *pk) {
    try {
        const auto& appmsg = pk->peekDataAt<ApplicationDroneEnergy>(B(0), B(pk->getByteLength()));
        if (!appmsg)
            throw cRuntimeError("Message (%s)%s is not a ApplicationDronePosition", pk->getClassName(), pk->getName());

        EV_INFO << "Received Energy: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a energy" << endl << std::flush;

        //sendEnergySingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getResidual());
        if (droneMap.count(appmsg->getDrone_appAddr()) != 0) {
            droneMap[appmsg->getDrone_appAddr()].energy = appmsg->getResidual();
        }
        else {
            EV_INFO << "Received energy from an unregistered drone " << appmsg->getDrone_appAddr() << endl;
        }

    }
    catch(const cRuntimeError& e) {
        std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] manageNewEnergy_local threw an exception: " << e.what() << endl;
    }

    delete pk;
}

void UdpBasicAppJolie::manageNewAlert_local(Packet *pk) {
    try {
        const auto& appmsg = pk->peekDataAt<ApplicationDroneAlert>(B(0), B(pk->getByteLength()));
        if (!appmsg)
            throw cRuntimeError("Message (%s)%s is not a ApplicationDroneAlert", pk->getClassName(), pk->getName());

        EV_INFO << "Received Alert: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

        int droneAppAddr, uID;

        sscanf(pk->getName(), "UDPBasicAppDroneAlert-%d-%d", &droneAppAddr, &uID);

        if (receivedPktMap.count(appmsg->getDrone_appAddr()) == 0) {
            receivedPktMap[appmsg->getDrone_appAddr()] = std::map<long int, simtime_t>();
        }
        receivedPktMap[appmsg->getDrone_appAddr()][uID] = simTime();

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an alert" << endl << std::flush;

        //sendAlertSingleUAV_CoAP(appmsg->getDrone_appAddr(),  appmsg->getPosition().x, appmsg->getPosition().y, appmsg->getAccuracy(), appmsg->getClasse());
        checkReceivedAlert(appmsg->getDrone_appAddr(), appmsg->getPosition(), appmsg->getAccuracy(), appmsg->getClasse());


    }
    catch(const cRuntimeError& e) {
        std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] manageNewAlert_local threw an exception: " << e.what() << endl;
    }
    delete pk;
}

void UdpBasicAppJolie::manageNewImage_local(Packet *pk) {
    try {
        //const auto& appmsg = pk->peekDataAt<ApplicationDroneImage>(B(0), B(pk->getByteLength()));
        //if (!appmsg)
        //    throw cRuntimeError("Message (%s)%s is not a ApplicationDroneImage", pk->getClassName(), pk->getName());

        //EV_INFO << "Received Image: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

        int droneAppAddr, uID;
        double xD, yD;

        //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a fragment " << pk->getName() << endl << std::flush;

        sscanf(pk->getName(), "UDPBasicAppDroneImage-%d-%d-%lf-%lf", &droneAppAddr, &uID, &xD, &yD);

        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an image" << endl << std::flush;

        if (receivedPktMap.count(droneAppAddr) == 0) {
            receivedPktMap[droneAppAddr] = std::map<long int, simtime_t>();
        }
        receivedPktMap[droneAppAddr][uID] = simTime();

        //sendImageSingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getPosition().x, appmsg->getPosition().y);
        //checkReceivedImage(appmsg->getDrone_appAddr(), appmsg->getPosition());
        checkReceivedImage(droneAppAddr, Coord(xD, yD));

    }
    catch(const cRuntimeError& e) {
        std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] manageNewImage_local threw an exception: " << e.what() << endl;
    }

    delete pk;
}

void UdpBasicAppJolie::manageNewImageFragment(Packet *pk) {
    //try {

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a fragment" << endl << std::flush;

    //const auto& appmsg = pk->peekDataAt<ApplicationDroneFragmentOfImage>(B(0), B(pk->getByteLength()));
    //const auto& appmsg = pk->peekData<ApplicationDroneFragmentOfImage>();
    //if (!appmsg)
    //    throw cRuntimeError("Message (%s)%s is not a ApplicationDroneFragmentOfImage", pk->getClassName(), pk->getName());
    int droneAppAddr, image_id, fragment_number, fragment_total;
    double xD, yD;

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a fragment " << pk->getName() << endl << std::flush;

    sscanf(pk->getName(), "UDPBasicAppDroneFragImage-%d-%d-%d-%d-%lf-%lf", &droneAppAddr, &image_id, &fragment_number, &fragment_total, &xD, &yD);

    //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a fragment "
    //        << " Image_id: " << image_id
    //        << " fragment_number: " << fragment_number
    //        << " fragment_total: " << fragment_total
    //        << " Pos: " << Coord(xD, yD)
    //        << endl << std::flush;

    if (fragmentsLog[droneAppAddr].count(image_id) == 0) {

        fragmentsLog[droneAppAddr][image_id] = 1;
    }
    else {
        fragmentsLog[droneAppAddr][image_id]++;
    }

    if (fragmentsLog[droneAppAddr][image_id] >= fragment_total) {
        std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an image with fragments" << endl << std::flush;

        if (implementLocalJolie){
            checkReceivedImage(droneAppAddr, Coord(xD, yD));
        }
        else {
            sendImageSingleUAV_CoAP(droneAppAddr, xD, yD);
        }
    }

    //}
    //catch(const cRuntimeError& e) {
    //    std::cerr << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Throwed an exception: " << e.what() << endl;
    //}

    delete pk;
}

void UdpBasicAppJolie::checkReceivedAlert(int droneID, Coord dronePosition, double detectAccuracy, const char *detectClasse) {

    if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        rcvmsg_time_t rtt;
        rtt.timestamp = simTime();
        rtt.type = A_DETECT;

        dr->msgRcv_timestamp_list.push_front(rtt);
    }

    if ((detectAccuracy >= focusActivationThreshold) && (!isAlone)) {
        startFocus(droneID, dronePosition, detectAccuracy);
    }
    if ((detectAccuracy >= detectThreshold) && (isAlone)) {
        startAlone(droneID, dronePosition, detectAccuracy);
    }
}

void UdpBasicAppJolie::startAlone(int droneID, Coord dronePosition, double detectAccuracy) {

    if (detectAccuracy > bestDetectValue) {
        bestDetectValue = detectAccuracy;
    }

    if (jstate != JIOT_ALARM) {
        jstate = JIOT_ALARM;

        startFinalAlarmPublishing();
    }
}

void UdpBasicAppJolie::startFocus(int droneID, Coord dronePosition, double detectAccuracy) {

    if (jstate != JIOT_ALARM) {
        if (jstate == JIOT_COVER) {
            bestDetectValue = detectAccuracy;

            sendPolicyStop(droneID, dronePosition);
            droneFocusStop.push_back(droneID);

            for (auto& d : droneMap) {
                double dist = d.second.mob_position.distance(dronePosition);

                if ( (dist <= (uavRadiusSensor * SQRT_3 * uavFocusRadius)) && (droneID != d.second.src_appAddr) ) {
                    sendPolicyFocus(d.second.src_appAddr, dronePosition);
                    droneFocusStop.push_back(d.second.src_appAddr);
                }
            }

            lastBestDetectValue = simTime();

            jstate = JIOT_FOCUS;

            scheduleAt(simTime() + focusTime, focusTime_selfMsg);
        }
        else if (jstate == JIOT_FOCUS){
            if (bestDetectValue < detectAccuracy) {
                bestDetectValue = detectAccuracy;
                lastBestDetectValue = simTime();

                for (auto& dfs : droneFocusStop) {
                    sendPolicyCover(dfs);
                }
                droneFocusStop.clear();

                sendPolicyStop(droneID, dronePosition);
                droneFocusStop.push_back(droneID);

                for (auto& d : droneMap) {
                    double dist = d.second.mob_position.distance(dronePosition);

                    if ( (dist <= (uavRadiusSensor * SQRT_3 * uavFocusRadius)) && (droneID != d.second.src_appAddr) ) {
                        sendPolicyFocus(d.second.src_appAddr, dronePosition);
                        droneFocusStop.push_back(d.second.src_appAddr);
                    }
                }
            }
            //else if (((simTime() - lastBestDetectValue) > limitFocusOffset) || (bestDetectValue > detectThreshold)) {
            else if (((simTime() - lastBestDetectValue) > limitFocusOffset) && (bestDetectValue > detectThreshold)) {
                jstate = JIOT_ALARM;
                startFinalAlarmPublishing();
            }
        }
    }
}

void UdpBasicAppJolie::checkReceivedImage(int droneID, Coord dronePosition) {
    char buff[128];

    if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        rcvmsg_time_t rtt;
        rtt.timestamp = simTime();
        rtt.type = A_IMAGE;

        dr->msgRcv_timestamp_list.push_front(rtt);
    }

    snprintf(buff, sizeof(buff), "imageSelf_%d", imageIdx);

    imageCheck_type newImg;
    newImg.dID = droneID;
    newImg.pos = dronePosition;
    imageChecking[imageIdx] = newImg;

    ++imageIdx;

    cMessage *self_message = new cMessage(buff);
    scheduleAt(simTime() + truncnormal(googleImageTime, googleImageTime/20.0), self_message);
}

void UdpBasicAppJolie::checkReceivedGoogleResult(int droneID, Coord dronePosition) {
    double detectAccuracy = 0;

    if (simTime() >= alarmTime) {
        //double maxconf = alarmMaxAccuracy - truncnormal(0, alarmGaussDeviationMax);
        //if (maxconf < 0) maxconf = 0;

        double maxconf = alarmMaxAccuracy;

        detectAccuracy = maxconf / exp( pow(dronePosition.distance(alarmPosition), 2.0) / (2 * pow(alarmGaussDeviationDistance, 2.0) ) );
    }

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Analyzed the image. Accuracy: " << detectAccuracy << endl << std::flush;


    if ((detectAccuracy >= focusActivationThreshold) && (!isAlone)) {
        startFocus(droneID, dronePosition, detectAccuracy);
    }
    if ((detectAccuracy >= detectThreshold) && (isAlone)) {
        startAlone(droneID, dronePosition, detectAccuracy);
    }

    /*if (detectAccuracy >= detectThreshold) {
        if (isAlone) {
            startAlone(droneID, dronePosition, detectAccuracy);
        }
        else {
            startFocus(droneID, dronePosition, detectAccuracy);
        }
    }*/
}

void UdpBasicAppJolie::sendPolicyFocus(int droneID, Coord dronePosition) {
    policy p;

    bool isThisDetect = isDetect;

    p.p_id = P_FOCUS;
    p.drone_id = droneID;
    snprintf(p.p_name, sizeof(p.p_name), "focus");

    if ((isStimulus) || (isAOB)) {
        if (droneMap.count(droneID) != 0) {
            if (droneMap[droneID].activeAction == A_IMAGE) {
                isThisDetect = false;
            }
            else {
                isThisDetect = true;
            }
        }
    }

    if (isThisDetect) {
        snprintf(p.a_name, sizeof(p.a_name), "detect");
        p.a_id = A_DETECT;
        snprintf(p.a_class, sizeof(p.a_class), "car-crash");
        p.a_period = detectPeriodShort;
    }
    else {
        snprintf(p.a_name, sizeof(p.a_name), "image");
        p.a_id = A_IMAGE;
        p.a_period = imagePeriodShort;
    }

    /*if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        intevalmsg_time_t itt;
        itt.timestamp = simTime();
        itt.intervalmsg = p.a_period;

        dr->activeAction = p.a_id;
        dr->pol_time_list.push_back(itt);
    }*/

    p.springs[SPRING_COVER_IDX].distance = uavRadiusSensor * SQRT_3;
    p.springs[SPRING_COVER_IDX].position = Coord::ZERO;
    p.springs[SPRING_COVER_IDX].s_id = P_COVER;
    p.springs[SPRING_COVER_IDX].stiffness = coverStiffness;
    snprintf(p.springs[SPRING_COVER_IDX].s_name, sizeof(p.springs[SPRING_COVER_IDX].s_name), "cover");

    p.springs[SPRING_FOCUS_IDX].distance = (uavRadiusSensor * SQRT_3 / 3.0);
    p.springs[SPRING_FOCUS_IDX].position = dronePosition;
    p.springs[SPRING_FOCUS_IDX].s_id = P_FOCUS;
    p.springs[SPRING_FOCUS_IDX].stiffness = focusStiffness;
    snprintf(p.springs[SPRING_FOCUS_IDX].s_name, sizeof(p.springs[SPRING_COVER_IDX].s_name), "focus");

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending policy: " << p << endl << std::flush;

    send_policy_to_drone(&p);
}

void UdpBasicAppJolie::sendPolicyStop(int droneID, Coord dronePosition) {
    policy p;

    bool isThisDetect = isDetect;

    p.p_id = P_STOP;
    p.drone_id = droneID;
    snprintf(p.p_name, sizeof(p.p_name), "stop");

    if ((isStimulus) || (isAOB)) {
        if (droneMap.count(droneID) != 0) {
            if (droneMap[droneID].activeAction == A_IMAGE) {
                isThisDetect = false;
            }
            else {
                isThisDetect = true;
            }
        }
    }

    if (isThisDetect) {
        snprintf(p.a_name, sizeof(p.a_name), "detect");
        p.a_id = A_DETECT;
        snprintf(p.a_class, sizeof(p.a_class), "car-crash");
        p.a_period = detectPeriodShort;
    }
    else {
        snprintf(p.a_name, sizeof(p.a_name), "image");
        p.a_id = A_IMAGE;
        p.a_period = imagePeriodShort;
    }

    /*if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        intevalmsg_time_t itt;
        itt.timestamp = simTime();
        itt.intervalmsg = p.a_period;

        dr->activeAction = p.a_id;
        dr->pol_time_list.push_back(itt);
    }*/

    p.springs[SPRING_COVER_IDX].distance = uavRadiusSensor * SQRT_3;
    p.springs[SPRING_COVER_IDX].position = Coord::ZERO;
    p.springs[SPRING_COVER_IDX].s_id = P_COVER;
    p.springs[SPRING_COVER_IDX].stiffness = coverStiffness;
    snprintf(p.springs[SPRING_COVER_IDX].s_name, sizeof(p.springs[SPRING_COVER_IDX].s_name), "cover");

    p.springs[SPRING_STOP_IDX].distance = 0;
    p.springs[SPRING_STOP_IDX].position = dronePosition;
    p.springs[SPRING_STOP_IDX].s_id = P_STOP;
    p.springs[SPRING_STOP_IDX].stiffness = stopStiffness;
    snprintf(p.springs[SPRING_STOP_IDX].s_name, sizeof(p.springs[SPRING_COVER_IDX].s_name), "stop");

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending policy: " << p << endl << std::flush;

    send_policy_to_drone(&p);
}

void UdpBasicAppJolie::sendPolicyCover(int droneID) {
    policy p;

    bool isThisDetect = isDetect;

    p.p_id = P_COVER;
    p.drone_id = droneID;
    snprintf(p.p_name, sizeof(p.p_name), "cover");

    if ((isStimulus) || (isAOB)) {
        if (droneMap.count(droneID) != 0) {
            if (droneMap[droneID].activeAction == A_IMAGE) {
                isThisDetect = false;
            }
            else {
                isThisDetect = true;
            }
        }
        else {
            isThisDetect = true;
        }
    }

    if (isThisDetect) {
        snprintf(p.a_name, sizeof(p.a_name), "detect");
        p.a_id = A_DETECT;
        snprintf(p.a_class, sizeof(p.a_class), "car-crash");
        p.a_period = detectPeriodLong;
    }
    else {
        snprintf(p.a_name, sizeof(p.a_name), "image");
        p.a_id = A_IMAGE;
        p.a_period = imagePeriodLong;
    }

    /*if (droneMap.count(droneID) != 0) {
        drone_info_t *dr = &droneMap[droneID];

        intevalmsg_time_t itt;
        itt.timestamp = simTime();
        itt.intervalmsg = p.a_period;

        dr->activeAction = p.a_id;
        dr->pol_time_list.push_back(itt);
    }*/

    p.springs[SPRING_COVER_IDX].distance = uavRadiusSensor * SQRT_3;
    p.springs[SPRING_COVER_IDX].position = Coord::ZERO;
    p.springs[SPRING_COVER_IDX].s_id = P_COVER;
    p.springs[SPRING_COVER_IDX].stiffness = coverStiffness;
    snprintf(p.springs[SPRING_COVER_IDX].s_name, sizeof(p.springs[SPRING_COVER_IDX].s_name), "cover");

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending policy: " << p << endl << std::flush;

    send_policy_to_drone(&p);
    //send_policy_to_drone(&p);
}

void UdpBasicAppJolie::startFinalAlarmPublishing(void) {
    cancelEvent(focusTime_selfMsg);
    scheduleAt(simTime() + truncnormal(finalAlarmDelayTime, finalAlarmDelayTime/10.0), end_msg);
}

void UdpBasicAppJolie::msg1sec_call(void) {
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

    if (saveVectorCoverage) {
        double cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle;
        calculateCoverage(cov_abs, cov_rel_all, cov_rel_hex, cov_rel_circle);

        coverageStatsAbs.record(cov_abs);
        coverageStatsRelAll.record(cov_rel_all);
        coverageStatsRelHex.record(cov_rel_hex);
        coverageStatsRelCircle.record(cov_rel_circle);
    }

    int numDetect = 0;
    for (auto& dd : droneMap) {
        if (dd.second.activeAction == A_DETECT){
            ++numDetect;
        }
    }
    if (droneMap.size() > 0) {
        detectRatio.record( ((double) numDetect) / ((double) droneMap.size()) );
    }
    else {
        detectRatio.record(0);
    }

    // make: node positions log
    std::ofstream ofs;
    ofs.open (logFilePositions, std::ofstream::out | std::ofstream::app);
    if (ofs.is_open()) {
        //std::stringstream ss;
        int numberNodes = this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize();
        auto nowT = std::chrono::system_clock::now();
        unsigned long int timeEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(nowT.time_since_epoch()).count();
        double maxX, maxY;

        ofs
                << "S" << simTime()
                << " R" << timeEpoch
                //<< " X" << mob->getConstraintAreaMax().x
                //<< " Y" << mob->getConstraintAreaMax().y
                << " U" << uavRadiusSensor
                << " N" << numberNodes;

        for (int i = 0; i < numberNodes; i++) {
            IMobility *uavNeigh = dynamic_cast<IMobility *>(this->getParentModule()->getParentModule()->getSubmodule("host", i)->getSubmodule("mobility"));
            Coord neighPos = uavNeigh->getCurrentPosition();
            maxX = uavNeigh->getConstraintAreaMax().x;
            maxY = uavNeigh->getConstraintAreaMax().y;
            ofs << " P" << neighPos.x << ";" << neighPos.y;
        }

        ofs << " X" << maxX << " Y" << maxY << " ";

        ofs << endl;
        ofs.close();
    }
}

void UdpBasicAppJolie::msg5sec_call(void) {
    if ((isStimulus) || (isAOB)) {
        //double sum_d2i, sum_i2d, count_d2i, count_i2d;
        double avgPDR = calculatePDR_allUAV();

        /*sum_d2i = sum_i2d = count_d2i = count_i2d = 0;

        //use the stimulus to update the behavior
        for (auto& d : droneMap) {
            drone_info_t *di = &(d.second);

            //checkChangeRule(d.first);

            double dronePDR = calculatePDR_singleUAV(d.first);

            if (di->activeAction == A_DETECT) {
                double respD2I = 0; //pow(avgPDR, 2.0) / (pow(avgPDR, 2.0) + pow(1.0 - dronePDR, 2.0));

                if (isStimulus) {
                    respD2I = pow(avgPDR, 2.0) / (pow(avgPDR, 2.0) + pow(1.0 - dronePDR, 2.0));
                }
                else if (isAOB) {
                    //respD2I = (dronePDR)^(1/avgPDR);
                    respD2I = pow(dronePDR, (1.0 / avgPDR));
                }

                sum_d2i += respD2I;
                ++count_d2i;

                if (dblrand() < respD2I) {
                    di->activeAction = A_IMAGE;

                    policy pnew = di->lastSentPolicy;
                    pnew.a_id = A_IMAGE;
                    snprintf(pnew.a_name, sizeof(pnew.a_name), "image");

                    send_policy_to_drone(&pnew);
                }
            }
            else if (di->activeAction == A_IMAGE) {
                double respI2D = 0; //pow(1.0 - avgPDR, 2.0) / (pow(1.0 - avgPDR, 2.0) + pow(dronePDR, 2.0));

                if (isStimulus) {
                    respI2D = pow(1.0 - avgPDR, 2.0) / (pow(1.0 - avgPDR, 2.0) + pow(dronePDR, 2.0));
                }
                else if (isAOB) {
                    //respI2D = 1 - ((dronePDR)^(1/avgPDR));
                    respI2D = 1.0 - pow(dronePDR, (1.0 / avgPDR));
                }

                sum_i2d += respI2D;
                ++count_i2d;

                if (dblrand() < respI2D) {
                    di->activeAction = A_DETECT;

                    policy pnew = di->lastSentPolicy;
                    pnew.a_id = A_DETECT;
                    snprintf(pnew.a_class, sizeof(pnew.a_class), "car-crash");
                    snprintf(pnew.a_name, sizeof(pnew.a_name), "detect");

                    send_policy_to_drone(&pnew);
                }
            }
        }*/

        //if (count_d2i > 0) {
        //    detect2imageRis.record(sum_d2i / count_d2i);
        //}
        //if (count_i2d > 0) {
        //    image2detectRis.record(sum_i2d / count_i2d);
        //}
        avgPDR_vec.record(avgPDR);
    }
}

void UdpBasicAppJolie::checkChangeRule(int droneID) {
    if (isStimulus || isAOB) {
        if (droneMap.count(droneID) != 0) {
            drone_info_t *di = &droneMap[droneID];
            double avgPDR = calculatePDR_allUAV();
            double dronePDR = calculatePDR_singleUAV(droneID);

            avgPDR_vec.record(avgPDR);

            if (di->activeAction == A_DETECT) {
                double respD2I = 0; //pow(avgPDR, 2.0) / (pow(avgPDR, 2.0) + pow(1.0 - dronePDR, 2.0));

                if (isStimulus) {
                    respD2I = pow(avgPDR, 2.0) / (pow(avgPDR, 2.0) + pow(1.0 - dronePDR, 2.0));
                }
                else if (isAOB) {
                    //respD2I = (dronePDR)^(1/avgPDR);
                    respD2I = pow(dronePDR, (1.0 / avgPDR));
                }

                detect2imageRis.record(respD2I);

                if (dblrand() < respD2I) {
                    di->activeAction = A_IMAGE;

                    policy pnew = di->lastSentPolicy;
                    pnew.a_id = A_IMAGE;
                    snprintf(pnew.a_name, sizeof(pnew.a_name), "image");

                    send_policy_to_drone(&pnew);
                }
            }
            else if (di->activeAction == A_IMAGE) {
                double respI2D = 0; //pow(1.0 - avgPDR, 2.0) / (pow(1.0 - avgPDR, 2.0) + pow(dronePDR, 2.0));

                if (isStimulus) {
                    respI2D = pow(1.0 - avgPDR, 2.0) / (pow(1.0 - avgPDR, 2.0) + pow(dronePDR, 2.0));
                }
                else if (isAOB) {
                    //respI2D = 1 - ((dronePDR)^(1/avgPDR));
                    respI2D = 1.0 - pow(dronePDR, (1.0 / avgPDR));
                }

                image2detectRis.record(respI2D);

                if (dblrand() < respI2D) {
                    di->activeAction = A_DETECT;

                    policy pnew = di->lastSentPolicy;
                    pnew.a_id = A_DETECT;
                    snprintf(pnew.a_class, sizeof(pnew.a_class), "car-crash");
                    snprintf(pnew.a_name, sizeof(pnew.a_name), "detect");

                    send_policy_to_drone(&pnew);
                }
            }
        }
    }
}

void UdpBasicAppJolie::manageReceivedBeacon(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationBeacon>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationBeacon -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());

    Ipv4Address rcvIPAddr = appmsg->getSrc_info().src_ipAddr;
    if (rcvIPAddr != myIPAddr){
        //if (neighMap.count(rcvIPAddr) == 0) {
        //    neighMap[rcvIPAddr] = std::list<neigh_info_t>();
        //}
        neigh_info_t rcvInfo;
        rcvInfo.timestamp_lastSeen = simTime();
        rcvInfo.info = appmsg->getSrc_info();
        rcvInfo.uavReferee = appmsg->getUavReferee();
        rcvInfo.isGW = appmsg->isGW();

        //neighMap[rcvIPAddr].push_front(rcvInfo);
        neighMap[rcvIPAddr] = rcvInfo;

        //std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received a beacon from (" << rcvInfo.info.src_ipAddr << ")" << endl << std::flush;
    }
}


bool UdpBasicAppJolie::handleNodeStart(IDoneCallback *doneCallback)
{
    simtime_t start = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(start, selfMsg);
    }
    return true;
}

bool UdpBasicAppJolie::handleNodeShutdown(IDoneCallback *doneCallback)
{
    if (selfMsg)
        cancelEvent(selfMsg);
    // if(socket.isOpened()) socket.close();
    return true;
}

void UdpBasicAppJolie::handleNodeCrash()
{
    if (selfMsg)
        cancelEvent(selfMsg);
}

/*
static void
policy_get_handler(coap_context_t *ctx, struct coap_resource_t *resource,
              const coap_endpoint_t *local_interface, coap_address_t *peer,
              coap_pdu_t *request, str *token, coap_pdu_t *response)
{
    unsigned char buf[3];
    const char* response_data     = "Hello World!";
    response->hdr->code           = COAP_RESPONSE_CODE(205);
    coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_data  (response, strlen(response_data), (unsigned char *)response_data);

    std::cout << "Received a GET for policy. hdr-code: " << COAP_RESPONSE_CLASS(request->hdr->code) << endl;

    unsigned char* data;
    size_t         data_len;
    //if (COAP_RESPONSE_CLASS(request->hdr->code) == 2)
    {
        if (coap_get_data(request, &data_len, &data))
        {
            //printf("Received: %s\n", data);
            std::cout << "Received |" << data << "| from a client" << endl;
        }
    }
}
*/

/*
static void policy_post_handler (coap_context_t *ctx, struct coap_resource_t *resource,
              const coap_endpoint_t *local_interface, coap_address_t *peer,
              coap_pdu_t *request, str *token, coap_pdu_t *response)
{
    //unsigned char buf[3];
    //const char* response_data     = "Hello World!";
    //response->hdr->code           = COAP_RESPONSE_CODE(205);
    //coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    ////coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    //coap_add_data  (response, strlen(response_data), (unsigned char *)response_data);

    std::cout << simTime() << " - (" << 0 << "|" << "10.0.0.1" << ")[GWY] SERVER THREAD - Received a POST for policy. hdr-code: " << COAP_RESPONSE_CLASS(request->hdr->code) << endl;

    unsigned char* data;
    size_t         data_len;
    //if (COAP_RESPONSE_CLASS(request->hdr->code) == 2)
    {
        if (coap_get_data(request, &data_len, &data))
        {
            char buffRis[1024];

            memset(buffRis, 0, sizeof(buffRis));
            memcpy(buffRis, data, std::min(sizeof(buffRis), data_len));

            //printf("Received: %s\n", data);
            std::cout << simTime() << " - (" << 0 << "|" << "10.0.0.1" << ")[GWY] SERVER THREAD - Received |" << buffRis << "| from a client" << endl;

            Document d;
            d.Parse(buffRis);

            StringBuffer buffer;
            Writer<StringBuffer> writer(buffer);
            d.Accept(writer);

            std::cout << simTime() << " - (" << 0 << "|" << "10.0.0.1" << ")[GWY] SERVER THREAD - " << buffer.GetString() << std::endl;

            UdpBasicAppJolie::manageReceivedPolicy(d);
        }
    }
}
*/
void UdpBasicAppJolie::serverCoAP_thread(void) {

    /*using namespace std::placeholders;

    coap_address_t   serv_addr;
    coap_resource_t* policy_resource;
    fd_set           readfds;
    unsigned char buf[3];
    std::cout << "UdpBasicAppJolie::serverCoAP_thread BEGIN" << std::flush << endl;

    // Prepare the CoAP server socket
    coap_address_init(&serv_addr);
    serv_addr.addr.sin.sin_family      = AF_INET;
    serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
    serv_addr.addr.sin.sin_port        = htons(5683); //default port
    ctx                                = coap_new_context(&serv_addr);
    if (!ctx) exit(EXIT_FAILURE);

    // Initialize the hello resource
    policy_resource = coap_resource_init((unsigned char *)"policy", 6, 0);
    coap_register_handler(policy_resource, COAP_REQUEST_GET, policy_get_handler);
    coap_register_handler(policy_resource, COAP_REQUEST_POST, policy_post_handler);
    //coap_register_handler(policy_resource, COAP_REQUEST_POST, std::bind(&UdpBasicAppJolie::policyPostHandler, this, _1, _2, _3, _4, _5, _6, _7));
    //coap_register_handler(policy_resource, COAP_REQUEST_POST, std::bind(&UdpBasicAppJolie::policyPostHandler, this, _1, _2, _3, _4, _5, _6, _7));
    coap_add_resource(ctx, policy_resource);

    //coap_add_option(ctx, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);

    std::cout << "UdpBasicAppJolie::serverCoAP_thread going in SELECT..." << std::flush << endl;

    //Listen for incoming connections
    while (1) {
        FD_ZERO(&readfds);
        FD_SET( ctx->sockfd, &readfds );
        int result = select( FD_SETSIZE, &readfds, 0, 0, NULL );
        if ( result < 0 ) // socket error
        {
            exit(EXIT_FAILURE);
        }
        else if ( result > 0 && FD_ISSET( ctx->sockfd, &readfds )) // socket read
        {
            coap_read( ctx );
        }
    }

    std::cout << "UdpBasicAppJolie::serverCoAP_thread END" << std::flush << endl;*/
}

void UdpBasicAppJolie::manageReceivedPolicy(rapidjson::Document &doc) {
    policy newPolicy;
    bool parseOK = true;

    if (doc.HasMember("uav")) {
        if (doc["uav"].HasMember("id")) {
            if (doc["uav"]["id"].IsInt()) {
                newPolicy.drone_id = doc["uav"]["id"].GetInt();
            }
            else {
                parseOK = false;
            }
        }
        else {
            parseOK = false;
        }
    }
    else {
        parseOK = false;
    }

    if (doc.HasMember("id")) {
        if (doc["id"].IsInt()) {
            newPolicy.p_id = doc["id"].GetInt();
        }
        else {
            parseOK = false;
        }
    }
    else {
        parseOK = false;
    }

    if (doc.HasMember("name")) {
        if (doc["name"].IsString()) {
            memset(newPolicy.p_name, 0, sizeof(newPolicy.p_name));
            snprintf(newPolicy.p_name, sizeof(newPolicy.p_name), "%s", doc["name"].GetString());
        }
        else {
            parseOK = false;
        }
    }
    else {
        parseOK = false;
    }

    if (doc.HasMember("action")) {
        if (doc["action"].HasMember("id")) {
            if (doc["action"]["id"].IsInt()) {
                newPolicy.a_id = doc["action"]["id"].GetInt();
            }
            else {
                parseOK = false;
            }
        }
        else {
            parseOK = false;
        }
        if (doc["action"].HasMember("name")) {
            if (doc["action"]["name"].IsString()) {
                memset(newPolicy.a_name, 0, sizeof(newPolicy.a_name));
                snprintf(newPolicy.a_name, sizeof(newPolicy.a_name), "%s", doc["action"]["name"].GetString());
            }
            else {
                parseOK = false;
            }
        }
        else {
            parseOK = false;
        }

        if (doc["action"].HasMember("class")) {
            if (doc["action"]["class"].IsString()) {
                memset(newPolicy.a_class, 0, sizeof(newPolicy.a_class));
                snprintf(newPolicy.a_class, sizeof(newPolicy.a_class), "%s", doc["action"]["class"].GetString());
            }
            else {
                parseOK = false;
            }
        }

        if (doc["action"].HasMember("parameters")) {
            if (doc["action"]["parameters"].HasMember("period")) {
                if (doc["action"]["parameters"]["period"].IsDouble()) {
                    newPolicy.a_period = doc["action"]["parameters"]["period"].GetDouble();
                }
                else {
                    parseOK = false;
                }
            }
        }
    }
    else {
        parseOK = false;
    }


    if (doc.HasMember("springs")) {
        if (doc["springs"].IsArray()) {
            for (auto& s : doc["springs"].GetArray()) {
                int idxVect = -1;

                if (s.HasMember("id")) {
                    if (s["id"].IsInt()) {
                        int spr_id = s["id"].GetInt();
                        switch (spr_id) {
                        case P_COVER:
                            idxVect = SPRING_COVER_IDX;
                            break;
                        case P_FOCUS:
                            idxVect = SPRING_FOCUS_IDX;
                            break;
                        case P_STOP:
                            idxVect = SPRING_STOP_IDX;
                            break;
                        default:
                            parseOK = false;
                            break;
                        }
                        if (parseOK) {
                            newPolicy.springs[idxVect].s_id = spr_id;
                        }
                    }
                    else {
                        parseOK = false;
                    }
                }
                else {
                    parseOK = false;
                }

                if (idxVect >= 0) {
                    if (s.HasMember("name")) {
                        if (s["name"].IsString()) {
                            memset(newPolicy.springs[idxVect].s_name, 0, sizeof(newPolicy.springs[idxVect].s_name));
                            snprintf(newPolicy.springs[idxVect].s_name, sizeof(newPolicy.springs[idxVect].s_name), "%s", s["name"].GetString());
                        }
                        else {
                            parseOK = false;
                        }
                    }

                    if (s.HasMember("parameters")) {
                        if (s["parameters"].HasMember("distance")) {
                            newPolicy.springs[idxVect].distance = s["parameters"]["distance"].GetDouble();
                        }
                        if (s["parameters"].HasMember("position")) {
                            if (s["parameters"]["position"]["x"].IsDouble()) {
                                newPolicy.springs[idxVect].position.x = s["parameters"]["position"]["x"].GetDouble();
                            }
                            else {
                                parseOK = false;
                            }
                            if (s["parameters"]["position"]["y"].IsDouble()) {
                                newPolicy.springs[idxVect].position.y = s["parameters"]["position"]["y"].GetDouble();
                            }
                            else {
                                parseOK = false;
                            }
                        }
                        if (s["parameters"].HasMember("stiffness")) {
                            newPolicy.springs[idxVect].stiffness = s["parameters"]["stiffness"].GetDouble();
                        }
                        /*if (s["parameters"].HasMember("period")) {
                            newPolicy.springs[idxVect].period = s["parameters"]["period"].GetDouble();
                        }*/
                    }
                }
            }
        }
        else {
            parseOK = false;
        }
    }
    else {
        parseOK = false;
    }


    /*

    if (doc.HasMember("parameters")) {
        if (doc["parameters"].HasMember("distance")) {
            if (doc["parameters"]["distance"].IsDouble()) {
                newPolicy.distance = doc["parameters"]["distance"].GetDouble();
            }
            else {
                parseOK = false;
            }
        }
        else {
            parseOK = false;
        }
        if (doc["parameters"].HasMember("position")) {
            if (doc["parameters"]["position"].HasMember("x")) {
                if (doc["parameters"]["position"]["x"].IsDouble()) {
                    newPolicy.position.x = doc["parameters"]["position"]["x"].GetDouble();
                }
                else {
                    parseOK = false;
                }
            }
            else {
                parseOK = false;
            }
            if (doc["parameters"]["position"].HasMember("y")) {
                if (doc["parameters"]["position"]["y"].IsDouble()) {
                    newPolicy.position.y = doc["parameters"]["position"]["y"].GetDouble();
                }
                else {
                    parseOK = false;
                }
            }
            else {
                parseOK = false;
            }
        }
        if (doc["parameters"].HasMember("stiffness")) {
            if (doc["parameters"]["stiffness"].IsDouble()) {
                newPolicy.stiffness = doc["parameters"]["stiffness"].GetDouble();
            }
            else {
                parseOK = false;
            }
        }
        else {
            parseOK = false;
        }

        if (doc["parameters"].HasMember("period")) {
            if (doc["parameters"]["period"].IsDouble()) {
                newPolicy.period = doc["parameters"]["period"].GetDouble();
            }
            else {
                parseOK = false;
            }
        }
        else {
            newPolicy.period = 0;
        }
    }
    else {
        parseOK = false;
    }

    */

    std::cout << simTime() << " - (" << 0 << "|" << "10.0.0.1" << ")[GWY] SERVER THREAD - Parsing policy: " << parseOK << std::endl;

    if (parseOK) {
        UdpBasicAppJolie::policy_queue_mtx.lock();
        UdpBasicAppJolie::policy_queue.push_back(newPolicy);
        UdpBasicAppJolie::policy_queue_mtx.unlock();
    }
    else {
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::cerr << "ERROR while parsing policy --> " << doc.GetString() << endl;
    }
}

void UdpBasicAppJolie::serverCoAP_init(void) {
    //t_coap = std::thread (std::bind(&UdpBasicAppJolie::serverCoAP_thread, this));
}

void UdpBasicAppJolie::serverCoAP_checkLoop(void) {

    UdpBasicAppJolie::policy_queue_mtx.lock();
    while (UdpBasicAppJolie::policy_queue.size() > 0) {
        policy actPolicy = UdpBasicAppJolie::policy_queue.front();
        UdpBasicAppJolie::policy_queue.pop_front();

        std::cout << "Policy received!!!  --->  "<< actPolicy << endl;

        send_policy_to_drone(&actPolicy);
    }
    UdpBasicAppJolie::policy_queue_mtx.unlock();

}
/*
static void
message_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
        const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received,
        const coap_tid_t id)
{
    unsigned char buff[128];
    unsigned char* data;
    size_t         data_len;
    if (COAP_RESPONSE_CLASS(received->hdr->code) == 2)
    {
        if (coap_get_data(received, &data_len, &data))
        {
            //printf("Received: %s\n", data);
            memcpy(buff, data, data_len);
            buff[data_len] = 0;
            //std::cout << "Received |" << data << "| of length: " << data_len << " after CoAP Drone registration" << endl;
            std::cout << "Received |" << buff << "| after CoAP Drone registration" << endl;
        }
    }
}
*/

void UdpBasicAppJolie::registerUAVs_CoAP_init(void) {

    for (unsigned int i = 0; i < addressTable.size(); i++) {
        registerSingleUAV_CoAP(i);
    }

}

void UdpBasicAppJolie::stats_CoAP(unsigned long int timeEpoch) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    memset (buff, 0, sizeof(buff));

    //{\"address\":\"%s:%d\",\"id\":%d}
    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP stats: |" << timeEpoch << "|" << endl;
    buffStrLen = snprintf(buff, sizeof(buff), droneStatsStringTemplate, timeEpoch);

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/stats", jolieAddress);


    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    coap_add_data  (request, buffStrLen, (unsigned char *)buff);

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;

    // Set the handler and send the request

    //coap_register_response_handler(ctx, message_handler);
    //coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
    //coap_send(ctx, ctx->endpoint, &dst_addr, request);
    //FD_ZERO(&readfds);
    //FD_SET( ctx->sockfd, &readfds );
    //int result = select( FD_SETSIZE, &readfds, 0, 0, NULL );
    //if ( result < 0 ) // socket error
    //{
    ////    exit(EXIT_FAILURE);
    }
    //else if ( result > 0 && FD_ISSET( ctx->sockfd, &readfds )) // socket read
    //{
    //    coap_read( ctx );
    //}

    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}

void UdpBasicAppJolie::registerSingleUAV_CoAP(int idDrone) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    memset (buff, 0, sizeof(buff));

    //{\"address\":\"%s:%d\",\"id\":%d}
    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP registration using template: |" << droneRegisterStringTemplate << "|" << endl;
    buffStrLen = snprintf(buff, sizeof(buff), droneRegisterStringTemplate, gatewayRealAddress, gatewayRealAddressPort, idDrone);

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/register", jolieAddress);



    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP registration for Drone: " << idDrone << " having local IP: " << addressTable[idDrone]
              << " using string: |" << buff << "|. Sending to " << server_uri << " - port: " << jolieAddressPort << endl;

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    coap_add_data  (request, buffStrLen, (unsigned char *)buff);

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;


    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}


void UdpBasicAppJolie::sendPositionSingleUAV_CoAP(int idDrone, double x, double y) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP position for Drone: " << idDrone << " with position (" << x << ";" << y << ")" << endl;
    memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    buffStrLen = snprintf(buff, sizeof(buff), dronePositionStringTemplate, idDrone, x, y);

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/position", jolieAddress);

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    coap_add_data  (request, buffStrLen, (unsigned char *)buff);

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;


    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}


void UdpBasicAppJolie::sendEnergySingleUAV_CoAP(int idDrone, double residual) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP Energy for Drone: " << idDrone << " with residual (" << residual << ")" << endl;
    memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    buffStrLen = snprintf(buff, sizeof(buff), droneEnergyStringTemplate, idDrone, residual);

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/energy", jolieAddress);

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    coap_add_data  (request, buffStrLen, (unsigned char *)buff);

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;


    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}


void UdpBasicAppJolie::sendAlertSingleUAV_CoAP(int idDrone, double x, double y, double acc, const char *classe) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP alert for Drone: " << idDrone << " with position (" << x << ";" << y << ")" << endl;
    memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    buffStrLen = snprintf(buff, sizeof(buff), droneAlertStringTemplate, idDrone, x, y, acc, classe);

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/alert", jolieAddress);

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    coap_add_data  (request, buffStrLen, (unsigned char *)buff);

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;

    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}

void UdpBasicAppJolie::loadImageFromFile(std::stringstream &ss) {
    //ss << "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";
    ss << "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAoHBwgHBgoICAgLCgoLDhgQDg0NDh0VFhEYIx8lJCIfIiEmKzcvJik0KSEiMEExNDk7Pj4+JS5ESUM8SDc9Pjv/2wBDAQoLCw4NDhwQEBw7KCIoOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozv/wgARCAAbABQDAREAAhEBAxEB/8QAGAABAQADAAAAAAAAAAAAAAAABgQCBQf/xAAXAQEBAQEAAAAAAAAAAAAAAAACAwEE/9oADAMBAAIQAxAAAAHXxce6oUy4riW/tz86x0TqktzkAqS5aT//xAAcEAACAgIDAAAAAAAAAAAAAAACAwEEABIFETP/2gAIAQEAAQUCs7hK3PCYXY62YSQEt6ThOoDIla8DlqagXi4xvr//xAAbEQADAAMBAQAAAAAAAAAAAAAAAQIRITEQEv/aAAgBAwEBPwFJs+WZJykbHoinzxkiK6f/xAAaEQADAAMBAAAAAAAAAAAAAAAAARECEDES/9oACAECAQE/Aaio8jlHCmaXR6y0uH//xAAjEAABAwIFBQAAAAAAAAAAAAABAAIRAxIQITFBcTRRgaLh/9oACAEBAAY/ArGiHDVSTcF0/sFcXTJzKgqmewhBm4wDBTqgDaPqPC8p3K//xAAcEAEAAgIDAQAAAAAAAAAAAAABABEhMUFhccH/2gAIAQEAAT8hfPFs66gkR7NRQRol2P8AYjbkTK4Im57UB1mXfWJkYbJYXQ6g7t4IBjADZGPon//aAAwDAQACAAMAAAAQdr5ons//xAAaEQEAAwEBAQAAAAAAAAAAAAABABExECFB/9oACAEDAQE/EM2Jl8YsBvsN6Z6FkFILbZ98aT//xAAYEQADAQEAAAAAAAAAAAAAAAAAARExIf/aAAgBAgEBPxCWl3CheA0cErREk0hik4Pg2ZH/xAAfEAEBAAICAgMBAAAAAAAAAAABEQAhMUFRcWGBsdH/2gAIAQEAAT8QFonUHftKV0y/uKCIrIPc1hvJAYj2OFtKSqIRX4D3fhwgzhiYnDz1g0yw53dxyawpoCqEd6fw3iSFymV+1V8cZInAAzz7W4oYodt+MPBskrYTNAa/pn//2Q==";
}

void UdpBasicAppJolie::sendImageSingleUAV_CoAP(int idDrone, double x, double y) {
    /*char buff[512];
    unsigned char buf[3];
    int buffStrLen;
    std::stringstream ss;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP image for Drone: " << idDrone << " with position (" << x << ";" << y << ")" << endl;
    //memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    //buffStrLen = snprintf(buff, sizeof(buff), droneAlertStringTemplate, idDrone, x, y, acc, classe);
    snprintf(buff, sizeof(buff), droneImageStringTemplateP1, idDrone, x, y);
    ss << buff;
    loadImageFromFile(ss);
    ss << droneImageStringTemplateP2;

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/image", jolieAddress);

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    //coap_add_data  (request, buffStrLen, (unsigned char *)buff);
    coap_add_data  (request, ss.str().length(), (unsigned char *)ss.str().c_str());

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;

    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
     */
}

/*
void UdpBasicAppJolie::loadImageFromFile(std::stringstream &ss) {
    ss << "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAKAAoADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDl1OetOPSo1+YjH6049MZrkRoO5JFOA446VH0PWg7h0PFMY8HsKeGx16VEOGp/rnpigCTOCPSlBxUW7OPpxTgeKBWJMlsgDmng/MDxjGKiDEZI69KXeOmDQFic5HX7o6YpyleevFQ7sLjHFOU9enNAEgI3d6dwDwDUYOBk4p+7uvP0oAUPwSRzTh8zD3pobgjNCkA8nNADhn5sgEA8ZFOJO4knt3pM5VsUFs9+tAkGM4B6GlGCzAnkUZycenXNMLANuoKJVwenWl6DHOO9NDIMYPJpd3XBzQIQuVDD+9xTY2Zd4J5KnBPY0u0gEg5ppwBgnqeDQMz7oSTQiGRyQByB3rLNpIASjMAOw6mtwKGlYEZIP6U+WNFlAAOCMjAoAwFjukiLeY+4kDkUNHqEUu9bnAzyD3rdaNW+7uYcGmPbSBiFCkk5ye1Ah8N5O8KiQct6GrAkYxjOc/Wo0j5Q7BnGc5607BCgkdOvNAEiOwcgseRjPoKeF+7jqOBn0qAxth1VuSuQanD5iTdgMoH40DJWAyCTwOuKaVIbeG+XsKUnocZU1GZC2CQAOgoAsJINxGD6U48AY6e9VxkHORmpFZsYYjj3oESg560uBggUmRjIPahSDzSAUDjrSnOMZGKMe3Wmkc470DsOLYOcUAZGaOQOgNKOmaADAIzSjb1HWkxn2pQMDFAA2dm3jFIFwmMU7OO1ITQMTknNLg9aUZwOKXHzUrEjAGwrcUpQbc45qRQcA88UADoaLWBEAUc8GnKOCCM8d6eR6UhIBGTVFMQL8vSk2nINSDk8HigLk9aQhjfLyBzSliGIP4CpNoIwKUgFs456ClYCMOQOB3zSDLegJ60/DLkkCgjuRg+1NKwDDwcHn3owdoAxx2NPAymAPm6807jsKAItp3UYGMYqQA7jkUuzjI/GgCMquw8UpQYUA9BTwopWBA+4eeKQiuV560BM5AqwUHAI5oAAPygUICEqcDP6UEZxxVgkZ5H5U04PSmBXMTM2Fo8lgRnGParICqcg8mg88cfnS1ArtGA3saBHyeOKnYZPShehzTQEAjAYkDqKjMZKZAGfWrq8np2pMZXAHNAFfZ0DqOlJ5Me3dt5qywBP4UbMqAMUAVDGuMgc0CIDBx9T6Va2AHkcUp+XlQM9OegFAkUXUI4UjzFPfFZjFbKN/NOFc8e1bkwUJsyHB7gdDUF3p8ctsCy5K+tAzl14BJ7UrgY3UAk0MSee1A7jTgilyAooIyvNJtGKYheS27vnpS7uGP8AFg8U05H400ggD1FMCZGG0ZHOOlKrgqeMVEXLAAcH1pBIXyqEKFG457mkOxMX6c9akLAZBPNVS/twakyNxxQInUgjrSgjOccVCrHIp2eCTQBMJSpygBb36U8NjgEgHk46Z9KgDgsMdqeGLKccGgCYYXtjPc04cGofmKgE04HnAagVyYnGeKCQABgc+tMDep/GnAk/NkEelALccpDNgA5HXPSkOC2OKVTt5xTT97NBQoZVPTPY+wqXjAA6dveoVwr8981KuMAY7UAPA+WmlQ2MdqdwBik5ByKVwsRsqh9w4zwaJHXYXJ+7xTv4h2J6E9KpyOT5iEYGeT60AWUCgZBK5XPPen7lEgP4c1BbyCSPgcjjmpWbd8p7cigRMxDodpU7TgYowCyntVfAjzhTk8sPWnhiy/3R6GmgFZ/mIxyxwKQ4bIxz0qMkkBs8rSM+CXLALjBoAl+dRwD9PWiWchwRtAIxtNG1mlDq2UAAxSTWok8qTIO0k7e9AE8ZDEcdQT+VKrgxK+PvVXBJQkk4QZAHXmlU4+Xf8q9PrQBbDBRg8fWlDbWUEjFRDmI7iAT360wq6hlJDLkc0h3L3O7r0pMgmq4coQwTcQMeWTUqsxUAkRnrjrj2oGTAYHIpcjHSmhmYZXt696VDlMBec8mgTAUozQcg44pxBxzRcVxM+tB5707AJ+gpBnOMUFIQrx1NOYL3J4FIAPxpcigVg5HAzg0AADOelC8haCMKRQIMc00j5qXIHBPHalUcgk0DDbjk0YAanHkEimBudw/hoGPxgHFOUjC0wsThh37U7qRQA8gbcn1pMDdkClwDTiQR1oAj2s2cDvSgZOQMCl5J4PFKAScdhQLQaq5zzS9OMU9VHPNIOc896AuN29sEU7HGC/4UMRnBoG2gQFckd+KTyxkcVIMUuBnOaAI2QHgU0LnipDkEkUvJHSgCMLlj04oKdDxzTwMHpRjnJFADGU98UgXA5qTBx05oxzgjigBgXbzSMOMipMEHAHFNKjscUBcaAMYPU0BeOKcq5P3sUqgEMdufQZ6UARkGlIwvI4Pr0pxU4XJCkdxzTHQjghn7nHf3pXBIjmUFNjD5hyNtUVun8wKxICdQamv2CouJyuehxwDXK3OsajZXLrLiWLI5x2pDsOUjHemMcN1OKkB6/pSHkc1Q7CFuCCOnTFJuoJO4nOBimkY6mgLC5zu/2OTnvTFfzFDgEbuxpc9AfXgUoBeTDEHuMfypiE4z7UwjGD3zn/61Pz8gcrjPBHpSkYHrkUAIM43HpnpT8lhnBB9KiUH5QTyDnPpUxY8knJ9qBai4bGacjDbg1GCRznn0p6lieQKAJARkEdfSn4yOQQDUfOeoxTjk9CcUAO3cg88cVJkZAHB9TTE4xzml3biMjKjsO1MRJuz26GnDhj2GKjJxkg8U/duPOCD0pAPQnBB/nSkkr05pAR0KgH0pxOTgdKBjQCSCe1S5+YH2xgUzHUDnmnqp4PT3oGOGFZQc5JpQOvPekUk7y3JDcfSl+8uMc5pDGTKGUDcRjniqtwcqFKEA96v8AngdKSTBtwxXIP60CMxlMUuU7dAO9XI5f3YPl4ZepNQPGAQ4OOMnHaqTGRZ1bc49uxoCxouzAlywx29RSiRjAZmHy4J3VWklLWrSFlwRwBzzVaGeQW4hfJBGCPY00BqIyb0BI/eL8hHIJ/Cm3sQNqYNjBic5FUbC4CRBJxxFlgfu7ew5FaRciFW5bcM5J6CgQRlCkZXIOBuHoRUx8tVd8FTnAJ96rrJtBClcZ60RyiSIDr85znoKBlhVwFY4ywzkfyNVniZ9gXjBJOe9ToGYPt4weh7ip4YSu5ndWDcADqtAmZscxXqpDE4z2FWUMTh1SRQ+csSf5VXubco7xsTgZxnjNU4LjynEM6RBQcA96EBomR4pFjkwyyHCsG5zVwyxxpyfqAM81R+UuGaBHXJZW3cg4pnn/uSg3jA6tikUXzO2SCASBn5T0oW7iDANNIoPYLWbCscbs5cs2MnaeT9KsxuJPnxuX0zyKBNGmskU8pSIk7RncelS4UcA5Hr2NZTxokatHLsJJyM5z7U+z1BnYRPjk4XtQKxpLnk9/SkLEDoc+9R7xGATnBOM+lP3AnIbgetA0xykADOc04dckDFMyePUnAoXIkwTk9MZoC5IuNuew6UBQRy2M9j1oA4JIPXGPelIbOSVCj160AQ7sHBXPpmlD4OCBz0FSMgLZPSoZo1IJAOemRQA8SZBUDmo8HPAJB7ioo5Q/wApUqy9/WpI5FkZlKbSPQ0BcgaWSKXaCD35PardvMJOAcn09KqTpzgryBkEdqS3zE+5Ryep9aBmmp4PHenr3zTY+VxkdcmnEgMBnr0oYmGDjGaUdMU7g8d6FxnFImwBQQfWm4AGApp44NKDyc0xjeD1WlAB7Gl6noacQB2NADMegpADg5I+lSAc4xQBnnHFADB905IpSNuBkc05lXpxRtBGTigBgPPShs5GKdgUEA4ycUrgI2eMHikBPQc+9ObPYU4ZVPemAzJxmmnkEgc+lS4z2puzOcGgQ0DsQOlC4UlinJ/WnMoRhzuBHOKOOozn0pXGRgKCQinaeo9KbI4ViytggYyOce2KkHLHORx2qvcOscW5mUHBxjg/iaQLcrXbJKqwm3DK3XBPHuR1rjfEvm2CmEsTG5GDjJHtxWzLqN3c3kUVo0ay4z5rnAx9f8a5rxTq0sZMcwSSUYJI6fp1oSbY3uavHrSEcUbTyMUnOMZp3GDAYpg24wRzUgUnrTD3p3GNILNtHT1o6MBnocU4E8HP4UhUNu9+ntR1EwAAOAeCKDg9e1LsxgccDFIFxTENOAeKcQNtJwXxinYP1oAdjkccUqkZLGkGcKQe3IoG4Z4/OgQ8DByT1qQHoPSog5zzg04MW7Yx39aAJhw2e1OGA2MdajAJGc8elSKPU80gF56DoaeAe/ajGMGlBKq3cnpTAcoGMkc0v17UAEEjnqO9OAJ+UHJoARgoTPIBPWlDAgDsKVlJUK2MDt60hXDAjGO4FIEPBG5sCpcKelMQYBI9e1SDAegoACD8nXuTR8rBl2ke/agk5OOlLg4KsePTNBL3Kr7khlAwF285qqYle1Yn7m3gHjr16VbuEMijLYA+b5Rnj0NNnTyoGAYcqGXHAyf5fShls5xGeymS2kBELEeWT/FmtExsu046k4qDU4PtFvC0zEzQ4II4wD2pkF08qRK8pJ6DIxzTQrj5YFnhdHyI2XnHXOaZJqQt7RbeQMdgG1x29vyoZpvNcDCheDn/AAqjdXX+hz2zEB5mBViOD9BQSdTDHbS6e0qSEXBXftPBIHsOPeoLORHuAFZWGze8WOuf4j71Hbym3tvPRCFjQAg9ScdqxtI1R42vZ4gZHclWyuMH60gZ2H7uIBgMsexqeKJ5Y2IiB9ADgg1kWV5E1pDJdMc/x55/I1I2pwKcoZREGOMjBNIRav1Vc5Zg6pzu5INc3NDNcRGVI1aQfMB9PfrWydQSXaJHIy3VhyRWWdTLXUkakBEc4bGDj0poaK0E6pc24kfy2PVXYkV0KxJchwgWU9sNnH0rCuIkkky43Q5yg75p0aTWj74Nys4wADgD6UFGm1uqIJtzREHGBUsckW4ElFY8YUcmqAu5klCXMpUHB2suafJP9lb7ShR442G8A8kEelGojSkaFMO52ITwyjJBHrmkazt7jTi/3yJC25WIOD2NZOo3kN5HAI0kHzhvm6Y9a1htksjBDJtOQdwPSgBzSyjy1DxlmXkEkggdKlF3GZXLfeIwFHH5VTWUCIiQbpIwRleg/wD11PdxQGKGRG3SKu488igmO5aivIZAfKLYUBmDDmoruQBf3OASwx6isaHW0SbcgOSMFccVbe5eXazKMHnOaLmljTgnmkkjMjKF+6f8avY+c4Byv8XY1jB42XKEMuMHBxg1sW85uI0EZGFXBBPFDJY7YD0G72NMZOx+T2FTgYYOSNvoajlOG+UEg+h6UXEUniKtgHj1qOOYRTAnk/wkdvrVqcHaFwOe5rLkcRs4xuPqOKB2LdxIJJck/NjnFTLDmZWOSuzkVSgTzWVmJA6cVrxocfM30oGPiACYA5NOWEBkJ5+tOjUfdYE+4p38YXnigQoGOfu+w70gU8nrUhA3YGcULwO1ADQAe1GzPXipB+VBxnmgQ0LjigLTsnt096dgkdPxpCGKD1NIwwR707aRmhQR1oAbgEZI5oxkU89aXb3B4oAj2mkK1JtG0mkZcEAN979KQxpHalA3LmlIPTg4pygFc4xQIjwSeKXYc5p4x70YyKAG7R1oAwORSlPQ0uNyk+lAys0QZw2eR1BOP5VnarbGW1lCtjd0z0rVLsG4HXjioZJLcBo7ldqngMT096Ajvc4W58PX19Gs8SEIBgKrYVvUGuS1PSpY7t1csdp5U9AK9bfUNPsbEQtIXiUEr83JPpXJ6jLbamGS3iKN3LnqKadmUxqn5mzSbsc4z+NNPOCO9OzzxzRygP3DGcfrTcHrjNKQMYpOenSmlYBrAqST09BQPugjseaVQck5BX3oxt4B47j3oAXgjpg5yDS846UhJIxng+nalA4oAiz82cd8U8AjOO9OAGAMd6cQBmgVxiqPTkd809cbuB270oAxx1p2DvGKYr3GgnLAgDFSIOoI/Wmsg3E98U7hjkCgB6qAc0/g84xTVAp6kbsH0zSGPUcYzT9g2kHmmjgVIuDjNAhQg25xyT609QmeBg0LgkjsKUAE0DDaGzk9OnFNwAuCOT1JFSDBPBxz1HWnkBuuTjuaAICCjbc5zzTiTSYPJI5Bx9Kk6jmgY3cCAMHr1pxJMnAPSlUEZpXYjPUgjtQS9yNpAiPtBC98fyrPNwJIvKOSC/OR6VZmjVICo3fNz1qGGBGVkB5ABz70pFso3RBhZmJ4P1OBWM0zRr1bqevOB65rent1EzqWzvOB6Cs3ULPy4spnYeD/AI/SmiSlLcRREESMCfvMxzknpWXdXarqdsxk3BThk64NXZGje1R7hAcZGB1JHSucZXW7MknyHOfeqQM6q51iWPT2BzveUJH9KpwmfSmliPmO0p3MCOGb19qwZLqc+W0jkqHyAeo54rQutSmufLbzG+X5jgc89qqwjcsHkvJPNeYxqnTb3q3bThch5cgsSCTmubhe4WMRAMpPOPUVPp9z5cwDhmH0yM1LQjs5VN5bbhJGjFflyOhrmNT0+909Y5LiXeX/ALgrTN6kUEjySLgEbRWLrOvrPAgBDlehzQkM2IJ4pCssbZwMHP8AhVm8uFkjtjE+XiJJ7Zrh4NVcPuEm1vTHFEusSMxBkOO+PWjlYXO11W9jZIJk3PIABJjv+FV74xPAHjbPm4LFe2K5KPXpYcHO7FRza5NNGI8CMdylPkbDmOmin8zIaVjhSACelb9lfW8UNu3mBQBh1AzurzNdTkRshjjgc1ct9WAyryFBngrzQ4MOZHobzRiSYx3COrfMq9CD2rCn1Z23IQwK8EqetYL6irsTG/brnBNZz3rK5AJ596FELpHRRXQhZniR5PRScVtW2t200ESO+x8gAbetcTFqcvl+UgwxOAT2rSjVHZN6jB564IqXEq520Ahkv/LUMYtpYlTwT6UzTNWvNOllhmC/Zyx2nHPNc1odxPHcOgLFWbavPJ5re2tcSSwCIEryeaVhM6rzmlijIO5SOSozio9rLw27JPGDzXL2Wpz2bMI8tGvDIGwT9a0I9ejEL4UIh6BDnmiwjXmlCRAEguBnBNYe+S7uiSSEP8QHFRXOpQyR7YyWmY4wTzWrZWywWZSVskDJXtQilsXtP2xkoSp4/OtAZGNgGfesBJPMBMGFCdTmtmzkaSDeeSOooJLK785JBFSqRuqNGDHIXjvUgJAyBQFx2cE8/pRwB07ZpA2VJx2p6kHHHanYLjThVBP5UvUcinc7fmGab8xPtRYBecYxSBc9zT8nFHbPelYBnHTnilLDqORT1wenB+lIMZxjikwEyuMEdaMKOvSnYBznt0pOAOeaQDARuNJkZ5BPocdKeAoalwvqR7UANDE+3vSh88Uh4HSk/CgBykk4456e9A5OPfGajeNiMRv5bdj1xUJnngKicmftmNemfWgC1kFcjPBweP1pMgZ54pW8tn2+aAVXjnrQyOqcYagCJ2BUn24xWVc263ZWJyQ27nNSajdPGnmRDa6cj0NZp1qaZVeWzCyE/eHFDBGTrUK2kWDsHltlc9a5K811HiB2fOOMqcV0XiK5GpXiWrHys/eNcn4g0iDTzCbaYuWGTjmtIpdQbOr3AKCB+FP45PtTd/z8ClzlunBqSh4IyT7UpIKhqYAefSnDBXHpQAgAJAI3DPbtS4+c4PFLjnHTFKB3A4NADSPl4PenDge9OwNtCgDtz2oATaSRxTth9KVOH5GcU/OMkd6LisNVfalCjJ9acMgZI604cHpQFhgXvT9oAAApRkxk+hp4+Y8dqAsNX7h45zUnHm42/wAFKqg5yOaeBhgQOq4oGMKVIicUMxCj1qSMksRg0C0BAOQKco+YcUqLgnCk5qRQSOgyPSgY0xqWyDTwuDx6UoXHO3r61Mq8ZIoAoXETrauRnch3HHfjNPOGVXHRkBx6Eir+AVcHgkVnldilP415/CgVx+CoBJ5IxikC70Qg53A8U+Nw4XcMkDvSRSCJ0AHBBG30pAVZQpQ+o7E0638sRjceT1A7VlaheGC+8pVMiOfvL2qdTM8Q2H5T374oauV0HzRo16BCpHI5J4NVb6SNrBgBmQZUkdKfcQSiBvIf5lGfm7VgRag9neLa3OHhkyeR0NEWJbFCJjyGYEbhjP1rF1Fh9vkBOdrckVqXflmKYrxhuD+NYbkhmycknk1pEliFy6ke/GanguSCd2OTiqjPimGTA+UY5zWlrknQDXEMisVHAxmqr6mIiRGRjOaxvMJGM8U0kkknrT5AuW7nUJ7nIZzt9BVTcSAMkikpKpJIkdkg5FGTmkopgLmgUlFABRRRQAodgeDS7yevWm0UgHhmUgg81o2lyTdxl2JA7ZrLqRWIHBxSauF7HUw3iwzrIvDo27ANX11JvNa6Eu3f8uK4xJ3X+I1qwTRSwwidwvzZOO9Yyi0WpGq80iylxKygnOQODThYvLewxtKreYQcBsYzVea6iSdliwy4ABrQsbH7RtuUlzIOevSkVc25tJlsrqPYpZRjlea2mif7I8oOSo5HrWdYSXUtrI8k4VkYDJPNXzLNlU3DBXDEdjUtBexEg22iyFSC3XHpWjpV0s0MnltwOMUyWOP7FIN4GFOCP51T8MFoTJFKAquxKe9KwjoFcKn3Gb6U5HG9XCEA9jT4gVVwCGwelO25+g6e1NAAJX5zyOgFSLgj+lRgkKQDzVpVyM45I4NADAeCKTDH6dqm2+3FJt4osK4w5703OTxUpT5gMdTS+VnGOATg0ARAmgMw7U4QnJ5NOEPPPSh6jGbiRRztp3lnOAOKQKwBpWAjzQSMCpAh9KaY270WATd6UFiOopQpz0pSm4c0WAjLk8d6eJMrtBHPUU0wkZIPNV9kqsSFPtRYCdooX+cpz0zmqrhVIA+5/DzTfs1xySGIJyBTzFIBkqc+hosAwRwz/u3KjHPPrVS/S2jgbIT0xVgjkK0e3HoOnvVW9SJ438wA8cH1NJ6BFnGTiB7uYToPLRCyMDyTXIXk7SBmBOB93Jq/rN/It1KCcADaPU1zk1w0vy447VrCLe4ps9JBJOcClbPfrTIyD1NP6454qDQdkhehp6g7eRgmk2t0AqXnYAevtQDGYJbGOe5p2MDgU7DBuT2o54+lAhqnjJFOVT1P4UccDHOakVR1zQAwKS+cU8Lg89KB9409VPPcUBcBz9O1PCjcPpQMgcjjtT0XnJ70CuMxwQBxuqQABxjgUYATHfNKR1oAcvPzY68Yp6kZHHGPypqg7zjpGM09RuG4dGO4UDuLt4HHFS4Ks2B7UoAbgU9kOW5/i7UrskBkEbeucU5FAJPr6dqXABHP8RpyjGTg8/pQmwWgm0bcZNSAcLz1HShY2LqMdP1qdYifmxximO5ERlGY9eAKo3YKz7yMF+B7VrBCxxjtmqs8HmQMc7WB4zSEZq3CR3C+bwrdD71JtIvAigs5XOAO1TNokV1ES5IkAwrA8c96xrqfUNOfzYmaYRDbnHJougRZMEQuI0YBAxwT6mqtna3BupUWVAQx2KewFQtqEt9JDdSwlWRwCoHBrSsFhuNf3xgqoPIYEE07osyvtF+Lko8QzIduR0rD1u1lixvwDvIHHTHNd7qFgHuHkQAIr9R2rlPEbxrErzvhVyR6k1MdxdDjru4do2Qrt3YIz7VmO5Yk5qe5uvtBz0xnFUyc9K3SJYM2eSKjNPbpimds1oiGNoFGKKoQUUUUAFFFFABRRRQAUUUUAFFFAoAKKKDSAUMRUkcpR92M+xqEUtFgLRuWHOevarNtf3EY2pKyg+hrNzT1bGDnGKlxRVzsdB12OKUx3TFkZiSDXXabObmJ2yGUNlee3vXlNvMI5UdxkV1GjaisZeWORl/2e1ZSVikdtcMUgO7Pzjaw9qsLahRbSI+EXk+tY9lrEd2xhZ8sBnBFaC3+6MD7rIcAGpsDNeOUG8xG+EboT3rWiJaPJ/Gud0+6W9DkpieNsFR2FbFtdABlLDj0oAmIxL1/D1q2HPyYI4GCKowyrNNhTkjmrOSdzAcdDQImBbDAkYHNLwAQD0NRw5cSAg5xTwCAePxoEO3cgjtSrkAZI65qMA4zinDORgd6AuPBwCKTPY0DcD0oOc8g5+lAxc7cUZGDkdaCKCOKA1GHB4FGeaXHPSjaeuKA1ELY7ZpRgrnFLgjnFAye1AaiFc8d6QqSPp6U8cGmkc9DQA0vsAZmIFQS6pZwIzylmwewqdo13fOPk9+lV5mhjj2+UjAHOSKQFT+07WUOwYKWPG4dq5rWNVFhbFgVY7ycZ7VY8RmGDF0XUf3YwcV5XqLTTTSStMw3sflJ4xTSuxoqardC81CWZMhWOcVQOc9akkUo2w/UGoyPWuhES3PUprK7s8yGEThR8zLVKDU7WZirMI3PADcYNb8F7LGGDY2njFVptN02/dRNAFb1Uc1zXNUyJX3AOHVscEqakVxtY4I5qlceGr21jLae+9A2QjdTVeLUGiDR30Lxt/CxyAfepe42awbJoxuPJ4FQwyxyRpOJA0TdCOpNT7gqkH7x6Ac4q+ghcc5BpwOVxnmlzhmAX5QKXIK4xSGJ8u8j6ZNOHDHHQmhFycA49akK7BgdM0rkWAkY4605c0mOeTgemOtPVe+cUXHYMd8U4Lv7UoHGB+NSKrcBTxTCwqx8n/bGKmSHbtA/hWnonzIuOR0qwsZ+YqMn09KBEKxY4x97vU4twABg5HOamFuHCkk/nVkxpwoz0+bnrSejApi3XGDn1pzRZbgHDfKcntWgltvbO5UXGAWPSoZX02zWT7VcoB7timBWUMMHALA8DParkNp8mNw5OTz0rnL/AMZaLYEpEDMccEVQn+I0DR/uLL5xx1IosI6+fKtsjUkjuDUYSWZAHjBy2Dtz0rzm78Z6nNIzwKIx6ZqmfFuu7SFmZQfQ07DPU7a3kKPllTDEYPcVWvrSEnPmxAj73zV5Y+t6vISTeS59M8VVuLq/mYeZcP0ySDSsK56hqUdtDLC8c8OwDmMH9aqapc2MUEUtvOEuCwJfPT2NebO1wQxNw2VUEZY5NQBpXHzu2e43cZp8pR7DHqmn3UEcM93GjjkkHg15T4y1WO71ERW774Y8gY9c1k3Vy8Rwjtx71m5LHPerhC2oXHbsikJoCnOO1LtYtgDNaC3DtTcYFSeU/wDdNPW3kbgqaV7C5SBRjNNKmrYtJCcYp4sXPUjNHOh8jKBFG044rR+xPjGR+VPSyOCcjA9utHtELkZlgUY5q+bck4GM/SmtaleOtHtEHJLsUsUm01e+zNt6c0gtiT0o50HIyntNLtIq39lIbrT/ALNx60e0Q/ZsoYoCk1fEBx0p3kKONvNL2iBQZnYIpK0Ps2R0qJ7Y01UTJcGipRU7WxXHOSaiK84FXe4rMQCnAUnYUv0oDoOWrMN08PAOBVZM4p45PIqGUjVttSlhmWaM5KmupTXoriyJyFlOMk1wg4NSqcA4JAPvUNDO+0nxEltfu7uNr43e+K1JddsjfmS3n2RkdPevNowDF15BqcxDGDn25qbAeu2HiHTUj3PMgbHWrsXiLSHiwbtA7HpXjCwjbku3505rUspwxyemDRYTPa4Na08jm8TcenNXIdQsCxDXsZz0GeteCC3n3HbK4x704Q3nl5W5cY5yWquUi57+Lm2deLiMEds07zYCMrcR5+teAGTUgPMW6kAHbPWk+2ammG+1Sc9BnpRyhc9/ypORKhHsxpD8xyGUj/eNeEDWtajwEuJSvfmpY/EOtR8i6f2Balyhc9y5xjGPcGl2ttGCPxrxdPGWtoQC+fxzU/8Awm2sAYyPrT5WHMexbJUGXwQe2aY2VOW/IV49/wAJ7q2SCTx6irUXxF1IJh4s/wDAetTYLnq4PPOc0vI9a8xi+JU4X97bYb0Pep1+JhJ+a1APpuNFmO56LnDYJ4phyJMlsDt7+1cTF8TbEjEtuwPrVj/hY2lHGYsk+tFmDZ0NxbNOHzK3OMrngCqt8PJgYC5U4H3QeelYz+PdMuEZACmeMnj9ait9T0CacF7n526kng0rDRzUtrfXkjzSszgE7VNZl94eu1RbiXgMeFNdtceINFjvR5ThhH07A+1c14i8S3OrT+RFEkcatkAcEfjSV7hexzV5ZW6RO0kmJFGAtY5+7z6CtS/ffjzcEt1x3NZruH79OBXQtiT1FTkg5+X1qzHkc5yOwB5qohZW4I+p6VYA6HPzZrnsabF+GWWNAEYqM87jmrUjQXcLR3MSSj/cHP8A+qs8OTxnpUyOcA5C57etKwXKcvhqMN59hLs45jJ4NVWll06NRewNGqtneBkEfX61uJcOrEKxXIxtbvUv2lJVW3ucMjHBXGRmmFzHVhJtK8huQQeKeMbgAauf2PYXTFradopxn5W6flVWSzurSJTOoZM4DDn/APVQUh6kZwO/pUxyFwcA+tVYXLtlHBC8YJ5qwSW5I4qLhcnVQASTkrjrTpFAxkcmollDhOOG/pUwkWRc/wB2i+oCA9OOtSKBgkCmYBYYFGcDG04yKq4MvxYBHTPrU4Y5ByAD3HWsoylEJwcZPNULvVhp8ZeWYKg6Z70LVknS+YrriOVSeorN1PxFp+gxl7qXfMP+WamuE1jx5NIrW9iBGhUqXHUe9YcFhd6xKZZ5HMZPDP1bNXyaiub+rePL2/keOyYoh9BzWGsGrXgLXUsnl/eIY849a0LfTbe1VQGJkPtT50b+OUkAfKWOM+1N2TFcoLZRRF25yuCVJ55qUjy84VcgZbiptsjKwCu5bgsBxxVyDS9QunjC2e0MMI+cFqVykZiyIxOBn144pd6qcMQp7DHJrq7b4f6pePsJWFhzgjOR/wDrq8PhXrAjLmVV9gMk1POkBwzMdufmOeMY5NOBCkEAjsQBmu3i+GV6JAHnCc8k1U1bwTdaXbNPLcL5Y5PuKFUT0FY5WVQsUm7aflB3EYxWFcXQHyxtnHenarqRuGEMZ2xgAH3rMBy3pWyj1GPdi7bifzpVHOAM5pApdsDk9q3bPSXVVldck9qUpKKLhBszYbCV2UFeW6DvVxdM3cbgMelbC2pRlY+vJ9KUxqpyFOc8e9c7q3N40rFBLRY1A+9705o0B7VaYDooPvUWwk8EfjWbm2zX2aK2xd2KQqo5zUpQDjOTTdo6Y5ou+ocqIvlx+lGBtGOgqTZjoKBjHA5phyoiKqOSOT6UwquelTEAgYFNZScnFNNBYjYYwQKQKM89aeQcDNKF3En2p3QuW5EUGc8UuAKeF55FGBnpSuHKhMA9aQoN2QKkC+1GD2pXGooj2+gphQEgMKsBSfrSsjY5HShSDkuVBEvJI6dKgaEbiQuQa0tmOMdaQRjHPHBq1NoznRuZD2rH7qHJGRVXbtyCDkV0LQsCpQ54GT6VSu7Tfl40x6n1ranUuZVaNkZq8DnvT15pu3BwxxSg85rRmCTWhKBk81IBxxUQapo+RnOKhjuTRfxEdOKvLhlVt3HuKpwHL4yB7etbEESbAuGz16UAVgys23PB6cVYhjZxuCEBTjJqby1CcAMQCcEVPbQ5ThV34yDnpRdEsrrFjJzx3HelMG9ducdxnvV9YP3ZdmHPFJ9lUNksQMdup+laJaEMzmAyPUdqRogAGwTntWmLYcHcxXsGHNKbZiDhdi470IlmQIn2sYyPcUwQsSMqOnQ1rtbyKSphwMfeHeka1csMwkVdkLTqY/lY6Jg55o8tsYx+lbH2MhcspDZ4zTTat5eR1paD90ytp2EYOfUGlI6fKD9eorRFowUDbyaYLcqPnXrxRZAmUCir0TcT39KZ5Yxgpz/eJq+IQCVPU0GFQuJDxRZ9B3MprcbwMjn1pjWq9QMkVr/YkO1gCeKja3AHAwKTT6lGU1pGRkRnn/apVswkeAx46VomPHGelRmInOTxSsFygYpCQ2RjPTHSorqRxICcZ9RV6eMgBlPGMVlzb42Yvz6VLQXK8pZ8AkfLzyahUZU8CpmyV5HuajLADAqgPTFJJAI7VZRjgD2qoD84OTjFWYnGB3rA0La8ipAcANjOagWQCn7yM7T19aAJt3zDJ4FDKc7lPzHmo1ZGUKQThsZFSnBI7YHrQxNj0YLwRgnqR2p8c7hMByN3VexxUAPy9Tml3nJwfvdj2pAh89vbXKbZIhC47p3qnJDLCw/eExAcHGauoDjGKcrMjcHB/SosUZ0N1ldirjB6EY/GrcBLkgyFf5Grq2ltqDYuQ5ZRkOpwKb/YdwrGSCcMi9FNFguMLhcg8euKQsP4XbbjtUCmYlxPGVKn5iOmKg1PUoNI083UrK7E4jQd/rVWuIXV9Qt9PRZbx93HyxrwT715zqN9eeI9Sby9xQ4Cg9BinXNze+I9Q86ZyEBx6BR6V0WnafHYxBAiZUZ355BPrW0YqKuSzP0/wr5aCaYCR152ZrQnMcAZSckgLtA+5WmouLzEGnxEyOR0PK5716x4a+GtkNLD6jk3EoyzAYx7c079STxaGyu7y4P2YDanWSWug0rwjaTyA310JJGALKRkV7DD4Q0azkMT2+GbowXOay9RtdM0m9mjtoUUQQlsHo+e31965qtWyGjkZPDWkQ3kNvAHBlUsMHIzj0/nV+TRJLW0MZLAQqCSvIjJPB+tbs3h2K/YXtmpWeMAoAenAOKdNNeTgWyqhaTBKkd+hya5faOxokYFnLdWdzCDcsGB2qT/ABk9TXR22t3csjWdwUUOcKQMk9s4rO1zw5eRWEshlVwihlZDyn0/His3wreLcz3BvXCskWImLYG7NYym29R20Oz1Vbe1tILdrkLIG3yMfTHp2+leBfEjxeNT1D7DYSsLaL7xU8Me9bHjbxVdqbq1FyxI4GDmvJ5FJBc5yT+dd2Fh9oizb9Bg5yScmhVLPgDkUgJ9ODW3o2ltNKs0i/KOcetdkpKKuXGDnIt6PpJEYuHHJ6CtgJiMAH5j/D6VKW8tQqAKOgxUZbAHy/N61wTnzvU74U7IZtJBKnheCPWoXO0lj0PSpicNkfiOxqF8Ett79j2rNGliN+D9ajbinv057Uw4IyelUJojIz3pjAYx3qTBxwBTcdcCquTYac7QT0pODTsYABo29f0pphYiZRng0hGRg9akIxjjmkwN1ICMjjAHNCjJII7VLjGTTRjJOeaYmM29u1Lsz3p/4UnQ9KLjsIIweM9aAhKucDIqRc4wR81KFJzx1obBIZ0bA6mnlCQQTyOtO2HHT8aApwM9Kgqw0Dkc0/YpcHJBHp0p2Ax5H5Uqrj/CkPYi8vk8cH0phiRvlO6rQXGD0pGzk9TVXsTa5nXOnebGTHjI6ZrFKNE5Vgc11ONzDLbT6VT1KzEkAdMbu+K6KVRNWZyTp7mED1qZCOM44PeoWBDYx09KljwMZBrdnM1Zo1dNt/NLNlSznHStVLQoGAErqeAq8EH39qs+AVhn1SG1nCnzWwCa9sh8BWS3AuJnQlh2PzYpWuTOVjw1raROJY2UnjIXNaNtYssZ2wPtbnOw5Ne6WfhDS725jk8hTDFxjsT710f/AAjekKgUWMWAMDArSxHNofOkdgsqAi3cIP4Sp5NTpbKMIYihB+7ivoX/AIRrSCP+PCL8qjfwpo0gwbOPOc5xzVJIT1Pnx4gCcgls9AcYpjMHkAYbMcc17xceAdDmcsYMN6g1Xk+HOjOuMSD6EUybHiLEI4/eDFIIJGRsOjA9ia9if4X6aSdsjAdsnNUZPhZFkiO4X2zTA8qMIIGWG5e3YUqxLLxhS3+wMV6XL8K5lU7bmM+nFUpPhrqyKQhDr7MBQI8/FpsDEkjHTPNILFceYDvHbiu2bwDrcHAthgf7Wap3HhHW15Fs34JRoC0ORktiyM2TuA4XHWoTZhWxNGF5BCtyprp5fDusRoS9rIR7Rmqv9j6n0Fm4wc5ZTmkO+pz/APZ0gJkEn3v4KrNZNuPB4966M6dqYcgWRJPRttUp7e7gJNzZ+WQPvHoaCrmNJbER8ld2OOOagaDEfzjkYrYIUqD6/wAJ7UPbfJjCHd71knoNMwpYN5ReWyelZeqQrFMBswo54rqltPLbcTk+nUfnWJrMIjAc5Kt19qncZzs4CJwMBuargDuavXyhoYtitwPmJHFU0XK5wM+5q1sOx6QrDO70HSpI2wAe1U1k5xjg1MHBHHasS7l0PkZ4pVclSc1WBBwe3epEcY2ikBYWQgdf4s4H0pTKGYEAjjnnrVYSbWLY/CgP3YYBFMC4sg3AgHGOKmjPzHcQMDNUY5OgPGRxT1cc9SdvNIEXQ4bBDnnpTw+4YAy3HHrVHzQMDgR56+5ra0e0JmeSXG3BC5osM0IIDb26cZVhn6U4A8upIHtViZiYmQYxt4x2qhdzyoEWADcF+Yn0pNaaCYXU1tZ2c810wwEI2nua8juvM1W6Ch2ID5QdQBWh401l571rGKbevBcqeM+lWdA00wxLOy/PtDYNWo2Vx3Lem6YlvbpEycSHLA9eKvxwJJMzBAx+7sHRj2/KpYjtmHnfM33ww6KPSuz+Hmgf2rq0l3PFi2jOcf3qpIhs6fwF4PjsLYX15ErXDqCOMfSuzvbwQbY0xuYZA7VcVFVQqjAAwAOwrOvLBJpkkJwoGM+hpT2JIhdNLqQt5EKspY5BHTHFcrf2D3d7NNMm0Slih7Htn9K6bVrEsvn252zDjv8ANUT6dayNbIZiEiTZtLdT/wDrrgqO7KWhV01xZaQs0IXyidoDdR2zXPanI1nqI8pyzNknB4Knv+daXiCI2EZiglKrMM7T0AHce9Yd5pTpYmYzuyoQQD94KR0/PmsHqrG0VcbdeIbu3sJ4ntgqSDJZzxjGP/r15x4h16G30RWRAJN/yFTjPGK1PE12bLRp5PMbbI6oodsnpzgV5Vqd+b2fYCfKToPetsNQvK72G9CrPdz3MxkmkLHPX2pjzOYwMjGKaRj5QOaVIjI6onJJwa9JWRHSyLelWAuZV3A7Qa7FYVhQKnAAxUdhYC2t4wE5IyTVor97jvXHVqXdjuo01FEJ+bHHSmN6k4FTFQAOKZt3AjPGaxOi3Yrtxuz0FR7QORUxBVhx8r/0prLQhWZA4OTxUR54A4qw64BJqOQBSuB1pgRcE0EZGMU4r83Sgjjrg+lFxMY4GAB+dAHAx+NOIzwTSgY6GrWxJEVHmH0pNvtUpznJFNKHrQFiIjHWkAHpUuOOelNGCcc0ANx04pwj5weO4pwUE4oOeDSGAAPOeelPGM47ikwOlPUcsO1JsEhCpzjPHpTtvbFPCcinkc4HWpuUQ7ewHNOC4PQ1KI2P1pCp3E5NFwIiOw6+lBTI+lPI+ccf40gXk4BpgMVV4JFSLCu1lI4PTNSRoMYIqTavQZx6mlG6ZLSscxqdn5LAoOOpxVA5we+eK6a+jaTIKjAGKwJoyjEEcdq7ac7o4atOzuOsLie0u1khkKPGQVNev+G/Hb3awpK5MzHZljXjozjp06mrtjctazwTq2CW5Ga1W5yzV0fXHhq9gNv9n85Cy8nJxmugBVgMHIry7ww9reWUGowPvTaA+D0Nd/pl0tw7BGyoUYHpWrMl2NUUUDpzS1KNEIaTnFLS0xWG/lRj2FO5ooYWGkfSk2jHOKfgUYFILDFUA56UbQe350/AoouwsMKjuBj6Uw28J4MSH6ipjSYp3YWK/wBjgPBgi2joAtU77QdO1CIpcWkTccccitQUh9jRdhY4K9+GWmXAzGdhPcCsJ/hQ4c7J+M8V6rNKkKFmPy1Rl1EIAIgGz71nsKzPKW+GF6s/DkEnAYmsrxL8K9RjsiVdJAOWJHIr3WOUtCXPJx0NYHiHWBb6NOZk5AOPfipTSGmfLOo+HbmxmWB4yZP4gOntWLqUPkyCJkVGArrvEOsSm1mkeRTNMcJg8qB3rhnczHfK7F/U81aKud2pO7pUqyAHBFVUkbGcU4vjmsikXQ+BxSiQkA8Aj0qqZQGAzxjrSmRfM+Q5U+tAyx5gw/rineZuXd/eTGPeqvmgEAYODzn19KfvChM+uab2C5YMmVApyyKM5JqmZlGBk460wykPhj1PYdqQI0Y0N2BDACWLqWFd/FbpBBtXoFHXrmuZ8IWJaJr1sE8gD0rqDklN4PPUigLkewuQCcADFc14u1YaZo8jRkC4YbR7g8V0O8RSyPKfkC7uO1eOeI9Uk1vXJIoyWiViFFNK5LZW8PaedQ1Bpp1LRjqT6mvQoEEAj2ruC5UHpx0rJ03T/sFhAuP3h6+5rXc4ikY5JIwD0xxVSd7WH0Fhhe+nWBRgswTA9Ca+gPDujx6LpMFqgG4Lycc1454Es/tmswOwyqgZPuDXvOOc+opojcME0jjgZHA60cgVDcy+XbuxPQd6UmktQRn3sx/tG1i37SNzEfyrDsrqSLULgSx74y7MpIzgjqKvzzebrkBJ/wCWBOP5fjWZaR3E1xfwr8v3ijHqCa86d2wJNSc3t7bmSI+SoGeM4561S1R4Ll7l45M7RtXB4IAqtd6hf29+9iHDmRNgz7jBrDv7G70m7uUE+9IoPNOeh7VFtTWMjyv4iar52qmwtmzFBgsfQkVxSDG49eRye/FXL+d7rUbuZySZGIOPTNVgCE245Jr04JRjZDvdkTkk8VveHtP8243sPzrISMtIFC5xXofhqy2RozRj5hyKmpKysjWEdb9Ce6tZIUznAxVMBhkdu9dTf2pa1bdgLjg965+a2MMyKrblI5Jrhlud61KpAxgA/jTCpx0q26fMR27UzbkYHbrSLjdblRgVAGM/0qNl2nd6Grezgk1DIPlbjoMGmg1KpQR4Gc9+aYUO0exzzU8ijDntgc0xs8f7Qo6iZXBJU88/5xTCSQOlTYAYnHWmHBPTH0pksaQcZ4pQM0g460KaqJINgHGKaQetOJO7tTTnPWmMQ4oUZ5o6mlGVBoELgEjFBAFItLkHNIYwgk8VNCmN+480AADNKhyxODzUjRKBg08KOtRF+c9KfvAJGT1xUjHjPQdTRjHH8XehW4zjkdKUN8545x1oBjSoPUc0KuDxTj93PYdaeo7H8KBrYciU4pgnPTFKi8dealIDflTurCKD2/mRHDEdx+FYOo25WNped7HoegrpZEGMDI4xkVnajBvXIB4XGP61pSlZmNWNznUyflJ6jmp0xtRSoGMgn8KRk28gZB4zTYwcnPGQa7VJWZ58o2O58B+KJtIufsUsmLRhuBPTNfQHg2b7TYy3HeRt24dCPavk6N3W2VyeR0Ht0r6V+FOp/bvDkMW4fu0AAFdC1gc9rM9FXpS4pEzinVmWhBS0UUxhSUtFACYoxS0UCExRS0UAJSdqUmkpPQL9BKZISEYgZIGakHI5pPXNG24O70OSvf7TvrkfuyqKeMdMVpWOnukJSRc7mznHStnAxSgEAc1L11M0tTNv5ZLW0drfBZFIwa8Q8d+ILqa2KGQ72O1lU9K9z1S3e4s3ij+83evHtf0W3sIrt5QPPIJG7nH0rlqXTLijw6/heeYgsWI6e1Z21lJUjpXT6xi3YGRMTgDoOua5190jGU/KorpjsWdV8y8liBSBjlecjPNcsup3Kj7+frU41y5AA4NLkYkzod75JI79DTlkcEcAY6D1rAGvSEYZKcNdORlOlHIyrm80jbuMbvvEUec5AJ6D0rFXW4i5LKeacdYhC5GfpQ4sLo1vNfCnHIp9p5l3dJboDuY/nzWX/als0YO/Bra8K3dnJqSTTTqu096n3kNNHqVpZx6fbrFGnylRwKcoYOOp+bv0xSvqNhOFK3SDj+8KbHJAXGZ0ZQQT83apd7ktnN+ONT/srQpBkCaThcehrzXwvaifUHuJs4X9Sa2fiXq4vdaW0jIZLcdQeDmn+GbYxaaqxou+RQzE+ua1StERtGUAKTk7X4H9KfNKRHIiA+2ajmQ4zGD1BwKsabbvd6hDbckyPnJ7c81mUep/DzSorHTPtcy/O43L+NeiIQVUjkY61zVkYLO3ghBAaNcH0I7Vdj1Mxj7u4kcYqkzNPc1ZHUHJbGBj86x7yb7QJCCxjZfLIHr61fEizwmXb823IGfSskXN5HbuDbhRnIYiom9BIoyqYtbtHYnAtxkk4yR0q1pslvF9pedyHklYKT6AVzGu3k3nwXU7LwrL8vTiobTXL5Y18+yEsW7cSByQPSuVuxV7EOrKyeKoFEjYwC5B6AmruuWZmS7eJt4MBjU56iso31nc3K3MUwSUlmdH7L6Viv4rETTQMSqEFgCeoqYrmY47njEgKXF0h42OVJH1qMK0mAD8x4q1qDxNPcToeZJSSP1qC2GZFOfeu7pc0jvY1dOtA8qoPmI6kV6boVjs2DPRa4bQLYPdIScBuK9E0pTtY5O3oDXPNu51RVi5dWyqu1sMNvJPY1zUyF3YYAI7V1F0oCPk8Y61zdzGElLA8Gsp7nTFmftJypA+ophAwQB+NTuoB4qE4AJJqTVsrSYK4xUDkmVk6Dbx7mrUoAXnv0NUmysmM0kK5G7Devp3FRM2N2R9PanPySTUbYK5p9RNkRJLcCmtw1KxOTio2Jypq0hPYcxC9+aapOM0juc9KaM7c5oWjJHkg8dvWkweo6UgBJwDTznGBTsK43HGc0ZJGBRn16d6AeD6UWATJUj0pcjnimmgnAHFDWhRMCMdKFbnrTByetKMZxmpsO9iTk5yfpT8/KTjvmotvI5p27GR60guShtw4PHenKfmJ7YqFW2jGKejHceOMUmNllRlBnt29akUZZgOc9PaoF3FRgc96nDdsUFR2JljwMEc+tPK7TSLjauRzSlWz1pANMYIPGaqyqrBhjqMVdIGM55wRiqlwMMhB2jFHXQhq5z91AIk5PyZ61S25YkdO1a9yFYvlCRnv2rLKbZNo5BPWu2DvE86qrMc3EQVfpXsfwW1Ew3klkW+UjjNeNgYyD0xxXdfDm8eDWrVkOCx59664O8Dlkj6hU8e460/IqGE5iU9yoNSnrSGhaKO9FMYUUUUAFFFFACZGetIx4z2oA5pCPlJpXACelQPcoj7Ry3pT5VMiZBwaprYnzA7OSamVyXoywJnkkwg4qUEhSXYU2CPyuOuTROheJgOvalIL6FC91P7OcR4JHWs6PX5jLgoCB6VJNZOvnSyDOF4Fc7KH06zmnB3M3UelZqVkRc7mC7SdQen1Ncx4rGkW0DXN9GshJOEHU8VY0O8ja0R55EBIyDXAeNfEMVtO6AJcHfjB6CsqkknqaQPLPEtrcS3El80WIScA44x2rk7hQ8nlqfl6nFdl4s1eS4gWAP+6PO1egrjPKMcJk3fNnvW0HoUzNooorYkKTNLSYpjDNKDSUooAXNKrspyrEfQ02kpAWkvbheRM/8A31Vldav4+VupAcY+92rOpeOwpWQIlkleeRpJGLO3Ukdat22q3lthY5ytUVz6nFOVctnJpMLGyNfv1x++yfWrtl4rvrC5S4RgWU+nSsBmwAAelML5GNxzUWuUz1K3+LVzgNKqudoUjFdrYfF3RYbaHzIiz4+b2r51+YH8c8U4b2JAOBRyCsfUFr8W9AlkIceWorZHxH8OXlpIq3QAxjGea+Rdj4LbyMdjUhkmjBCyEZ9DUyp3FY+ndUvtH1CwfyruPYqNgE8knvVOPxBJbpApMZSMcYxXztHfXIOTPJ16Bq1bTXbxJVDTOUHrWEqNmPlueya9pGn6jp0t1azIlyRuKg4yO4rhNTeJY4pnALeWUAznA960tC1Sx1F4Y33CTkHJ4Pp+tVvEenraRSEgfM/zH0PpUJWKSsed3q7WEaggsdwJ70+3jIweN3THpVnVpA2oLGEwIlxj+tV4B86AH5i2D9K6b+6aRWp2Xh6IKVB54yD713unbltCrAYz3rhdEZQy8kKOK7a0k/dgEHHf2rmb1OmK0LN0waI5Jx3rBnbO4hRhcYrbfHlNWHMQN+7oazkzaJTb5lDHqRyKqnBjIxzmpJThVwfXiq7SDvkdsVGpoNfLDBORVOQYck1b657envVaXIzkcjtVqIIqnIBNMY8CpXHzFcUxlGE9SenpTasJsgYYJFRNwetTOR1zz6VAynk+lUtguIzEjFIOlBJ2g460g4FFhMAOeKcQQMg80zIz1oz780Ei8+vNAOAc0obkDv60pAIoAb1Oe1PNIFXFAA6UwFA5FKo5yaOnvT8YPsR1pDTEJI6DOaeQc00MMjOc9MVIuM43fjUuwCduRShuQeQKXaSCO/oaaHXABYA96n0HdE4YAg9c1L93Bqg15EOVfNWILpJRw2aLMd0y4hJINTjqRmo4kIQH1qTaF5PepuO4YAPJqOZSQCOcetPJU9KCpYYob1B7mbcDcjhzweprDb5WIXkA1t3q+WGHUGsaXAb5Tj2IrrovU4q6GFgZSGGF6Z9Diu0+HUQudbtQPvKduPxrim+Ziv8Ae/T3rvPhZIg8UQbsA5xXZSfuM4Z7H05ECIkGOiipSORUadPYgYp+eabBMWiiihDCiiimAUUUUAJTTTuvFNNKwgNJ+FKaq3Mnl4+YgHvionoJlgnHXgetRLN5kjKOg71CrLNHtD4ycfWo/s7RkbZSGNZzkxC3cEssTbGySOmK5TUIZYbG5DxtuI/KtldVlineNyWCnn2rUjePULYl0BDcGs07xBJHAWDxLZRRlgWJwyk9K4PxpHFFdm3HIJyTnOa9K1vww63jSWYwjDjA715trml3Ueq+XJCzSMuQCc4rGe44/EeX6tKgkaJMnb3NZDOWXBJIrd162NpPMJtodm6DqKwQd3QV1w2Le5VopaMVuISilIoxQAlKKTjNKcdqAEpQKMU5RSAaRzTh3o4p6qCaTYDwg2D3p4G0dqeqDZ17VAclsVIx5OTjFM4ycj6Ud6a3Jphe445HU8+tEeSeuAKYeR1p8RIDDHUUCHFwQcHrSMwJOaiIAAB60vHagZIh2jirUJyMAcAcnPSqecCpoMlsA8E4P0qZK47mxZXstlcQvESCOSP5Gu21vUxrWgiRI9kikO3+1xjNeeFwBlgchsDHoOtdTo9ysmjXkbyDzNvCnsvaseUtM5W8maS5kY/fJAJH0qazI88sB0Xge9Upn3zyHtu61ftVUBCvXNaP4S4anZaKrYQEdg3FdvHIrlVX+NNze2PWuI0mJ3hA3EY5JFdhH97eOF8sAD1NccjqjsWJiwiLL1PGK5zUZcP5RJBzW+ZMIRjP41z94nmzE45BzWfQ1RmvI4zgnI457VW812QgnB9asSzxQlmd8E84HeqMl9AV3CQ59MVSRTaRaWTau5vwqKTJ+Y8561CL+Lbw2w+pHWo3vo2QqDyTnNCRPMTTHDSEdgKiYfMD6DionuVIzkfNSNKNmQwyGqmh8wpwOcc1Hzk9KTzDkv2PShsNgg/Wn0shXGupIxim8KMHrUpxnrxUbAFqNREPIPakOQak2DNAQetFhXGqT1NOHFOCDPtTVYZIKmiwCgdzTqYX2sFP3SKb5mTggZHcmjfQZKDgZNMLgJgn3zVZ7hRkjbhUyOarT3u0jDAgpVqDZDmkXmuQrKxYYXqDUb36KGwQuT1zWJLclhyeagaRj3rWNHuZSrGxJrUjgKQNq9D3qv8A2k5fk9Qeazt3rTlx1Naezj2M3VbLizsV4JFTwXDocg9O1UkdFHJ4z0qYSx5bnFTKA41LHUafqys6iXoK2sAgOo3KemK4FJ02/ewa6DR9XRNsM8n7sdDmuWpSfQ6YVE9zaYEckUhJK4PQ1KWWQExzLtPQCmsrbRwcetc9tbGjknYo3cRMBcAZWsK4CifGeoziulnAEW3rnrXOXir57HoRXTTbTOfELQqPlcYAyTXR+Dbk2/iK2cZUlgSa5zIYZx2rQ0mQxXsMq5DBgTXfTVlY8+ex9i2j+bbRN6qD+lTjrWL4YvVvdEtXDZIQA1tA8mmyY7C9qPSlooRQUUUUwCiiigBM80UnekyQagQtUdQtXuoiqOVNXWIFQPcxoMH+dTITOJubDW7KUuhZkzwAelT22pNDZO92ZFlUcA+tdijpIuQMj3qOa0t50ZXiQgjHSplZktHCwavLcz7Nn3u+OtdVpMjmDy2GMc1OdFswSyRBWxgEU6Ow8rlXI9qiUbLQEhJJGjywAPXOfSuG1m1nn1lbzaogC7c98+ldtcWbEkxMeB0J/Gua1XT5jbubiXZGmWGD3xXNPcuF+Y+c/HdskWtzkE/MfWuWReOK6jxtqCXerbEAwowWHeubkULboByx7V2Q+EqW5Q57ig0tBrcQelByO9HpQaTE9xMGlxRRmgBRRzTh0pcUhoZipowM0zFSoMcmkBMM+X1qtn5j9e1TkhUqvxk9qQCkHg0xutOyfrTSec4pgJxTlJXoe1N3+1ICaYhcA0tN3UuRSGL1qW3OGIz1qLjt3qaENvHFJ7FaMtk7gxzzjj3NalnETbMYvvvGQ6+mBk/nWar7SCAOQR+dbGmownkA4XyiWJ+lZjObiBKkY6nJrW08fPgjp0+tZkDASuf4cnA9q0bY7ZUOeW4xTm7FU3qd1oYZojwM9z3rqQuEPGcKOvFc7o0YigDOQqt/ET0rVvPEei2KP5l0sjKACB3Nckk29EdqdiaQLCpIcknuD+lY17dQ2sbu7YbkbaxtV8fxSIVsrYBugz0xXG3upX19KZHZgCeAKuNG+5Lq2NW+1COWbIfp0rMnvRyEO0+tUHjk3ck/jTfJcjJBraNOKMnUkyc3jjo5/OmfbZAchjTRaNjOaaYCO1XaBn7Vkv26XA+Y8dKmj1F+dxzVTyGK5x7YpvlspPFPlix+1Zqx6oOA3IHSpotQjYnnbnrWGB82KUKTyO1S6USlWOlW8hCjnOKmSZGdSwXY3oea5YtIhIB/KhbmSPoxBHSodG+zLVbudfiPJwfxprbD0HbrXNDVJlBBOc1JHrUycAfnU+wZX1hHQOAF6cY5qHcjOwLBQO5NYE2qXEr7txXjHFQG4kdSpY4FCoPdsTrm1PeQqmCxJz2qlLfuzfu84xjmoYbUyruYnFSm1xjnp2NaWiiHUbK2ZCOuBTWQ85OfSrhg29RkU9IUwQ4wD0NHOQ22UBb5bBJqzHp6sOSavpsxhV47ZqTpgnAH86TqMSjcpDToSOp4708afb8/T1qcyosZyeM00TwFtpZsn2ocpPYrkGHTbXbwHz6jpS/2XAQCWarAZSQEY4HbNSH2BBqed9ylTuZ/9kqxOJB+NI2jzgEo24jp6GtAhSR1z3qazuRAzDO5H42ntT9oNwsYAu7q2fb5jqw4wTVuLX9QTgTHAqxr9vC0SXETDpgisEHGeB0rRRjJXsQ5uLSPTpdPuRodvqsZOyUAupHK1zN4N8jOBhu69sV6v4QW31TwZbQTfMJFCMcdCK4Lxj4budBuSdjNbPnbKK5+WzuU6vMmclkkjP3e2K0LMlGBHJbistZVO1fU/lV+2k27WIICsK64X0Ryz2PqT4dQyReGoXlPLAYrsBgE1yPw8vY7zwrbiNslAAc11/eqluRF6C5paaaXtQhoWiikzTGLRRmjNADR61BJOivtJwffpViopYlkUhhmoYmZ2o3csI+VlxjOa5eXVLiadsYMSnkqea6LUdOuJIW8mU56bR6Vw+r6XqtqhZUIVjklahptmcnqdXFq8y6eZoVXbjjNJF4mb7MCY9z4yeDXHWHiC5iVLFwnPBLU2+1bbOIEzuUZbaeKTiyeY6xfGUbylQB8vUEEYNblrq9pdxqRMgduNteVWsguZCy9Q/PoauTzTwyM9u+3acjArTlbQ1I7rUriTTN0xYmNj27V55408UzzQJHbBgGbBb1ruNEv08QaS9vcgFwuOeua4vW7KKBZrWUBnif5cVy1oWZpTleR41faeUu2knCgsd2DXNzsXmldThUOAK3fFV7LJfNztMeVIFc6uGjYsTg81tT2LluVwaCRigUjVuIUkZopKB0pMTAHmlPNNH3qkxikAoHApQM0gGcClHt070gQoFPBxzSDI5zxSn2pDFYjGahJGakYkDgVGRzTAFprZyacOKYx5piAH2pAeaTNApgFKPejJNHNAC8EirKHkDPaq6jPerMWSuSKiWxSJkDFTzxtNaUNyojugobf5IQHt6ms/ac555GMetdB4etopnuUbDbkK4P8PFR0KOVgfZzjNatpmdJplH+qGfpWeyLHvi4+WQgN64rd8Np5sOpKQADEcFvXFVZMadjFk1m9dAnnuFHAANT6HptxrmoJbRknJyxNY55APfvXqHwss43ea4ZeexoqWhG6KjJuRbk8FWGjxx+aoeZhyXPArmtVjhS6Mdts2KcZA4ruPGNyYsvIcYG8fWvNHvly3BII5J71yqUmdMkh82Nu4hT64FVSCvIwVPb0oe6ztwQFxwBUBnAYnNWrkOxNsHek2jPC1ALg9/wppuXXoeBTszN2LyQB15GDmmGIYKgZ96Ir8LEG28jrmovtSlVAUgL6GjlkLQabdeuKYbfAIAqRbhck1Lu3nGKeqHZFfyUycDtUd5aBIlkHfrV5AOMDvzTL/AhIA4qoSbYNKxiE80AZ5pwQlsDqa0rXTNwJlYqCMgDvWzaRkotsyz1qSBN8qr6mrN1aLCSEJNQwqVdSD0NLmTQmnc6MW0ccITHIGTUDRqWyAcVZ8zMYbHykdfeoskL754rld7nS7JIiC5PA6etV3n2oUTBOefapJA5TjqQKq+W2Mbec96pEtoDIxGM8CkBZgQuSasx2oCF5TwOwqnJMfmMQ2gdPWqSuTexP+8wEMeaAxTO8BcditVEupFcHd9a6zS44tTjO9AXI6USXKrjUrmFC6OwUErV8AqwUE/UdaTV9BudMdZ1HyNzkfw0lo4lUFz8w9O/vWc9k0bR0Rfhtkl6Fs96iew8pgyt8uTxVvTEDiVwSoHX3q8yhySFzisG2act1c5fUMNYsnpzWAFO8EcnFddq9mRYPLgLlsYrJ0TTjdSu+MhTxXXSlaOpzVI3qJHrvw2vYJvD6WolUTA/NFXbX2mQarYSWl3DujIwCecV4JFFfaZd+ZbSmJh0CdDXfeGviV5QS11ccDgSCom01oT7NqJwvi/wZP4cvWliPmWjE7T6VjI4eLcvykYAz619Cz/2V4js1VSlwjg8Z6V4f4n0c6JrMtsoHkscoa3hL3kZTVonuHwaui2jvEW3V6sK8M+Cl62ZYsZHrXuY6kd61kZRWgHrSjpSGlHSpRS3Foopp602NjsUYpO9FK4rhTTTqac5pANJBNVbie1UGOd02nsattkD9frXl/i/V3t9SlVCdue54WqijOWx0mseErHVITPZlEn/gcV5/Np9xouoOt/E3zA/P/CcUuleKr6yu1O6R/mzg/drvFurHxhpDRFF+044Ddj7VbgZ3R58qG2thOH2xtzgdDk0jX07J5cbgD1qpqMT2aS6Zdq2I3J4HbtTDJFHBCqb+BwxHWiKsxG94K1Ke0154ydyScEdh71j/ABL1kWF8I7JibiQ5Zz0FXfDiST63ATG0as2CazviVp0cXiLCMJPkztb1rGva5dN2keT3ts080rTthm5Df3j6VkANCjIcHjArX1m5CuY14lAw2OwrFRiWLO3I/pShsdD3IM0Y9aAAelBrQQY4o6UppMUCYmeelOzmgClPFDAOcU4N7UmcjFIDjoaQIcc+9BbpTc570HPHNIB+TSHmm8nvS5PSgY1uKaSacQTTTwaYhM0lKaKYCUooooAVRzV2LPlHPXPFU0+8B61bOPMQIMDocnvUyGty0eYwQTkcfQd66Xw7aXdwsQtYgSzFd57nHeuaRiYeDwDyAPzrtPCOqR2F4plH+jkFlHvioLaOE1K3ls9SurecbZFc5GO9dbp8EeleE/tMwzJMCefTGMVj+IpV1XxjcyFSizSLgEYzgYq/4t1BVs7fTogAAAeO2BjFXuJaHG98Y4PSvRvAGpJZaZOCcMOnNedHPGD0rX0p38pkiJLEgYHvUVVeJpDSR0/iHWn1JpU3EkcKMVyRR8kFTk11dnodxL80iHaBljVW8tEhBCD2yfSuaM0lY6pI5tugGMHofemshUAsa1ljgjmVmGVHJ3daz0Q32oqkY++5AB9K2i7mUtCGOKWdiYkyuM802eI20hSQ84B4NelWnhSBdPOLtI5NhyCMf55rzfUoXi1B0eQSENtJqoS5mYydi7ZtA1spkUMmecjvV029tcQ+bAFyTyMVQe38i1t/3mUkJOB+tS6dL5FwF4CMfWlIw59SOW3RWKvwfUUgQKMqT9TVu+2tO2F2qBnd2NVlfK5yDnpU9C1O7G+YUdsDJHpSXUm62bKnNKVy5I4yOlRXbbYSPWiPxG3QowD96OOc1vxKQqj1GCTWRp8BluF9M81vSQrEchyVPY06kveLpxKVzHvkORuAHUcVj5Idhjqa6DbvJAI981k6jbCGUFB8popvox1YWV0aVnIHsFjZuVJLf0pzbc7g2cisyzk2lgOd2BWh0DYXoMj6UpK1yL8wpKqOT14pAU25J3Go2PI4OSM+wpyAOwGCd1ShJXHXTn7EzKQCT2rPt2jSPdIMkmrbW7Fdqg8npSW1sHDq4zjt6VSkkTysymCs7lPu54ruvC1zp1n5U0kwBRSHB7ZHFct9hXI7DnOKkSEBto6EAkevNFSSkrGkYHTa9rcOouIIFbyxwSTwTWNaQtBG2V4PerdnYxvC8xc7s9BVtrIqpy2MjIB61hzW0OpR0G253ouMgD04rUhBPHTK5P1rMhjKDhuK07cgg7mG7IrJvUcTO8RELo57k4yaq+GEAsGYcZbr7Vc8UMi6MAo+82Kk8P2yrpELHowzWt7UmZpe/cmZM59CcVm6nZqbbcqY2ntW2V2kqB3qK4QOjoQT34HHSoUnojacU00cnp/iDUNHuVe1lZQDypPB9q6C71qLxRE8kyLHchMBO/HeuUvV2XDDj5SeMVPo8wtNRV3UfNGcnHWu6GtmefUWlj3j4K2sUVnMSoL564r2AE15P8K72wsNHZrieKGVz0ZsV6THrWmu21LyIknGN1bSWpzxTTsXz1pw6UxZFkUMpyPUU8UkOzTFpp606mtwc0MbA0c0uciopQzRHYcH1qRDi+PSgnPfFcvf2OqqxkjlLjqCDWDcapriHYWkyOBgU01YjmaZ2moXilPLVseprir/AEm3vLqZZQXjZvvdTTS2tiFndGIIzyKyPt10s7kwSlyc7gSP0pKVmZSlcyLuOW0byUgZlUkK2O1P8OanPpmrxzOrJGDjp1Bro7HWIYmBu4N45ypX1retNK0rV4hKkJWTtgdK2VTQzszL8bW8Usdpq0MfyMuGJH86xo7+2mEAFtGSDgjHQYr0S70dbnQ3sW+Y7flzyBWDa+C8QsQ4VwRg461nz2LsypYEvfRiGFQQ3ygCuQ+JySQXolmCiZh1HYV6dpukT2lypk2kBuGA5rgPihZ3FxqaKqb8jJPtWFV3RpSj72p8/wB+S1yzk5B61VjAbnFXtTA+3yRqvCEjHuKqIfkzwOaqOx0NalXPzcUGlFGK0M7iHqKXGDilxxSGgAFHWkwDSEcgCmMdikA680EYxg9KByx+lFhoM9qXPFIKKViRwoJ6008UUWKE6c96dnIpKD0piGr1pO9L/DSYpjFFFJRSESRECVc+tWByyHHc1VU4bNWEmO8cd6TAtIxWEIOGYnJ9R6V3XhSCFruziliD7sYB7VwzYNyMD0/GvT/AVujavZyzDciShD/sjOanS5VnYb8SfA15o10uu28atbkKQoH3a8qkea+und2JOS30r7a1axtr/R7iCZY2ieJlBPIXIODXxdcW5sdXvLXOfLlZcjvg1T0Vwim3qdFoPhoXlpMWQFyhZc9qXwNaIfEUtrMBlc4+orrvAqK9v8w6iuduIzoXxDJUYjmcEH/ern5rpo6XG1j0EaekJCeY/wA4PGOK4nVIl+2SpwY1Y4PrXf3MxiVJAcuy5H0Nclf2kb3EpH3ScmuO9joscBeRvNMyKhDE4+lWrDTJ7F47pU3yIeldfpljbSS+ewBBbGKL5YYpTswoPbPWtvaOwOKZzWo63fXUIWXCKOAE4PWuYeB5ZZWIbOc5Ndddw23lSSA8g4H41jlVIOP4elXCXKZTgmilHESsccjEhM8fjWlaWFtOzbpCuzmqjYHOeepp3m8DYapts5pUTSudLtnt5XF3vdUJVB04rNFuPKjIAyvXFW7ayNzZzzwvgpgAH+Kr9r4fuJFB89RkdB/DSvZamajYxGX5ycfSqd8pEXzferrdQ8Oy2enyXXmoWHOM/erlSj397HEoI5AKgdKqGrub2ujS0Sxf7KJsDDMQPyq1cKR8mQSBWnFbrbxJEo+UdaoX6gTEp0rKcryudcIWKaoeN2OafPaLc25QfeFIwwMnvU8Z+Xg1N7O5o0rnMrC0F1scEAGtRCGAyTydtSanatLAsifeQkmqFvMfKweWBORW7fOrnHKPKzRSLzFZgenrTAMKTnlcdK09KaJrYqQCx/h9KvCO2bh4wCTvNZ3sSk0c2WZLgqGwBzzUwbY6jb9/OT61qa1Z2DQRT26/vAcNzWcykRhCR8nSldDSIfk34Gc80bS6nsQv9abjCqe9PUjilr0N43saWmubeBkYgkngntV+SVpF+cgsOhFZCSgx4AGc1ZjuHUFDg81DT3Zorotp0welPhfy8kfmfaqyzE5wPmFWAwjiZ3YJtHzE/wAVQld6DV0Z3iW4LiCBiCD83Fb9tGLa1hgXoEBrkHmXUtWQKp2LjH4V1+8uV+XoAAauppFRFFXZJgkYJp8a435OeD/KmpnncOKcv3TyQR94+o9KzfxJmj7nC6zH5V0z9m4qvau5CkqMgYGa1fFMKfayYs7WUfL6e9R6BZm8cbm/cx8bvWu2E/c5jjcbzuWrGK5UKUmk2/7R4H0rUfUJ7aRGS8beD03Uk7wbzDGfunafpWPcqTclsAkNwDQq12dEaMeW/U+gvht4qfUYVtbhyzgcEmvSQeB718xeE9a/s29gnB2jfhxn8q+ktPulvLKGZWDBlByK3TuefWg4suUh5FJS4qjG4187Dt69qyxJe+aygcZrWI4ppHHy1DQyoZp1A3JuP+z0qNnUDfJbqfU46U2dmS6WNjtUjqKxdQnmkmaJJGKgcqO9YttOxnd3NK51JVICBXUdR6UjPYInntbqSw9K4W+uNSiux5aHaMAD0HpRNrd+I9ko8sbhtA60Xb2Ivqdqul6Zqa+YsSAjqBUEmjPaSA2RZR1OOlYGg+IGguXibBfvXRjxND8wKZI7CqV+pWhswMy2iGQ7SB82az7++miCPGv7vdyaluL5X0ZrkLwVz9KpopvtKUocAsCc/SlU7j0NGC+8+QJjnr+lcR8SJBaQpJGpaaTgDvjFdJZs0OpxQkDCjGQa5/xG8Z10tc/MsYO0Gs6l2i6b1ufO+qwJpdzLO0e6SXJKP1XPeueRizMzKFBOa6fxxOk/iO58pg0aAbQO1c1EQtnITg7jwK2p/DqaPcqAHvRRk5pT+lamQlJmlz70lAwAycGkPX6Uv86T+ZoAOlGO/el4opghooJwadSEHNBVgHNAxkigcUuRj3oATvQeCQKXg896QgbaYhDyKbnml7Ug60DClpKWkIO1Pjba4J7c0zsaUZzz6UAbVtEZ9TgQfx4xXpQtzpWilRL5c8pDA554rh/CVuL7xJaIw+6pYD1wM1veLLwy3syqxURIAMdAetc8pWZ3YelzK7Ld5458TWds1oly5Tuw5z7V5800lxqElzMP3kpLN9a1bTUJLgGGVsjqD68VmKC8jEjGGOKbloEqaT0PVfAIAtdr4HHBrH+JFu6Pa36DBX5TitXwV/yDg7HkHOK19d0tNZ0ue2J+cjcjY61gpe8O10M0O8j1XQbe4Uh2jiCsO9ZFy4847R97OQa43R9avvCV9La3MbGIHaVPTFbx17TL2Qzq4Ryc7SaVSlroXB6aj4maFSoONrAjHesrU5XfLEkleB+NaC3loCf9IRuc9az7i4t5DIwlTB4HNRGMl0KujGd5BgMeBwPeoH3FlAxn2rTFvEyBjPH+dRyJboMiZGZfetEn2IdjLKkkgg4705YDgDkelTm4tP7+GBycd6YdQtgCMk5P5VVpEOxo2AMESwnJG/J9qvy3MthE5C5UjGPWsH+2dqlYYjuJ6moJrq/vn2yMQnt2odNvdkOJp3esfaVIfcpA4QmpPD1oUEtzIpEjHjPesmO2Bu03SeYOOvau0jt/Lhjx2HBpylZWRpCNyEsXmXtu61n3yDcfnxjitAfNJk8EZrPuuchhzmsU7nVoym3zALjIHenR8VGwAyRmlTJPWk1fUaWpZVTzwCG6g1jX9hJbziWNTsc8YrdiyoBPQ8Zp9xtSNN2Dg/KD3zWkZcpnUppnPQXTWTAuCGPerb6nG+WDngACpbpI5dgKgj1qgLCJ0B3YOeRVJxZj7OxP9uTaRvyD2Pal+0wySku4HFVzpcZXIkOfSmrpaspPmHNO0BWfYna4thxv6dKYbmAMNrjn1po0kZyZDipY9GiGS8n0oagVaXQha8ijwd2ee1Sf2tEOUQ7qtJo9qjbnOR6Yq6un2CgH7P16Gpbpoq0jIGryEHbD170zF7fOsbFgD0HYV0MVnbq3EKgVPsjjkDKvBHJA6UnUil7qKUJPcrabpcdhiVyGkA6dq1lLbTjp1zVSBCQ248Z4z3q2ApyDxxxXPOTkzRRsTRZKEk9ak6xkZOOfw4psCqI8d6mUEsemCcEenFLqNnJ+IQWuEccnbg47iodDka30+fHIY8D0q/4gQrhAQGQfeqroyiTT5sH94x4HrW8G/ZmXKrlmBFeYN0LYzmq+tQhLwbRkD0q4iPsAIAI4qvqeSdwzxwTRFo1StqRWEpCMD65Ge1e5fC7xZFc2y6ZPIfOHQnvXgEcoXoeM/N74rqvDWoPaajbXEZ2kMOlbQnY58RDmjc+pweSB2pc8jniqenTm40+3lJ5ZASafczmJOMZrZzPNloyznnHFITx6ViTXlwp3A59hRPfztZyOo5x8tClcnmG69PHEYz5gDDsDXMzeI4LW7V2G4r196oXdzcyO812GI6D61ysU7iaaSZCUBO3PanGN2ZX1OzuvE9hcszxx4ZsZB7e9Y+sOz6a88JBYvww7UaXZ2V/pFzPKv71eVI4qpNfj7J9naInPK46U4rlZAywCQSW95LJt4/eDvUl9r8YuQLQ/LI3PqBTILeF8bnBbPAPcUlzZW8U6SKFI3Dp2qnFS1A9MG0+E0cnaDFk+9c8uueXCI4H4+7+lbt6NvhBEzgeUM1zNtY6fLZFvNHmE4IBxjispRuUavh6d5tZIdyxOCKwPG12YdTnTYWdshQOuT0rc8J23k6tISdwAwhz2qPxXpgV5dVcgtEeh7VNTSJrTPm7XITZ3MvnDM0g5B7ZrG8jNuuwcg11/iKwlv9ZecxsFdQ2T0xXOSDyjsUgjpTg9DZmQOvNBpvel6jmtrGQp9aTrR2pMkcUbDFwM0h4GaXvQRxTAOOKMUY4FGcUhpAAM9KU57mkByaMc0xhRx3o5BpO9AAQCQR+NIwHalz0pDQAnOKQdaWkHWgAFLSdqOxpCF7VLAu+ZFx7VEOlWrFC1wDjjBoew0j0DwZZC0trnU2ADLhUJ/WsXW7kTyzuGPzNyPWugkH2PwFaqpIabkkexzXGXMhmbceMnmuO95HtUI2pjrGAzGTGcqv8APioyu24+zjJZTt/DvWtoNuZPMRefMIAP41HLYvb6pdBuSDgn0zTTV2YyjeTO98Fgvpkhx9zjA74710cJYMhzuyOB6VyPgeV0guCM+WpwD611UEqrcITwG7+lYy0JS6GR4g0+zv8AaLmFSzdCo5rkrjwbaO2YpSma7rUoxLO0iHIzkAVjSKWxgEEHJpqbQ+U5STwWyji6z7VTuPCdzBJtaYdMg+1dwsbl+enr6VRlgfe4aUuD+lUqjGoI46Pw5K3HngU7/hGHOc3A4610c1qtsXcvlWUAY7VWbKMQrZHr60KtITpoxD4cjHBmB+lKNJtoF+YbvetB2YvxjrVeRzt5Pej2kieRXITHDGQqRcepqtLIw3AYAINSyysSOapTOTJgEVSbY7WJ7FBLdKFJLAV3sEYeyjLdVHNcXoCFp2fA49q7GxYMjqSTntUT0ZULcpQuFRZsoSBWVdEbzzkVrsN8jpn5lY8fhWPd5Lds96hFoqtz0NLH1pnIzUsYIcDHWlK9h6FmJiBk9KivpPljUnndUyR4RQ3TPrUV9GwiIkXDRnIPrVdhvYqhSV4GeKgQlVH0NXrW2LpuBOAOn1qpdRCG4ZBn0+lNMh6ArcgZ5xUq5C1UVgDk9qtKx49KGiSZRxUixnOSeKjiIZQM96sJ6ZpMpDgm7Ht1qwileD+FMiXcB7nFXY4d6s/cHaBUNstIYq5xUwjJOSOKVIHzyKsLE3G7j2pFFcRnPSpRGPSpjHg08IKloRHEMHJGPapgCSeeo/WgJ6mlLbWAI5J4pPYDnPEcZNusoOdxwayNLnaFiF9eK29VlSS2aI/Kwc4rBjR4WO773XAreL9wg6ISA5JIANQ3oxEWAzg1QSUkBDnjmrazK2NzcN2NKKsPcwjgrJ6s35V0WikPNbqBxkDNc/IoSWUBh9444rqPCFo15qNrEBku4/DmtXuiKrtE+m9DGzRrQMP+WYxUl8kkqgKpzUltEbayhQfwIBzUf2758bTgVozyZ6sy5BcxvgxnFMSOXedwOD2roFkjlxxSSLEEJfA960iZtHn2vt5TGI8Ac9K5dUWSUpzhwT0rb8TXQvr8xQMV/g3dqz73RJ9Na2eOcurryPQ1rAzsV4d1vaSRK20NnpSRMiW6swyAdrH0p6xMoVZMEt36Yq88McOg3DBFb5uveqsJozWiiecMmQqj5veobeLzLtcMcM42qfQGpIJWJIIGGXIx2pAfLv7NlGCzU7CZ6N4iYQeDVVh/CFOK88ghNtbNM8rFiwxzwOK9B8XAnwqoPsfrxXmpnM8B+bCdOvpRGKaKludr4GuWudTmYnhFxWjrNvc3d7NGV3W/dfWsv4borPcuB26/jXVzQvPfuqttAOTXPWjdcqNYHiPjmB7K28raI2xheO1eSZw3PLZPNe4fFfT7lkFyQRHGDk+teJxqJIZHbudwP9Kyp32Zv0MkAg0pxQOaSuwxFNHGKDRQAdWoOelApT0yaTGJ0xzSDJPIpwAIFGeD7UikIKOexoGetFMA5xzSDGDSikBGaAG0vvQetJQAUg60tIOtABQelFBpAANTwzmI/KPeoKXnNDH1PS55BeeBLQRnLxHnHbNcjMhWRlYe/wClbXgy7+0R3GmyH5ZFIXPY4qhqUBgdY3GHUkHPt0rkatI9jDTTjY6DwREn2kSSD92MkfXFZusyN/akzrnbKTk+laXhxmtdFmuAu6Tfhcdsis68UTyEl8EHr61m9GU4q+h0XgeT/RZ05AHb1rqYmXeOc4HSuM8MTta3MsJGQRxXVwMTMD61DMWrSLDqCAMdBj61B5KqDwDnireNxqOVQilzxg4OalsbKNwoGCqnAGCapyspHK8jnpWjKC67QcK3eqMqhXOT0GKAM+eNWY8dxWXchA7gDbzwK1LhiMEEYCnNc/M7ykuT93rTQ2NOMls9KqNhkIGSQehqSSU/exgdPrVWSfkFePWq1uQ9ytK3ygg/MOCPSqZbMh55H61YlIIYDqTUfk7nBXsK2i0tyHsdb4WsTNpU7qm5yw/Ct6yspUfkYA9a5zw/rD6XC8Yx83rWhJrtw2cEDPpWTd2XG1rFrULQ20gnxwSc1z12VE54OCM1bl1Ga4+V3JA7VVmYvjHXHekkVcq7Qeg5qWPHyk9Ox75oJGBkipI/9Z2ye1D2GX7S2855A4+6AQBUt3aJOVPJBODnpgVJbbYEB5yR8x9KWW6SCIvKCARkKfWpZaYxLWCzt2kYAKvqetc3fzie9llVcLnIA71Yvr+S4AGDyOR2A9qpQgmIE9c9PSritCJEJHykHrmpUkOVB6dDUjIN/P41DIPmxyPemQWF/djGcVcibKBsjHtWYMMNxYnHGKtQHbgH7voKl3sUa8Y3KCOCO1XYwWYEdD2HrVC2OCDng9zWnAB93v2qGWmy9CqMMbScdSe1TMqkAFelRxSfLtPGOvvUu9c8k0iiMgHoKAAOtK23tTCRkA1IhcAn2qKXjawPIPWpiQBypqtIwUFyeB2oewHP6sA0pDHHBOao3UDRiJweqjNaOqFGO91IwOlZ97MGMEY/hQZrWOxDIEdtxyaduOOG75qurDBOTQSB0JzTC4PnzC23IJya9L+E+nC61pJXHyQKW+przaNGZuSfp7V7p8L9P/s7RGv8DLnAJHb1q0YV5Wi7neahfXMbtkfuxgDHpUVrqieZ5bupfpg0kt0LsOEXjbye1c7dhY72JYj85I5BqleTPMvdHcyu8MIkDDnsBXN6g93fOUikIB9DXSWCiTT1WbrjBzUJ0uJpsxtgeorZJolnHR+Fb6WXeORnPXpV2bwxqsiBWk3DPU9hXb28PkrgmpiODz1rWOwcp5vqXhS7gi86FSxAyR1rnZbi+itJrY25YMckY5Fe0lfl9vT1rPk0+2W7M3lLkjkkcU+awSj2PFbWRdi7gQc456ip4tr61aDeDgjK+leiX2jWDaqxS2TY43MFHeuW1PS4LbxTb+QgVePl7ir5iHHU6Xx7KYfC644PGPyryy2P+hoXBA3Hgd69L+JGB4dhXJ4I6d64DSLH7bayEk4i5xTjYTTO8+HCFYLkdB2/OuptDu1S5z06VheBkCWs+OvFbemgvf3JHQHNQ99TSByPxLtLjVLaHTbaLJl4Y46CvC/FeiJ4ft4NOJzPu3MemB6V9TajGvm+eyBxtweOlfM/xGkluPFkh2lgf09K5L2kzpWx5rgetIaKK7DAQ0opaSgYd6UnNNopMB+OMUnQ8UmTQpJzjigocRzkGkJpp65oJOaAFzQAOuabk4NA6UAHeg9aKQ0ALSDrSik70AFIaWigApe9NpyjmgDf8K3X2XWrclsAsQa6DxZalLzchyHXd+NcfbfLKrxnDKNwI9RXoOsBb7R7W8UffQAn0OMcfjXLU+K56GDlbQytKuHbTREp5L5I/CmyBSTleSxrOsZXguPKHDFtuPT3rQlLA9ABnHJ5zWMtzsae5vW9tssbS5jyDKxBxWyruSmwsAqjOa5i1u5X0uOMygeSx28citiIu+nrK8pYk4yKze5lI2oLgngtzUjyF8ITxmsmCcRrwMn3qQXx+YHAHQ1LAuXFwqygkg9uKzbq4Q7wRg54qKW43MqAlQWHzd6z7mdpn+bG7lQOxx3ppXGR3lyigjnJrJkxhwASSRmrU7b1UDGwgknuMdqpSZVST8oIBGPrVJElaUlWx23VVZj8wxUs/Dt/vVATzgjk96tEsh5Y1Zt42zntUUQy+Kuqm0MSaogNhY425qVcjAJxSdFyG49KQsAM5FKw07FxVLHINRSSMr4I9qhjuxE5BIIHc1N5kcyhi4bPp2pJFKSGHn5SM1btADKDkLiq5AXntUkagS4JAJ6YNK5VzXmYZBBBBHPNYWoSNJIGY/KDgDNW5HjiYKOXJyST+dYd5eJNIdq7RuJAB6ZpqLYOSSJxjCnPByMU4INuBVdJjgADIA6VOjljsJ991G2gr3HbQcmmSRiTrxgcYqQEA4x35pQMsecc8GkhFFAcMvcVbiKKQwPbkVDdKY3Eq4255PrUsCF89we4qpbDuattGy4O/hsYHpWtA2JcEcetZdumNvzcYwM1pWyMAcgn3rKWxaZcUjbgN361LnnNRICF4Bp45yM1JVxWOTnNDNhgQeaaPemP1GBmpFdEpk2kleT6GqrOW35kByMgUrHhs8fWq0aSy5ygAUE5z1oBtGZqLmSEL/E3esyWJmZWz0GKuTMTMSwwgzgZ71GhQREsAGNbLYgolGVtpFMKt5hAGeKts+/LMOOgpkalZGJ6HAqoiuX9Ps3uZoEjUl3IGAO1fSuiadHY6HbW235fLwwx3xXj3w40/wA3WknljLRRnuOK9wkt7yYA25AQ1vGGh5+JqXdkYl85tpJBDwCMbRTdJ0ZjdJPPlgxyM9q3IdERN1xM++UdQ3apIpZGYeWhYDpVqLRzvQvx2oVSmeM5qWOEJznpUdtJI+fNBBq1gYqw3GMGLAg0/HIzQKWqQagc/hTCAeGHWnmmn6cikxmVcSLZ3DOiqUHBUDJrh7mU33ieJyjKrPkZ9q7HVZo7WYlnG5xwMdT71zMFtt1S3kKMAZNxOc0tiZp3uW/iAy/2ZAjDPGcVzVlbNDYMYQB5i5NdB8Q2Pk2kaDJbP5Vjfa7a004tLKqLsAzngVrEy1bOr8Grts5j3rV0wgTXDMQBu/GvLLH4r6NoVtNAu66YkhWjGFB9Ca4LUfid4kvpZzau8MDE4EanA9Oaie5vCOlz3zxb4u03w/p0huLhDOVO2MsCc18v694nn1q/kmigwS/Bx2FV5zq2tTiW5E80jcck5atbTPC+qyYjSwdD2ZqxUNbmrnyqxwmaTNHFHeugyFozSdqO1ABnNFJS5pMYvakGecGl7UlILh1oNJQeaYw5FAoNJQAtIelANOxxQAgHGaTvT1HFIww1ACdaTFKKKQgAJ7U8LkZ+vH0oQ1KigkDGc0mxot2sYy2OgQZP1r0TRM3/AIJ8kpvaByAB1H1/nXntuwhmUAfe7HvjkfrXpPw5hkubm6stpbzVLKo7tisakLq5vh6nLM4i7jkt7sSjgg9T3NaUTi8lQrGVJ/i681o6pphj1C5tZfkdSchh0qCJILRY44izkfxDoDXOz1E+ZcwC1ls7cF8ku/IIrajyLdUJwBzgcA0yORZNNDTICwJOSaq2VyZ45SybsH5cVmzOUk2WXO12G7GDj61GZDtZSQcmgneAW7rnFVSXH8IAHbNSV0HsxDZ5wOxNQSHg9eOQfekZznJGBUbMcE9qqIiF5SGHyZAHQdqqSybwwbgfw5qdi3Kg4J5zVWZg3XJP0qkSVZWzux94n8qrFjwccip5myeePpUGD+dWiJPUlg4OccmrqrnerHBHQ+tRWoG9AU7kVY2nkkYI5NMkjOAv17elV2cbGHpU79CVxmqbMVBGAc9cUAV2J6A/XNJ5zx/d+UelKSd1Rvkg1aIuX49TGwBlzj171IupFclI159ayVG0g4qTf2xQ4oOclnupJH3MMHnpVYdsY4qU4I54pmPmGBn3poOYnSVkXmrCAtgDvzVUKSfmGKuQAFwM8+lQ7FJk8GQDvPOePerHPTAznkEdBT4rbOWBBG7n2qyyDBAUEetQXcyrzLQEYGBzj29aSwlzGVPHoRUlwWOW2cDqPaoIf3MgdQME8g9BQ9gNy3Q7FzyO3qa07ZcDIJ56j0qrbovlDHpkVciK9uw5qJbGqLK5xjNJ2wDz60i8pmgkZ46VA7itlhwaYSeueRSFxuAFRmYEsQOnrSsLQJm/dEgbvWqy3JiU7lwGGAc1PJIvAzx6VTlkjy8br905WmkJ26GS7FlIYYG48VC4Lkkdh0q5NCSeWycEn2qOBAVJ71oIqKsjsQVwB0FWoIHIDOPkDZJ9auxW/myKoxzWtp2nTXd6traQ+bMWwQORitIK7Ik7RbPTfh1Yq2j70QDeeCa9LhK29uAx+6O1cx4X0eew0pYfK2sBx9e9dDbwSiEpIwznPWuyKsjyJPmlcguLwzvsjBA/nVyxi8qMnHJqOS4t4MqQA9VhfsG3JgjpwaphJ6mwfvD1PelB49ayLnUpYIi7KAD3p9pqQkiBPf0pWDmNTPTijdhsVXF2hwaI2EkrHPAppBzFnrUMrMIXI+8KUzID15FRyXEYQnOc0mirnLFJdQ1NPMZuuGXHFdBJplvHEu1Anl8k/wBaNPhVmaY/ePtVy4UNbSL2KkH8ql7AtTwb4sfEBBqCWenZdoeN2eDXjd9r2qakxNxdvt6bFOBXR+MgIvEl0jj5RIVAxz1rmLq2QMJU+63GKmlNuLZXKkX/AAzpLarqkfm/6sNyc8N7V9AWXh/S7fSI/wDiXQ4UZOOprxzwhJHAikY4PX0Neyadqa3ulPAu0y7Dj34q2T9vlOXj8VaLYX7wNGu0N8oAA/Cnan8RIbY7bO2yw9utcilrZ2F1dPqSDejMUVjySfSsRC1xf8fLuJwPQVFwtd2OKopaK1GHakpaKAEpQcUUUgHZozTaWgVhp60tGKKYwpMUc0A0DDHNK2aQUp6UACgY60EfN1pM8UdTQAClHSkopCHA4qxb8zIO2arrjFWIPmkQD1pPYC1tPDBh8pr3X4I6SJZJtRcEmNSAfqK8LiKlGBGMd/TmvdPgnr9rbCXT55BG0vKEnqR/9amleIPdFP4saYtj4ja4hG0TqGI9TjmvN7m6+xoZT/e4X14r2H4vhLi9051YFQhQkc85yDXlt9owuowGYrzXJNJSsepRknQZy0mrXVxJtMhCMcbR2rqNLcQ2kWGAPTr1qtbaHaafOZJW8wjlfQGhcfa2C4Ct0A9amqk7JCjfdm2eW+U/KRVeUH1psOUiZWbc6nkGlfByM/MeQaxcdTR6EDbicH8KjbOMU9m+YgHOKZknGR1pxAgZcYOe39aqTqVOSflJrQKZXp2qq8RLYOTkZ+lNA3oZU5Gcgce1NQ9OcfWnXSncQMYGeaTB8oHitFsYt6li2bEwyeACauDbICWbAb9azYmGTzzjFadmVMYBUfKOAe9JtiuQTxES4CkH9DVWSFtgZcjJ5FdAhgwWmIBPT2qldSW4kxG+5f4jQmxmI0Eo52GmGGTsuM9a05bhRyOSentVVpckgcHuapMXKmV2tmAyM4HSlS1fHPerkVzF5W09RUglUqQOKbloPlRVW0JHzU5bYBhxx3qypYgYQtzg0RLI0xVRggHj37CpuNRRJFYRry7bmI4qzFDE0gXZl+GyKUW00Vm8mfnQBtvrVeFbmaFngJTAHOP0oKsjait0S3VRjcD90+9Vpl8okEHaOM+/pWdHqc6Fo5QfMUjLfSr81+k8I3NkdWHrUu62DYy51DRoQxG7g/nUTxlTkHgdc9DViU7lxnIzkCljG91GMj0pPQW5t2gIiTHQgdavJgL2qpZspjHHSp94xlRwDyPWobuaImDkjIIx6UbywJJB29MVW3yhsqAQentTyGBGf0oSAjeQBgeVJPIppb5uOmKJsBxuB/GmZOSOMHoaVtQELBmGaikx5+4ilzn6A0FTknbwTgZ7VSV9BN2RVlV5phHCheSQ7cDrTP7NvrVir2kqgj0610XhHSZ9Q19RboWaME89M16u3h27jg82aBMgdCM1006CaOWpWseQaF4Y1bV5ibWB2A6NjGK9t8EeCl0GJbm4x9pPJJ96veHle0VI9sScc7RiunVfUg55reNNROaVdy0GSKQGZDgAGubutTe3kGFZj6iugvLhYYyrHls9KxEtPPJ5yxPGasxsZQvpJpWLLIUP8WORUcU85vtoBEee9dImkswyeoGKrnSbiKfegBFBLKOpyk6azFjnOAKl06dFsVMmQcdRS6lZ3M8ZjER/Ki3hnhgWN4CePSmmLU0IrmI8GQGrtm4YPg8Vmxwb8AwEH1xWrb24hhYY5YdKLlIpNOHnkUkAA8Z4pJnCwls4x6c1FHbCSVy/VW71l+IZ3gjjCMVDHBx3pPUo6XTMtaK/96rj/dPTFZug7m0qHJrTcDaT9alopHyf8SbA2/jq6VlbaZg6+4NM8R6dY2sdmLRADMmZYz1XjrXb/FHTvM8f2+/AjkRcnHoa4PU7aZteuYN24qh2ZPQVEdirtnNaVqT2V4UB4DYwe9eiaB4gddStlyArMARXlstnIruUVjtbk46Vd0vVZbe7g7spGPeqvoQ1c7zx/DHFrivx5bJuzXPxSJbWM2oNjcvCZra8cE3MenT4yZEGR6VzGuzpbaTDZj7x5NSnqM5XNGaSitAFopKM0ALSGjNFABS80lFAC0UUUAFJS0lAAKD6UUGmMO1AoooASlzSUUAOB4qaJ9rhhxjrUFPX1pMC+u7yS2Op6Vs6GZ3vk+zytHKVOMHGPXFYQlPk4zyOa6HwoobW0LE4VM8VpTjdWIk7K51cF3fXSG3vZDKrEBSxyVxUWo2l9bXQDZZCpK456VDNdLGJWVSWEmBV62vb2OYibB4+UNzwac8M5I1pYpRjynMSXc04x5LZB5rofDvgbU9dtJrsMYY0BYA8Zx2qxLcBYmAtY/Mz94Dn8KlsvGOt6fEYIYC0C9jwTXPLDNI3eMi2kjmGke3mlhlP79H2sPUCpJpiTvHHy9BTtVU/2lJcSEKsg833ye1VJmMcDkjkCuSWjOpPmV0OV/4wTzzUysCFqjHLuROMVZTOVPtUFK5OOO/ao2DckHtgZpQcjpQE3MeegzQhLVGRdRhUX5cFiTn8agZQYRtrQ1KMgRY5HIqnykYUjvVJmbWpVR9kmewHNTpqQiVhjkciqrq3zHFVOWfB71sopkS0L8t28pMhPK9hViGzkmt/PGcMcYHepNLgjfzuBuX19K6bSoY5rQx7OIWIGPpxUSaXQE+xz9vpU7L5hRip4JxwKINOaa68jBxnv6V3UoSLSoyFDMSeAPUVHpcca6kZHjBBix06GsuYaZzv9gQkHapPHasmay+z3qW7ghycYFdrJIluDg8sen41zt9H52ppOr/uw3Oep9qfOi7mja6aY8BUBHHJ6Co9Q042l3BfQKCCw3KK2YpfNYbUKLt2habqCRnSZBMdqhgwNF30FzF2w02C5spo2jGSpIf0Jqhp9hEjLgBh3XsalTxHp2m6UGmdXk2/KinkH1NcbD4wFujlY23HOOfWrjCTJ9oka11YxNdXYUAqoLZHQVwz3UiyuqvkZPWlk1i8LSFZmUSZyPUVTQNI/A5ziuiFPlWplKrd2Rt2tw8sQP8AF05q/a4B3HOR1qhax+WNhHTmr9soM4Ung1zTtc3ib1kNluGAzkmkvJjBD5mOM0+yAMYCnjmo7yLzQyE/KMGsNjVE0RGAR0IyakIUgEHBFV4+VBHY4qQuAWOOAua0QxHRpDgt68+mKqKw6gg4PXNKLvfEzgfwkVFCirEoUHPU5pEt2Jh8ykDrmmSylHAJ3DsPenxuVLHHB6VWnJMiknrlsD2ppXaE27HtHwi0uNdNfUZCDIWIr0u5+a3ZVAJ9K8f8G6vd6L4djMUDSLJ8xHoCa66w8Wfa5SksbRrxhvU16MVZHmVXdnTJAiTEbAMgDNaQABwv61mwSCSPMfznOa0EYkZZMGm7Ga0IZ7Xz2BY9KSKzWNtxUZFW8YpaVwSGqOtJgZ6c04Ug60mygPTmkyO4p3GeaDg8YoFYaCPamtKig7mHHrTvLGcVDJapICGNO4hplteu9Rnr71Q1S0sr+Bd8ijZyBmppNHicDLnPWoDoKEg72596LhYl0OVfsghzwtaTSKRtB5qlbaebUjyyCDV0jsyjJyMigq7seMfF2QQa9ZXDrx/OvPrCB9V1y4lcFSUIFezfFfSRqHh5bqKDzJ4TkDHbvXjuk+LdOs8JJbEPnazelYNtOyNYovWnhuW3inSPy5fO7MOnFcLr1k1pqscCQ+W0a7iBW/Jrl7Hqd1LBN/ou4FST0zWhrOnJfSabqNsBNLcKUlx9KabCxLLC+seHtMugAzQriQ9hjtXn/iOTdqjYI244HpXoXh9pINJ1DT5UKNAd7D+VeZas5kvpM9ieaqO5Bn0UmaM1qAtJmiigAzRmiigAzS0lFADqKSjNIQtFJmjNAAaSiimMKWkozQAUUUUAKKVetNpy9aGD2JQxBJHXFdT4Nie41B9vB2nJ9OK5ZcFwD0713XgNAkd84xkrgE/Wt6KuZTfumq2nZVgGH3gasuP35ckbdoUfWpHGcgAdiPpUTlCWI79M119Dk5g2NzuPIHagI+zGSFYY+lQyT7ZDszkDGB3oDTuMg/h6Ukr6Ma3bKuqWxeKJuWkUjn2rJYBjgDANdSiEx4PIJAzXMXqi2vpYSec8V5WLo8ruj1cLVvGxDsCnipY8gYqIjKqQetSI249elcPQ7LkiyLznrUqk4+vFVQwJbA6jNToTtX06ipHcZdxkwYHVSKzpUO8D3Oa2G5J9zk1QuIwNzepziqQupmNGckH7vaq0sJiPmL1FaSgHg0yWPcwBHB71rGTRnJGMt7NE7MjYJ61esfEN3ZIyI2VbrVS+tWhlJ6gjORVMDFdKSkjnu0zoo/Fl8ispIZTV7R/F0kOo77o/uiMYFciOmPWlIqXTiWpyPQrjxBpLvvDHnnFZs2uWGx9mSxbIrkcYxx+dAGKj2UTTnZ2ieMIo1GFJPTms7V/FlxfW/wBmjwkffHeudCE9jSMhXqKpQimS5NiPIzAZNR5NO6dqAK0Whm9RmD1ra0y0BhMrCqdpbebMq46nGK6qS2W2s1hXq3X2rGrUtoXTp63M+KIsrEn2Aq5ZRkXKuB931/Klji2KBjmrFt8swyc1zNnTazNWBNilQMc5OKbL/HgHFSjJ5U4zUUxw55qSktBseFjBPWmurLvBwQ/Whn+UdM0MQ6EdqEBQHEm3GMelSA4PFNYYfrRkBhg5pkMdLLtIHao1BuLiFcD52C/rRIpePOed2Pwq/o8Kya7Yxlfl3gEfjWkVqiJStFn0N4b0+1h8O2qPCrbUwQRVu40iwmgPlWwV+wA61oaciJYxKqgALVvHvwRXenoec9Xc5kWN8hD2h2kcYq9Z3N9Edl2uecA1qshxlTj6UKhYAPg470CSHAhsH2p+M0mMEU6lYqwmKMCloxRYYmOKO1LijHFMQmBRgelFFSAYHpRiijtQFhO9IScHinYFIRxQBXuESeF45EBRlO4EZyK+RviN4cm8N+KruOMEW8r74yOBg84r6/IyOuDXm3xf8I/8JF4bkuYIwbq1+YYHLDHNLlRUXY+bNN1PEjQTjKyHBPpxXSWl5Pp+qaY3nZtnYAc9K4bBiZldSrqSMdxWxbTm40xQXBa1O/6j0pOISZ6bchbbUdVOc+fbiQH14rx29YvdysRxk16rJONS0uC6TIzb7HweRxXlN58s8i56E0R0YrFSiiitACiiigAooooAKKKKAFooooAKSlpKACiiigAooooAKKKKACnCm0tAEi8/hXoPhIRwaI7OOWlA/A157ECzhR3rubGYQaZbIpHdmz3rpw5hV0RtPdKJiv8ArHUlVYdBSPuYx7vxx3rPWVU3H7v8RHrUouNx3AnavSuvQ5ki8nAJ+77nrVmKWIDplh3NZpkDELnqMipI5N52nhjxSkr2sD0NZWUAqQMKoJrmdfg8u98/1IrTEj5YE5BO2luIWvLKY4BVAOT1H0rnxNPnjbsdFCThKxzYmQFVc449KFZVXcD/ABVWyjZTByDwT1pe2RjAFeJJcuh7CleJKWO84HGMCrEcx+RMcAYqoG5Bz2p0T/PyfpUtDRorz9c1WnTBL54qWNxs3PknPAFLIQ0RRANrdSe1JAZiDkE96ceQeM8dDTguHUe1BXoQOvFX0Aja3E6Ed8VjzWLRAtn9K3o/lY9u1SPbIyZP3T1rSM2iHFHI4wadjPetCWz+ZtvLZqs1uyrkituZMnlsNQLkbj9al8yNBwoNQsmFyBTCDT3HYkafLZAxUTsWPNG0k8CnbCOoo0JsRgE9BU8cQfBAye4FTRWu8D37itCwsyZUQr1dSCPTPeplNJFRhdmloNgsjGdiPl7GrlywZ8A55rRW3FnGAAMnGcVnyRkyGTHFckneRvGNhoXaM9afbp+83YojXjJ6VNCQrMccCpb1AuJ/qy3oahmxuJz3pfOCgKR15qpdyjcrqcA9adtB3HSH92T37UyC5JDBgOOtMgk37gx4PSoJIihJ3YBppCbJXcM+QODTC+3PqKBIFjIPXHBqKBRPIBzkdadiWy/bxB4lf17Vv+DolfxXaq43DdkVj2kaxuwAOAOK1/C7mPxHHKOCoq47mVXSLPoTzhDEFDDpwKsxXKyKpLDpWBomL/8AeTsSccD2roY7aJVACcY612dDz0Tr0znrS9KEAC4xgUufeqKSExTqSigYtGcUU09aAHZozTScGk3D0oC47NGR61EZAvPaqlxqtnaIWnnWNR6sAalO4kX9wzjPNGRj+tcXqXxM8P6eSPtXmsOwrBl+NuhoCFiYgdqfKwbPU80hIz1FeCav8dJHc/YYBEF6d81zcnxn1x3L7m59BVezYmz6ePTII6VG8fmI6OAQwxk/SvmP/hc+uDoWJ9xUkfxv16N135YDqMU/ZsEzI+LHg6Xwz4kkuoUJtLliykdj3HtXEWUvk3SoeVk+9+Nd14x+Jcvi7SPsU9riTduVsdsV52pwCVzkdM1DjYq9zv8AwfdESXelSgnILox/lXIa9am31GVQMYYg/WrVtfPb3dnfxlhtGJMd6v8AiaBLi2N/G2RIA2KnqBx9FFFWAUUUUAFBoHWlNACUUUUAFFFFABS0lLQAUlKOtTQ27TvsQE4BJOOmKAIaSplt5GjeRUJRerDoKioASilooASlooGaALNov74H0rZS+Iiwo4A5rEViq8HFTJKVA5471rB2MpK5uw38YwVByeCTVyPUOG2gdMJ71zUc5QnoQexqSK6ZJhz9B2FaqoZ8h1Ed67OrrjG3C/UdakW8YyZXrj5feucS5ljDBD1ORnt9KsJeEkbyFx6VoqpnKLTOjivgxCOuG9qsw3DKoGdqO2D6kVzcN6Fn+Q8AfePQ1Yi1AEZ35fpjHSm5JoqzuQX8TR3spC4TPy1DG3BHFaVyBcvgjDYA3E9ay2j8m4CtxkkCvHrxtI9WlK8B/IOQetPHDjpgU1cZYcZAzSFevtWBsmWEdlJAI9anVg0QJ65qiMFhjqeBU8DFlYL/AAdaQ7isAD70xSc4NSFCWzxtIzmkUc+ppAGOami5RlNRgDORUigjJFVewDZbeNgMD8aybqHa+3NbLufLVQuT3qhdKGcYH4mmnqBnNDnOORTBAM8rVrAXcD09aaMZ61pcVrkPkDo3yr7VN5KsMlQyDp6mnqhLgjGMdKlSDcx9RzxRzFKKEt7bc6xxnLE7tvpW/ZWRjlZ9gBPOM1U0xYIQzlgHP8R61ce6jLROjttB2n3zWUnctKxYkd/LfcORgKM+tV8Mrsj/AHF61M7K3QE4bNRSELkgEgnnPeoGJglVH5VIucYAHFNj+6MjjHFPwoA9TSYDJMueetQTx7l2n8KnJHOOoqrK5D7t3HpTsJsdFCQuCORTbkYgLEfMO1OhnGSGbk0s7RPGAG5NUtCGyhOQ3lbMgMBx71bsIdrsSCGHWqxRxMuBlf5GtsFGRAvXGG+tO4rkkeAQAaR706bLFco2G3Y/DvUkURXIOOBzVLW4gdEZ0+9v4PccVUXqTLVHsfhbxZpc+kxI92kZXoxODk12tlrNuyhWuI3yMhtw5FfHlvfyQ5iExQ9AR0Faia1fxsm26cOoxneea6r3RxOFmfYUd5CyjDqf905qUSKW4K18nWvjbW7VQEu5ODxg1oQ/FHXrWXeZy4Bx81UmSfUe4Y68fSo3mVcAt19BXzxD8cdTiYK6Kw9TxWhZfHCUsWuIYyvpmi4HvasCOM/jSHk56YryC3+OumFtj25/BhWmfjPobQkiOQEdsincVj0t2VBudgAO5NYOs+MdG0WEvcXaMy5+VTzXifi34n3GsSNFptw0MR681wVzFd6i5ae93FuoLUDSPUvEXxrnd2i0qIKAMBmHJrzq613xD4gumMhmYNz1IAp1npVpBGqSSoy9yTkit+3it4QFt7hCP7uea3pwRnKTT0OWh0G6mUm5lbJ7VoW3h60WPLruYepreKAEKoX1IB6002zMSVXr711JI5pzk+tjNXSLDCf6MF28M1TrYWqgqsAIHcgc1e+ySuMKvBOSueKR7eVBkq3XoO1VyomTkutyullZEsDbrux3App0rTnHz26fhVoRkEseDjoaUA9unrTSQudopnRrAD5YAG9cdvSua8R+F/JiF5Yx4T+JK7AuvQ8kelTqySbVkQlSMEEdaiVNXKjVaZ5Zpg8xTBt35BAX3ra0+JbvSbi0bmSLop603xBpEui6gL+zU+QW5x2NWNsDzW93ZybXYBZ1yOtebUhZs7YyujhaKWiqGJRS0UAHeg9aKKAEopaSgAopaKAEpaKWgAAJr1LwJ4cjbwXrOqXMXGwLG/HOa8wiQvKqjua99S2Hh/4MxxFNz3ZzVxVyJM86ayg034f3NxsVmu5yi56riuDNei+NZEs/B+kWCLtMmZjivOjUvccRaKSipGLSim0uaYDiTS7+KZmjNO9hWJNwxSiT3wfWowaTNNMViz55xgsTjpT0nAXqd3aqmaUGq5gcS/FcleCWZeoHoasfb5MgnBPGeKy1bFOEmD9aOclxNy2v5HdS6gKTliD0Aq9dWcl3EJR/rFXKkHrz0rmVl2g4JyRgfjXT6Xci40tBk71yrGuave10dVB6WKUbPtbchBA5z9akVvmI5yaddFo7nIBYbemetRMQoLfMCRnGelchumSFDxjqD+tSRuYwSv8AwKnpEHEbLnBXOc96dJF8uVIwOtJ7lLcewBwAeAKYFJxjihCWKgAZIqUcYyeemBSLuIVzg54HWnqODgUu0AdBSdBxQAxgQc888VSuAd/B6VdZs4APSqsoDEk9aaQIpt3z0pik5xgVPIoAxiotgUketVcQgcnhQalXzAowSCaijXa/3qtQkE5LduM0DJoc5O4Acc+3vV+2UJsBAxgHB9aqQE+XliOtWomy+SeKTLiXSc/PnknoO9QXDHovQHOKXcQB061G/wB7JAIzUlE9qGfk9MdKJSFPWp7cAxjAI+lK6c42cYpCZnb3ZsAgAcnNPCqQXcDaDVS6vBBPIqRbzt6HoOaW3uzNG6uMLnJz/KqSIbNEQRA7ioBomtkkjXgA+oqu9/aeSNs+GyAVA5q6jJtD/pQyTOMZguFBViMDHetKNUGGAOT1HpTH+WQEbsnsKcrEk9fzosFidN2zH8QbOM9RTNSfdo0+U7kgenHWgNkZAyfem3LL9gniOfu5ppCa0PPXUkjA+Y85q1bYUlgCzfxZ7VCyDfjdjmplypxnj+ddKZyvcn87ejYzgHtSkpImVcsD+lQgnnt/WmjIYkZ47UX1IGygg4yCPeoHZCdoxx7VYOJCSV/Oq8qAHPIJ4qriI3Cgk7RyOMUhZgcqXBHUZ607aQOR0oOSQQOvWncGhVl5yAR6kGpUuJQDhjj1pjAAfSmg8Z7+lFxEn2uVdy7m575ph1C5UjbKwx3B5qJieneoS3NXGTJ5Unc0BreoL0uH/E1NF4l1KM8TsfxrIbJpK09oxOEXujoI/F2pxtlZjV6HxxfxkMzBz6GuQ6UuTV+1aQnSje9jvI/HkjFWmiRvUAVah8bWh/1sYwfSvOixoyaarMn2SPT/APhLNKfB2lR61dg1vTZcMlweOea8kDkdzinCZx0dgPrQqzuS6KZ63c32m3tpJAZQVcHIbpXnoQWUxeL5lhfccHIIrI+0ygYEjfnWhpNwWuGhfcySjHGKyqNPU1jGyMiiiioKCiiigAooooAKSlpMUxi0UUUAFFFA5oA0tFtzc6rbxBch3C/nxXvvxFK2HhnQdGHU7CfpwMV5D8ObI3ni2xG3cokGRXr/AI+mF/4+0/TimY4AMn04zWq0RjJ6nlXxMnH9rWtkPu28IAA6DPNcJXR+Nro3fim9fPCuUHsBxXOVkzSOwUUUUhhRRRTGFFFFABS0lFAhaKSincBacDTKdmk9RWFzz1P1rf8ADjNIs0XG3AP61z2a2/DbE3jRDjcvWpqK8bI0hozWvowBHtGWB5+lZvn8MGX5TkdOnNbVzmOcjrx1rMnjUqwxwxHTrXH1sdY6ybymOQcYwozxzVsECI7uCp5HrWdGoJfO4cjb7Yq95hOT2Y55oaGhgfDZAxgfjzVmAq6lQCSn3jWZcELgHIIOc56+1W7FzyGypbr7ik1oVculfm3DoelRuxUHinggt8nI7A01xnIJwTUhcq5wOTSEE8rj60OOx5poXHQ0IpCOrk43L+VQ7GDckVZY4Hb8qiJBOM1RLISp39qUDjnA4607Gfm7ZxRgEY9elAywmQi5PGKspg5xmqiPjAJ4H6VZRmw2Bkk4x7etSUiwzAdjQrBuMEYwc+lQsQccnPSnQEG4AIbHt3x60rDuaSiaNUKkj5sbcdR61JfTNCmFc7iOOOlTxAhFIYsv3iT1HtWZqIOZDuyr+9CJk7GPdsskpwSScdamgVUhHzHcT3NVHBMmRx2qeJWOM4rS1jNssRxpktsXd1zjmr9mxbKtnj1NU1XCHGKsQBjls/lSY0y5lgxz0xT0XBYgDp1FQ7wRg5/GpQ2ASOMikUKWG0cfN6Uq+YySh1H3cfWmYZSM9aVAS2WOcNyM9aL6iexxNwuZSQVUhiMH60siPGu5hnjqOgq1rumtb3bOg+RiWGPzrO89jEcMcDgqa6Y6o45JpkhY7u9Csd3WnW6/aSyhgrAcBuM0yWK4tpTG8fIPWi2oiVdu8c8GmYGME5wTjNRGcAEAjdnvTPPYAZHTriqJuTYznNR7QtN+0KaY8wxkU7BcGzkk5xTWIC7gTSPMcAVEzkj2ppCAmmGjNIeapCDOaWkozTGFFJmlzQAppKM0UAGT60UZozQAU+NzG4YHBHQjtTM0UAFFWRaZHDg0v2GUqSMfnRYVyrRU/wBllBxsyaa0MifeQj8KAuRUU7ac9DSEexpAJRRRQAUUUUxhSjrSUvemgZ698CtL+0+JDdEArGvA989a6i5unu/G+sXzjcLVGQHtkd6Z8DLZbPQ77UWAyiEg+1ZM+oPF4X8SasoAaaQhD684rToZNXZ47qU7XWo3E7dXkYn86p09m3HOeScmmd6yZogooooGFFFFABRRRSEFFFFABRRRQAUUUUAFamhTCHVYmJwCcEmssdauaZ/yEYAem8UPYuO52eoLm5f1x0rNbG0jpgZyK2tR5udygfMo5/Ssh02kjG7+97CuFP3jrKmSpALHkZPHNSpKCpXrj1qGdfkR0O7sW/pVdpSj8d2qkrgWZyrrgDkdzUQuWG192NhxgUjyjDOOQe1Vi4BOOCcHJp8onI3oLlJSVVSNuOfXNTkhh83T2rEt7oeZlup4BFaQmXdhemP1rNpouLTCULu4HFREjkCnswycn6VAxBOc4NKzGncVuRzTB2OKduB6HmkUAn5jVDsJjpjpnkU7qcClGOg6Uqj5s0DHKBjn8amgPVCSDjOTUQGakQH5j3C0WGmSyYBUgZzUtmCxODglgPwqrIuXUnOTyMe/FWLfETYbqOMDvmkwudABFbHDFhkYCnvXPX8v+shwB6Edq1xMtyqByMgbQvcY71z2qSp5hEcuCTjFJbkT2Ku1nYY+mTVyECFQsgVsnvVOBMqSxIxVhiAq7vu56961toZ9i55aZJCLg+1ToyiPA+U+lQqAQuHNSADPTNQ+xSJ15AyfzqcHdgAdKgTBHNTKBnFSWSK2QQe3enKBu5zk5P04xQuPu43H+8O1OYEKAOvc0mJmXqY+a33fdwVIPesG704hnaIDnHBrqr2Dz7fJAyhyCay2ibJyFwea1jJozlC5yjO/zAjDLgehFaMV4sp2ySHjAy3pUuoWyNNvQBQwrMKbWxtXHQ5NbKSexzuLTZuJ4ftr5GktrpVkJ+6T1+lZV3pF3bOysu7b1JqGOQ2s4eOVlx1IPSt2fUPtlnHPvAuE+X/fqzM5d1dDhhj8KQ9QPzreN5CykXVuOeMgVVbR1uCGs5AynsTyKoDJY5FJnirE9nPbuUkjII9KgwaYhtFL3pKACkxTqKYXG4oxS0UDCjtRilxSATvSHrRRTAKUHFJS0ASb29TThNIv3XI/Go8EdqKZJOLudTkPTxqE5GGIb6iqtJ2oAvJfANl4lanG6tZH+eADjtWfn3ozxRYLGgsdlMzDeYztGCegNNbTW3fupEdT3ziqOeaXcQMZNIZJLbPC+1l/Ko9vOKetxID1zjsaQyZOSOfagNSeOxkkXcg3cdKabaRRlkIUdafDqE0AwnSpJNUmkwSF/Lin1E7nV+GPiHeeGtHudNW38yOZCm7PIzVC58XvP4SOjCMgmQu7evNc285Zmwg+bHWmZODwMGrb0CxNDZS3BAhAYnt3NQywvFIUkQqw6g1ZtJ5LOeO6ib94jZx2NbniG+tdatre7hjVLgDEwHHNQByxFJV1NPkkPLqufU09dMYySIZEG3v60hmfRWkukSGJpBKmFOKedDm27t6kexoAyqK0/wCxpthYEcCmPo92rYCg8ZzmgDPoq2+m3UbYMTH6c1A9vKmNyMM+ooAjzRQVI60bTQMKXrilRGkYKoyTWh9jW3RHfmQnpSbsIrw2Ms0TyqBsXrmktWK3MO04YOOfxqzNMVhJBIDcYXgVWs42luYwoJIYUr6FQ1Z6DdAtGhCjPl5H4Vkz5UDPG8cenWtaYpwqk8IBn+dZsy+vzZ4Gegrh+0d6WhRnXBYYAAPIHTFZ8sZDbiRk9BWnMuxs54LZwaquq+W5YZOcfSrT1M2ijvdEKgDHrUMj7iMjGB2qzMEUAAZWqT8OfStY6mTVx6y7XU54FaccpyCDlW6e1Y/GPc1PFcNGMdqJQuhqVjZBzjjkdqa+AxJ71WWYld+eT2pfMI61jqappk5wBj1pyjk4qDzDgE85p8bYLE0bF3sTKex/P0oJYHg/jUQbIAHGaVSSMZHXFK47k6t2qVWyTj0xVQMVbGafE5IIH50XC5ZjU4bPapUYbD1z7VHGw25JxjrU0m2NWAYA4zzQK42S4WOISLyRxhaw3d3lYkZOc1NNeZjARdoYk5+lVVZmywODV2M5SLUcvlpgLkk8YrQRHyN6AHsCaowweUAzgFm557VfBw3rkdaGK5MmcMSQcdPap4yRgGoIht61YUfMOaktEqj58YqdfX0qHkZIOamQ9qllllMcEUYznjrT4sEKOOKlCjIx60hMgkiJhZR029Kxnf52Rk4xgcV0m3LdOM9PwrHuQ7Oy7QCnOfWgZi3EAaEqFLY+6fSudnUpJgnnuK6qZSFdFztAz+Nc3eptmJPJPOa2pvUwqIrscoCevSpgxjUBV4xUK/NGwP4VJwVHJ6VscrJBdhsI3AxUezy/mhkK5P4VWmXD5zT7aVxIqgjGeh6VVtBNmnDrbxqY7mITIOMjrV2HStM1UZt7gQytyFNZktqJ1ZkHTtVBfMhk3JlGXuKaC5fv/D99YMd8RdP76cispgVOCMH0rqtH8Vy2Q2XY86I8YYZzXQxweHvER2oiRTkdBxVWEeZUvauy1PwU0Uh+ySBhnGD/ACrnbvRb6yz51uwHtzRYd0Z9FBBBwQRRSAKSl7UlACUUtFMYlLRRQBIST1pOKcAaTAzVkCcU3jFOIpBQMTikpcUY5pDACjFLQKAuN70UveikAlKKKO1CAQn3pQTRSGgB+T0zSq5ByD/9eo80lAWJC7E/ePPvQXY87j780yikFiUTSKpUOdpPIzT1uZUyFkYL6ZqvRQFi39vmIxvNTx6rMmDnJ6c1m0UCsbkOuyru3gE9sVOdWinhIkjBKdOK50VbtbWadsoCEBwTRcTR0EcGnXMapLDh8biw96r3OgWxiM0E+B6GojcjT5V24cFNuD0FV7m+a6kRASNv93pQ2JXuSxLBp0TsSHcjAqiZXlLO68jkHNDqzEAk80l0fKRI1P1qNzQjkLTyiNBkdgO1dXomlJaxJNLy5PSsfRNPM7eaeADwa66JAkSjPI71jWnZWR0UYdRrgZbA6/L+dU5Fy+CPu8VbcjPWoHO4gVzrc6ChcDI3AdDVRuSeOC1X5gSzAdBVJwVhBxzmqS1JkVZUDAgDpVN4twyB0rQb7wBquV5b3rROxkzPKlTk96bmrbRZXnoKrPCc5FaxknuRYElYNtzxVlJwBgmqXlsOcU0k9D0puKYXsaay9vyqVJgV3VlrKe/4U9ZiBjtUOmUpW3NEzAk47dKRpQOnPeqQnIxUhnUjgdqnkKU1YtB8nIbn0q1AcgqD7kmsuOcgg46CrS38cZZSuQRRysfOaAuAFJJwnHFVru/UyElvmHQDvVK5vPPxHGNoOM+/0qS1055FWSZSE7A9TTULasOa5UMks74A6dAPrWtaWccKh2O52HQ9qnht4423Iq46VNs5xilKXREpMiGCduM47mpVwe3SmN8p3AfWpBxHwOTUPU06Ey4IxVhd2Dx0qtGMgAnmrKEjKjNSNEn3VyT1q2q45AHIqsELpgiragFdo7ClYoktnxJtIq2q/MPrVeBATnB3CrMYORzQ0G5IRnoOao38QVll2/L/ABc9avAlRkEelRTxBwVI4xx6UrDMC5gZQSfn/jBHYVzGpJ8wbOc967WWJhHKACGVOp6GuR1ZBGEJ7+lXT3M5q6MmLhyvqKkUHZ0qJP8AW5B4qxEPkIPrXWcL3I7hMQBsVUVwj5xzmtOQbrcqRWURhs+9MDZtZP3ZOOtUpsGVjin27MQBnikkQcdetFwK28ghuTjsanguWt33xMyN1JHWqzcMR2oVyKEJnYaZ4nVlWK8yD0DZ6+9bL3UgiZ4is0Z7Nya85zuHatXTrqWEgh2I9D0qrk9ToJo9EvGxdwmCQ9MDFUpPCNvOrNZ3YPouaglu1uAPOAJ9aiV2ifdBKwweQGxxSuWU7vw5qFpktFuUfxLzWW0ToSHUqR2PFdlbeILmD5JDuj7ZXNXRfeH9UAW7i2SHqwGKAPPcc0d67ifwlYXu59OuBweATWNeeEdVtRuEJkX1WgVzApKsTWVzb/62F0+oqDHGc0xkmT2FJg9TS8etH45FaEiEZ5pMcU7p16UcYNSxjKTvT+9JjnNABSdDS0dqAG0UYpcUgEoBoxRigYHrSGig0gCkxS0ZFAwApaTNL1pCCkpaUUAJQOtSxxGU4HbnJq1GI4dpC5bP4UXC4kGnPJH5rkKmeeeasXV8Ibf7JANoBBLDvUck52OwGBnAwaqPg/L1OetIBBvlO4k++atwIEt2buaiUFV4HUVYBxAARilcBMFivpVKZi9yc+uKuE4xz04qlGN9wB6tQhpXZ2OhwmOzCgdea1Nx8ogDoar2KhYlUdcVNnEbHPOa4pNtnfFWWhGcelRvxyvFSE9ajYkmpGyo+AeO5qo7fMUxyPyq+6jOe3cetUph8xGPk9BVJiZVcEAMQOpFQEHJPftVl8YAPQHNQHj6Zq0zNoZtPNKEz95aenLtnoelSIoYnnpTRNiDyA5IBAHpiqz2LNnaRWmIwQDQyIRkA81SlYVjDa3kBxtJNRsjAkfpW1IjhcZxioGCZPyj61ftBONzIOc96UHHrV826k0fZx0A5q+dEqLRUQtyQDVuHT5Z+RjnsanjQeXwuD05rSiQIFc9hkioc+xaiRWOmeWN0uC4/StXA+VccClUowUrjBGcjpUgGWGR1rJybNIxsRbVj4UDn2qPkE8CrJTdkkdKikUDHynmpYymQSTSqCeM44p7Lk8CkUHdk8Uh7onjAAwealU4YknrUMbj06U8El1GOKARejGFyWqygzkg8mqceTz2zVyMcdOaCixEGXBJFWAeVxmqgUccc1ZQksoVu3pQBJGSR059TTpc8ADOaFPGDnIpR9ce9AyrNE54cFlJ5288VyHiCMJIykfxenQV3HABCnb2IHc1yniZAbeV1AySMe1EH7xL2Zx0f+twOmaniPcHIJqGEjz0wOMc1PG2QTjAyeldhwS3LLAGGU9wPlrKZecg1sx4MRyOo5rIkBWU4HFMRJbnBJBxUpPHrVeNtrYx1qfIKk80gK7KM+1QnrzVphlfeq7AfjQhCBscE1pWjYTr+dZjYzxVi1lIfB6VVh2NCQEkAfpVeSRo2OOlWVyylqrSDnkcd6VgJY7ll2rkkN1pzvHt3kZwfWqedpOKa248Z4JoGaUF8IXBjldR1wDW5D4hnVQPOLD0J61yGDnrxUgYjGBii5J2ra3BcxlLuBWBGOBzWZKmgy5TyXRjzuFYqXBGM5JHep0mDHB+7696dwRj8elJjn0p445zTWHNaiFPTrTf4aUmm9qlgA+9+FFAoPHSgYUUpGAKSkIDSUppDQMKSlpKACkNLSGgYUYoxR2NABS4pyqzcAEn2q/BpNxKA7Dah5JNSwuUFUsdqqSavW+k3E25iuEXkmtWO2tbJlEQ3yAZLN0FQ3M7GBkQ8E54pXFcoyIkQ2w9f4vp2pgHII6dfxqR1OPqc0x3WNSe4pARTSER+UOh5pkK8ZNRZ3N9atIhCge9MBR2OeKnYgxKAartlDkYq0GxHEeOQaQELZ3EZHWq0A/0kf71TNkSKG79KiXKXIHo2aOhcdzurH5rYHuamYgc7eO9R2SgWa7u4zT3bKYGK4nuegvhIWOHYj0pjA5HPSn8fjUTNxyTmpE9wOCc9hVV1ADZ7nirDjOACOetQSELnn5RTQmVJMk9qrsoOcjn2qzIdxycZqJsg8dfarM2Iq/J1GKkjUEfWmhR3NSKw2g5PFFwHBMMBjtQEGwZ9aXI6c0uc54oVx2RE4GTnkVAUU5OKsMOvFRFeDTsJorlMnimmPHPPHpVgKFGKbz0qrisRRrkYOcDmtCL94CoGDt7+lVlBH1qeEmOEu33Sw/M0XGjUtLSKNPlY7mG7np+FTom4ZI5zwaeqP8Au3ZuCPlqRUKuDn1qWUM2/KVH3qikVtvBGR61Mc5BzSMBsbd12/1qRlB4yJMsRn2qNmX9ann4fAFV24bOKY7WFDjacCnr0Xg5qHHUgdasJgquRyKALUZ+QAdc1djYEAd6or0yAOtWUZwxx6UgLi4Ixmp0YqFGWP0qtG+7oUHrkVIrAuo5JHpQUWQ3yjIP40pGR14qND8wwD708ctjH50XC47IU5AzgZrmPFIATg43c4rpX5Bxwuc8Vxfie4Z7jBY4zRBakN2TOZhGJeT61aiUKq89TUEef3jA54xzU8fyugyeB+tdhwy1LkbfuzxWXdLicds1phSuRnqM1mzFmc5A4796CSLHPXpUwOAB61Dz0qRSSOaAHNjGKhdRjNTnmopFxjmhDKzYzSoxBofqeaaOKoZp20wKYINOcDGao28mx8etaQwynPcUMCpIBkkVDkB+tTyqEXuar5Gc4qRDt2XyOlP3ZPFQfxZpQ3NAWLQJpysR2qFSKeDTAr4BFIeTg9KAcNz0pHNbCQHFJ260ucYpBjripYMT2FB4o75oIzzQAopM+1ICaOaADNHegUY5pAFJTu3Q/lScDmkMTmlxmrMFjPcEeWmc+9aEejxREG5kOT/AtFwMhI2dgFUn6DNaFrpDyyESnyhjPPetNBbxAGJAgXqTx/OmT6gm9SD5jE9h0pXEWLK3s7EOzkM4Q4VupNVpNRRlVdzAc7lHYVSuJ5JnJL9AdvGCKidslhgDPGfWkIkWZ5SzPjBO3FPUcDHzVCqjdjPGSfx7VOgYxqWOPYUhsR8DGR2rPuX3PVi4lPIC4GOuaok5poEOiXc30q8OUBJ5FVrdTljjoKt7P3JLDA9RQwKsjBj6+tW4/wDUA4G0DA9aokjd6D1q/EMxnDfIBSArTE5U4OBUTYEoOT261PIcocdqgb5lVvTrQilud1ZHzbGNyRwoFPO0oSMZrK0K5Daeys3IPArRdgQoHeuKWkjvWsQDcY71ExOMcU88e9QykgHFSkO6EdsMvH5VXkbdlQBgsRzT3bt3qHcNwwMncaqwmyPgc7aYMA5H60vzdCaTj1qjNilc08fdHqKTPNBPzYPSgBysd2eaUk56gfWo8ndwaCxzg0K4DySBgkE9qidjTizAYIHsajY9/wCVWA0Z3HNDdQT0pOT1p3oM0D1FH4/hWlYqHiKOo2k55qinHBPT2rUtYwAAW+bqBQCL+f3eCfu8AVIinaHJBqJQHVjjjNSgjG0dKlsY1gMewqNsbCG4BHB9ae5CjnpUBYYySCvYZ6VIEEud3IqJl5+oqV+vJzmmYPUc0DuRAEVJnnI+9+lI2D9aFPzZxzQMnTle+c1ZRyOctzVVGOPbNWU6Zz3xQBYibJO4cCp0bByOtV42xuzUwJABBoGWYpCpAZsA9zUhJDYJ6/rVYklfcdyOKeJAFDn/AIESeKkY6eYQqzKR3GK8+1aYy3ZyScV1WqX8aWjRxqd5PJrh5GLSsWJ3bq2pq5jUlZCLgJk+tSwvk8DH1FMY4O0jHFTW5PAwGHrXQtDkdmywcsuFI56ZrPuAN5x1bvV1wM56BeR71SlIYsadrgQ4IbaeaepwOtRrjIJJNSIOSc8U7ASrkjlajkHzcDn3p4HpmkYY5pCKrj5jxzTMVM4OMmoaYCqcMDWlbyF0JXt1rMqxbSFZBzgenrSYMt3PMSMAee1U2OeT0NaTAFN4OTjkelZzxlRjPynkUgI9pzSHg04Z6UhGKYD0PepRgjiq4ODUsTcnJpAQ4GaCAaUZJ9aDkdsVsIQjikHSlINGDSYbhzQfek+bNOIJoCw3qeM0mDTuQPejHOfvUANAowakCMTtCtk9Mc5q7BpsjqWnV4x6461NwKKguQq5JPFalnpyRfvboDPULUv7m2VVgKFl6kDJqB5GlUqzknrmk2CLbXwIwqCEfw461BJcFs85f1NVgSTkrSuTnOKQx7ZkwSSw75pgLHJDDA9BimbiT1pCwFADjjsCPqc00n5hSbjuxTlGXGaQD4RvkKHp61PIdkLMTgnOB9OlRxBT+dR3UnIXPAoEyrMxIUZ5qEgflSsctmlVd3FPYCzCDhgTxgcVO/ywkg/L/dqKFSSTnoBTrgjaOKQFNznBHT09Ku2oYJzjB6VR4YDHWrluRgDPPemAspwpGOtV9mDjvnpVqXBG/HtiqxGD75pDLukylJ9hbGTyK6XcCEIIxXGbyjhl65ro7O6We3JX+HrWFWP2jrpSvGxf3gk8/lULt3AP1NMZsE4PBFNJGQFb8KyuiwZ/mwe4qMfcAHr1owRyR3pSQQOKQMjPD4pu3mpOc9KaVJNO4rCnAxQSpGcU45xwKbyFzkUBYYSAelMPzHinZOaj3EE5FUiRxYgdvxpm485P5UjfN25pDkcYqwDcuc5pd4Ix3zxUOSCc+tAYDI5AI7UBc0YMEhyPm6Eegq/Ey5zj5vWsqKaQlEG3AXGT1q7BKHZggKqBlQep9aRSZprICQQ3HepgcdT9KoRsBnbUglPBB+tFhkjuCFGTUTMemBTTIQp7+lRtITgUrAKWPUjpS89cdajyCc5p4PFFgFxSoPm60gOKUcGpsBKpAPHOOTUyncc44PzCoBnIx0qYL0IPI7UgJg4YZAqSNiw25GB3FV1K4GFIHc5pySBBgDljSYy4rYwMnp36VFdTbIv6DnNMZ1ZNm8qR3rGvrwJbsyMQ2cdetOKC5Q1W6NxMAH3AdhxisfBMx54BpXdn3EnrTUG1Dk9a6IRscs5XYr4aXIParUKhdtVkXPerAyCBWtjF9x5Y7iKrTj5jgCpA3z4JxUU4wcg5qrWBMqscN1GKcjZprqScnpSpkrigomU4ONxp7YJAz1qNcjqakb7uQKgRFIvBxzioHUjtVls5OBULjPNC0EQ0+NtjhsZ5puKKoDWgkWToMg8VBcIVRtwyQ2AfSm2RO1sHGOasTqWh3A/ePSpC5ngEE5pp96eUYNg+tNcY5oGMFKvBpG65pM0wHk7jnPNIeOKXgtkjFNPWthAc04BiMjFNzzzSj0qWAAZOccUpPpSoGZ1C857DvV+KxXkyHb7HtQDZnqrswCgknjitCHSZAR57iOM9T1NWolgiXbGA/o1PZyGbb/3yec1LYJj4xb2i4gQOR0cnrUdxdSXB/eOQB0APFRyvnBAwDULcNgipsMRmxnBABPOBTMjHP4Gh2HamcnJPSgB4PrwajY8nmm5B6nmk4H1pAKd2MCm9eTS59qTNAhRycZqRD3BHHrTQPQCpY0cqQqjOeR60ASkFI3boq8gnvWfO+6Unt6VendViYEkhQQoNZrEbutMBlTRDORUPerMCnvQwLCDb070yZ8r0ORUvA6darznnAJ5pAVwSO351ahIXB4yaqnI96sRNkAkDimBPJzwG/CqzZByasKRknA6VFIMjkYpDID9081bsLr7PIQT8jdqqttx60ZA5xmh6qxcJWOmVgw7bmHAHSndcAAD0rPsJC4xn5scVoKW2gsuGHQetcUo2Z0xdxQuFPrTf4cU8527gOvX2puOM9qBtjMHjJ5NNA+Y0884IBx60hX0P4UAJgcgU0nANPycYNRt0OapANLAnAqPoTk0/IPIFQyHnjrVaEyBiTSMBkHP60MelNxkciqERyYDHHc00njufrxSnGevSkzzyfpQIlikOR0xn0q5DIdxLMQdmFPpVJRyB61NGTnBHIFFikzQSTKqQSCe3rVhZMbgBx0qkj4VSO1TCTrzxnOaRQ92HTBpqMMnI6U1m4zzim5J570BclDc+1Sg56A1AzDPB6VIjEdTQFyX2pVI55powT1p6A5PApMRKBwCDTlzggGm5OznpQGCgZPBqSkPBwoGcjvmhX4zgfj2qLjcRUDzIH2kMQRwRQBZurlUgYAjDDGT1+tcxeSmWQqTlFHGO9Wby5MnyrjYvGTVB22ru6k1pBGcmQHPzBR0pZAcbRTkBU5J+8vWmR7nfBYcVvFHM3qTQp8oJFOfG4HsRSxgL1Jx3JqKZsliPu54PrVkoRSAchST70+dcoGwKiTOAcnFWJDlMDBpXCxnMwycGpIxlaR1Ck8U5BxTKHDk4I4qXHGAeKYOODTweKgQ0kgknvUDAd+anbpUZU0CZXIppqVxg1G1UgQ+GUxv7HgitWIqYhnsOlYwxnmtC0m3ZBHTpSaGRyIPMOCagbBGKuyqC2cYzVRxg9BSERn600U8j2FNHemA40hHT60p+9QcYzzWwkNIy+PWlCnoOucUnJOcH61e020a6uB/cVgSaljZe021NoEupYw27KqD9KfITn5lFWL6RZWiijBVYySSDVByQvXJJ6mpYhM/dwvHNIrEc8g5oxxgUoUg5ANSNIUkE4/hPeoS3ykE8ipGB29arP0xQhoQtkYFNycYNJnA4ppb3oYxwAzQ1NzxSEkdaBACSeaVOd1NGQc5pU78nNIRMq7gCPWrIUZYA8j+dQxqQoxU2SFLADIGaAKt1Kjo4xg7hj6VSPWnyymRs4qPvVJDHqpLD61dRDVVFJ6VaThcGkBJjBPNV5RytWCOSG69sVWkJ3YPakBCami6VC3Xipo+Y85xQIlFDgletNB6UrUAVmBHejkrj1p0i+lM6CgpaE9rJ5cy/MQfWtyBt28F87B19a50Yz7VpWEpDMByGHQ1lUjfU3gzYPTI744o4K4psTEgZ4IGDjvTuMn1rn20NBvsKTB9aXGDRgHmnYBCpxnNQk5DZqX6NUTjAPIpoBnbiom9akIIXHemNwvNUgZH1pSDim4yRTu3FMgjZT14+lIQMbu9O789aTHX3pgAJIzT0bGTTVPyjHWnAHOP4fWgZZVgqKKez8YFQc8BhyKd6UrDuTBiUwTS7h61CrHbjA608cnigL3JVf5setWFcMCMdBVbAHJqWPGDQBZAAUcU8HBHPaoV6U9Cg+8ST70rFLYlyQAc9eMUjP260hbaMA8H17U1nb5wuMgVL3EMeUbWx/Dzn1qhPckkMm4k9vSnyyuse3IznmqLEs2TmqSJuRSnOAwO3OR7moJCCxH8RHJ7VIzbBgDAqEc8/kK1ijOUhCc7BnoKkgTq3X/a9KiQbzx261YRAv17CtFoYtkhwiHLcY+961Sk+bAD9RxU05znn6iqpxxjt0qmIlgI38n5RUrnA68mq8JAYgjj0qWVtxGKBohfr1oRvU0rAk54HtQM+gouMeqnPXNPXOaRRjpmnAHNSIUqCKj27s5OBUpHFMYDGMUAV3Tng1C3HWrL8E4qtIckU0CG5qzaMQ/BxmqtPRsOKoZqtG52sSD7VSlXkHGMnmrKEMAQT0pkigEd6mxNiqw54pop7dTUdA9j/2Q==";
}

void UdpBasicAppJolie::sendBigImageSingleUAV_CoAP(int idDrone, double x, double y) {

}

void UdpBasicAppJolie::sendPartImageSingleUAV_CoAP(int idDrone, double x, double y) {
    char buff[512];
    unsigned char buf[3];
    int buffStrLen;
    std::stringstream ss;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP image for Drone: " << idDrone << " with position (" << x << ";" << y << ")" << endl;
    //memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    //buffStrLen = snprintf(buff, sizeof(buff), droneAlertStringTemplate, idDrone, x, y, acc, classe);
    snprintf(buff, sizeof(buff), droneImageStringTemplateP1, idDrone, x, y);
    ss << buff;
    loadImageFromFile(ss);
    ss << droneImageStringTemplateP2;

    coap_context_t*   ctx;
    coap_address_t    dst_addr, src_addr;
    static coap_uri_t uri;
    fd_set            readfds;
    coap_pdu_t*       request;
    unsigned char     get_method = 1;
    unsigned char     post_method = 2;
    //const char*       server_uri = "coap://192.168.1.177/register";
    char              server_uri[64];

    snprintf(server_uri, sizeof(server_uri), "coap://%s/image", jolieAddress);

    // Prepare coap socket
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    // The destination endpoint
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    // Prepare the request
    coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
    request            = coap_new_pdu();
    request->hdr->type = COAP_MESSAGE_NON; //COAP_MESSAGE_CON;
    request->hdr->id   = coap_new_message_id(ctx);
    request->hdr->code = post_method;
    coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    //coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
    coap_add_option(request, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);
    //coap_add_data  (request, buffStrLen, (unsigned char *)buff);
    coap_add_data  (request, ss.str().length(), (unsigned char *)ss.str().c_str());

    //std::cout << "Sending URI: |" << uri.path.s << "| of length: " << uri.path.length << std::endl;

    // Set the handler and send the request

    coap_send(ctx, ctx->endpoint, &dst_addr, request);
    coap_new_message_id(ctx);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
}*/

} // namespace inet

