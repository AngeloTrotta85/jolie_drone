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

#include "UdpBasicAppJolie.h"

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
        jolieAddress = par("jolieAddress");
        jolieAddressPort = par("jolieAddressPort");
        gatewayRealAddress = par("gatewayRealAddress");
        gatewayRealAddressPort = par("gatewayRealAddressPort");

        coapServer_loopTimer = par("coapServerLoopTimer");
        neigh_timeout = par("neigh_timeout");

        myAppAddr = this->getParentModule()->getIndex();
        myIPAddr = Ipv4Address::UNSPECIFIED_ADDRESS;


        mob = check_and_cast<IMobility *>(this->getParentModule()->getSubmodule("mobility"));

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

        coapServer_selfMsg = new cMessage("coapServer_loop");
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);

        self1Sec_selfMsg = new cMessage("1sec_self");
        scheduleAt(simTime() + 1, self1Sec_selfMsg);
    }
    else if (stage == INITSTAGE_LAST) {
        addressTable.resize(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize(), Ipv4Address::UNSPECIFIED_ADDRESS);

        std::cout << "UdpBasicAppJolie::initialize found " << addressTable.size() << " drones" << endl << std::flush;

        serverCoAP_init();
    }

    //std::cout << "UdpBasicAppJolie::initialize END - Stage " << stage << std::flush << endl;
}

void UdpBasicAppJolie::finish()
{
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
        double d = mob->getCurrentPosition().distance(n.second.begin()->info.mob_position);
        if (d < minDistance) {
            d = minDistance;
            closer = n.second.begin()->info.src_appAddr;
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
    payload->setDistance(p->distance);
    payload->setDrone_id(p->drone_id);
    payload->setPosition(p->position);
    payload->setStiffness(p->stiffness);
    for (int j = 0; j < (sizeof(p->p_name) / sizeof(char)); j++) {
        payload->setP_name(j, p->p_name[j]);
    }

    packet->insertAtBack(payload);
    packet->addPar("sourceId") = getId();

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
    if (msg == coapServer_selfMsg) {
        serverCoAP_checkLoop();
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);
    }
    else if (msg == self1Sec_selfMsg) {
        msg1sec_call();
        scheduleAt(simTime() + 1, self1Sec_selfMsg);
    }
    else if (msg->isSelfMessage()) {
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
    else if (msg->getKind() == UDP_I_DATA) {

        // process incoming packet
        if (strncmp(msg->getName(), "UDPBasicAppDroneReg", 19) == 0) {
            manageNewRegistration(check_and_cast<Packet *>(msg));
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDronePos", 19) == 0) {
            manageNewPosition(check_and_cast<Packet *>(msg));
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneEnergy", 22) == 0) {
            manageNewEnergy(check_and_cast<Packet *>(msg));
        }
        else if (strncmp(msg->getName(), "UDPBasicAppDroneAlert", 21) == 0) {
            manageNewAlert(check_and_cast<Packet *>(msg));
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

    delete pk;
}

void UdpBasicAppJolie::manageNewAlert(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationDroneAlert>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationDroneAlert", pk->getClassName(), pk->getName());

    EV_INFO << "Received Alert: " << UdpSocket::getReceivedPacketInfo(pk) << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Received an alert" << endl << std::flush;

    sendAlertSingleUAV_CoAP(appmsg->getDrone_appAddr(), appmsg->getPosition().x, appmsg->getPosition().y);

    delete pk;
}

void UdpBasicAppJolie::msg1sec_call(void) {
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

void UdpBasicAppJolie::manageReceivedBeacon(Packet *pk) {
    const auto& appmsg = pk->peekDataAt<ApplicationBeacon>(B(0), B(pk->getByteLength()));
    if (!appmsg)
        throw cRuntimeError("Message (%s)%s is not a ApplicationBeacon -- probably wrong client app, or wrong setting of UDP's parameters", pk->getClassName(), pk->getName());

    Ipv4Address rcvIPAddr = appmsg->getSrc_info().src_ipAddr;
    if (rcvIPAddr != myIPAddr){
        if (neighMap.count(rcvIPAddr) == 0) {
            neighMap[rcvIPAddr] = std::list<neigh_info_t>();
        }
        neigh_info_t rcvInfo;
        rcvInfo.timestamp_lastSeen = simTime();
        rcvInfo.info = appmsg->getSrc_info();
        rcvInfo.uavReferee = appmsg->getUavReferee();
        rcvInfo.isGW = appmsg->isGW();

        neighMap[rcvIPAddr].push_front(rcvInfo);

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
    //TODO if(socket.isOpened()) socket.close();
    return true;
}

void UdpBasicAppJolie::handleNodeCrash()
{
    if (selfMsg)
        cancelEvent(selfMsg);
}

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

void UdpBasicAppJolie::serverCoAP_thread(void) {

    using namespace std::placeholders;

    coap_address_t   serv_addr;
    coap_resource_t* policy_resource;
    fd_set           readfds;
    unsigned char buf[3];

    std::cout << "UdpBasicAppJolie::serverCoAP_thread BEGIN" << std::flush << endl;

    /* Prepare the CoAP server socket */
    coap_address_init(&serv_addr);
    serv_addr.addr.sin.sin_family      = AF_INET;
    serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
    serv_addr.addr.sin.sin_port        = htons(5683); //default port
    ctx                                = coap_new_context(&serv_addr);
    if (!ctx) exit(EXIT_FAILURE);

    /* Initialize the hello resource */
    policy_resource = coap_resource_init((unsigned char *)"policy", 6, 0);
    coap_register_handler(policy_resource, COAP_REQUEST_GET, policy_get_handler);
    coap_register_handler(policy_resource, COAP_REQUEST_POST, policy_post_handler);
    //coap_register_handler(policy_resource, COAP_REQUEST_POST, std::bind(&UdpBasicAppJolie::policyPostHandler, this, _1, _2, _3, _4, _5, _6, _7));
    //coap_register_handler(policy_resource, COAP_REQUEST_POST, std::bind(&UdpBasicAppJolie::policyPostHandler, this, _1, _2, _3, _4, _5, _6, _7));
    coap_add_resource(ctx, policy_resource);

    //coap_add_option(ctx, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_JSON), buf);

    std::cout << "UdpBasicAppJolie::serverCoAP_thread going in SELECT..." << std::flush << endl;

    /*Listen for incoming connections*/
    while (1) {
        FD_ZERO(&readfds);
        FD_SET( ctx->sockfd, &readfds );
        int result = select( FD_SETSIZE, &readfds, 0, 0, NULL );
        if ( result < 0 ) /* socket error */
        {
            exit(EXIT_FAILURE);
        }
        else if ( result > 0 && FD_ISSET( ctx->sockfd, &readfds )) /* socket read*/
        {
            coap_read( ctx );
        }
    }

    std::cout << "UdpBasicAppJolie::serverCoAP_thread END" << std::flush << endl;
}

void UdpBasicAppJolie::manageReceivedPolicy(rapidjson::Document &doc) {
    policy newPolicy;
    bool parseOK = true;

    if (doc.HasMember("drone")) {
        if (doc["drone"].HasMember("id")) {
            if (doc["drone"]["id"].IsInt()) {
                newPolicy.drone_id = doc["drone"]["id"].GetInt();
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
    }
    else {
        parseOK = false;
    }

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
    t_coap = std::thread (std::bind(&UdpBasicAppJolie::serverCoAP_thread, this));
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
void UdpBasicAppJolie::registerUAVs_CoAP_init(void) {

    for (unsigned int i = 0; i < addressTable.size(); i++) {
        registerSingleUAV_CoAP(i);
    }

}

void UdpBasicAppJolie::registerSingleUAV_CoAP(int idDrone) {
    char buff[512];
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

    /* Prepare coap socket*/
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    /* The destination endpoint */
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    /* Prepare the request */
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
    /*coap_register_response_handler(ctx, message_handler);
    coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
    coap_send(ctx, ctx->endpoint, &dst_addr, request);
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
    }*/

    coap_send(ctx, ctx->endpoint, &dst_addr, request);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
}


void UdpBasicAppJolie::sendPositionSingleUAV_CoAP(int idDrone, double x, double y) {
    char buff[512];
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

    /* Prepare coap socket*/
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    /* The destination endpoint */
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    /* Prepare the request */
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
    /*coap_register_response_handler(ctx, message_handler);
    coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
    coap_send(ctx, ctx->endpoint, &dst_addr, request);
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
    }*/

    coap_send(ctx, ctx->endpoint, &dst_addr, request);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
}


void UdpBasicAppJolie::sendEnergySingleUAV_CoAP(int idDrone, double residual) {
    char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP Energy for Drone: " << idDrone << " with residual (" << residual << ")" << endl;
    memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    buffStrLen = snprintf(buff, sizeof(buff), dronePositionStringTemplate, idDrone, residual);

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

    /* Prepare coap socket*/
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    /* The destination endpoint */
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    /* Prepare the request */
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
    /*coap_register_response_handler(ctx, message_handler);
    coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
    coap_send(ctx, ctx->endpoint, &dst_addr, request);
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
    }*/

    coap_send(ctx, ctx->endpoint, &dst_addr, request);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
}


void UdpBasicAppJolie::sendAlertSingleUAV_CoAP(int idDrone, double x, double y) {
    char buff[512];
    unsigned char buf[3];
    int buffStrLen;

    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP BEGIN" << std::flush << endl;

    std::cout << simTime() << " - (" << myAppAddr << "|" << myIPAddr << ")[GWY] Sending CoAP alert for Drone: " << idDrone << " with position (" << x << ";" << y << ")" << endl;
    memset (buff, 0, sizeof(buff));

    //{\"drone\":{\"id\":%d},\"position\":{\"x\":%.02lf,\"y\":%.02lf}}
    buffStrLen = snprintf(buff, sizeof(buff), droneAlertStringTemplate, idDrone, x, y);

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

    /* Prepare coap socket*/
    coap_address_init(&src_addr);
    src_addr.addr.sin.sin_family      = AF_INET;
    src_addr.addr.sin.sin_port        = htons(0);
    src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    ctx = coap_new_context(&src_addr);

    /* The destination endpoint */
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family      = AF_INET;
    dst_addr.addr.sin.sin_port        = htons(jolieAddressPort);
    //dst_addr.addr.sin.sin_addr.s_addr = inet_addr("192.168.1.177");
    dst_addr.addr.sin.sin_addr.s_addr = inet_addr(jolieAddress);

    /* Prepare the request */
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
    /*coap_register_response_handler(ctx, message_handler);
    coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
    coap_send(ctx, ctx->endpoint, &dst_addr, request);
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
    }*/

    coap_send(ctx, ctx->endpoint, &dst_addr, request);


    //std::cout << "UdpBasicAppJolie::registerSingleUAV_CoAP END" << std::flush << endl;
}

} // namespace inet

