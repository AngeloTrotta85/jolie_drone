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


#include "UdpBasicAppJolie.h"

#include <arpa/inet.h>

#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

namespace inet {

Define_Module(UdpBasicAppJolie);

UdpBasicAppJolie::~UdpBasicAppJolie()
{
    cancelAndDelete(selfMsg);
}

void UdpBasicAppJolie::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    std::cout << "UdpBasicAppJolie::initialize BEGIN - Stage " << stage << std::flush << endl;

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

        coapServer_loopTimer = 0.1;

        myAppAddr = this->getParentModule()->getIndex();
        myIPAddr = Ipv4Address::UNSPECIFIED_ADDRESS;

        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new cMessage("sendTimer");

        coapServer_selfMsg = new cMessage("coapServer_loop");
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);
    }
    else if (stage == INITSTAGE_LAST) {
        addressTable.resize(this->getParentModule()->getParentModule()->getSubmodule("host", 0)->getVectorSize(), Ipv4Address::UNSPECIFIED_ADDRESS);

        serverCoAP_init();
    }

    std::cout << "UdpBasicAppJolie::initialize END - Stage " << stage << std::flush << endl;
}

void UdpBasicAppJolie::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
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

void UdpBasicAppJolie::sendPacket()
{
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    auto creationTimeTag = payload->addTag<CreationTimeTag>();
    creationTimeTag->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = chooseDestAddr();
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void UdpBasicAppJolie::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
    setSocketOptions();

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;

    while ((token = tokenizer.nextToken()) != nullptr) {
        destAddressStr.push_back(token);
        L3Address result;
        L3AddressResolver().tryResolve(token, result);
        if (result.isUnspecified())
            EV_ERROR << "cannot resolve destination address: " << token << endl;
        destAddresses.push_back(result);
    }

    IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
    if (ift) {
        for (int i = 0; i < (int)addressTable.size(); i++) {

            char buf[32];
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

    registerUAVs_CoAP_init();
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
        serverCoAP_mainLoop();
        scheduleAt(simTime() + coapServer_loopTimer, coapServer_selfMsg);
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
        processPacket(check_and_cast<Packet *>(msg));
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
}

void UdpBasicAppJolie::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
    delete pk;
    numReceived++;
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
policy_handler(coap_context_t *ctx, struct coap_resource_t *resource,
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

void UdpBasicAppJolie::serverCoAP_thread(void) {

    coap_address_t   serv_addr;
    coap_resource_t* policy_resource;
    fd_set           readfds;

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
    coap_register_handler(policy_resource, COAP_REQUEST_GET, policy_handler);
    coap_add_resource(ctx, policy_resource);

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

void UdpBasicAppJolie::serverCoAP_init(void) {

    //std::thread first (std::bind(&UdpBasicAppJolie::serverCoAP_thread, this));     // spawn new thread that calls foo()
    //std::thread first (serverCoAP_thread_test);     // spawn new thread that calls foo()

    t_coap = std::thread (std::bind(&UdpBasicAppJolie::serverCoAP_thread, this));

}

void UdpBasicAppJolie::serverCoAP_mainLoop(void) {

}

static void
message_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
        const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received,
        const coap_tid_t id)
{
    unsigned char* data;
    size_t         data_len;
    if (COAP_RESPONSE_CLASS(received->hdr->code) == 2)
    {
        if (coap_get_data(received, &data_len, &data))
        {
            //printf("Received: %s\n", data);
            std::cout << "Received |" << data << "| after CoAP Drone registration" << endl;
        }
    }
}

void UdpBasicAppJolie::registerUAVs_CoAP_init(void) {
    char buff[32];
    unsigned int i = 0;
    int buffStrLen;

    std::cout << "UdpBasicAppJolie::registerUAVs_CoAP_init BEGIN" << std::flush << endl;

    for (auto& a : addressTable) {
        std::cout << "Sending CoAP registration for Drone: " << i << " having local IP: " << a << endl;
        memset (buff, 0, sizeof(buff));
        buffStrLen = snprintf(buff, sizeof(buff), "Drone%d", i);

        coap_context_t*   ctx;
        coap_address_t    dst_addr, src_addr;
        static coap_uri_t uri;
        fd_set            readfds;
        coap_pdu_t*       request;
        const char*       server_uri = "coap://127.0.0.1/register";
        unsigned char     get_method = 1;

        /* Prepare coap socket*/
        coap_address_init(&src_addr);
        src_addr.addr.sin.sin_family      = AF_INET;
        src_addr.addr.sin.sin_port        = htons(0);
        src_addr.addr.sin.sin_addr.s_addr = inet_addr("0.0.0.0");
        ctx = coap_new_context(&src_addr);

        /* The destination endpoint */
        coap_address_init(&dst_addr);
        dst_addr.addr.sin.sin_family      = AF_INET;
        dst_addr.addr.sin.sin_port        = htons(5683);
        dst_addr.addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1");

        /* Prepare the request */
        coap_split_uri((const unsigned char *)server_uri, strlen(server_uri), &uri);
        request            = coap_new_pdu();
        request->hdr->type = COAP_MESSAGE_CON;
        request->hdr->id   = coap_new_message_id(ctx);
        request->hdr->code = get_method;
        coap_add_data  (request, buffStrLen, (unsigned char *)buff);
        coap_add_option(request, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);

        /* Set the handler and send the request */
        coap_register_response_handler(ctx, message_handler);
        coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
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

        ++i;
    }

    std::cout << "UdpBasicAppJolie::registerUAVs_CoAP_init END" << std::flush << endl;
}

} // namespace inet

