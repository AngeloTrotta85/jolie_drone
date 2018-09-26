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

#ifndef __INET_UDPBASICAPPJOLIE_H
#define __INET_UDPBASICAPPJOLIE_H

//#ifndef COAP_MAX_PDU_SIZE
//#define COAP_MAX_PDU_SIZE      165000 /* maximum size of a CoAP PDU */
//#endif /* COAP_MAX_PDU_SIZE */

#include <inet/common/INETDefs.h>

#include <coap.h>
#include <vector>
#include <thread>         // std::thread
#include <mutex>          // std::mutex

#include <arpa/inet.h>
#include <cstdio>

#include <inet/applications/base/ApplicationPacket_m.h>
#include <inet/applications/base/ApplicationBase.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <inet/common/geometry/common/Coord.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "../base/ApplicationBeacon_m.h"
#include "../base/ApplicationPolicy_m.h"
#include "../base/ApplicationDroneAlert_m.h"
#include "../base/ApplicationDronePosition_m.h"
#include "../base/ApplicationDroneEnergy_m.h"
#include "../base/ApplicationDroneRegister_m.h"
#include "../base/ApplicationDroneImage_m.h"

#include "inet/mobility/single/VirtualSpringMobility.h"

#define P_COVER 1
#define P_STOP 2
#define P_FOCUS 3

#define A_NONE 1
#define A_IMAGE 2
#define A_DETECT 3

#define SPRING_COVER_IDX 0
#define SPRING_STOP_IDX 1
#define SPRING_FOCUS_IDX 2

/*
typedef struct {
  size_t length;    // length of string
  unsigned char *s; // string data
} str;
*/

namespace inet {

/*
class Policy {
public:
    typedef struct spring {
        int s_id;
        char s_name[32];

        double distance;
        Coord position;
        double stiffness;

        double period;
    } spring;

public:
    int p_id;
    char p_name[32];

    std::list <spring> springs;

    int a_id;
    char a_name[32];

    int uav_id;

public:
    Policy() {
        p_id = -1;
        sprintf(p_name, "");

        a_id = -1;
        sprintf(a_name, "");

        uav_id = -1;
    };

    friend std::ostream& operator<< (std::ostream& stream, const Policy& pol) {
        stream
                << "Policy ID: " << pol.p_id << "; "
                << "Policy name: " << pol.p_name << "; "
                << "Action ID: " << pol.a_id << "; "
                << "Action name: " << pol.a_name << "; "
                << "drone ID: " << pol.uav_id << "; ";
        for (auto& s : pol.springs) {
            stream
                << "Spring ID: " << s.s_id << "; "
                << "Spring name: " << s.s_name << "; "
                << "distance: " << s.distance << "; "
                << "position: " << s.position << "; "
                << "stiffness: " << s.stiffness << "; "
                << "period: " << s.period;
        }
        return stream;
    };
};
*/


/**
 * UDP application. See NED for more info.
 */
class INET_API UdpBasicAppJolie : public ApplicationBase
{
public:

    typedef struct {
        simtime_t timestamp_lastSeen;
        node_info_msg_t info;
        int uavReferee;
        bool isGW;
    } neigh_info_t;

    typedef struct spring {
        int s_id;
        char s_name[32];

        double distance;
        Coord position;
        double stiffness;
    } spring;

    typedef struct policy {
        int p_id;
        char p_name[32];

        int drone_id;

        int a_id;
        char a_name[32];
        double a_period;

        spring springs[3];

        policy() {
            p_id = drone_id = a_id = -1;
            p_name[0] = 0;
            a_name[0] = 0;
            a_period = 0;
            for (auto& s : springs) {
                s.s_id = -1;
                s.s_name[0] = 0;
                s.distance = s.stiffness = 0;
                s.position = Coord(0, 0);
            }
        }

    } policy;

    friend std::ostream& operator<< (std::ostream& stream, const policy& pol) {
        stream
                << "Policy ID: " << pol.p_id << "; "
                << "Policy name: " << pol.p_name << "; "
                << "Action ID: " << pol.a_id << "; "
                << "Action name: " << pol.a_name << "; "
                << "Action period: " << pol.a_period << "; "
                << "drone ID: " << pol.drone_id << "; ";
        for (auto& s : pol.springs) {
            stream
                << "Spring ID: " << s.s_id << "; "
                << "Spring name: " << s.s_name << "; "
                << "distance: " << s.distance << "; "
                << "position: " << s.position << "; "
                << "stiffness: " << s.stiffness;
        }
        return stream;
    }

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

    // JSON message template
    const char *droneRegisterStringTemplate = nullptr;
    const char *dronePositionStringTemplate = nullptr;
    const char *droneEnergyStringTemplate = nullptr;
    const char *droneAlertStringTemplate = nullptr;
    const char *droneImageStringTemplateP1 = nullptr;
    const char *droneImageStringTemplateP2 = nullptr;

    // address in the REAL world
    const char *jolieAddress = nullptr;
    int jolieAddressPort;
    const char *gatewayRealAddress = nullptr;
    int gatewayRealAddressPort;

    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;

    int myAppAddr;
    Ipv4Address myIPAddr;
    std::vector<Ipv4Address> addressTable;

    //CoAP
    cMessage *coapServer_selfMsg = nullptr;
    double coapServer_loopTimer;
    coap_context_t*  ctx;
    std::thread t_coap;

    // statistics
    int numSent = 0;
    int numReceived = 0;

    //internal variables
    IMobility *mob;

    cMessage *self1Sec_selfMsg = nullptr;

    std::map<Ipv4Address, std::list<neigh_info_t>> neighMap;


    cMessage *alertStart_selfMsg = nullptr;

public:
    //thread variables
    static std::list<policy> policy_queue;
    static std::mutex policy_queue_mtx;

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

    void serverCoAP_thread(void);

    void msg1sec_call(void);

    virtual void manageReceivedBeacon(Packet *msg);
    virtual Packet *createBeaconPacket();
    int getCloserUAV(void);

    virtual void send_policy_to_drone(policy* p);

    void manageNewRegistration(Packet *pk);
    void manageNewPosition(Packet *pk);
    void manageNewEnergy(Packet *pk);
    void manageNewAlert(Packet *pk);
    void manageNewImage(Packet *pk);

    void loadImageFromFile(std::stringstream &ss);

    virtual void serverCoAP_checkLoop(void);
    virtual void serverCoAP_init(void);
    virtual void registerUAVs_CoAP_init(void);

    void registerSingleUAV_CoAP(int idDrone);
    void sendPositionSingleUAV_CoAP(int idDrone, double x, double y);
    void sendEnergySingleUAV_CoAP(int idDrone, double residual);
    void sendAlertSingleUAV_CoAP(int idDrone, double x, double y, double acc, const char *classe);
    void sendImageSingleUAV_CoAP(int idDrone, double x, double y);
    //void sendBigImageSingleUAV_CoAP(int idDrone, double x, double y);

public:
    UdpBasicAppJolie() {}
    ~UdpBasicAppJolie();

    //void policyPostHandler(coap_context_t *ctx, struct coap_resource_t *resource,
    //        const coap_endpoint_t *local_interface, coap_address_t *peer,
    //        coap_pdu_t *request, struct str *token, coap_pdu_t *response);

    //static void addNewPolicy(policy &p);
    static void manageReceivedPolicy(rapidjson::Document &doc);
};

} // namespace inet

#endif // ifndef __INET_UDPBASICAPPJOLIE_H

