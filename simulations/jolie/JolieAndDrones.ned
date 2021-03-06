//
// Copyright (C) 2006 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

package jolie_drone.simulations.jolie;

//import inet.common.lifecycle.LifecycleController;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
//import inet.node.inet.AdhocHost;
import inet.node.aodv.AodvRouter;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.contract.IIntegratedVisualizer;

network JolieAndDrones
{
    parameters:
        int numDrones = default(0);
    submodules:
        visualizer: <default("IntegratedCanvasVisualizer")> like IIntegratedVisualizer if hasVisualizer() {
            parameters:
                @display("p=100,50");
        }
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=100,150");
        }
        radioMedium: Ieee80211ScalarRadioMedium {
            parameters:
                @display("p=100,250");
        }
        gateway: AodvRouter {
            parameters:
                @display("p=150,58;i=device/accesspoint");
        }
        //lifecycleController: LifecycleController {
        //    parameters:
        //        @display("p=100,350");
        //}
        host[numDrones]: AodvRouter {
            parameters:
                @display("r=,,#707070;p=250,58");
        }
}
