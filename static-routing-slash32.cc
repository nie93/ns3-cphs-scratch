/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
*/

// Test program for this 3-router scenario, using static routing
//
// (a.a.a.a/32)A<--x.x.x.0/30-->B<--y.y.y.0/30-->C(c.c.c.c/32)

#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include <boost/crc.hpp>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/v4ping-helper.h"

using namespace ns3;

boost::uint16_t get_ccitt_checksum(void) {

  unsigned char data[] = { 
    0xaa, 0x41, 
    0x00, 0x12, 
    0x00, 0x01, 
    0x5e, 0x69, 0x69, 0xf0, 
    0x00, 0x00, 0x14, 0x4c, 
    0x00, 0x02 };
  std::size_t const    data_len = sizeof( data ) / sizeof( data[0] );
  boost::crc_basic<16>  crc_ccitt( 0x1021, 0xFFFF, 0, false, false );
  crc_ccitt.process_bytes( data, data_len );
  boost::uint16_t const  expected = 0x323d; // The expected CRC for the given data

  std::cout << std::hex 
    << "crc_ccitt()     : 0x" << crc_ccitt.checksum() << std::endl
    << "expected        : 0x" << expected << std::endl << std::dec;

  return crc_ccitt.checksum();
}
 
class StackHelper {
public:
  
  inline void AddAddress (Ptr<Node> n, uint32_t interface, Ipv6Address address)
  {
    Ptr<Ipv6> ipv6 = n->GetObject<Ipv6> ();
    ipv6->AddAddress (interface, address);
  }
  
  inline void PrintIpv4Address(Ptr<Node> n, std::string name) {  
    Ptr<Ipv4> ipv4 = n->GetObject<Ipv4> ();
    std::cout << "  Ipv4 Addresses of \"" << name << "\" : "<< std::endl;
    for (uint32_t j=1; j<ipv4->GetNInterfaces (); j++) {
      Ipv4InterfaceAddress iaddr = n->GetObject<Ipv4> ()->GetAddress (j, 0);
      std::cout << "    Iface " << j << ": " << iaddr.GetLocal() << std::endl ;
    }
  }

  inline void PrintIpv4RoutingTable (Ptr<Node> n, std::string name)
  {
    Ptr<Ipv4StaticRouting> routing = 0;
    Ipv4StaticRoutingHelper routingHelper;
    Ptr<Ipv4> ipv4 = n->GetObject<Ipv4> ();
    Ipv4RoutingTableEntry route;

    routing = routingHelper.GetStaticRouting (ipv4);

    std::cout << "  Routing table of \"" << name << "\" : " << std::endl;
    std::cout << "    Destination\t" << "Mask\t\t" << "Gateway\t\t" << "Iface\t" << std::endl;

    for (uint32_t i = 0; i < routing->GetNRoutes (); i++) {
      route = routing->GetRoute (i);
      std::cout << "    " 
        << route.GetDest () << "\t"
        << route.GetDestNetworkMask () << "\t"
        << route.GetGateway () << "\t"
        << route.GetInterface () << "\t"
        << std::endl;
    }
  }

  inline void PrintIpv6RoutingTable (Ptr<Node> n)
  {
    Ptr<Ipv6StaticRouting> routing = 0;
    Ipv6StaticRoutingHelper routingHelper;
    Ptr<Ipv6> ipv6 = n->GetObject<Ipv6> ();
    uint32_t nbRoutes = 0;
    Ipv6RoutingTableEntry route;

    routing = routingHelper.GetStaticRouting (ipv6);

    std::cout << "Routing table of " << n << " : " << std::endl;
    std::cout << "Destination\t\t\t\t" << "Gateway\t\t\t\t\t" << "Interface\t" <<  "Prefix to use" << std::endl;

    nbRoutes = routing->GetNRoutes ();
    for (uint32_t i = 0; i < nbRoutes; i++) {
      route = routing->GetRoute (i);
      std::cout << route.GetDest () << "\t"
        << route.GetGateway () << "\t"
        << route.GetInterface () << "\t"
        << route.GetPrefixToUse () << "\t"
        << std::endl;
    }
  }
};
 
NS_LOG_COMPONENT_DEFINE ("StaticRoutingSlash32Test");

int main (int argc, char *argv[]) {

  LogComponentEnable ("PacketSink",               LOG_LEVEL_INFO);
  LogComponentEnable ("V4Ping",                   LOG_LEVEL_INFO);
  LogComponentEnable ("UdpServer",                LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);

  // Run as Real-Time Simulation
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Allow the user to override any of the defaults and the above
  // DefaultValue::Bind ()s at run-time, via command-line arguments
  CommandLine cmd;
  cmd.Parse (argc, argv);

  Ptr<Node> nA       = CreateObject<Node> ();
  Ptr<Node> nA2      = CreateObject<Node> ();
  Ptr<Node> nA3      = CreateObject<Node> ();
  Ptr<Node> nB       = CreateObject<Node> ();
  Ptr<Node> nC       = CreateObject<Node> ();
  Ptr<Node> nC2      = CreateObject<Node> ();
  Ptr<Node> nTNorth  = CreateObject<Node> ();
  Ptr<Node> nD       = CreateObject<Node> ();
  Ptr<Node> nD2      = CreateObject<Node> ();
  Ptr<Node> nD3      = CreateObject<Node> ();
  Ptr<Node> nE       = CreateObject<Node> ();
  Ptr<Node> nF       = CreateObject<Node> ();
  Ptr<Node> nF2      = CreateObject<Node> ();
  Ptr<Node> nTSouth  = CreateObject<Node> ();

  NodeContainer nodeContainerAA = NodeContainer (nA, nA2, nA3);
  NodeContainer nodeContainerCT = NodeContainer (nC, nC2, nTNorth);
  NodeContainer nodeContainerDD = NodeContainer (nD, nD2, nD3);
  NodeContainer nodeContainerFT = NodeContainer (nF, nF2, nTSouth);

  // Point-to-point links
  NodeContainer nAnB = NodeContainer (nA, nB);
  NodeContainer nBnC = NodeContainer (nB, nC);
  // NodeContainer nBnD = NodeContainer (nB, nD);
  // NodeContainer nBnF = NodeContainer (nB, nF);
  NodeContainer nCnE = NodeContainer (nC, nE);
  NodeContainer nDnE = NodeContainer (nD, nE);

  InternetStackHelper internet;
  internet.Install (nB);
  internet.Install (nE);
  internet.Install (nodeContainerAA);
  internet.Install (nodeContainerCT);
  internet.Install (nodeContainerDD);
  internet.Install (nodeContainerFT);

  // We create the channels first without any IP addressing information
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("50ms"));
  NetDeviceContainer dAdB = p2p.Install (nAnB);
  NetDeviceContainer dBdC = p2p.Install (nBnC);
  // NetDeviceContainer dBdD = p2p.Install (nBnD);
  // NetDeviceContainer dBdF = p2p.Install (nBnF);
  NetDeviceContainer dCdE = p2p.Install (nCnE);
  NetDeviceContainer dDdE = p2p.Install (nDnE);

  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("300Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (0)));

  NetDeviceContainer csmaDevicesAA = csma.Install (nodeContainerAA);
  NetDeviceContainer csmaDevicesCT = csma.Install (nodeContainerCT);
  NetDeviceContainer csmaDevicesDD = csma.Install (nodeContainerDD);
  NetDeviceContainer csmaDevicesFT = csma.Install (nodeContainerFT);

  std::string tapNorthName = "nstap00";
  std::string tapSouthName = "nstap01";
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));
  tapBridge.SetAttribute ("DeviceName", StringValue (tapNorthName));
  // tapBridge.Install (nTNorth, csmaDevicesCT.Get (2));

  // Later, we add IP addresses.
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.252");
  Ipv4InterfaceContainer iAiB = ipv4.Assign (dAdB);
  ipv4.SetBase ("10.1.1.4", "255.255.255.252");
  Ipv4InterfaceContainer iBiC = ipv4.Assign (dBdC);
  ipv4.SetBase ("10.1.1.8", "255.255.255.252");
  // Ipv4InterfaceContainer iBiD = ipv4.Assign (dBdD);
  // ipv4.SetBase ("10.1.1.12", "255.255.255.252");
  // Ipv4InterfaceContainer iBiF = ipv4.Assign (dBdF);
  // ipv4.SetBase ("10.1.1.16", "255.255.255.252");
  Ipv4InterfaceContainer iCiE = ipv4.Assign (dCdE);
  ipv4.SetBase ("10.1.1.12", "255.255.255.252");
  Ipv4InterfaceContainer iDiE = ipv4.Assign (dDdE);
  ipv4.SetBase ("10.1.1.16", "255.255.255.252");

  ipv4.SetBase ("172.16.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iAs = ipv4.Assign (csmaDevicesAA);
  ipv4.SetBase ("172.16.31.0", "255.255.255.0");
  Ipv4InterfaceContainer iDs = ipv4.Assign (csmaDevicesDD);


  ipv4.SetBase ("192.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iCiTNorth = ipv4.Assign (csmaDevicesCT);
  ipv4.SetBase ("192.168.31.0", "255.255.255.0");
  Ipv4InterfaceContainer iFiTSouth = ipv4.Assign (csmaDevicesFT);

  
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // Ipv4StaticRoutingHelper ipv4RoutingHelper;
  // Ptr<Ipv4StaticRouting> staticOutRouteA = ipv4RoutingHelper.GetStaticRouting (nA->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> staticOutRouteA3 = ipv4RoutingHelper.GetStaticRouting (nA3->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> staticOutRouteB = ipv4RoutingHelper.GetStaticRouting (nB->GetObject<Ipv4> ());                                  
  // Ptr<Ipv4StaticRouting> staticOutRouteC = ipv4RoutingHelper.GetStaticRouting (nC->GetObject<Ipv4> ());                                  
  // Ptr<Ipv4StaticRouting> staticOutRouteC2 = ipv4RoutingHelper.GetStaticRouting (nC2->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> staticOutRouteF = ipv4RoutingHelper.GetStaticRouting (nF->GetObject<Ipv4> ());                                  
  // Ptr<Ipv4StaticRouting> staticOutRouteF2 = ipv4RoutingHelper.GetStaticRouting (nF2->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> staticOutRouteTNorth = ipv4RoutingHelper.GetStaticRouting (nTNorth->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> staticOutRouteTSouth = ipv4RoutingHelper.GetStaticRouting (nTSouth->GetObject<Ipv4> ());

  // staticOutRouteA->AddNetworkRouteTo 
  //   (Ipv4Address("192.168.1.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.2"), 1);
  // staticOutRouteA3->AddNetworkRouteTo 
  //   (Ipv4Address("192.168.1.0"), Ipv4Mask("/24"), Ipv4Address("172.16.1.1"), 1);

  // staticOutRouteB->AddNetworkRouteTo 
  //   (Ipv4Address("192.168.1.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.6"), 2);
  // staticOutRouteB->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.1.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.1"), 1);
  // staticOutRouteB->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.31.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.10"), 3);

  // staticOutRouteC->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.1.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.5"), 1);
  // staticOutRouteC->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.31.0"), Ipv4Mask("/24"), Ipv4Address("10.1.1.10"), 1);
  // staticOutRouteC2->AddNetworkRouteTo
  //   (Ipv4Address("172.16.1.0"), Ipv4Mask("/24"), Ipv4Address("192.168.1.1"), 1);

  // staticOutRouteTNorth->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.1.0"), Ipv4Mask("/24"), Ipv4Address("192.168.1.1"), 1);
  // staticOutRouteTNorth->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.31.0"), Ipv4Mask("/24"), Ipv4Address("192.168.1.1"), 1);
    


  // Create the UdpEcho client/server application to send UDP datagrams of size
  // [172.16.31.3]  <---> [192.168.1.2]
  Ptr<Node> fromN = nD3;
  Ptr<Node> toN = nC2;
  Ipv4InterfaceAddress ifInAddrTo = toN->GetObject<Ipv4> ()->GetAddress (1, 0);

  uint16_t port = 9;   // Discard port (RFC 863)
  UdpEchoClientHelper udpEchoClient (InetSocketAddress (ifInAddrTo.GetLocal (), port));
  udpEchoClient.SetAttribute ("MaxPackets", UintegerValue (1000));
  udpEchoClient.SetAttribute ("PacketSize", UintegerValue (1040));
  ApplicationContainer udpClientApp = udpEchoClient.Install (fromN);
  udpClientApp.Start (Seconds (1.0));
  udpClientApp.Stop (Seconds (9.0));

  UdpEchoServerHelper udpEchoServer (port);
  ApplicationContainer udpServerApp = udpEchoServer.Install (toN);
  udpServerApp.Start (Seconds (1.0));
  udpServerApp.Stop (Seconds (9.80));


  // Create the UdpServer application to receive C37.118 synphasor UDP packets
  UdpServerHelper udpServer (4713);
  ApplicationContainer udpPdcApps01 = udpServer.Install (nA3);
  udpPdcApps01.Start (Seconds (0.0)); 
  udpPdcApps01.Stop (Seconds (9.90));
  ApplicationContainer udpPdcApps31 = udpServer.Install (nD3);
  udpPdcApps31.Start (Seconds (0.0)); 
  udpPdcApps31.Stop (Seconds (9.90));


  StackHelper stackHelper;
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nA, "nA");
  stackHelper.PrintIpv4RoutingTable (nA, "nA");
  stackHelper.PrintIpv4Address      (nA2, "nA2");
  stackHelper.PrintIpv4RoutingTable (nA2, "nA2");
  stackHelper.PrintIpv4Address      (nA3, "nA3");
  stackHelper.PrintIpv4RoutingTable (nA3, "nA3");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nB, "nB");
  stackHelper.PrintIpv4RoutingTable (nB, "nB");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nC, "nC");
  stackHelper.PrintIpv4RoutingTable (nC, "nC");
  stackHelper.PrintIpv4Address      (nC2, "nC2");
  stackHelper.PrintIpv4RoutingTable (nC2, "nC2");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nD, "nD");
  stackHelper.PrintIpv4RoutingTable (nD, "nD");
  stackHelper.PrintIpv4Address      (nD2, "nD2");
  stackHelper.PrintIpv4RoutingTable (nD2, "nD2");
  stackHelper.PrintIpv4Address      (nD3, "nD3");
  stackHelper.PrintIpv4RoutingTable (nD3, "nD3");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nE, "nE");
  stackHelper.PrintIpv4RoutingTable (nE, "nE");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nF, "nF");
  stackHelper.PrintIpv4RoutingTable (nF, "nF");
  stackHelper.PrintIpv4Address      (nF2, "nF2");
  stackHelper.PrintIpv4RoutingTable (nF2, "nF2");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nTNorth, "nTNorth");
  stackHelper.PrintIpv4RoutingTable (nTNorth, "nTNorth");
  std::cout << "--------------------------------------" << std::endl;
  stackHelper.PrintIpv4Address      (nTSouth, "nTSouth");
  stackHelper.PrintIpv4RoutingTable (nTSouth, "nTSouth");
  std::cout << "--------------------------------------" << std::endl;

  AsciiTraceHelper ascii;
  p2p.EnableAsciiAll (ascii.CreateFileStream ("etc/static-routing-slash32/static-routing-slash32.tr"));
  p2p.EnablePcapAll  ("etc/static-routing-slash32/PCAPs/p2p-");
  csma.EnablePcapAll ("etc/static-routing-slash32/PCAPs/csma-");

  AnimationInterface::SetConstantPosition (nA,  5, 3);
  AnimationInterface::SetConstantPosition (nA2, 3, 1);
  AnimationInterface::SetConstantPosition (nA3, 3, 5);
  AnimationInterface::SetConstantPosition (nB, 15, 3);
  AnimationInterface::SetConstantPosition (nC, 25, 3);
  AnimationInterface::SetConstantPosition (nC2, 27, 5);
  AnimationInterface::SetConstantPosition (nTNorth, 27, 1);
  AnimationInterface::SetConstantPosition (nD,  5, 23);
  AnimationInterface::SetConstantPosition (nD2, 3, 21);
  AnimationInterface::SetConstantPosition (nD3, 3, 25);
  AnimationInterface::SetConstantPosition (nE,  15, 23);
  AnimationInterface::SetConstantPosition (nF, 25, 23);
  AnimationInterface::SetConstantPosition (nF2, 27, 25);
  AnimationInterface::SetConstantPosition (nTSouth, 27, 21);

  AnimationInterface anim ("etc/static-routing-slash32/anim.xml");
  anim.UpdateNodeDescription (nA,  "nA:  172.16.1.1");
  anim.UpdateNodeDescription (nA2, "nA2: 172.16.1.2");
  anim.UpdateNodeDescription (nA3, "nA3: 172.16.1.3");
  anim.UpdateNodeDescription (nB,  "nB:  10.1.1.{2,5,9,13}");
  anim.UpdateNodeDescription (nC,  "nC:  10.1.1.6, 192.168.1.1");
  anim.UpdateNodeDescription (nC2, "nC2: 192.168.1.2");
  anim.UpdateNodeDescription (nD,  "nD:  172.16.31.1");
  anim.UpdateNodeDescription (nD2, "nD2: 172.16.31.2");
  anim.UpdateNodeDescription (nD3, "nD3: 172.16.31.3");
  anim.UpdateNodeDescription (nE,  "nE:  10.1.1.{10,14}");
  // anim.UpdateNodeDescription (nF,  "nF:  10.1.1.14, 192.168.31.1");
  // anim.UpdateNodeDescription (nF2, "nF2: 192.168.31.2");
  anim.UpdateNodeDescription (nTNorth,  "nTNorth:  192.168.1.3");
  // anim.UpdateNodeDescription (nTSouth,  "nTSouth:  192.168.31.3");
  anim.UpdateNodeColor       (nTNorth, 0, 0, 0); // gray
  anim.UpdateNodeColor       (nTSouth, 0, 0, 0); // gray


  get_ccitt_checksum();

  Simulator::Stop (Seconds(10.0));
  Simulator::Run ();  
  Simulator::Destroy ();

  return 0;
}