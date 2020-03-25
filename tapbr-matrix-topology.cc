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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

// ---------- Header Includes -------------------------------------------------
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/modes.h>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/applications-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/assert.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/v4ping-helper.h"
#include "ns3/udp-client-server-helper.h"

#define ATTACK_TARGET_NODE_NUMBER 17
#define ATTACK_START_TIME         3.0000
#define ATTACK_STOP_TIME          3.0100
#define ATTACK_PACKET_SENT        100
#define CONST_RANDOM_NUMBER_SEED  1008611
#define CTRLCTR_HOST_NODE         17
#define HIJACKED_NODE_NUMBER      23
#define LISTENING_PORT_START_TIME 1.0001
#define LISTENING_PORT_STOP_TIME  9.9000
#define TCP_DOS_SINK_PORT         9089
#define TCP_SINK_PORT             11
#define UDP_HEARTBEAT_ECHO_PORT   60001
#define UDP_DOS_SINK_PORT         9099
#define UDP_ECHO_PORT             9009
#define UDP_SINK_PORT             9
#define NORMAL_TCP_COMM_TIMES     100

using namespace std;
using namespace ns3;

// ---------- Prototypes ------------------------------------------------------

vector<vector<bool> > readNxNMatrix (std::string adj_mat_file_name);
vector<vector<double> > readCordinatesFile (std::string node_coordinates_file_name);
void printCoordinateArray (const char* description, vector<vector<double> > coord_array);
void printMatrix (const char* description, vector<vector<bool> > array);
vector<std::string> readNodeNames (std::string node_names_file_name);
Ipv4Address getNodeIpv4Addr(Ptr<Node> n, uint j);
void printNodesIpv4Addr(NodeContainer nodes, std::vector<std::string> names);


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


// TypeId PdcApplication::GetTypeId (void) {
//   static TypeId tid = TypeId ("ns3::PdcApplication")
//     .SetParent<Application> ()
//     .SetGroupName("Applications")
//     .AddConstructor<PdcApplication> ()
//     .AddAttribute ("Remote", "The address of the destination",
//                    AddressValue (),
//                    MakeAddressAccessor (&PdcApplication::m_peer),
//                    MakeAddressChecker ())
//     .AddAttribute ("PmuID", "The PMU ID of the device",
//                    UintegerValue (0),
//                    MakeUintegerAccessor (&PdcApplication::m_pmuid),
//                    MakeUintegerChecker<uint16_t> ())
//     .AddAttribute ("Protocol", "The type of protocol to use. This should be "
//                    "a subclass of ns3::SocketFactory",
//                    TypeIdValue (UdpSocketFactory::GetTypeId ()),
//                    MakeTypeIdAccessor (&PdcApplication::m_tid),
//                    // This should check for SocketFactory as a parent
//                    MakeTypeIdChecker ())
//     .AddTraceSource ("Tx", "A new packet is created and is sent",
//                      MakeTraceSourceAccessor (&PdcApplication::m_txTrace),
//                      "ns3::Packet::TracedCallback")
//     .AddTraceSource ("TxWithAddresses", "A new packet is created and is sent",
//                      MakeTraceSourceAccessor (&PdcApplication::m_txTraceWithAddresses),
//                      "ns3::Packet::TwoAddressTracedCallback")
//   ;
//   return tid;
// }


// PdcApplication::PdcApplication () 
//   : m_socket (0),
//     m_running ()
// {
//   NS_LOG_FUNCTION (this);
// }

// PdcApplication::~PdcApplication () {
//   NS_LOG_FUNCTION (this);
// }

// void PdcApplication::DoDispose (void) {
//   NS_LOG_FUNCTION (this);
//   m_socket = 0;
//   Application::DoDispose ();
// }

// void PdcApplication::StartApplication (void) {
//   m_running = true;
//   m_packetsSent = 0;
//   m_socket->Bind ();
//   m_socket->Connect (m_peer);
//   SendPacket ();
// }

// void PdcApplication::StopApplication (void) {
//   m_running = false;

//   if (m_sendEvent.IsRunning ()) {
//     Simulator::Cancel (m_sendEvent);
//   }

//   if (m_socket) {
//     m_socket->Close ();
//   }
// }


// C37118CommandFrame::C37118CommandFrame () {}

// C37118CommandFrame::C37118CommandFrame (const Time &t) 
//   : m_time (t) {
// }

// C37118CommandFrame::~C37118CommandFrame () {}

// TypeId C37118CommandFrame::GetTypeId (void) {
//   static TypeId tid = TypeId ("ns3::C37118CommandFrame")
//     .SetParent<Header> ()
//     .AddConstructor<C37118CommandFrame> ();
//   return tid;
// }

// TypeId C37118CommandFrame::GetInstanceTypeId (void) const {
//   return GetTypeId ();
// }

// void C37118CommandFrame::Print (std::ostream &os) const {
//   // This method is invoked by the packet printing
//   // routines to print the content of my header.
//   os << "At Time = " << m_time << ", PDC request PMU ID: " << std::endl;
// }

// uint32_t C37118CommandFrame::GetSerializedSize (void) const {
//   // we reserve 2 bytes for our header.
//   return 2 * sizeof(uint32_t);
// }

// void C37118CommandFrame::Serialize (Buffer::Iterator start) const {
//   uint16_t m_sync, m_framesize, m_pmuid, m_cmd, m_chk;
//   uint32_t m_soc, m_fracsec;


//   // start.WriteU16 ( 0xaa41 );  // SYNC      (2)
//   // start.WriteU16 ( 0x0012 );  // FRAMESIZE (2)
//   // start.WriteU16 ( 0x0001 );  // IDCODE    (2)
//   // start.WriteU32 ( 0x0001 );  // SOC       (4)
//   // start.WriteU32 ( 0x0001 );  // FRACSEC   (4)
//   // start.WriteU16 ( 0x0001 );  // CMD       (2)
//   // start.WriteU16 ( 0x0001 );  // CHK       (2)

//   start.WriteU16 ( m_sync );     // SYNC      (2)
//   start.WriteU16 ( m_framesize );// FRAMESIZE (2)
//   start.WriteU16 ( m_pmuid );    // IDCODE    (2)
//   start.WriteU32 ( m_soc );      // SOC       (4)
//   start.WriteU32 ( m_fracsec );  // FRACSEC   (4)
//   start.WriteU16 ( m_cmd );      // CMD       (2)
//   start.WriteU16 ( m_chk );      // CHK       (2)

//   // uint32_t SOC, FRACSEC;
//   // double dSOC;
//   // FRACSEC = (uint32_t) (modf(m_timestamp.GetSeconds(), &dSOC) * TIME_BASE);
//   // SOC = (uint32_t) dSOC;
//   // FRACSEC &= 0xffffff;
//   // // Frame Size
//   // //Added frame size 
//   // //uint32_t frameSize = GetSerializedSize();
//   //   // IDCODE
//   // start.WriteU32(SOC);
//   // start.WriteU32(FRACSEC);
//   // //start.Write ((uint8_t *) &m_freq, sizeof (m_freq));
//   // // ??We dont have an individual frequency it is all packed in the vector we have to use the vector 
//   // //therefore the above line does not make sense.
//   // for(int i=0; i<m_vecMeasurements.size(); i++)
//   // {
//   //   start.WriteU16 (m_vecMeasurements[i].m_id);
//   //   start.WriteU32(m_vecMeasurements[i].freq);
//   // }
// }


// void C37118CommandFrame::SetData (const Time &t) {
//   m_timestamp = t;
// }

// Time C37118CommandFrame::GetTimeStamp(void) const {
//   return m_timestamp;
// }


class SpoofingApp : public Application {
 public:
   static TypeId GetTypeId (void);

   SpoofingApp ();
   virtual ~SpoofingApp();
 
   void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
   
 private:
   virtual void StartApplication (void);
   virtual void StopApplication (void);
 
   void ScheduleNextTx (void);
   void SendPacket (void);
 
   Ptr<Socket>     m_socket;
   Address         m_peer;
   uint32_t        m_packetSize;
   uint32_t        m_nPackets;
   uint32_t        m_counts;
   DataRate        m_dataRate;
   EventId         m_sendEvent;
   bool            m_running;
   uint32_t        m_packetsSent;
};
 
SpoofingApp::SpoofingApp ()
   : m_socket (0), 
     m_peer (), 
     m_packetSize (0), 
     m_nPackets (0), 
     m_counts (0),
     m_dataRate (0), 
     m_sendEvent (), 
     m_running (false), 
     m_packetsSent (0)
{
}
 
SpoofingApp::~SpoofingApp() {
  m_socket = 0;
}

TypeId SpoofingApp::GetTypeId (void) {
  static TypeId tid = TypeId ("ns3::SpoofingApp")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<SpoofingApp> ()
  ;
  return tid;
}

void SpoofingApp::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate) {
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void SpoofingApp::StartApplication (void) {
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();
}

void SpoofingApp::StopApplication (void) {
  m_running = false;

  if (m_sendEvent.IsRunning ()) {
    Simulator::Cancel (m_sendEvent);
  }

  if (m_socket) {
    m_socket->Close ();
  }
}

void SpoofingApp::SendPacket (void) {
  //Key and IV setup
  //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
  //bit). This key is secretly exchanged between two parties before communication   
  //begins. DEFAULT_KEYLENGTH= 16 bytes
  byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
  byte iv[ CryptoPP::AES::BLOCKSIZE ];
  memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

  std::string plaintext = "|PlainTextToBeEncryptedByAES-128-BitAlgorithm|";
  std::string ciphertext;
  std::string decryptedtext;

  CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
  CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
  stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() );
  stfEncryptor.MessageEnd();

  // CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  // CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
  // CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
  // stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
  // stfDecryptor.MessageEnd();

  // std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
  // std::cout << plaintext;
  // std::cout << std::endl << std::endl;

  // std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
  // for( uint i = 0; i < ciphertext.size(); i++ ) {
  //   std::cout  << std::hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
  // }
  // std::cout << std::dec << std::endl << std::endl;

  // std::cout << "Encrypted Text (" << ciphertext.size() << " bytes)" << std::endl;
  // std::cout << ciphertext;
  // std::cout << std::endl << std::endl;

  // std::cout << "Decrypted Text (" << decryptedtext.size() << " bytes)" << std::endl;
  // std::cout << decryptedtext;
  // std::cout << std::endl << std::endl;
  // std::cout << "---------------------------------------"<< std::endl;

  Ptr<Packet> pkt1 = Create<Packet> (
    reinterpret_cast<const uint8_t*> ( ciphertext.c_str() ), m_packetSize);

  Ptr<Packet> packet = Create<Packet> (m_packetSize);
  m_socket->Send (pkt1);

  if (++m_packetsSent < m_nPackets) {
    ScheduleNextTx ();
  }
}

void SpoofingApp::ScheduleNextTx (void) {
  Time tInterval = ( m_stopTime - m_startTime ) / m_nPackets;
  if (m_running) {
    // std::cout << "  "
    //   << Simulator::Now () << "  " << m_packetsSent << "/" << m_nPackets 
    //   << ": timeDelay = " << tInterval << std::endl;
    m_sendEvent = Simulator::Schedule (tInterval, &SpoofingApp::SendPacket, this);    
  }
}

NS_LOG_COMPONENT_DEFINE ("GenericTopologyCreation");

int main (int argc, char *argv[])
{  
  // ---------- Apply Logging Modules -----------------------------------------
  LogComponentEnable ("UdpServer",                LOG_LEVEL_DEBUG);
  LogComponentEnable ("GenericTopologyCreation",  LOG_LEVEL_DEBUG);
  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);

  // ---------- Simulation Variables ------------------------------------------;
  
  // Run as Real-Time Simulation
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  Config::SetDefault ("ns3::RateErrorModel::ErrorRate", DoubleValue (0.01));
  Config::SetDefault ("ns3::RateErrorModel::ErrorUnit", StringValue ("ERROR_UNIT_PACKET"));

  srand ( CONST_RANDOM_NUMBER_SEED );   // generate the same seed each time
  // srand ( (unsigned)time ( NULL ) );   // generate different seed each time

  double AppStartTime   = 4.0001;
  double AppStopTime    = 9.9001;
  double SimTime        = 30.00;

  //  DropTailQueue::MaxPackets affects the # of dropped packets, default value:100
  //  Config::SetDefault ("ns3::DropTailQueue::MaxPackets", UintegerValue (1000))

  std::string tr_name       ("etc/tapbr-matrix-topology/IEEE14-net.tr");
  std::string pcap_name     ("etc/tapbr-matrix-topology/PCAPs/IEEE14-net");
  std::string tap_pcap_name ("etc/tapbr-matrix-topology/PCAPs/IEEE14-tap");
  std::string flow_name     ("etc/tapbr-matrix-topology/IEEE14-net.flowmon.xml");
  std::string anim_name     ("etc/tapbr-matrix-topology/IEEE14-net.anim.xml");
  std::string adj_mat_file_name          ("scratch/matrix-topology_IEEE14_adjacency_matrix.txt");
  std::string node_coordinates_file_name ("scratch/matrix-topology_IEEE14_node_coordinates.txt");
  std::string node_names_file_name       ("scratch/matrix-topology_IEEE14_node_names.txt");

  CommandLine cmd;
  cmd.Parse (argc, argv); 

  // ---------- End of Simulation Variables ----------------------------------

  vector<vector<bool> > Adj_Matrix = readNxNMatrix (adj_mat_file_name);
  vector<vector<double> > coord_array = readCordinatesFile (node_coordinates_file_name);
  vector<std::string> node_names = readNodeNames(node_names_file_name);

  int n_nodes = coord_array.size ();
  // int matrixDimension = Adj_Matrix.size ();

  // ---------- End of Read Network Description Files ------------------------

  // ---------- Network Setup ------------------------------------------------

  NS_LOG_INFO ("Create Nodes.");
  NodeContainer nodes;   // Declare nodes objects
  nodes.Create (n_nodes);

  NS_LOG_INFO ("Create P2P Link Attributes.");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute  ("DataRate", StringValue ("10Mbps"));
  p2p.SetChannelAttribute ("Delay",    StringValue ("2ms"));

  NS_LOG_INFO ("Install Internet Stack to Nodes.");
  InternetStackHelper inetstack;
  inetstack.Install (NodeContainer::GetGlobal ());

  NS_LOG_INFO ("Assign Addresses to Nodes.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.0.0.0", "255.255.255.252");

  NS_LOG_INFO ("Create Links Between Nodes.");
  uint32_t p2pLinkCount = 0;
  for (size_t i = 0; i < 17; i++) {
    for (size_t j = i+1; j < 17; j++) {
      if (Adj_Matrix[i][j] == 1) {
        NodeContainer n_links = NodeContainer (nodes.Get (i), nodes.Get (j));
        NetDeviceContainer n_devs = p2p.Install (n_links);
        ipv4.Assign (n_devs);
        ipv4.NewNetwork ();
        p2pLinkCount++;
        NS_LOG_INFO ("matrix element [" << i << "][" << j << "] is 1");

        // Configure Error model
        // Create an ErrorModel based on the implementation (constructor)
        // specified by the default TypeId
        ObjectFactory factory;
        factory.SetTypeId ("ns3::RateErrorModel");
        Ptr<ErrorModel> em = factory.Create<ErrorModel> ();
        n_devs.Get (0)->SetAttribute ("ReceiveErrorModel", PointerValue (em));
      } else {
        NS_LOG_INFO ("matrix element [" << i << "][" << j << "] is 0");
      }
    }
  }

  
  NS_LOG_INFO ("Create CSMA Link Attributes.");
  CsmaHelper csma;  // csma helper for tap bridge
  csma.SetChannelAttribute ("DataRate", StringValue ("300Mbps"));
  csma.SetChannelAttribute ("Delay",    StringValue ("2ms"));
  
  NodeContainer nodeContainer_CC = NodeContainer (nodes.Get (0), nodes.Get (17));
  NodeContainer nodeContainer_01 = NodeContainer (nodes.Get (32), nodes.Get (34), 
                                                  nodes.Get (35));
  NodeContainer nodeContainer_31 = NodeContainer (nodes.Get (33), nodes.Get (36), 
                                                  nodes.Get (37));
  NodeContainer nodeContainer_06 = NodeContainer (nodes.Get (6), nodes.Get (18));
  NodeContainer nodeContainer_07 = NodeContainer (nodes.Get (7), nodes.Get (19));
  NodeContainer nodeContainer_08 = NodeContainer (nodes.Get (8), nodes.Get (20));
  NodeContainer nodeContainer_09 = NodeContainer (nodes.Get (9), nodes.Get (21), 
                                                  nodes.Get (22), nodes.Get (23));
  NodeContainer nodeContainer_10 = NodeContainer (nodes.Get (10), nodes.Get (24), 
                                                  nodes.Get (25));
  NodeContainer nodeContainer_11 = NodeContainer (nodes.Get (11), nodes.Get (26));
  NodeContainer nodeContainer_12 = NodeContainer (nodes.Get (12), nodes.Get (27));
  NodeContainer nodeContainer_13 = NodeContainer (nodes.Get (13), nodes.Get (28));
  NodeContainer nodeContainer_14 = NodeContainer (nodes.Get (14), nodes.Get (29));
  NodeContainer nodeContainer_15 = NodeContainer (nodes.Get (15), nodes.Get (30));
  NodeContainer nodeContainer_16 = NodeContainer (nodes.Get (16), nodes.Get (31));

  NetDeviceContainer csmaDevices_CC = csma.Install (nodeContainer_CC);
  NetDeviceContainer csmaDevices_01 = csma.Install (nodeContainer_01);
  NetDeviceContainer csmaDevices_31 = csma.Install (nodeContainer_31);
  NetDeviceContainer csmaDevices_06 = csma.Install (nodeContainer_06);
  NetDeviceContainer csmaDevices_07 = csma.Install (nodeContainer_07);
  NetDeviceContainer csmaDevices_08 = csma.Install (nodeContainer_08);
  NetDeviceContainer csmaDevices_09 = csma.Install (nodeContainer_09);
  NetDeviceContainer csmaDevices_10 = csma.Install (nodeContainer_10);
  NetDeviceContainer csmaDevices_11 = csma.Install (nodeContainer_11);
  NetDeviceContainer csmaDevices_12 = csma.Install (nodeContainer_12);
  NetDeviceContainer csmaDevices_13 = csma.Install (nodeContainer_13);
  NetDeviceContainer csmaDevices_14 = csma.Install (nodeContainer_14);
  NetDeviceContainer csmaDevices_15 = csma.Install (nodeContainer_15);
  NetDeviceContainer csmaDevices_16 = csma.Install (nodeContainer_16);

  ipv4.SetBase ("172.16.0.0", "255.255.255.0");
  Ipv4InterfaceContainer if_CC = ipv4.Assign (csmaDevices_CC);  
  ipv4.SetBase ("172.16.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if_01 = ipv4.Assign (csmaDevices_01);  
  ipv4.SetBase ("172.16.31.0", "255.255.255.0");
  Ipv4InterfaceContainer if_31 = ipv4.Assign (csmaDevices_31);  
  ipv4.SetBase ("172.16.6.0", "255.255.255.0");
  Ipv4InterfaceContainer if_06 = ipv4.Assign (csmaDevices_06);  
  ipv4.SetBase ("172.16.7.0", "255.255.255.0");
  Ipv4InterfaceContainer if_07 = ipv4.Assign (csmaDevices_07);  
  ipv4.SetBase ("172.16.8.0", "255.255.255.0");
  Ipv4InterfaceContainer if_08 = ipv4.Assign (csmaDevices_08);
  ipv4.SetBase ("172.16.9.0", "255.255.255.0");
  Ipv4InterfaceContainer if_09 = ipv4.Assign (csmaDevices_09);
  ipv4.SetBase ("172.16.10.0", "255.255.255.0");
  Ipv4InterfaceContainer if_10 = ipv4.Assign (csmaDevices_10);
  ipv4.SetBase ("172.16.11.0", "255.255.255.0");
  Ipv4InterfaceContainer if_11 = ipv4.Assign (csmaDevices_11);
  ipv4.SetBase ("172.16.12.0", "255.255.255.0");
  Ipv4InterfaceContainer if_12 = ipv4.Assign (csmaDevices_12);
  ipv4.SetBase ("172.16.13.0", "255.255.255.0");
  Ipv4InterfaceContainer if_13 = ipv4.Assign (csmaDevices_13);
  ipv4.SetBase ("172.16.14.0", "255.255.255.0");
  Ipv4InterfaceContainer if_14 = ipv4.Assign (csmaDevices_14);
  ipv4.SetBase ("172.16.15.0", "255.255.255.0");
  Ipv4InterfaceContainer if_15 = ipv4.Assign (csmaDevices_15);
  ipv4.SetBase ("172.16.16.0", "255.255.255.0");
  Ipv4InterfaceContainer if_16 = ipv4.Assign (csmaDevices_16);

  uint32_t csmaNetCount = 14; 

  // **********************************************************************
  //   Setting up TapBridge
  // **********************************************************************
  std::string tapName = "nstap00";
  std::vector<std::string> tapnode_names;
  tapnode_names.push_back (tapName);

  CsmaHelper csma_tap;  // csma helper for tap bridge
  csma_tap.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma_tap.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (0)));

  NodeContainer virtualLocalNodes;
  virtualLocalNodes.Create (3);
  Ptr<Node> tapNode = virtualLocalNodes.Get (0);
  Ptr<Node> virtLocNode01 = virtualLocalNodes.Get (1);
  Ptr<Node> virtLocNode02 = virtualLocalNodes.Get (2);

  inetstack.Install (virtualLocalNodes);
  NetDeviceContainer tapDevices = csma_tap.Install (virtualLocalNodes);
  
  Ipv4AddressHelper addresses;
  addresses.SetBase ("192.168.1.0", "255.255.255.0");  
  Ipv4InterfaceContainer virtLocIface = addresses.Assign (tapDevices);

  AnimationInterface::SetConstantPosition (tapNode,       0, 100);
  AnimationInterface::SetConstantPosition (virtLocNode01, 20.468875, 98.741559);
  AnimationInterface::SetConstantPosition (virtLocNode02,  5.775975, 84.423990);



  NodeContainer n_links01 = NodeContainer (nodes.Get (19), virtLocNode01);
  NetDeviceContainer n_devs01 = p2p.Install (n_links01);
  ipv4.SetBase ("20.0.0.0", Ipv4Mask("/24"));  
  ipv4.Assign (n_devs01);
  ipv4.NewNetwork ();
  p2pLinkCount++;
  
  // NodeContainer n_links02 = NodeContainer (nodes.Get (20), virtLocNode02);
  // NetDeviceContainer n_devs02 = p2p.Install (n_links02);
  // ipv4.Assign (n_devs02);
  // ipv4.NewNetwork ();
  // p2pLinkCount++;

  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));
  tapBridge.SetAttribute ("DeviceName", StringValue (tapName));
  tapBridge.Install (tapNode, tapDevices.Get (0));

  NS_LOG_INFO ("Initialize Global Routing.");
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // Ipv4StaticRoutingHelper ipv4RoutingHelper;
  // Ptr<Ipv4StaticRouting> tapRoute = ipv4RoutingHelper.GetStaticRouting (tapNode->GetObject<Ipv4> ());
  // Ptr<Ipv4StaticRouting> virtRoute01 = ipv4RoutingHelper.GetStaticRouting (virtLocNode01->GetObject<Ipv4> ());

  // tapRoute->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.13.0"), Ipv4Mask("/24"), Ipv4Address("192.168.1.2"), 1);
  // virtRoute01->AddNetworkRouteTo 
  //   (Ipv4Address("172.16.13.0"), Ipv4Mask("/24"), Ipv4Address("20.0.0.1"), 2);

  NS_LOG_INFO ("Number of P2P links in the adjacency matrix is: " << p2pLinkCount);
  NS_LOG_INFO ("Number of CSMA network created is             : " << csmaNetCount);
  NS_LOG_INFO ("Number of all nodes is                        : " << nodes.GetN ());

  // ---------- End of Network Set-up ----------------------------------------

  // ---------- Allocate Node Positions --------------------------------------

  NS_LOG_INFO ("Allocate Positions to Nodes.");

  MobilityHelper mobility_n;
  Ptr<ListPositionAllocator> positionAlloc_n = CreateObject<ListPositionAllocator> ();

  for (size_t m = 0; m < coord_array.size (); m++) {
    positionAlloc_n->Add (Vector (coord_array[m][0], coord_array[m][1], 0));
    Ptr<Node> n0 = nodes.Get (m);
    Ptr<ConstantPositionMobilityModel> nLoc =  n0->GetObject<ConstantPositionMobilityModel> ();
    if (nLoc == 0) {
      nLoc = CreateObject<ConstantPositionMobilityModel> ();
      n0->AggregateObject (nLoc);
    }
    // y-coordinates are negated for correct display in NetAnim
    // NetAnim's (0,0) reference coordinates are located on upper left corner
    // by negating the y coordinates, we declare the reference (0,0) coordinate
    // to the bottom left corner
    Vector nVec (coord_array[m][0], -coord_array[m][1], 0);
    nLoc->SetPosition (nVec);

  }
  mobility_n.SetPositionAllocator (positionAlloc_n);
  mobility_n.Install (nodes);

  // ---------- End of Allocate Node Positions -------------------------------


  // **********************************************************************
  //   0: Testing Tapbrige using UDP connection
  // **********************************************************************
  // Create the UdpEcho client/server application to send UDP datagrams of size
  // [virtLocNode01]  <---> [172.16.13.2]
  Ptr<Node> fromN = virtLocNode01;
  Ptr<Node> toN = nodes.Get (28);
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

  // [virtLocNode02]  <---> [172.16.14.2]
  Ptr<Node> fromN2 = virtLocNode02;
  Ptr<Node> toN2 = nodes.Get (29);
  Ipv4InterfaceAddress ifInAddrTo2 = toN2->GetObject<Ipv4> ()->GetAddress (1, 0);

  UdpEchoClientHelper udpEchoClient2 (InetSocketAddress (ifInAddrTo2.GetLocal (), port));
  udpEchoClient2.SetAttribute ("MaxPackets", UintegerValue (1000));
  udpEchoClient2.SetAttribute ("PacketSize", UintegerValue (1040));
  ApplicationContainer udpClientApp2 = udpEchoClient2.Install (fromN2);
  udpClientApp2.Start (Seconds (1.0));
  udpClientApp2.Stop (Seconds (9.0));

  UdpEchoServerHelper udpEchoServer2 (port);
  ApplicationContainer udpServerApp2 = udpEchoServer2.Install (toN2);
  udpServerApp2.Start (Seconds (1.0));
  udpServerApp2.Stop (Seconds (9.80));

  // **********************************************************************
  //   1: Attacker's application - SpoofingApp
  // **********************************************************************
  Ptr<Node> hijackNode = nodes.Get (HIJACKED_NODE_NUMBER);
  Ptr<Node> targetNode = nodes.Get (ATTACK_TARGET_NODE_NUMBER);
  Ptr<Socket> hijackSocket = Socket::CreateSocket (hijackNode, UdpSocketFactory::GetTypeId ());  
  Ptr<SpoofingApp> spoofApp = CreateObject<SpoofingApp> ();
  spoofApp->Setup(hijackSocket, Address (InetSocketAddress (getNodeIpv4Addr(targetNode, 1), UDP_SINK_PORT)), 48, ATTACK_PACKET_SENT, DataRate ("1Mbps"));
  spoofApp->SetStartTime(Seconds (ATTACK_START_TIME));
  spoofApp->SetStopTime(Seconds (ATTACK_STOP_TIME));
  hijackNode->AddApplication(spoofApp);    

  // **********************************************************************
  //   2a: Listening sockets for all hosts
  // **********************************************************************
  NS_LOG_INFO ("Setup TCP & UDP Packet Sinks.");
  PacketSinkHelper tcpSink ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), TCP_SINK_PORT));
  PacketSinkHelper udpSink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), UDP_SINK_PORT));  
  UdpEchoServerHelper heartbeatEchoServer (UDP_HEARTBEAT_ECHO_PORT);

  for (int i=17; i<n_nodes; i++) {
    ApplicationContainer listenerApps;
    listenerApps.Add (tcpSink.Install (nodes.Get (i)));
    listenerApps.Add (udpSink.Install (nodes.Get (i)));
    listenerApps.Add (heartbeatEchoServer.Install (nodes.Get (i)));
    listenerApps.Start (Seconds (LISTENING_PORT_START_TIME)); 
    listenerApps.Start (Seconds (LISTENING_PORT_STOP_TIME));
  }

  for (int i=17; i < n_nodes; i++) {
    Ipv4Address responding_ip_addr = getNodeIpv4Addr(nodes.Get(i), 1);
    UdpEchoClientHelper heartbeatEchoClient (InetSocketAddress (responding_ip_addr, UDP_HEARTBEAT_ECHO_PORT));
    heartbeatEchoClient.SetAttribute ("MaxPackets", UintegerValue (3));
    heartbeatEchoClient.SetAttribute ("Interval", TimeValue (Seconds (0.001)));
    heartbeatEchoClient.SetAttribute ("PacketSize", UintegerValue (463));
    ApplicationContainer heartbeatClientApp = heartbeatEchoClient.Install (nodes.Get(17));
    heartbeatClientApp.Start (Seconds (7.0));
    heartbeatClientApp.Stop (Seconds (8.0));
  }
  
  // **********************************************************************
  //   2b: Create a PDC application for the physical PMU device
  // **********************************************************************
  // Temporarily place a UdpSinkApplication for pre-study
  PacketSinkHelper udpPdcSink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 4713));  
  ApplicationContainer udpPdcSinkApp = udpPdcSink.Install (nodes.Get (31));
  udpPdcSinkApp.Start ( Seconds (0.0));
  udpPdcSinkApp.Stop ( Seconds (30.0));

  // UdpServerHelper udpServer (4713);
  // ApplicationContainer udpPdcApps = udpServer.Install (nodes.Get (31));
  // udpPdcApps.Start (Seconds (0.0)); 
  // udpPdcApps.Stop (Seconds (30.0));

  // Ptr<Node> pdcNode = nodes.Get (31);
  // Ptr<Socket> pdcSkt = InetSocketAddress (getNodeIpv4Addr(pdcNode, 1), 4713)
  // Ptr<C37118UdpServerApplication> pdcApp = CreateObject<C37118UdpServerApplication> ();
  // pdcApp->Setup( Address (pdcSkt) );
  // pdcApp->SetStartTime(Seconds (0.0));
  // pdcApp->SetStopTime(Seconds (30.0));
  // pdcNode->AddApplication(pdcApp);  


  // **********************************************************************
  //   3: Additional listening socket for CC host
  // **********************************************************************
  Ptr<Node> n_ctrlctr = nodes.Get (CTRLCTR_HOST_NODE);
  Ipv4Address ip_addr_ctrlctr = getNodeIpv4Addr(n_ctrlctr, 1);
  
  UdpEchoServerHelper echoServer (UDP_ECHO_PORT);
  ApplicationContainer serverApps = echoServer.Install (n_ctrlctr);
  serverApps.Start (Seconds (LISTENING_PORT_START_TIME));
  serverApps.Stop (Seconds (LISTENING_PORT_STOP_TIME));
    
  NS_LOG_INFO ("Setup CBR Traffic Sources.");
  
  UdpEchoClientHelper udpEchoClientCtrlCtr (InetSocketAddress (ip_addr_ctrlctr, UDP_ECHO_PORT));
  udpEchoClientCtrlCtr.SetAttribute ("MaxPackets", UintegerValue (1));
  udpEchoClientCtrlCtr.SetAttribute ("Interval", TimeValue (Seconds (0.05)));
  udpEchoClientCtrlCtr.SetAttribute ("PacketSize", UintegerValue (1024));

  for (int i=0; i<NORMAL_TCP_COMM_TIMES; i++) //NORMAL_TCP_COMM_TIMES
  {        
    // We needed to generate a random number (rn) to be used to eliminate
    // the artificial congestion caused by sending the packets at the
    // same time. This rn is added to AppStartTime to have the sources
    // start at different time, however they will still send at the same rate.
    Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
    double rn = x->GetValue (0, (AppStopTime - AppStartTime));
    uint32_t randomSrcNode = x->GetInteger (18, n_nodes-1); // Hosts are located at node_num >=18

    ApplicationContainer udpEchoClientApps = udpEchoClientCtrlCtr.Install (nodes.Get (randomSrcNode));
    udpEchoClientApps.Start (Seconds (AppStartTime + rn));
    udpEchoClientApps.Stop (Seconds (AppStopTime));
  }

  // **********************************************************************
  //   4: Ping a physical presented IP adderss
  // **********************************************************************
  V4PingHelper icmpv4Helper = V4PingHelper( Ipv4Address ("192.168.31.132") );
  icmpv4Helper.SetAttribute ("Interval", TimeValue (MilliSeconds(10)));
  ApplicationContainer icmpv4Apps = icmpv4Helper.Install (hijackNode);
  icmpv4Apps.Start (Seconds (20.0));
  icmpv4Apps.Stop (Seconds (23.0));


  // ---------- End of Create n*(n-1) CBR Flows ------------------------------

  // ---------- Simulation Monitoring ----------------------------------------
  NS_LOG_INFO ("Configure Tracing.");

  // AsciiTraceHelper ascii;
  // p2p.EnableAsciiAll (ascii.CreateFileStream (tr_name.c_str ()));
  p2p.EnablePcapAll (pcap_name.c_str());
  csma.EnablePcapAll (tap_pcap_name.c_str());  // Enable PCAPs for TapBridge

  Ptr<FlowMonitor> flowmon;
  FlowMonitorHelper flowmonHelper;
  flowmon = flowmonHelper.InstallAll ();

  // Configure animator with default settings
  AnimationInterface anim (anim_name.c_str ());
  for (uint i=0; i<node_names.size(); i++) {
    std::ostringstream stringStream;
    stringStream << int(i) << ": " << node_names[i];
    anim.UpdateNodeDescription (i, stringStream.str());
    if (i >= 17) {
      anim.UpdateNodeColor (nodes.Get(i), 0, 255, 0);
    }
  }  
  anim.UpdateNodeSize  (ATTACK_TARGET_NODE_NUMBER, 2.0, 2.0);
  anim.UpdateNodeSize  (HIJACKED_NODE_NUMBER, 2.0, 2.0);

  anim.UpdateNodeColor (targetNode, 0, 0, 255);     // blue
  anim.UpdateNodeColor (hijackNode, 255, 200, 0);   // yellow
  // anim.UpdateNodeColor (tapNodes.Get (0), 0, 0, 0); // black
  
  // printMatrix (adj_mat_file_name.c_str (), Adj_Matrix);
  // printCoordinateArray (node_coordinates_file_name.c_str (),coord_array);
  // printNodesIpv4Addr(nodes, node_names);
  // printNodesIpv4Addr(tapNodes, tapnode_names);

  StackHelper stackHelper;

  for (uint32_t i=0; i<17; i++) {
    Ptr<Node> n = nodes.Get (i);
    stackHelper.PrintIpv4Address ( n, node_names[i] );
    stackHelper.PrintIpv4RoutingTable ( n, node_names[i] );
    std::cout << "------------------------" << std::endl;
  }

  std::cout << "===========================================" << std::endl;
  
  // for (uint32_t i=0; i<tapNodes.GetN(); i++) {
  //   Ptr<Node> n = tapNodes.Get (i);
  //   stackHelper.PrintIpv4Address ( n, "" );
  //   stackHelper.PrintIpv4RoutingTable ( n, "" );
  //   std::cout << "------------------------" << std::endl;
  // }


  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (SimTime));
  Simulator::Run ();
  // flowmon->SerializeToXmlFile (flow_name.c_str(), true, true);
  Simulator::Destroy ();

  // ---------- End of Simulation Monitoring ---------------------------------

  return 0;

}

// ---------- Function Definitions -------------------------------------------

Ipv4Address getNodeIpv4Addr(Ptr<Node> n, uint j) {
    Ipv4InterfaceAddress iaddr = n->GetObject<Ipv4> ()->GetAddress (j, 0);
    return iaddr.GetLocal();
}

// void printNodesIpv4Addr(NodeContainer nodes) {  
//   for (uint32_t i=0; i<nodes.GetN(); i++) { 
//     Ptr<Node> n = nodes.Get(i);
//     Ptr<Ipv4> ipv4 = n->GetObject<Ipv4> ();
//     std::cout << "Node # " << int(i)  << std::endl;
//     for (uint32_t j=1; j<ipv4->GetNInterfaces (); j++) {
//       Ipv4Address localAddr = getNodeIpv4Addr(n, j);
//       std::cout<< "            " <<  localAddr << std::endl ;
//     }
//     std::cout << "------------------" << std::endl;
//   }
// }

void printNodesIpv4Addr(NodeContainer nodes, std::vector<std::string> names) {  
  for (uint32_t i=0; i<nodes.GetN(); i++) { 
    Ptr<Node> n = nodes.Get(i);
    Ptr<Ipv4> ipv4 = n->GetObject<Ipv4> ();
    std::string nodeDesc;
    if (i<names.size()){
      nodeDesc = names[i];
    } else {
      nodeDesc = "---<null>---";
    }
    std::cout << "Node # " << int(i)  << ":  " << nodeDesc << std::endl;
    for (uint32_t j=1; j<ipv4->GetNInterfaces (); j++) {
      Ipv4InterfaceAddress iaddr = n->GetObject<Ipv4> ()->GetAddress (j, 0);
      std::cout<< "            " <<  iaddr.GetLocal () << std::endl ;
    }
    std::cout << "  Apps installed: " << n->GetNApplications() << std::endl ;
    // for (uint32_t j=0; j<n->GetNApplications (); j++) {
    //   Ptr<Application> app = n->GetApplication(j);
    //   std::cout << "    - " << app << std::endl ;
    // }
    std::cout << "------------------" << std::endl;
  }
}

vector<vector<bool> > readNxNMatrix (std::string adj_mat_file_name) {
  ifstream adj_mat_file;
  adj_mat_file.open (adj_mat_file_name.c_str (), ios::in);
  if (adj_mat_file.fail ())
    {
      NS_FATAL_ERROR ("File " << adj_mat_file_name.c_str () << " not found");
    }
  vector<vector<bool> > array;
  int i = 0;
  int n_nodes = 0;

  while (!adj_mat_file.eof ())
    {
      string line;
      getline (adj_mat_file, line);
      if (line == "")
        {
          NS_LOG_WARN ("WARNING: Ignoring blank row in the array: " << i);
          break;
        }

      istringstream iss (line);
      bool element;
      vector<bool> row;
      int j = 0;

      while (iss >> element)
        {
          row.push_back (element);
          j++;
        }

      if (i == 0)
        {
          n_nodes = j;
        }

      if (j != n_nodes )
        {
          NS_LOG_ERROR ("ERROR: Number of elements in line " << i << ": " << j << " not equal to number of elements in line 0: " << n_nodes);
          NS_FATAL_ERROR ("ERROR: The number of rows is not equal to the number of columns! in the adjacency matrix");
        }
      else
        {
          array.push_back (row);
        }
      i++;
    }

  if (i != n_nodes)
    {
      NS_LOG_ERROR ("There are " << i << " rows and " << n_nodes << " columns.");
      NS_FATAL_ERROR ("ERROR: The number of rows is not equal to the number of columns! in the adjacency matrix");
    }

  adj_mat_file.close ();
  return array;

}

vector<vector<double> > readCordinatesFile (std::string node_coordinates_file_name) {
  ifstream node_coordinates_file;
  node_coordinates_file.open (node_coordinates_file_name.c_str (), ios::in);
  if (node_coordinates_file.fail ())
    {
      NS_FATAL_ERROR ("File " << node_coordinates_file_name.c_str () << " not found");
    }
  vector<vector<double> > coord_array;
  int m = 0;

  while (!node_coordinates_file.eof ())
    {
      string line;
      getline (node_coordinates_file, line);

      if (line == "")
        {
          NS_LOG_WARN ("WARNING: Ignoring blank row: " << m);
          break;
        }

      istringstream iss (line);
      double coordinate;
      vector<double> row;
      int n = 0;
      while (iss >> coordinate)
        {
          row.push_back (coordinate);
          n++;
        }

      if (n != 2)
        {
          NS_LOG_ERROR ("ERROR: Number of elements at line#" << m << " is "  << n << " which is not equal to 2 for node coordinates file");
          exit (1);
        }

      else
        {
          coord_array.push_back (row);
        }
      m++;
    }
  node_coordinates_file.close ();
  return coord_array;

}

vector<std::string> readNodeNames (std::string node_names_file_name) {
  ifstream node_names_file;
  node_names_file.open (node_names_file_name.c_str (), ios::in);
  if (node_names_file.fail ())
    {
      NS_FATAL_ERROR ("File " << node_names_file_name.c_str () << " not found");
    }
  vector<std::string> nodeNames;
  int m = 0;

  while (!node_names_file.eof ())
    {
      string line;
      getline (node_names_file, line);

      if (line == "")
      {
        NS_LOG_WARN ("WARNING: Ignoring blank row: " << m);
        break;
      }

      istringstream iss (line);
      std::string node_name;
      while (iss >> node_name)
      {
        nodeNames.push_back (node_name);
      }
      m++;
    }
  node_names_file.close ();
  return nodeNames;
}

void printMatrix (const char* description, vector<vector<bool> > array) {
  cout << "**** Start " << description << "********" << endl;
  for (size_t m = 0; m < array.size (); m++)
    {
      for (size_t n = 0; n < array[m].size (); n++)
        {
          cout << array[m][n] << ' ';
        }
      cout << endl;
    }
  cout << "**** End " << description << "********" << endl;

}

void printCoordinateArray (const char* description, vector<vector<double> > coord_array) {
  cout << "**** Start " << description << "********" << endl;
  for (size_t m = 0; m < coord_array.size (); m++)
  {
    cout << m << ":  " << coord_array[m][0] << '\t' << coord_array[m][1] << endl;   
  }
  cout << "**** End " << description << "********" << endl;
}

// ---------- End of Function Definitions ------------------------------------
