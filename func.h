#pragma once
#ifndef FUNC_H
#define FUNC_H
#endif // !FUNC_H
#include"pcap.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "myStructs.h"
#include "MFCApplication1Dlg.h"

/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
pcap_if_t* initCap();
int startCap(CMFCApplication1Dlg* dlg);
int updateTree(int index);
int updateEdit(int index);
int updateNPacket(CMFCApplication1Dlg* dlg);
DWORD WINAPI capThread(LPVOID lpParameter);
int analyze_frame(const u_char* pkt, struct datapkt* data, struct pktcount* npacket);
int analyze_arp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_ip(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_ip6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_icmp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_icmp6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_tcp(const u_char* pkt, datapkt* data, struct 
pktcount* npacket);
int analyze_udp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
