#include "func.h"
#include "pch.h"
#include "pcap.h"
#include "afxdialogex.h"
#include <windows.h>
#include"MFCApplication1Dlg.h"


pcap_if_t * initCap()
{
	int devCount = 0;
	pcap_if_t* alldev;
	pcap_if_t* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldev, errbuf) == -1)
		return NULL;
	for (dev = alldev; dev; dev = dev->next)
		devCount++;
	return alldev;
}

int updateNPacket(CMFCApplication1Dlg* dlg) {
	CString str_num;
	str_num.Format(_T("%d"), dlg->npacket.tcp);
	dlg->m_tcpEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.udp);
	dlg->m_udpEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.icmp);
	dlg->m_icmpEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.http);
	dlg->m_httpEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.arp);
	dlg->m_arpEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.icmpv6);
	dlg->m_icmpv6Edit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.ipv4);
	dlg->m_ipv4Edit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.ipv6);
	dlg->m_ipv6Edit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.others);
	dlg->m_othersEdit.SetWindowTextW(str_num);

	str_num.Format(_T("%d"), dlg->npacket.total);
	dlg->m_totalEdit.SetWindowTextW(str_num);

	return 1;
}

int analyze_arp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}
int analyze_ip(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}
int analyze_ip6(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}
int analyze_icmp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}
int analyze_icmp6(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}
int analyze_tcp(const u_char* pkt, datapkt* data, struct
	pktcount* npacket) {
	return 1;
}
int analyze_udp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	return 1;
}

int analyze_frame(const u_char* pkt, struct datapkt* data, struct pktcount* npacket) {
	int i;
	struct ethhdr* ethh = (struct ethhdr*)pkt;
	data->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
	if (NULL == data->ethh)
		return -1;

	for (i = 0; i < 6; i++)
	{
		data->ethh->dest[i] = ethh->dest[i];
		data->ethh->src[i] = ethh->src[i];
	}

	npacket->total++;

	data->ethh->type = ntohs(ethh->type);

	switch (data->ethh->type)
	{
	case 0x0806:
		return analyze_arp((u_char*)pkt + 14, data, npacket);      //mac 头大小为14
		break;
	case 0x0800:
		return analyze_ip((u_char*)pkt + 14, data, npacket);
		break;
	case 0x86dd:
		return analyze_ip6((u_char*)pkt + 14, data, npacket);
		return -1;
		break;
	default:
		npacket->total++;
		return -1;
		break;
	}
	return 1;
}

DWORD WINAPI capThread(LPVOID lpParameter) {
	int res, nItem;
	struct tm* ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr* header;									 
	const u_char* pkt_data = NULL, * pData = NULL;    
	u_char* ppkt_data;

	CMFCApplication1Dlg* pthis = (CMFCApplication1Dlg*)lpParameter;
	if (NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}

	while ((res = pcap_next_ex(pthis->pkt, &header, &pkt_data)) >= 0)
	{
		if (res == 0)				
			continue;

		struct datapkt* data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data, 0, sizeof(struct datapkt));

		if (NULL == data)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
			continue;

		//将数据包保存到打开的文件中
		/*if (pthis->dumpfile != NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile, header, pkt_data);
		}*/

		updateNPacket(pthis);

		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);

		data->len = header->len;								
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		buf.Format(_T("%d"), pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem, 1, timestr);

		buf.Empty();
		buf.Format(_T("%d"), data->len);
		pthis->m_listCtrl.SetItemText(nItem, 2, buf);
		
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem, 3, buf);

		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem, 4, buf);

		pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02x:"), data->iph6->saddr[n]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->saddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 6, buf);

		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02x:"), data->iph6->daddr[n]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->daddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 7, buf);

		pthis->npkt++;

	}
	return 1;
}

int startCap(CMFCApplication1Dlg* dlg) {
	int if_index, filter_index, count;
	u_int netmask;
	struct bpf_program fcode;

	if_index = dlg->m_selectNetCom.GetCurSel();
	filter_index = dlg->m_selectFuncCom.GetCurSel();

	if (0 == if_index || CB_ERR == if_index)
	{
		MessageBox(NULL, _T("请选择网卡"), _T("提示"), MB_OK );
		return -1;
	}
	if (CB_ERR == filter_index)
	{
		MessageBox(NULL, _T("过滤器配置错误"), _T("提示"), MB_OK);
		return -1;
	}

	dlg->dev = dlg->alldev;
	for (count = 0; count < if_index; count++)
		dlg->dev = dlg->dev->next;

	if ((dlg->pkt = pcap_open_live(dlg->dev->name,	
		65536,																															
		1,													
		1000,												
		dlg->errbuf											
	)) == NULL)
	{
		MessageBox(NULL, _T("无法打开接口"+CString(dlg->dev->description)), _T("提示"), MB_OK);
		pcap_freealldevs(dlg->alldev);
		return -1;
	}

	if (pcap_datalink(dlg->pkt) != DLT_EN10MB)
	{
		MessageBox(NULL, _T("不适用于非以太网络"), _T("提示"), MB_OK);
		pcap_freealldevs(dlg->alldev);
		return -1;
	}

	if (dlg->dev->addresses != NULL)
		netmask = ((struct sockaddr_in*)(dlg->dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	if (0 == filter_index)
	{
		char filter[] = "";
		if (pcap_compile(dlg->pkt, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(NULL, _T("语法错误"), _T("提示"), MB_OK);
			pcap_freealldevs(dlg->alldev);
			return -1;
		}
	}
	else {
		CString str;
		char* filter;
		int len, x;
		dlg->m_selectFuncCom.GetLBText(filter_index, str);
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (x = 0; x < len; x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(dlg->pkt, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(NULL, _T("语法错误"), _T("提示"), MB_OK);
			pcap_freealldevs(dlg->alldev);
			return -1;
		}
	}


	if (pcap_setfilter(dlg->pkt, &fcode) < 0)
	{
		MessageBox(NULL, _T("过滤器设置错误"), _T("提示"), MB_OK);
		pcap_freealldevs(dlg->alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	/*CFileFind file;
	char thistime[30];
	struct tm* ltime;
	memset(filepath, 0, 512);
	memset(filename, 0, 64);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
	strcpy(filepath, "SavedData\\");
	strcat(filename, thistime);
	strcat(filename, ".lix");

	strcat(filepath, filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if (dumpfile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	pcap_freealldevs(alldev);*/

	LPDWORD threadCap = NULL;
	dlg->m_ThreadHandle = CreateThread(NULL, 0, capThread, dlg, 0, threadCap);
	if (dlg->m_ThreadHandle == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("%d."), code);
		MessageBox(NULL, _T("创建线程错误，代码为"+CString(str)), _T("提示"), MB_OK);
		return -1;
	}
	return 1;
}

