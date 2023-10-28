#include "func.h"
#include "pch.h"
#include "pcap.h"
#include "afxdialogex.h"
#include <windows.h>
#include"MFCApplication1Dlg.h"

int analyze_frame(const u_char* pkt, struct datapkt* data, struct pktcount* npacket);
int analyze_arp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_ip(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_ip6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_icmp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_icmp6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
int analyze_tcp(const u_char* pkt, datapkt* data, struct
	pktcount* npacket);
int analyze_udp(const u_char* pkt, datapkt* data, struct pktcount* npacket);


CString print_packet_hex(const u_char* pkt, int size_pkt) {
	
	CString buf;
	int i = 0, j = 0, rowcount;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf, 0, 256);

	for (i = 0; i < size_pkt; i += 16)
	{
		buf.AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf.AppendFormat(_T("%02x  "), (u_int)pkt[i + j]);

		if (rowcount < 16)
			for (j = rowcount; j < 16; j++)
				buf.AppendFormat(_T("    "));


		for (j = 0; j < rowcount; j++)
		{
			ch = pkt[i + j];
			ch = isprint(ch) ? ch : '.';
			buf.AppendFormat(_T("%c"), ch);
		}

		buf.Append(_T("\r\n"));

		if (rowcount < 16)
			return buf;
	}
}

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

	str_num.Format(_T("%d"), dlg->npacket.total);
	dlg->m_totalEdit.SetWindowTextW(str_num);

	return 1;
}

int analyze_arp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	int i;
	struct arphdr* arph = (struct arphdr*)pkt;
	data->arph = (struct arphdr*)malloc(sizeof(struct arphdr));

	if (NULL == data->arph)
		return -1;

	for (i = 0; i < 6; i++)
	{
		if (i < 4)
		{
			data->arph->ar_destip[i] = arph->ar_destip[i];
			data->arph->ar_srcip[i] = arph->ar_srcip[i];
		}
		data->arph->ar_destmac[i] = arph->ar_destmac[i];
		data->arph->ar_srcmac[i] = arph->ar_srcmac[i];
	}

	data->arph->ar_hln = arph->ar_hln;
	data->arph->ar_hrd = ntohs(arph->ar_hrd);
	data->arph->ar_op = ntohs(arph->ar_op);
	data->arph->ar_pln = arph->ar_pln;
	data->arph->ar_pro = ntohs(arph->ar_pro);

	strcpy(data->pktType, "ARP");
	npacket->arp++;
	return 1;
}

int analyze_ip(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	int i;
	struct iphdr* iph = (struct iphdr*)pkt;
	data->iph = (struct iphdr*)malloc(sizeof(struct iphdr));

	if (NULL == data->iph)
		return -1;
	data->iph->check = iph->check;
	npacket->ipv4++;

	data->iph->saddr = iph->saddr;
	data->iph->daddr = iph->daddr;

	data->iph->frag_off = iph->frag_off;
	data->iph->id = iph->id;
	data->iph->proto = iph->proto;
	data->iph->tlen = ntohs(iph->tlen);
	data->iph->tos = iph->tos;
	data->iph->ttl = iph->ttl;
	data->iph->ihl = iph->ihl;
	data->iph->version = iph->version;
	data->iph->op_pad = iph->op_pad;

	int iplen = iph->ihl * 4;							
	switch (iph->proto)
	{
	case PROTO_ICMP:
		return analyze_icmp((u_char*)iph + iplen, data, npacket);
		break;
	case PROTO_TCP:
		return analyze_tcp((u_char*)iph + iplen, data, npacket);
		break;
	case PROTO_UDP:
		return analyze_udp((u_char*)iph + iplen, data, npacket);
		break;
	default:
		return-1;
		break;
	}
	return 1;
}

int analyze_ip6(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	int i;
	struct iphdr6* iph6 = (struct iphdr6*)pkt;
	data->iph6 = (struct iphdr6*)malloc(sizeof(struct iphdr6));

	if (NULL == data->iph6)
		return -1;

	npacket->ipv6++;

	data->iph6->version = iph6->version;
	data->iph6->flowtype = iph6->flowtype;
	data->iph6->flowid = iph6->flowid;
	data->iph6->plen = ntohs(iph6->plen);
	data->iph6->nh = iph6->nh;
	data->iph6->hlim = iph6->hlim;

	for (i = 0; i < 16; i++)
	{
		data->iph6->saddr[i] = iph6->saddr[i];
		data->iph6->daddr[i] = iph6->daddr[i];
	}

	switch (iph6->nh)
	{
	case 0x3a:
		return analyze_icmp6((u_char*)iph6 + 40, data, npacket);
		break;
	case 0x06:
		return analyze_tcp((u_char*)iph6 + 40, data, npacket);
		break;
	case 0x11:
		return analyze_udp((u_char*)iph6 + 40, data, npacket);
		break;
	default:
		return-1;
		break;
	}
	return 1;
}

int analyze_icmp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	struct icmphdr* icmph = (struct icmphdr*)pkt;
	data->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

	if (NULL == data->icmph)
		return -1;

	data->icmph->chksum = icmph->chksum;
	data->icmph->code = icmph->code;
	data->icmph->seq = icmph->seq;
	data->icmph->type = icmph->type;
	strcpy(data->pktType, "ICMP");
	npacket->icmp++;
	return 1;
}

int analyze_icmp6(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	int i;
	struct icmphdr6* icmph6 = (struct icmphdr6*)pkt;
	data->icmph6 = (struct icmphdr6*)malloc(sizeof(struct icmphdr6));

	if (NULL == data->icmph6)
		return -1;

	data->icmph6->chksum = icmph6->chksum;
	data->icmph6->code = icmph6->code;
//	data->icmph6->seq = icmph6->seq;
	data->icmph6->type = icmph6->type;
	data->icmph6->op_len = icmph6->op_len;
	data->icmph6->op_type = icmph6->op_type;
	for (i = 0; i < 6; i++)
	{
		data->icmph6->op_ethaddr[i] = icmph6->op_ethaddr[i];
	}
	strcpy(data->pktType, "ICMPv6");
	npacket->icmpv6++;
	return 1;
}

int analyze_tcp(const u_char* pkt, datapkt* data, struct
	pktcount* npacket) {
	struct tcphdr* tcph = (struct tcphdr*)pkt;
	data->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	if (NULL == data->tcph)
		return -1;

	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;

	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;

	data->tcph->dport = ntohs(tcph->dport);
	data->tcph->seq = tcph->seq;
	data->tcph->sport = ntohs(tcph->sport);
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window = tcph->window;
	data->tcph->opt = tcph->opt;

	if (ntohs(tcph->dport) == 80 || ntohs(tcph->sport) == 80)
	{
		npacket->http++;
		strcpy(data->pktType, "HTTP");
	}
	else {
		npacket->tcp++;
		strcpy(data->pktType, "TCP");
	}
	return 1;
}

int analyze_udp(const u_char* pkt, datapkt* data, struct pktcount* npacket) {
	struct udphdr* udph = (struct udphdr*)pkt;
	data->udph = (struct udphdr*)malloc(sizeof(struct udphdr));
	if (NULL == data->udph)
		return -1;

	data->udph->check = udph->check;
	data->udph->dport = ntohs(udph->dport);
	data->udph->len = ntohs(udph->len);
	data->udph->sport = ntohs(udph->sport);

	strcpy(data->pktType, "UDP");
	npacket->udp++;
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
		return analyze_arp((u_char*)pkt + 14, data, npacket);     
		break;
	case 0x0800:
		return analyze_ip((u_char*)pkt + 14, data, npacket);
		break;
	case 0x86dd:
		return analyze_ip6((u_char*)pkt + 14, data, npacket);
		//return -1;
		break;
	default:
		npacket->total++;
		//return -1;
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

		if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
			continue;
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
		char filter[] = "tcp or udp or icmp or icmp6";
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

	LPDWORD threadCap = NULL;
	dlg->m_ThreadHandle = CreateThread(NULL, 0, capThread, dlg, 0, threadCap);
	return 1;
}

int updateTree(int index, CMFCApplication1Dlg* dlg) {
	POSITION localpos;
	CString str;
	int i;

	dlg->m_treeCtrl.DeleteAllItems();

	localpos = dlg->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(dlg->m_localDataList.GetAt(localpos));

	HTREEITEM root = dlg->m_treeCtrl.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"), index + 1);
	HTREEITEM data = dlg->m_treeCtrl.InsertItem(str, root);

	HTREEITEM frame = dlg->m_treeCtrl.InsertItem(_T("链路层数据"), data);

	str.Format(_T("源MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->src[i]);
	}
	dlg->m_treeCtrl.InsertItem(str, frame);

	str.Format(_T("目的MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->dest[i]);
	}
	dlg->m_treeCtrl.InsertItem(str, frame);

	str.Format(_T("类型：0x%02x"), local_data->ethh->type);
	dlg->m_treeCtrl.InsertItem(str, frame);

	if (0x0806 == local_data->ethh->type)							
	{
		HTREEITEM arp = dlg->m_treeCtrl.InsertItem(_T("ARP协议头"), data);
		str.Format(_T("硬件类型：%d"), local_data->arph->ar_hrd);
		dlg->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), local_data->arph->ar_pro);
		dlg->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), local_data->arph->ar_hln);
		dlg->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), local_data->arph->ar_pln);
		dlg->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), local_data->arph->ar_op);
		dlg->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_srcmac[i]);
		}
		dlg->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_srcip[i]);
		}
		dlg->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方MAC："), local_data->arph->ar_hln);
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_destmac[i]);
		}
		dlg->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_destip[i]);
		}
		dlg->m_treeCtrl.InsertItem(str, arp);

	}
	else if (0x0800 == local_data->ethh->type) {					//IP

		HTREEITEM ip = dlg->m_treeCtrl.InsertItem(_T("IP协议头"), data);

		str.Format(_T("版本：%d"), local_data->iph->version);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("IP头长：%d"), local_data->iph->ihl);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), local_data->iph->tos);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), local_data->iph->tlen);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), local_data->iph->id);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("段偏移：%d"), local_data->iph->frag_off);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), local_data->iph->ttl);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("协议：%d"), local_data->iph->proto);
		dlg->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%02x"), local_data->iph->check);
		dlg->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		dlg->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = local_data->iph->daddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		dlg->m_treeCtrl.InsertItem(str, ip);

		if (1 == local_data->iph->proto)							
		{
			HTREEITEM icmp = dlg->m_treeCtrl.InsertItem(_T("ICMP协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmph->type);
			dlg->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), local_data->icmph->code);
			dlg->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("序号:%d"), local_data->icmph->seq);
			dlg->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), local_data->icmph->chksum);
			dlg->m_treeCtrl.InsertItem(str, icmp);

		}
		else if (6 == local_data->iph->proto) {				

			HTREEITEM tcp = dlg->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

			HTREEITEM flag = dlg->m_treeCtrl.InsertItem(_T(" 标志位"), tcp);

			str.Format(_T("cwr %d"), local_data->tcph->cwr);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), local_data->tcph->ece);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), local_data->tcph->urg);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), local_data->tcph->ack);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), local_data->tcph->psh);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), local_data->tcph->rst);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), local_data->tcph->syn);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), local_data->tcph->fin);
			dlg->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("紧急指针:%d"), local_data->tcph->urg_ptr);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("校验和:0x%02x"), local_data->tcph->check);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("选项:%d"), local_data->tcph->opt);
			dlg->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (17 == local_data->iph->proto) {				
			HTREEITEM udp = dlg->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			dlg->m_treeCtrl.InsertItem(str, udp);
		}
	}
	else if (0x86dd == local_data->ethh->type) {		
		HTREEITEM ip6 = dlg->m_treeCtrl.InsertItem(_T("IPv6协议头"), data);

		str.Format(_T("版本:%d"), local_data->iph6->flowtype);
		dlg->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("流类型:%d"), local_data->iph6->version);
		dlg->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("流标签:%d"), local_data->iph6->flowid);
		dlg->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), local_data->iph6->plen);
		dlg->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), local_data->iph6->nh);
		dlg->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("跳限制:%d"), local_data->iph6->hlim);
		dlg->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		int n;
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		dlg->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		dlg->m_treeCtrl.InsertItem(str, ip6);

		if (0x3a == local_data->iph6->nh)							
		{
			HTREEITEM icmp6 = dlg->m_treeCtrl.InsertItem(_T("ICMPv6协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmph6->type);
			dlg->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), local_data->icmph6->code);
			dlg->m_treeCtrl.InsertItem(str, icmp6);
			//str.Format(_T("序号:%d"), local_data->icmph6->seq);
			//dlg->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("校验和:%d"), local_data->icmph6->chksum);
			dlg->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-类型:%d"), local_data->icmph6->op_type);
			dlg->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-长度%d"), local_data->icmph6->op_len);
			dlg->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-链路层地址:"));
			int i;
			for (i = 0; i < 6; i++)
			{
				if (i <= 4)
					str.AppendFormat(_T("%02x-"), local_data->icmph6->op_ethaddr[i]);
				else
					str.AppendFormat(_T("%02x"), local_data->icmph6->op_ethaddr[i]);
			}
			dlg->m_treeCtrl.InsertItem(str, icmp6);

		}
		else if (0x06 == local_data->iph6->nh) {				

			HTREEITEM tcp = dlg->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->tcph->sport);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("目的端口:%d"), local_data->tcph->dport);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("序列号:0x%02x"), local_data->tcph->seq);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("确认号:%d"), local_data->tcph->ack_seq);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("头部长度:%d"), local_data->tcph->doff);

			HTREEITEM flag = dlg->m_treeCtrl.InsertItem(_T("标志位"), tcp);

			str.Format(_T("cwr %d"), local_data->tcph->cwr);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), local_data->tcph->ece);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), local_data->tcph->urg);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), local_data->tcph->ack);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), local_data->tcph->psh);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), local_data->tcph->rst);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), local_data->tcph->syn);
			dlg->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), local_data->tcph->fin);
			dlg->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("紧急指针:%d"), local_data->tcph->urg_ptr);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("校验和:0x%02x"), local_data->tcph->check);
			dlg->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("选项:%d"), local_data->tcph->opt);
			dlg->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (0x11 == local_data->iph6->nh) {				
			HTREEITEM udp = dlg->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			dlg->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			dlg->m_treeCtrl.InsertItem(str, udp);
		}
	}

	return 1;
}

int updateEdit(int index, CMFCApplication1Dlg* dlg) {
	POSITION localpos, netpos;
	localpos = dlg->m_localDataList.FindIndex(index);
	netpos = dlg->m_netDataList.FindIndex(index);

	struct datapkt* local_data = (struct datapkt*)(dlg->m_localDataList.GetAt(localpos));
	u_char* net_data = (u_char*)(dlg->m_netDataList.GetAt(netpos));

	dlg->m_edit.SetWindowText(print_packet_hex(net_data, local_data->len));

	return 1;
}