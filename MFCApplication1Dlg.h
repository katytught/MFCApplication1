
// MFCApplication1Dlg.h: 头文件
//

#pragma once
#include"myStructs.h"
#include"pcap.h"


// CMFCApplication1Dlg 对话框
class CMFCApplication1Dlg : public CDialogEx
{
// 构造
public:
	CMFCApplication1Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION1_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_selectNetCom;
	CComboBox m_selectFuncCom;
	CButton m_startBut;
	CButton m_stopBut;
	CTreeCtrl m_treeCtrl;
	CEdit m_edit;
	CEdit m_tcpEdit;
	CEdit m_httpEdit;
	CEdit m_ipv6Edit;
	CEdit m_udpEdit;
	CEdit m_arpEdit;
	CEdit m_ipv4Edit;
	CEdit m_icmpEdit;
	CEdit m_icmpv6Edit;
	CEdit m_totalEdit;
	afx_msg void OnClickedButtonStart();
	CListCtrl m_listCtrl;
	int npkt;
	CPtrList m_localDataList;
	CPtrList m_netDataList;
	struct pktcount npacket;
	pcap_if_t* dev;
	pcap_if_t* alldev;
	pcap_t* pkt;
	char errbuf[PCAP_ERRBUF_SIZE];
	HANDLE m_ThreadHandle;
	afx_msg void OnClickedButtonStop();
	afx_msg void OnItemchangedPacket(NMHDR* pNMHDR, LRESULT* pResult);
};
