
// MFCApplication1Dlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"
#include"func.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include <pcap.h>
using namespace std;


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 对话框



CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO2, m_selectNetCom);
	DDX_Control(pDX, IDC_COMBO3, m_selectFuncCom);
	DDX_Control(pDX, IDC_BUTTON2, m_startBut);
	DDX_Control(pDX, IDC_BUTTON1, m_stopBut);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT3, m_edit);
	DDX_Control(pDX, IDC_EDIT4, m_tcpEdit);
	DDX_Control(pDX, IDC_EDIT6, m_httpEdit);
	DDX_Control(pDX, IDC_EDIT12, m_ipv6Edit);
	DDX_Control(pDX, IDC_EDIT7, m_udpEdit);
	DDX_Control(pDX, IDC_EDIT8, m_arpEdit);
	DDX_Control(pDX, IDC_EDIT9, m_ipv4Edit);
	DDX_Control(pDX, IDC_EDIT10, m_icmpEdit);
	DDX_Control(pDX, IDC_EDIT14, m_icmpv6Edit);
	DDX_Control(pDX, IDC_EDIT13, m_othersEdit);
	DDX_Control(pDX, IDC_EDIT11, m_totalEdit);
	DDX_Control(pDX, IDC_LIST2, m_listCtrl);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO2, &CMFCApplication1Dlg::OnSelchangeNet)
	ON_CBN_SELCHANGE(IDC_COMBO3, &CMFCApplication1Dlg::OnSelchangeFunc)
	ON_BN_CLICKED(IDC_BUTTON2,&CMFCApplication1Dlg::OnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnClickedButtonStop)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 消息处理程序

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0, _T("编号"), 3, 100);                        //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1, _T("时间"), 3, 100);
	m_listCtrl.InsertColumn(2, _T("长度"), 3, 100);
	m_listCtrl.InsertColumn(3, _T("源MAC地址"), 3, 225);
	m_listCtrl.InsertColumn(4, _T("目的MAC地址"), 3, 350);
	m_listCtrl.InsertColumn(5, _T("协议"), 3, 100);
	m_listCtrl.InsertColumn(6, _T("源IP地址"), 3, 200);
	m_listCtrl.InsertColumn(7, _T("目的IP地址"), 3, 250);
	
	
	alldev = initCap();

	if (alldev == NULL)
		return FALSE;

	int devCount = 0;
	
	for (dev = alldev; dev; dev = dev->next)
	{
		if (dev->description)
			devCount++;
			m_selectNetCom.AddString(CString(dev->description));  //////////////////////////////Problem 1字符集问题
	}
	CString str_count;
	str_count.Format(_T("%d"), devCount);
	m_selectNetCom.AddString(_T("共检测到"+CString(str_count)+"个设备，请选择"));

	m_selectFuncCom.AddString(_T("选择协议"));
	m_selectFuncCom.AddString(_T("tcp"));
	m_selectFuncCom.AddString(_T("udp"));
	m_selectFuncCom.AddString(_T("ip"));
	m_selectFuncCom.AddString(_T("icmp"));
	m_selectFuncCom.AddString(_T("arp"));


	m_selectNetCom.SetCurSel(m_selectNetCom.GetCount()-1);
	m_selectFuncCom.SetCurSel(0);

	m_stopBut.EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCApplication1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCApplication1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCApplication1Dlg::OnSelchangeNet()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CMFCApplication1Dlg::OnSelchangeFunc()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CMFCApplication1Dlg::OnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码
	this->npkt = 1;													
	this->m_localDataList.RemoveAll();				
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket), 0, sizeof(struct pktcount));
	updateNPacket(this);

	if (startCap(this) < 0)
		return;
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowTextW(_T(""));
	this->m_startBut.EnableWindow(FALSE);
	this->m_stopBut.EnableWindow(TRUE);
}

void CMFCApplication1Dlg::OnClickedButtonStop()
{
	// TODO: 在此添加控件通知处理程序代码
}
