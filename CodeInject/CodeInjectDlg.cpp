
// CodeInjectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "CodeInject.h"
#include "CodeInjectDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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


// CCodeInjectDlg 对话框



CCodeInjectDlg::CCodeInjectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_CODEINJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCodeInjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_WINDOWTITLE, m_editWindowTitle);
	DDX_Control(pDX, IDC_EDIT_PID, m_editPid);
	DDX_Control(pDX, IDC_EDIT_ASM, m_editAsm);
	DDX_Control(pDX, IDC_DRAG, m_Pic);
	DDX_Control(pDX, IDC_EDIT_LOG, m_editLog);
}

BEGIN_MESSAGE_MAP(CCodeInjectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTNINJECTCODE, &CCodeInjectDlg::OnBnClickedBtninjectcode)
	ON_BN_CLICKED(IDC_BTNINJECTDLL, &CCodeInjectDlg::OnBnClickedBtninjectdll)
END_MESSAGE_MAP()


// CCodeInjectDlg 消息处理程序

BOOL CCodeInjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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

	m_editWindowTitle.SetWindowText(L"拖放图标到目标窗口,或直接输入PID");

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CCodeInjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CCodeInjectDlg::OnPaint()
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
HCURSOR CCodeInjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CCodeInjectDlg::DebugLog(CString str)
{
	m_editLog.SetSel(-1, -1);
	m_editLog.ReplaceSel(str + "\r\n", 1);
}

void CCodeInjectDlg::DebugErr(CString str)
{
	DebugLog(str);
	MessageBox(str);
}

void CCodeInjectDlg::OnBnClickedBtninjectcode()
{
	//取得编辑框内容
	CString strAsm;
	m_editAsm.GetWindowText(strAsm);
	if (strAsm.IsEmpty())
	{
		DebugLog(L"请输入汇编代码");
		return;
	}
	m_editLog.SetWindowText(L"");

	int pid = GetDlgItemInt(IDC_EDIT_PID);
	if (pid)
	{
		InjectBin(pid);
		return;
	}
	DebugErr(L"没有pid");
}


void CCodeInjectDlg::OnBnClickedBtninjectdll()
{
	int pid = GetDlgItemInt(IDC_EDIT_PID);
	if (pid)
	{
		InjectDll(pid);
		return;
	}
	DebugErr(L"没有pid");
}

BOOL CCodeInjectDlg::AdjustPr()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		TRACE("OpenProcessToken执行失败");
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		TRACE("LookupPrivilegeValue执行失败");
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		TRACE("AdjustTokenPrivileges执行失败");
		CloseHandle(hToken);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

void CCodeInjectDlg::InjectBin(DWORD pid)
{
	if (!AdjustPr())
	{
		return;
	}
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	if (!hProcess) 
	{
		DebugLog(L"OpenProcess失败");
		return;
	}
	//LPVOID pParam = VirtualAllocEx(hProcess, NULL, 4, MEM_COMMIT, PAGE_READWRITE);
	LPVOID pAddr = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pAddr)
	{
		DebugLog(L"VirtualAllocEx失败");
		return;
	}
	CString strTmp;
	CString strAsm;
	strTmp.Format(L"开辟的地址:%08X", pAddr);
	DebugLog(strTmp);
	DebugLog(L"机器码如下:");
	char error[BYTE_MAX] = { 0 };
	int count = m_editAsm.GetLineCount();
	BYTE buf[WORD_MAX] = { 0 };
	int m = 0;
	int j = 0;
	for (int i = 0; i<count; i++)
	{
		TCHAR cmd[BYTE_MAX] = { 0 };
		int len = m_editAsm.GetLine(i, cmd, BYTE_MAX);
		if (len == 0) continue;
		cmd[len] = '\0';
		t_asmmodel t_asm;
		char szCmd[BYTE_MAX] = { 0 };
		TcharToChar(cmd,szCmd);
		j = m_asm.Assemble(szCmd, (DWORD)pAddr + j, &t_asm, 0, 4, error);
		if (j <= 0)
		{
			strTmp.Format(L"error=\"%s\"", error);
			DebugLog(strTmp);
		}
		for (int k = 0; k<j; k++)
		{
			buf[m] = (BYTE)t_asm.code[k];
			strTmp.Format(L"%02X", buf[m]);
			strAsm = strAsm + strTmp;
			m = m + 1;
		}
		DebugLog(strAsm);
		strAsm = "";
	}

	buf[m] = 0x0c2;
	buf[m + 1] = 0x04;
	buf[m + 2] = 0x00;

	if (!WriteProcessMemory(hProcess, pAddr, buf, 4096, NULL)) 
	{
		DebugLog(L"WriteProcessMemory失败");
		return;
	}
	DWORD dwThreadID;
	DWORD dwParam = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddr, NULL, 0, &dwThreadID);
	if (!hRemoteThread) 
	{
		DebugLog(L"CreateRemoteThread失败");
		return;
	}
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
}

void CCodeInjectDlg::TcharToChar(const TCHAR * tchar, char * _char)
{
	int iLength;
	//获取字节长度   
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	//将tchar值赋给_char    
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

void CCodeInjectDlg::InjectDll(DWORD pid)
{
	if (!AdjustPr())
	{
		return;
	}
	TCHAR szFileName[MAX_PATH] = { 0 };

	OPENFILENAME openFileName = { 0 };
	openFileName.lStructSize = sizeof(OPENFILENAME);
	openFileName.lpstrInitialDir = NULL;
	openFileName.nMaxFile = MAX_PATH;
	openFileName.lpstrFilter = L"DLL(*.dll)\0*.dll\0";
	openFileName.lpstrFile = szFileName;
	openFileName.nFilterIndex = 1;
	openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!GetOpenFileName(&openFileName))
	{
		DebugLog(L"打开DLL文件失败");
		return;
	}


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		DebugLog(L"打开进程失败");
		return;
	}

	LPVOID lpAdd = NULL;
	lpAdd = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpAdd == NULL)
	{
		DebugLog(L"给进程分配内存失败");
		return;
	}
	char szPath[MAX_PATH] = { 0 };
	TcharToChar(szFileName, szPath);
	if (!WriteProcessMemory(hProcess, lpAdd, szPath, strlen(szPath)+1, NULL))
	{
		VirtualFreeEx(hProcess, lpAdd, MAX_PATH, MEM_RELEASE);
		DebugLog(L"写入DLL路径失败");
		return;
	}

	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA"), lpAdd, 0, NULL);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, lpAdd, MAX_PATH, MEM_RELEASE);
}