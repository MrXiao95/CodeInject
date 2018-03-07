
// CodeInjectDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "CodeInject.h"
#include "CodeInjectDlg.h"
#include "afxdialogex.h"
#include "ShowProcessDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CCodeInjectDlg �Ի���



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
    ON_BN_CLICKED(IDC_BTNVIEWPROCESS, &CCodeInjectDlg::OnBnClickedBtnviewprocess)
END_MESSAGE_MAP()


// CCodeInjectDlg ��Ϣ�������

BOOL CCodeInjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	m_editWindowTitle.SetWindowText(L"�Ϸ�ͼ�굽Ŀ�괰��,��ֱ������PID");

    if (!AdjustPr())
    {
        return TRUE;
    }

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CCodeInjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
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
	//ȡ�ñ༭������
	CString strAsm;
	m_editAsm.GetWindowText(strAsm);
	if (strAsm.IsEmpty())
	{
		DebugLog(L"�����������");
		return;
	}
	m_editLog.SetWindowText(L"");

	int pid = GetDlgItemInt(IDC_EDIT_PID);
	if (pid)
	{
		InjectBin(pid);
		return;
	}
	DebugErr(L"û��pid");
}


void CCodeInjectDlg::OnBnClickedBtninjectdll()
{
	int pid = GetDlgItemInt(IDC_EDIT_PID);
	if (pid)
	{
		InjectDll(pid);
		return;
	}
	DebugErr(L"û��pid");
}

BOOL CCodeInjectDlg::AdjustPr()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		TRACE("OpenProcessTokenִ��ʧ��");
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		TRACE("LookupPrivilegeValueִ��ʧ��");
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		TRACE("AdjustTokenPrivilegesִ��ʧ��");
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
		DebugLog(L"OpenProcessʧ��");
		return;
	}
	//LPVOID pParam = VirtualAllocEx(hProcess, NULL, 4, MEM_COMMIT, PAGE_READWRITE);
	LPVOID pAddr = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pAddr)
	{
		DebugLog(L"VirtualAllocExʧ��");
		return;
	}
	CString strTmp;
	CString strAsm;
	strTmp.Format(L"���ٵĵ�ַ:%08X", pAddr);
	DebugLog(strTmp);
	DebugLog(L"����������:");
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
		DebugLog(L"WriteProcessMemoryʧ��");
		return;
	}
	DWORD dwThreadID;
	DWORD dwParam = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddr, NULL, 0, &dwThreadID);
	if (!hRemoteThread) 
	{
		DebugLog(L"CreateRemoteThreadʧ��");
		return;
	}
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
}

void CCodeInjectDlg::TcharToChar(const TCHAR * tchar, char * _char)
{
	int iLength;
	//��ȡ�ֽڳ���   
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	//��tcharֵ����_char    
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

void CCodeInjectDlg::InjectDll(DWORD pid)
{
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
		DebugLog(L"��DLL�ļ�ʧ��");
		return;
	}


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		DebugLog(L"�򿪽���ʧ��");
		return;
	}

	LPVOID lpAdd = NULL;
	lpAdd = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpAdd == NULL)
	{
		DebugLog(L"�����̷����ڴ�ʧ��");
		return;
	}
	char szPath[MAX_PATH] = { 0 };
	TcharToChar(szFileName, szPath);
	if (!WriteProcessMemory(hProcess, lpAdd, szPath, strlen(szPath)+1, NULL))
	{
		VirtualFreeEx(hProcess, lpAdd, MAX_PATH, MEM_RELEASE);
		DebugLog(L"д��DLL·��ʧ��");
		return;
	}

	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA"), lpAdd, 0, NULL);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, lpAdd, MAX_PATH, MEM_RELEASE);
}

void CCodeInjectDlg::OnBnClickedBtnviewprocess()
{
    CShowProcessDlg dlg;
    if (dlg.DoModal() == IDOK)
    {
        m_editPid.SetWindowText(dlg.GetSelectPid());
    }
}
