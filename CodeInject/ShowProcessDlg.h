#pragma once
#include "afxcmn.h"
#include <tlhelp32.h>


// CShowProcessDlg �Ի���

class CShowProcessDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CShowProcessDlg)

public:
	CShowProcessDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CShowProcessDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SHOWPROCESS_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
    virtual BOOL OnInitDialog();
private:
    CListCtrl m_listProcess;
public:
    afx_msg void OnBnClickedBtninjectdll();
    void InsertProcessInfo(PROCESSENTRY32& pe);
    afx_msg void OnNMClickListprocess(NMHDR *pNMHDR, LRESULT *pResult);
    CString GetSelectPid();
private:
    CListCtrl m_listModule;
    CString m_strPid;
public:
    void Uninstall(DWORD dwPid, CString szGameDllPath);
    void TcharToChar(const TCHAR *tchar, char *_char);
    afx_msg void OnBnClickedBtnuninjectdll();
    afx_msg void OnBnClickedBtnrefresh();
};
