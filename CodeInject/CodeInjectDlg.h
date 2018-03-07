
// CodeInjectDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "DragPic.h"
#include "XASM.h"

// CCodeInjectDlg �Ի���
class CCodeInjectDlg : public CDialogEx
{
// ����
public:
	CCodeInjectDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CODEINJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	CEdit m_editWindowTitle;
	CEdit m_editPid;
	CEdit m_editAsm;
	CDragPic m_Pic;
	CEdit m_editLog;
	XASM m_asm;
public:
	afx_msg void OnBnClickedBtninjectcode();
	afx_msg void OnBnClickedBtninjectdll();
	void DebugLog(CString str);
	void DebugErr(CString str);
	BOOL AdjustPr();
	void InjectBin(DWORD pid);
	void InjectDll(DWORD pid);
	void TcharToChar(const TCHAR * tchar, char * _char);
    afx_msg void OnBnClickedBtnviewprocess();
};
