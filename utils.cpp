#include "main.h"


DWORD getAccessToSACL() {
	HANDLE hProcess; // ���������� ��������
	HANDLE hTokenHandle; // ���������� ������� �������
	struct {
		DWORD PrivilegeCount;
		LUID_AND_ATTRIBUTES Privileges[2];
	} tp; // ������ ���� ��������� ������ TOKEN_PRIVILEGES, ��������� ��������� ������ �� ���� ����������
	DWORD dwErrCode; // ��� ��������

	// �������� ���������� ��������
	hProcess = GetCurrentProcess();
	// �������� ������ ������� ��������
	if (!OpenProcessToken(
		hProcess, // ���������� ��������
		TOKEN_ALL_ACCESS, // ������ ������ � ������� �������
		&hTokenHandle)) // ���������� �������
	{
		dwErrCode = GetLastError();
		printf("Open process token failed: %u\n", dwErrCode);
		return dwErrCode;
	}

	// ������������� ����� ���������� ����������
	tp.PrivilegeCount = 2;
	// ���������� ������������� ���������� ��� ��������� ������
	if (!LookupPrivilegeValue(
		NULL, // ���� ������������� ���������� �� ��������� ����������
		SE_SECURITY_NAME, // ���������� ��� ������
		&(tp.Privileges[0].Luid)))
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}
	// ��������� ���������� ������
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// ���������� ������������� ���������� ��� ��������� ����� �������
	if (!LookupPrivilegeValue(
		NULL, // ���� ������������� ���������� �� ��������� ����������
		SE_TAKE_OWNERSHIP_NAME, // ���������� ��� �������� �������
		&(tp.Privileges[1].Luid)))
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}
	// ��������� ���������� ��������� ����� ����������
	tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	// ������������� ����� � ������������ ��� �������� ��������
	if (!AdjustTokenPrivileges(
		hTokenHandle, // ���������� ������� ������� ��������
		FALSE, // �� ��������� ��� ����������
		(PTOKEN_PRIVILEGES)&tp, // ����� ����������
		0, // ����� ������ ���
		NULL, // ���������� ��������� ���������� �� �����
		NULL)) // ����� ������ �� �����
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}

	return ERROR_SUCCESS;
}