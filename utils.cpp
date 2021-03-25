#include "main.h"

PISECURITY_DESCRIPTOR getSecurityDescriptor(HANDLE fileDescriptor) {
	PISECURITY_DESCRIPTOR pSecurityDescriptor; // ��������� �� SD
	DWORD dwErrCode; // ��� ��������� ������

	// �������� ���������� ������������ �����
	dwErrCode = GetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
		BACKUP_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
		PROTECTED_SACL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION,
		NULL, // ����� ��������� �� SID ��������� �� �����
		NULL, // ����� ��������� �� ��������� ������ �� �����
		NULL, // ��������� �� DACL �� �����
		NULL, // ��������� �� SACL �� �����
		(PSECURITY_DESCRIPTOR*) &pSecurityDescriptor); // ����� ��������� �� SD
	if (dwErrCode != ERROR_SUCCESS) {
		printf("Get security info failed.\n");
		printf("Error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	
	// ���������, �������� �� �� �������� ���������� ������������
	if (!IsValidSecurityDescriptor(pSecurityDescriptor))
	{
		dwErrCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode); // ���� ���������� - ������� �� ���������
	}

	return pSecurityDescriptor;
}

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