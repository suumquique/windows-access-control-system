#include "main.h"

#define MAX_FILE_PATH_LEN 1000

HANDLE createFileAndGetDescriptor() {
	wchar_t fileName[MAX_FILE_PATH_LEN];
	wprintf(L"Input a file name to create (with extension): ");
	if (!wscanf(L"%s", fileName)) {
		wprintf(L"Cannot read file name.\n");
		exit(1);
	}

	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa;

	DWORD dwErrCode; // ��� ��������
 // �������������� ������ ����������� ������������
	if (!InitializeSecurityDescriptor(
		&sd,
		SECURITY_DESCRIPTOR_REVISION))
	{
		dwErrCode = GetLastError();
		printf("Initialize security descroptor failed.\n");
		printf("Error code: %d\n", dwErrCode);
		exit(dwErrCode);
	}
	// ������������� SID ��������� �������
	if (!SetSecurityDescriptorOwner(
		&sd, // ����� ����������� ������������
		NULL, // �� ������ ���������
		SE_OWNER_DEFAULTED)) // ���������� ��������� �� ���������
	{
		dwErrCode = GetLastError();
		perror("Set security descriptor owner failed.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// ������������� SID ��������� ������ ���������
	if (!SetSecurityDescriptorGroup(
		&sd, // ����� ����������� ������������
		NULL, // �� ������ ��������� ������
		SE_GROUP_DEFAULTED)) // ���������� ��������� ������ �� ���������
	{
		dwErrCode = GetLastError();
		perror("Set security descriptor group failed.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}

	// ��������� ��������� ����������� ������������
	if (!IsValidSecurityDescriptor(&sd)) {
		dwErrCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// �������������� �������� ������������
	sa.nLength = sizeof(sa); // ������������� ����� ��������� ������
	sa.lpSecurityDescriptor = &sd; // ������������� ����� SD
	sa.bInheritHandle = FALSE;

	DWORD dwDesiredAccess = STANDARD_RIGHTS_ALL; // ������������� ��������� ������� � �����
	DWORD dwShareMode = 0; // ������������, ��� ������� � ����� �� �����, ���� ��� ���������� �� ������
	HANDLE fileHandle = CreateFileW(fileName, dwDesiredAccess, dwShareMode, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"Cannot create file with current security attributes.\n");
		exit(1);
	}

	wprintf(L"File with specified security attributes was successfully created.\n\n\n");

	return fileHandle;
}