#include "main.h"

PSID getUserSIDByAccountName(wchar_t* accountName) {
	wchar_t* lpDomainName = NULL;
	DWORD dwErrCode; // ��� ������
	DWORD dwLengthOfSID = 0; // ����� SID
	DWORD dwDomainLength = 0;
	DWORD dwLengthOfUserName = UNLEN; // ����� ����� ������� ������
	SID* lpSID = NULL; // ��������� �� SID
	SID_NAME_USE type_of_SID; // ��� ������� ������

	// ���������� ����� SID ������������
	if (!LookupAccountName(
		NULL, // ���� ��� �� ��������� ����������
		accountName, // ��� ������������
		NULL, // ���������� ����� SID 
		&dwLengthOfSID, // ����� SID
		lpDomainName, // ���������� ��� ������
		&dwDomainLength, // ����� ����� ������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER) {
			// ������������ ������ ��� SID
			lpSID = (SID*) new char[dwLengthOfSID];
			lpDomainName = new wchar_t[dwDomainLength];
		}
		else {
			// ������� �� ���������
			printf("Lookup account name failed.\n");
			printf("Error code: %d\n", dwErrCode);
			return NULL;
		}
	}
	// ���������� SID � ��� ������ ������������
	if (!LookupAccountNameW(
		NULL, // ���� ��� �� ��������� ����������
		accountName, // ��� ������������
		lpSID, // ��������� �� SID
		&dwLengthOfSID, // ����� SID
		lpDomainName, // ����� �� �����
		&dwDomainLength, // ����� ������ �� ���������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		printf("Lookup account name failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return NULL;
	}

	return lpSID;
}

DWORD changeOwner(HANDLE fileDescriptor) {
	wchar_t userName[UNLEN]; // ��� ������ ��������� �����
	BOOL tryAgain = FALSE; // ���������� �� ��� ������ ��������� ����� ��� �������
	DWORD dwErrCode; // ��� ��������
	wprintf(L"\nEnter the username of the new owner of the file: ");
	wscanf(L"%s", userName);
	// �������� ��������� �� SID ����� �� �����
	PSID fileOwnerPSID = getUserSIDByAccountName(userName);
	// ���� ��� ������� �������, ���������� ������������, ����������� �� ��� ���
	while (fileOwnerPSID == NULL) {
		wprintf(L"Incorrect account name. Try again? Yes - 1, No - 0: ");
		wscanf(L"%d", tryAgain);
		if (tryAgain) {
			wscanf(L"%s", userName);
			fileOwnerPSID = getUserSIDByAccountName(userName);
		}
		else return 1;
	}

	// ������������� ������ ��������� �����
	dwErrCode = SetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		OWNER_SECURITY_INFORMATION, // �������� ������ ��� ��������� �����
		fileOwnerPSID, // ����� �� SID ������ ���������
		NULL, // ��������� ������ �� ��������
		NULL, // DACL �� ��������
		NULL); // SACL �� ��������
	if (dwErrCode != ERROR_SUCCESS)
	{
		printf("Set named security info failed.\n");
		printf("Error code: %u\n", dwErrCode);
		return dwErrCode;
	}
	printf("The new owner of the file is set.\n");

}