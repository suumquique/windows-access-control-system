#include "main.h"

PSECURITY_DESCRIPTOR getSecurityDescriptor(HANDLE fileDescriptor) {
	PSECURITY_DESCRIPTOR pSecurityDescriptor; // ��������� �� SD
	DWORD dwRetCode; // ��� ��������

	// �������� ���������� ������������ �����
	dwRetCode = GetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		NULL, // ����� ��������� �� SID ��������� �� �����
		NULL, // ����� ��������� �� ��������� ������ �� �����
		NULL, // ��������� �� DACL �� �����
		NULL, // ��������� �� SACL �� �����
		&pSecurityDescriptor); // ����� ��������� �� SD
	if (dwRetCode != ERROR_SUCCESS) {
		printf("Get named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		exit(1);
	}

	return pSecurityDescriptor;
}

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
	wprintf(L"\nEnter the username of the new owner of the file : ");
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

	// �������� ��������� �� ���������� ������������ �����
	PSECURITY_DESCRIPTOR fileSecurityDescriptorPtr = getSecurityDescriptor(fileDescriptor);

	if (!IsValidSecurityDescriptor(fileSecurityDescriptorPtr)) {
		wprintf(L"Invalid security descriptor\n");
		return NULL;
	}

	// ������������� ������ ��������� ����� �� SID ������������
	if (!SetSecurityDescriptorOwner(fileSecurityDescriptorPtr, fileOwnerPSID, FALSE)) {
		dwErrCode = GetLastError();
		wprintf(L"Cannot set this user as new file owner.\n");
		wprintf(L"Error code: %d\n", dwErrCode);
		return dwErrCode;
	}
	else wprintf(L"New file owner successfully assigned\n");


}