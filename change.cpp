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
		wscanf(L"%d", &tryAgain);
		if (tryAgain) {
			wprintf(L"\nEnter the username of the new owner of the file: ");
			wscanf(L"\n%s", userName);
			fileOwnerPSID = getUserSIDByAccountName(userName);
		}
		else return 1;
	}
	getwchar(); // ��������� ���������� � ������ ������� ������

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
	printf("The new owner of the file is successfully set.\n\n");

	return ERROR_SUCCESS;
}

DWORD changeACL(HANDLE fileDescriptor) {
	PSECURITY_DESCRIPTOR pSecurityDescriptor; // �������� ���������� ������������ �����
	PACL pDacl; // ��������� �� DACL �����
	PACL pSacl; // ��������� �� SACL �����
	DWORD dwRetCode; // ��� ��������
	DWORD flags[] = { SE_DACL_PROTECTED, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_SACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ };
	SECURITY_DESCRIPTOR_CONTROL allFlagsBitmask = 0; // ����� DACL � SACL, ������� ����� ������������� ��� ��������
	SECURITY_DESCRIPTOR_CONTROL flagsToSetBitmask = 0; // ����� DACL � SACl, ������� ����� ������������� (���������)
	size_t index; // �����, �� �������� ����� �������� �� ������� flags ���� ��� �������� ��� ����������
	WCHAR choice; // ����� ������������, ������� ����� ��������������� � ����� (������)
	

	dwRetCode = GetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION, // ��� ����������
		NULL, // ��������� �� SID ��������� �� �����
		NULL, // ��������� �� ��������� ������ �� ����� 
		&pDacl, // ��������� �� DACL
		&pSacl, // ��������� �� SACL
		&pSecurityDescriptor); // ����� ��������� �� SD
	if (dwRetCode != ERROR_SUCCESS)
	{
		printf("Get named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
 
	wprintf(L"\nEnter the security descriptor flags you want to set \
(SE_DACL_PROTECTED - 1, SE_DACL_INHERITED - 2, SE_DACL_AUTO_INHERIT_REQ - 3, SE_SACL_PROTECTED - 4, SE_SACL_INHERITED - 5, SE_SACL_AUTO_INHERIT_REQ - 6).\n\
For example, to set flags 1, 4 and 6, you need to enter 146: ");
	choice = getwchar(); // ��������� ���� ������
	while (choice >= '1' && choice <= '6') { // ���� ������������ ���� �� �����, ���������� ����������
		index = choice - '0' - 1; // ����������� ������ char � ����� (int) ���������� '0' � �������� ������� ��� ��������� �������
		allFlagsBitmask |= flags[index]; // ��������� � ������� ����� ���� ������ �������������� ����
		flagsToSetBitmask |= flags[index]; // ��������� � ������� ����� ������ ��� ��������� ������� ����
		choice = getwchar();
	}

	wprintf(L"\nEnter the security descriptor flags you want to delete \
(SE_DACL_PROTECTED - 1, SE_DACL_INHERITED - 2, SE_DACL_AUTO_INHERIT_REQ - 3, SE_SACL_PROTECTED - 4, SE_SACL_INHERITED - 5, SE_SACL_AUTO_INHERIT_REQ - 6).\n\
For example, to set flags 1, 4 and 6, you need to enter 146: ");
	choice = getwchar(); // ��������� ���� ������
	while (choice >= '1' && choice <= '6') { // ���� ������������ ���� �� �����, ���������� ����������
		index = choice - '0' - 1; // ����������� ������ char � ����� (int) ���������� '0' � �������� ������� ��� ��������� �������
		allFlagsBitmask |= flags[index]; // ��������� � ������� ����� ���� ������ �������������� ����
		choice = getwchar();
	}

	if (!SetSecurityDescriptorControl(
		pSecurityDescriptor,
		allFlagsBitmask,
		flagsToSetBitmask))
	{
		dwRetCode = GetLastError();
		printf("Set security descriptor control failed.");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}

	dwRetCode = SetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
		PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION, // �������� ���������� � DACL
		NULL, // ��������� �� ��������
		NULL, // ��������� ������ �� ��������
		pDacl, // DACL ��������
		pSacl); // SACL ��������
	if (dwRetCode != ERROR_SUCCESS)
	{
		printf("Set named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}

	return ERROR_SUCCESS;
}