#include "main.h"

Account getUserAccountFromSID(PSID lpSID) {
	LPTSTR lpDomainName = NULL, userName = NULL;

	DWORD dwErrCode;
	DWORD dwLengthOfUserName = 0, dwLengthOfDomainName = 0;
	SID_NAME_USE type_of_SID;
	if (!LookupAccountSid(
		NULL, // ���� �� ��������� ����������
		lpSID, // ��������� �� SID
		userName, // ��� ������������
		&dwLengthOfUserName, // ����� ����� ������������
		lpDomainName, // ���������� ��� ������
		&dwLengthOfDomainName, // ����� ����� ������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER) {
			// ������������ ������ ��� ��� ������
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
			userName = (LPTSTR) new wchar_t[dwLengthOfUserName];
		}
		else {
			printf("Lookup account SID for length failed.\n");
			printf("Error code: %d\n", dwErrCode);
		}
	}
	// ���������� ��� ������� ������ �� SID
	if (!LookupAccountSid(
		NULL, // ���� �� ��������� ����������
		lpSID, // ��������� �� SID
		userName, // ��� ������������
		&dwLengthOfUserName, // ����� ����� ������������
		lpDomainName, // ���������� ��� ������ 
		&dwLengthOfDomainName, // ����� ����� ������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		printf("Lookup account SID failed.\n");
		printf("Error code: %d\n", dwErrCode);
	}

	Account currentSIDOwner = { userName, lpDomainName };
	return currentSIDOwner;
}

void printAllSecurityDescriptorInformation(PSECURITY_DESCRIPTOR securityDescriptorPtr) {
	BOOL bOwnerDefaulted = FALSE; // ���� ��������� �� ���������
	BOOL bGroupDefaulted = FALSE; // ���� ��������� ������ �� ���������
	PSID pSidOwner = NULL; // ��������� �� SID ��������� ������� 
	PSID pSidGroup = NULL; // ��������� �� SID ��������� ������ �������
	SECURITY_DESCRIPTOR_CONTROL wControl; // ����������� ����� �� SD 
	DWORD dwRevision; // ������ ����������� ������������ 
	DWORD dwRetCode; // ��� ��������

	// �������� SD ��������� �������
	if (!GetSecurityDescriptorOwner(
		securityDescriptorPtr,
		&pSidOwner,
		&bOwnerDefaulted))
	{
		printf("Get security descriptor owner failed.\n");
		dwRetCode = GetLastError();
		printf("Error code: %u\n", dwRetCode);
		exit(dwRetCode);
	}
	// �������� SD ��������� ������ ��������� �������
	if (!GetSecurityDescriptorGroup(
		securityDescriptorPtr,
		&pSidGroup,
		&bGroupDefaulted))
	{
		printf("Get security descriptor group failed.\n");
		dwRetCode = GetLastError();
		printf("Error code: %u\n", dwRetCode);
		exit(dwRetCode);
	}
	
	wprintf(L"File owner %s set by default\n", bOwnerDefaulted ? L"is" : L"isn`t");
	wprintf(L"File group-owner %s set by default\n", bGroupDefaulted ? L"is" : L"isn`t");

	if (!GetSecurityDescriptorControl(
		securityDescriptorPtr,
		&wControl,
		&dwRevision))
	{
		dwRetCode = GetLastError();
		printf("Get security descriptor control failed.\n");
		printf("Error code: %u\n", dwRetCode);
		exit(dwRetCode);
	}
	printf("\nThe following control flags are set: \n");
	// ���������� ���������� �� ������������ �����
	if (wControl & SE_DACL_AUTO_INHERITED)
		printf("SE_DACL_AUTO_INHERITED\n");
	if (wControl & SE_DACL_DEFAULTED)
		printf("SE_DACL_DEFAULTED\n");
	if (wControl & SE_DACL_PRESENT)
		printf("SE_DACL_PRESENT\n");
	if (wControl & SE_DACL_PROTECTED)
		printf("SE_DACL_PROTECTED\n");
	// ������� �� ������ ������ ����������� ������������
	printf("\nDescriptor revision: %u\n", dwRevision);

}

void printFileSecurityInfo(HANDLE fileDescriptor) {
	PSID pSidOwner; // ��������� �� SID ��������� �������
	PSID pSidGroup; // ��������� �� SID ��������� ������ �������
	PSECURITY_DESCRIPTOR pSecurityDescriptor; // ��������� �� SD
	LPTSTR lpStringSid; // ��������� �� ������ SID
	DWORD dwRetCode; // ��� ��������

	// �������� ���������� ������������ �����
	dwRetCode = GetSecurityInfo(
		fileDescriptor, // ���������� �����
		SE_FILE_OBJECT, // ������ ����
		GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&pSidOwner, // ����� ��������� �� SID ���������
		&pSidGroup, // ����� ��������� �� ��������� ������
		NULL, // ��������� �� DACL �� �����
		NULL, // ��������� �� SACL �� �����
		&pSecurityDescriptor); // ����� ��������� �� SD
	if (dwRetCode != ERROR_SUCCESS) {
		printf("Get named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		exit(dwRetCode);
	}
	// ����������� SID ��������� � ������
	if (!ConvertSidToStringSid(pSidOwner, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		exit(dwRetCode);
	}
	// �������� SID ���������
	wprintf(L"File owner SID: %s\n", lpStringSid);
	// ����������� ������ ��� ������
	LocalFree(lpStringSid);
	// ����������� SID ��������� ������ � ������
	if (!ConvertSidToStringSid(pSidGroup, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		exit(dwRetCode);
	}
	// �������� SID ��������� ������
	wprintf(L"File group SID: %s\n", lpStringSid);
	// ����������� ������ ��� ������
	LocalFree(lpStringSid);

	// �������� ���������, ���������� �������� � ����� ������ (���������) �����
	Account fileOwner = getUserAccountFromSID(pSidOwner);
	// �������� �������� � ��� ������
	wprintf(L"File owner name: %s\n", fileOwner.userName);
	wprintf(L"File owner domain: %s\n", fileOwner.domainName);
	printAllSecurityDescriptorInformation(pSecurityDescriptor);

	// ����������� ������ ��� �����������
	LocalFree(pSecurityDescriptor);
}