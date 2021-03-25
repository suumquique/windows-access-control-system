// Файл с заголовками всех функций и библиотек проекта
#include "main.h"

int main(){
	DWORD dwErrCode = getAccessToSACL();
	if (dwErrCode != ERROR_SUCCESS) {
		wprintf(L"Cannot get access to SACL\n");
		wprintf(L"Error code: %d\n", dwErrCode);
		return dwErrCode;
	}

	HANDLE fileDescriptor = createFileAndGetDescriptor();
	printFileSecurityInfo(fileDescriptor);
	changeOwner(fileDescriptor);
	system("pause");
}