#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD get_pid(LPCTSTR name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pentry;
	pentry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &pentry);
	DWORD pid = 0;
	do {
		if (!lstrcmp(pentry.szExeFile, name)) {
			pid = pentry.th32ProcessID;
			break;
		}
	} while (Process32Next(snapshot, &pentry));
	CloseHandle(snapshot);
	return pid;
}

#define _ERROR(n) \
	switch (n) { \
		case 1: \
			puts("error: too few arguments!"); \
			return n; \
		case 2: \
			puts("error: not found process!"); \
			return n; \
		case 3: \
			puts("error: can't write process memory!"); \
			return n; \
		case 4: \
			puts("error: can't create process thread!"); \
			return n; \
		case 5: \
			puts("error: not found dll on process!"); \
			return n; \
	}

int main(int argc, char const *argv[]) {
	int ac = 0;
	char const **av = malloc(argc);

	bool free_mode = false;
	bool not_found_wait = false;

	for (size_t i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--free")) {
				free_mode = true;
			} else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--not-found-wait")) {
				not_found_wait = true;
			}
		} else {
			av[ac++] = argv[i];
		}
	}

	if (ac < 2) {
		puts("error!");
		_ERROR(1);
	}

	HANDLE h = NULL;
	HANDLE th = NULL;

	if (av[0][0] == '*') {
		STARTUPINFOA si;
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		memset(&pi, 0, sizeof(pi));

		if (CreateProcessA(
			NULL,
			(char *)&av[0][1],
			NULL,
			NULL,
			true,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&si,
			&pi
		)) {
			h = pi.hProcess;
			th = pi.hThread;
		} else {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
	} else {
		DWORD pid = get_pid(av[0]);
		if (!pid) {
			if (not_found_wait) {
				do {
					Sleep(1000);
					pid = get_pid(av[0]);
				} while (!pid);
				Sleep(5000);
			} else {
				_ERROR(2);
			}
		}
		h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	}

	if (!h) {
		_ERROR(2);
	}

	DWORD dll_name_sz = strlen(av[1]) + 1;
	SIZE_T writed_len;
	LPVOID rmt_dll_name = VirtualAllocEx(h, NULL, dll_name_sz, MEM_COMMIT,PAGE_READWRITE);
	if (WriteProcessMemory(h, rmt_dll_name, av[1], dll_name_sz, &writed_len)) {
		if (writed_len != dll_name_sz) {
			VirtualFreeEx(h, rmt_dll_name, dll_name_sz, MEM_COMMIT);
			CloseHandle(h);
			_ERROR(3);
		}
	} else {
		CloseHandle(h);
		_ERROR(3);
	}

	HANDLE pthrd;

	if (!free_mode) {
		DWORD pthrd_id;
		pthrd = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)&LoadLibraryA, rmt_dll_name, 0, &pthrd_id);
		if (!pthrd) {
			CloseHandle(h);
			_ERROR(4);
		}
	} else {
		DWORD pthrd_id;
		pthrd = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)&GetModuleHandleA, rmt_dll_name, 0, &pthrd_id);
		if (!pthrd) {
			CloseHandle(h);
			_ERROR(4);
		}
		WaitForSingleObject(pthrd, INFINITE);

		DWORD rmt_dll;
		GetExitCodeThread(pthrd, &rmt_dll);
		CloseHandle(pthrd);

		if (!rmt_dll) {
			_ERROR(5);
		}

		pthrd = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)&FreeLibrary, (LPVOID)rmt_dll, 0, &pthrd_id);
		if (!pthrd) {
			CloseHandle(h);
			_ERROR(4);
		}
	}

	WaitForSingleObject(pthrd, INFINITE);
	DWORD pthrd_r;
	GetExitCodeThread(pthrd, &pthrd_r);
	CloseHandle(pthrd);

	printf("result: %d\n", pthrd_r);

	if (th) {
		ResumeThread(th);
		CloseHandle(th);
	}

	CloseHandle(h);
	return 0;
}
