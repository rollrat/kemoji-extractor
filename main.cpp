#define _CRT_SECURE_NO_WARNINGS

// origin: https://github.com/cloudchamb3r/moji-dump-osx/blob/main/dump.cpp

#include <Windows.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <tlhelp32.h>

DWORD FindProcessByName(const wchar_t *szProcess) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 ProcessEntry32;

  if (hSnapshot) {
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(hSnapshot, &ProcessEntry32)) {
      if (wcscmp(ProcessEntry32.szExeFile, szProcess) == 0)
        return ProcessEntry32.th32ProcessID;
    }
    CloseHandle(hSnapshot);
  }
  return 0;
}

int main() {
  DWORD *Result = 0;
  DWORD pid, value, count;

#if 0
  printf("Process Pid : ");
  scanf_s("%d", &pid);
#else
  pid = FindProcessByName(L"^_^.exe");
#endif
  
  constexpr int riff_magic = 0x46464952;
  constexpr int webp_magic = 0x50424557;
  constexpr int mem_buffer_sz = 0x8000;

  SYSTEM_INFO sys_info;
  MEMORY_BASIC_INFORMATION mbi;
  DWORD vqAddr;
  DWORD lpfOldProtect;
  HANDLE hProcess;

  if (!(hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
    return NULL;

  if (!hProcess)
    return NULL;

  GetSystemInfo(&sys_info);
  vqAddr = (DWORD)sys_info.lpMinimumApplicationAddress;

  for (count = 0; vqAddr < (DWORD)sys_info.lpMaximumApplicationAddress;) {
    if (VirtualQueryEx(hProcess, (LPVOID)vqAddr, &mbi, sizeof(mbi)) !=
        sizeof(mbi))
      continue;

    if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT &&
        mbi.RegionSize > 0) {

      BYTE *readmem = new BYTE[mbi.RegionSize];
      VirtualProtectEx(hProcess, mbi.BaseAddress, mem_buffer_sz,
                       PAGE_EXECUTE_READWRITE, &lpfOldProtect);

      if (!ReadProcessMemory(hProcess, mbi.BaseAddress,
                             reinterpret_cast<LPVOID>(readmem), mbi.RegionSize,
                             NULL))
        goto ENDVPE;

      for (int i = 0; i < mbi.RegionSize - 16; i++) {
        if ((i + mem_buffer_sz + 1) > mbi.RegionSize)
          break;

        int _riff_magic = *((int *)(readmem + i));
        int _size = *((int *)(readmem + i + 4));
        int _webp_magic = *((int *)(readmem + i + 8));

        if (riff_magic == _riff_magic && webp_magic == _webp_magic &&
            _size != 0) {
          printf("%X %X\n", (DWORD)mbi.BaseAddress + i, _size);

          auto webp_dump_size = _size + 12;
          auto webp_dump = std::make_unique<char[]>(webp_dump_size);

          std::ofstream webp(std::to_string((DWORD)mbi.BaseAddress + i) +
                                 ".webp",
                             std::ios_base::binary);

          webp.write((char *)(readmem + i), webp_dump_size);
          webp.close();
        }
      }

    ENDVPE:
      VirtualProtectEx(hProcess, mbi.BaseAddress, mem_buffer_sz, lpfOldProtect,
                       NULL);
      delete[] readmem;
    }
    vqAddr = (DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize;
  }

  CloseHandle(hProcess);
}
