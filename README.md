# ETW-Patcher
A simple C++ script that first checks if `NtProtectVirtualMemory` and `NtAllocateVirtualMemory` are hooked or not. Then it loads the `ntdll.dll` with LoadLibrary and gets the address of the function `EtwEventWrite` using GetProcAddress. Finally, it writes the patch bytes into the process.

# Usage

- Without ETW bypass.
![image](https://github.com/Gurpreet06/ETW-Patcher/assets/74554439/31a65aff-0b38-4867-bcb2-6133c97f2680)

- With ETW bypass.
![image](https://github.com/Gurpreet06/ETW-Patcher/assets/74554439/fa56c143-8327-4917-be69-9e502df57b78)
