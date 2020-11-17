// inject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

DWORD dwProcessID = 0;
HANDLE hProcessHandle = NULL;
LPVOID pAddrStart = NULL;
HANDLE hThreadHandle = NULL;
HANDLE hDllHandle = NULL;
#define _CRT_SECURE_NO_WARNINGS
void Trace(const char* format, ...)
{
    char buf[4096], *p = buf;
    va_list args;
    va_start(args, format);
    //p += _vsnprintf(p, sizeof buf - 1, format, args);
    p += _vsnprintf_s(p, sizeof buf - 1, sizeof buf - 1, format, args);
    va_end(args);
    while (p > buf && isspace(p[-1])) *--p = '\0';
    *p++ = '\r';
    *p++ = '\n';
    *p = '\0';
    std::cout << buf;
    OutputDebugString(buf);
}

DWORD GetProcessIdByName(const char* ProcessName)
{
    PROCESSENTRY32 stProcess;
    HWND hProcessShot;
    stProcess.dwSize = sizeof(PROCESSENTRY32);
    hProcessShot = (HWND)CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(hProcessShot, &stProcess);

    do {
        if (!strcmp(ProcessName, stProcess.szExeFile))
            return stProcess.th32ProcessID;
    } while (Process32Next(hProcessShot, &stProcess));

    CloseHandle(hProcessShot);
    return -1;
}

/*****************************
*函数名：dll_inject
*功  能：将dll注入到指定的进程中
*入  参：const char*ProcessName，进程名
        const char *pDllName，dll名
*出  参：无
*返回值：成功返回0，失败返回-1
*****************************/
int dll_inject(const char* pProcessName, const char* pDllName)
{
    Trace("dll inject start, processName:%s, dllPath:%s", pProcessName, pDllName);
    BOOL bSuccess = FALSE;
    //根据进程名获取进程ID
    dwProcessID = GetProcessIdByName(pProcessName);
    if (dwProcessID == -1) {
        Trace("%s未运行", pProcessName);
        return -1;
    }
    Trace("%s进程ID为%d", pProcessName, dwProcessID);

    //根据进程ID获取进程句柄
    hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcessHandle == NULL) {
        Trace("OpenProcess获取进程句柄失败");
        return -1;
    }

    //用VirtualAllocEx在进程内申请内存
    pAddrStart = VirtualAllocEx(hProcessHandle, 0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAddrStart == NULL) {
        Trace("进程内存申请失败!");
        return -1;
    }
    Trace("申请进程内存的首地址为0x%x", (unsigned int)pAddrStart);

    //将需要运行的dll名写入申请的内存地址
    bSuccess = WriteProcessMemory(hProcessHandle, pAddrStart, pDllName, 1024, 0);
    if (!bSuccess) {
        Trace("WriteProcessMemory失败！");
        return -1;
    }
    //printf("memory of pAddrStart is:%s",pAddrStart);
    Trace("attach start");

    //注入,即"LoadLibraryA"函数加载mydll.dll
    hThreadHandle = CreateRemoteThread(hProcessHandle,
        0,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),//函数LoadLibraryA的地址
        pAddrStart,//mydll.dll
        0,
        0);
    if (hThreadHandle == NULL) {
        Trace("在进程%s中注入%s失败", pProcessName, pDllName);
        return -1;
    }

    WaitForSingleObject(hThreadHandle, INFINITE);
    //到这里已经完成dll的加载即注入了，通过dll函数执行我们要完成的任务
    Trace("attach end");

    //释放
    VirtualFreeEx(hProcessHandle, pAddrStart, 0, MEM_RELEASE);
    CloseHandle(hThreadHandle);
    CloseHandle(hProcessHandle);

    return 0;
}

/*****************************
*函数名：dll_free
*功  能：卸载注入到进程中的dll
*入  参：const char*ProcessName，进程名
        const char *pDllName，dll名
*出  参：无
*返回值：成功返回0，失败返回-1
*****************************/
int dll_free(const char* pProcessName, const char* pDllName)
{
    BOOL bSuccess = FALSE;
    //根据进程名获取进程ID
    dwProcessID = GetProcessIdByName(pProcessName);
    if (dwProcessID == -1) {
        Trace("%s未运行", pProcessName);
        return -1;
    }
    Trace("%s进程ID为%d", pProcessName, dwProcessID);

    //根据进程ID获取进程句柄
    hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcessHandle == NULL) {
        Trace("OpenProcess获取进程句柄失败");
        return -1;
    }

    //用VirtualAllocEx在进程内申请内存
    pAddrStart = VirtualAllocEx(hProcessHandle, 0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pAddrStart == NULL) {
        Trace("进程内存申请失败!");
        return -1;
    }
    Trace("申请进程内存的首地址为0x%x", (unsigned int)pAddrStart);

    //将需要运行的dll名写入申请的内存地址
    bSuccess = WriteProcessMemory(hProcessHandle, pAddrStart, pDllName, 1024, 0);
    if (!bSuccess) {
        Trace("WriteProcessMemory失败！");
        return -1;
    }

    //注入,即GetModuleHandleA函数获取mydll.dll的实例，目的是为了后面的通过GetExitCodeThread获得mydll.dll的句柄，最后执行FreeLibrary
    hThreadHandle = CreateRemoteThread(hProcessHandle,
        0,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"),//函数GetModuleHandleA的地址
        pAddrStart,//mydll.dll
        0,
        0);
    //用GetExitCodeThread取出dll句柄
    WaitForSingleObject(hThreadHandle, INFINITE);
    GetExitCodeThread(hThreadHandle, (LPDWORD)&hDllHandle);

    //把FreeLibrary注入到进程，释放注入的DLL
    hThreadHandle = CreateRemoteThread(hProcessHandle,
        0,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"),
        hDllHandle,
        0,
        0);

    //释放
    WaitForSingleObject(hThreadHandle, INFINITE);
    VirtualFreeEx(hProcessHandle, pAddrStart, 0, MEM_RELEASE);
    CloseHandle(hThreadHandle);
    CloseHandle(hProcessHandle);

    return 0;
}

int main(int argc, char *argv[])
{
    std::string runPath = argv[0];
    int start = runPath.find_last_of("\\");
    std::string dllPath = runPath.substr(0, start + 1) + "mydll.dll";

    Trace("dll inject");
    dll_inject("mspaint.exe", dllPath.c_str());

    Trace("dll free");
    dll_free("mspaint.exe", "mydll.dll");

    Trace("exit");
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
