﻿// TerminateThreadEx.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<Windows.h>
#include<tuple>
#include<TlHelp32.h>
#include<chrono>
#include<process.h>
enum class EnumStatus {
	RETRY,
	ENUMSTOP,
	ENUMCONTINUE,
};
#if defined _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif
typedef class DATA_CONTEXT {
public:
	BYTE ShellCode[0x30];				//x64:0X00   |->x86:0x00
	LPVOID pFunction;					//x64:0X30	 |->x86:0x30
	PBYTE lpParameter;					//x64:0X38	 |->x86:0x34
	LPVOID OriginalEip;					//x64:0X40	 |->x86:0x38
}*PDATA_CONTEXT;
#if !defined(_WIN64)

#else
BYTE ContextInjectShell[] = {			//x64.asm
	0x50,								//push	rax
	0x53,								//push	rbx
	0x9c,								//pushfq							//保存flag寄存器
	0xe8,0x00,0x00,0x00,0x00,			//call	next
	0x5b,								//pop	rbx
	0x48,0x83,0xeb,0x08,				//sub	rbx,08
	0x51,								//push	rcx	
	0x48,0x83,0xEC,0x28,				//sub	rsp,0x28					//为call 的参数分配空间
	0x48,0x8b,0x4b,0x38,				//mov	rcx,[rbx+0x38]				//lparam 路径地址
	0xff,0x53,0x30,						//call	qword ptr[rbx+0x30]			//call Fn
	0x48,0x83,0xc4,0x28,				//add	rsp,0x28					//撤销临时空间
	0x59,								//pop	rcx
	0x48,0x8b,0x43,0x40,				//mov	rax,[rbx+0x40]				//取rip到rax
	0x48,0x87,0x44,0x24,0x24,			//xchg	[rsp+24],rax				
	0x9d,								//popfq								//还原标志寄存器
	0x5b,								//pop	rbx
	0x58,								//pop	rax
	0xc3,								//retn		
};
#endif
static_assert(sizeof(ContextInjectShell) < 44, "ShellCode OverSize");
template<typename Pre>
void GetThreads(Pre bin) {
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hThreadSnap) return;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	for (BOOL bOk = Thread32First(hThreadSnap, &te32); bOk; bOk = Thread32Next(hThreadSnap, &te32)) {
		EnumStatus Status = EnumStatus::ENUMCONTINUE;
	loop:	Status = bin(te32);
		if (EnumStatus::ENUMSTOP == Status)break;
		if (EnumStatus::RETRY == Status) {
			goto loop;
		}
		if (EnumStatus::ENUMCONTINUE != Status) break;
	}
}
typedef VOID(NTAPI* pNtTestAlert)(VOID);
#pragma pack(push)
#pragma pack(1)
template<class Fn>
class ThreadData {
public:
	Fn fn;
};
template<class Fn, class... Args>
class ThreadData2 : public ThreadData<Fn> {
public:
	std::tuple<Args...> params;
};
DATA_CONTEXT  datactx;
#pragma pack(pop)
template <class Fn>
decltype(auto) ThreadFunction(void* param) noexcept {
	auto threadData = static_cast<ThreadData<Fn>*>(param);
	//拷贝一份
	ThreadData<Fn> newdata{};
	memcpy(&newdata,threadData,sizeof(threadData));
	newdata.fn();
	delete threadData;
}

void __stdcall APCRoutine(ULONG_PTR lpParameter){
	_endthreadex(lpParameter);
}
void TerminateThreadEx(HANDLE hThread, UINT nIndex = ERROR_SUCCESS) {//安全的终止线程  safe terminate thread
	if (!hThread) return;
	DWORD dwExitCode = 0;
	// 获取线程的退出码 如果线程已经退出则返回
	if (!GetExitCodeThread(hThread, &dwExitCode) || dwExitCode != STILL_ACTIVE) return;
	// 获得线程的ID
	DWORD dwThreadID = GetThreadId(hThread);
	//遍历所有线程
	if (dwThreadID == GetCurrentThreadId()) ExitThread(nIndex);
	//插入用户apc
	QueueUserAPC(APCRoutine, hThread, nIndex);
	auto threadData = new ThreadData<pNtTestAlert>;
	threadData->fn = (pNtTestAlert)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");
	GetThreads([&](const THREADENTRY32& te32)->EnumStatus {
		if (te32.th32ThreadID == dwThreadID) {
			//暂停线程
			SuspendThread(hThread);
			//获取上下文
			CONTEXT ctx{};
			ctx.ContextFlags = CONTEXT_FULL;
			GetThreadContext(hThread, &ctx);
			//设置rip
			if (ctx.XIP == NULL) {
				ResumeThread(hThread);
				return EnumStatus::ENUMCONTINUE;
			}
			DWORD oldProtect = 0;
			VirtualProtect(&datactx, sizeof(datactx), PAGE_EXECUTE_READWRITE, &oldProtect);
			ZeroMemory(&datactx, sizeof(datactx));
			datactx.pFunction = reinterpret_cast<LPVOID>(&ThreadFunction<pNtTestAlert>);
			datactx.OriginalEip = reinterpret_cast<LPVOID>(ctx.XIP);
			datactx.lpParameter = reinterpret_cast<PBYTE>(threadData);
			ctx.XIP = (uintptr_t)datactx.ShellCode;
			memcpy(datactx.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
			SetThreadContext(hThread, &ctx);
			ResumeThread(hThread);
			return EnumStatus::ENUMSTOP;
		}
		return EnumStatus::ENUMCONTINUE;
	});
}

int Count = 0;
DWORD Foo(LPVOID lpParameter) {
	while (true) {
		Sleep(5);
		std::cout << "Hello" << Count++ << std::endl;
	}
}
int main()
{ //启动Foo线程
	HANDLE hThread = CreateThread(NULL, 0, Foo, NULL, 0, NULL);
	//执行while循环等待5s
	auto start = std::chrono::high_resolution_clock::now();
	while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() < 5) {
		//休眠100ms
		Sleep(100);
	}
	//终止线程
	TerminateThreadEx(hThread);
	CloseHandle(hThread);
	while (true) {
		Sleep(200);
		std::cout << "hello world" << std::endl;
	}
	
	system("pause");//进程结束了dll就没了所以要暂停
    std::cout << "Hello World!\n";
}

