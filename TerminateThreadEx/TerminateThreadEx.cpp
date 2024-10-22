// TerminateThreadEx.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include<Windows.h>

#include"TerminateThreadEx.h"
int Count = 0;
DWORD Foo(LPVOID lpParameter) {
	while (true) {
		Sleep(5);
		std::cout << "Hello" << Count++ << std::endl;
	}
}
int main()
{ //启动Foo线程
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Foo, NULL, 0, NULL);
	//执行while循环等待5s
	auto start = std::chrono::high_resolution_clock::now();
	while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() < 5) {
		//休眠100ms
		Sleep(100);
	}
	//终止线程
	Terminate::TerminateThreadEx(hThread);
	CloseHandle(hThread);
	while (true) {
		Sleep(200);
		std::cout << "hello world" << std::endl;
	}
	
	system("pause");//进程结束了dll就没了所以要暂停
    std::cout << "Hello World!\n";
}

