#ifndef __API_H_INCLUDED
#define __API_H_INCLUDED

#include <Windows.h>
#include <string>
class HackIH;
class PointerIH;

class HackIH {
private:
	typedef  BOOL (__stdcall *ENUMP)(
		_Out_ DWORD *pProcessIds,
		_In_  DWORD cb,
		_Out_ DWORD *pBytesReturned
		);
	HMODULE PSAPI = LoadLibraryA("psapi.dll");
	DWORD PROCESS_ID=0;
	char TEMP_PROC_NAME[MAX_PATH+1] = {};
	std::string WINDOW_NAME="";
	std::string PROC_NAME="";
	
	BOOL IS_OPEN = 0;
	DWORD LAST_ERROR;
public:
	~HackIH();
	HackIH(DWORD Pid) : PROCESS_ID(Pid) {}
	HackIH(DWORD Pid, std::string ProcName) : PROCESS_ID(Pid), PROC_NAME(ProcName) {}
	HackIH(DWORD Pid, std::string ProcName, std::string WindowName) : PROCESS_ID(Pid), PROC_NAME(ProcName),WINDOW_NAME(WindowName) {}

	void SetPid(DWORD Pid);
	void SetWindow(std::string WindowName);
	void SetProcess(std::string ProcessName);
	
	DWORD GetPid();
	char* GetProcName();
	PVOID GetModuleAddress(char* ModuleName);
	BOOL SolvePointer(PointerIH &hPointer);
	BOOL ReadPointer(PointerIH &hPointer,PVOID* OutBase);
	DWORD GetLastError();

	BOOL Write(PointerIH hPointer,void* Value,size_t size);
	BOOL Read(PointerIH hPointer, void* Value,size_t size);

	PVOID Allocate(DWORD Size);
	
	BOOL WriteDW(PointerIH hPointer, DWORD Value);
	DWORD ReadDW(PointerIH hPointer);


};

class PointerIH{
private:
	DWORD OFFSETS[16] = {};
	BYTE OFFS_AMOUNT = 0;
public:
	DWORD BASE_ADDR;

	PointerIH(PVOID BaseAddr) : BASE_ADDR((DWORD)BaseAddr){}
	PointerIH(DWORD BaseAddr) : BASE_ADDR(BaseAddr){}
	PointerIH(PVOID BaseAddr, DWORD* Offsets,BYTE Amount);

	BOOL SetBaseAddr(PVOID BaseAddr);
	BOOL AddOffset(DWORD Offset);
	BOOL RemoveOffset();
	DWORD GetOffsets(DWORD* Out_Offsets);
	

	PointerIH & operator=(const PointerIH &rhs);
	PointerIH & operator=(const int &rhs);
	PointerIH & operator=(const PVOID &rhs);

	PointerIH & operator+=(const PointerIH &rhs);
	PointerIH & operator+=(const int &rhs);
	PointerIH & operator+=(const PVOID &rhs);

	PointerIH & operator-=(const PointerIH &rhs);
	PointerIH & operator-=(const int &rhs);
	PointerIH & operator-=(const PVOID &rhs);

	const PointerIH & operator+(const PointerIH &rhs) const;
	const PointerIH & operator+(const int &rhs) const;
	const PointerIH & operator+(const PVOID &rhs) const;

	const PointerIH & operator-(const PointerIH &rhs) const;
	const PointerIH & operator-(const int &rhs) const;
	const PointerIH & operator-(const PVOID &rhs) const;

	PointerIH & operator<<(const int &rhs);
	PointerIH & operator<<(const PVOID &rhs);

	explicit operator bool() const;
	bool operator!() const;
};

#endif
