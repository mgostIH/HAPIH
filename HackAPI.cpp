#include "HackAPI.h"
HackIH::~HackIH(){
	
	FreeLibrary(PSAPI);
}


DWORD HackIH::GetLastError(){
	return LAST_ERROR;
}


void HackIH::SetPid(DWORD Pid){
	PROCESS_ID = Pid;
}


void HackIH::SetWindow(std::string WindowName){
	WINDOW_NAME = WindowName;
}


void HackIH::SetProcess(std::string ProcessName){
	PROC_NAME = ProcessName;
}


DWORD HackIH::GetPid(){
	if (PROCESS_ID == -1){
		return GetCurrentProcessId();
	}
	if (PROCESS_ID) {
		HANDLE TempHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PROCESS_ID);
		if (TempHandle) {
			CloseHandle(TempHandle);
			return PROCESS_ID;
		}
		PROCESS_ID = 0;
		
	}
	
	if (!PROC_NAME.empty()){
		PROCESS_ID = 0;
		if (!PSAPI) return 0;
		DWORD P_Ids[0x1000];
		DWORD O_Pids = 0;
		ENUMP ENUMPROCESSES = (ENUMP)GetProcAddress(PSAPI, "EnumProcesses");
		if (!ENUMPROCESSES(P_Ids, 0x1000, &O_Pids)) return 0;
		for (int i = 0; i < O_Pids; i++){
			char ProcName[MAX_PATH+1] = {};
			DWORD ProcSize = MAX_PATH;
			HANDLE TempHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, P_Ids[i]);
			QueryFullProcessImageNameA(TempHandle, 0, ProcName, &ProcSize);

			if (strrchr(ProcName, '\\'))
			if (ProcName[0])
			if (!PROC_NAME.compare(strrchr(ProcName, '\\') + 1)){
				PROCESS_ID = P_Ids[i];
				return PROCESS_ID;
			}

			CloseHandle(TempHandle);
		}
		
	}

	if (!WINDOW_NAME.empty()){
		PROCESS_ID = 0;
		GetWindowThreadProcessId(FindWindowA(NULL, WINDOW_NAME.c_str()), &PROCESS_ID);
		if (PROCESS_ID){
			return PROCESS_ID;
		}
	}
	return 0;
}


char* HackIH::GetProcName(){
	HANDLE TempHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetPid());
	if (!TempHandle) return (char*)PROC_NAME.c_str();
	DWORD ProcSize = MAX_PATH;
	if (QueryFullProcessImageNameA(TempHandle, 0, TEMP_PROC_NAME, &ProcSize)){
		CloseHandle(TempHandle);
		return strrchr(TEMP_PROC_NAME, '\\') + 1;
	}
	return (char*)PROC_NAME.c_str();
}


PVOID HackIH::GetModuleAddress(char* ModuleName){
	if (!ModuleName){
		ModuleName = GetProcName();
		if (!ModuleName) return 0;
	}
	
	HMODULE hMods[0x1000];
	WNDPROC ENUMPMODULES = (WNDPROC)GetProcAddress(PSAPI, "EnumProcessModules");
	if (!ENUMPMODULES) return 0;
	DWORD OutMods;
	if (!GetPid()) return 0;
	HANDLE TempHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetPid());
	if (!TempHandle) return 0;
	ENUMPMODULES((HWND)TempHandle, (int)hMods, 0x1000, (LPARAM)&OutMods);
	WNDPROC GETMODFILENAME = (WNDPROC)GetProcAddress(PSAPI, "GetModuleFileNameExA");
	if (!GETMODFILENAME) {
		CloseHandle(TempHandle);
		return 0;
	}
	for (int i = 0; i < (OutMods/4); i++){
		char TempModName[MAX_PATH] = {};
		if (GETMODFILENAME((HWND)TempHandle, (UINT)hMods[i], (WPARAM)TempModName, MAX_PATH)){
			if (!strcmp(ModuleName, strrchr(TempModName, '\\') + 1)){
				CloseHandle(TempHandle);
				return (PVOID)hMods[i];
			}
		}
	}
	CloseHandle(TempHandle);
	return 0;
}


BOOL HackIH::Write(PointerIH hPointer, void* Value, size_t size){
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, GetPid());
	if (!hProc) {
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	DWORD old, bkup;
	PVOID BaseAddr=0;
	if (!ReadPointer(hPointer, &BaseAddr)) {
		return 0;
	}
	if (!VirtualProtectEx(hProc, BaseAddr, size, PAGE_EXECUTE_READWRITE, &old)){
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}

	if (!WriteProcessMemory(hProc, BaseAddr, Value, size, 0)){		//Actually write to it
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	if (!VirtualProtectEx(hProc, BaseAddr, size, old, &bkup)){
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	LAST_ERROR = 0;
	return 1;
}


BOOL HackIH::Read(PointerIH hPointer, void* Value, size_t size){
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ  , FALSE, GetPid());
	if (!hProc) {
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	DWORD old, bkup;
	PVOID BaseAddr = 0;
	if (!ReadPointer(hPointer, &BaseAddr)) {
		return 0;
	}
	if (!VirtualProtectEx(hProc, BaseAddr, size, PAGE_EXECUTE_READWRITE, &old)){
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}

	if (!ReadProcessMemory(hProc, BaseAddr, Value, size, 0)){		//Actually write to it
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	if (!VirtualProtectEx(hProc, BaseAddr, size, old, &bkup)){
		CloseHandle(hProc);
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	LAST_ERROR = 0;
	return 1;
}


BOOL HackIH::ReadPointer(PointerIH& hPointer,PVOID * OutBase){
	DWORD PointerOffs[16];
	DWORD OffsAmount = hPointer.GetOffsets(PointerOffs);
	if (!hPointer.BASE_ADDR) return -1;
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ, FALSE, GetPid());
	if (!hProc) {
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	DWORD BaseAddr = hPointer.BASE_ADDR;
	DWORD old, bkup;
	for (int i = 0; i < OffsAmount; i++){
		DWORD TempBase = BaseAddr;
		if (!VirtualProtectEx(hProc, (PVOID)BaseAddr, 4, PAGE_EXECUTE_READWRITE, &old)){
			CloseHandle(hProc);
			LAST_ERROR = ::GetLastError();
			return 0;
		}

		
		if (!ReadProcessMemory(hProc, (PVOID)(BaseAddr), &TempBase, 4, 0)) {		//Read the Pointer
			CloseHandle(hProc);
			LAST_ERROR = ::GetLastError();
			return 0;
		}
		if (!VirtualProtectEx(hProc, (PVOID)BaseAddr, 4, old, &bkup)){
			CloseHandle(hProc);
			LAST_ERROR = ::GetLastError();
			return 0;
		}
		BaseAddr = TempBase +PointerOffs[i];
	}
	hPointer = 0;
	memcpy(OutBase, &BaseAddr, 4);
	LAST_ERROR = 0;
	return 1;
}


PVOID HackIH::Allocate(DWORD Size){
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, GetPid());
	if (!hProc) {
		LAST_ERROR = ::GetLastError();
		return 0;
	}
	PVOID Address = VirtualAllocEx(hProc, 0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Address){
		LAST_ERROR = ::GetLastError();
		CloseHandle(hProc);
		return 0;
	}
	LAST_ERROR = 0;
	CloseHandle(hProc);
	return Address;
}





BOOL HackIH::WriteDW(PointerIH hPointer, DWORD Value){
	if (Write(hPointer, &Value, 4)){
		LAST_ERROR = 0;
		return 1;
	}
	return 0;
}


DWORD HackIH::ReadDW(PointerIH hPointer){
	DWORD Value;
	if (Read(hPointer, &Value, 4)){
		LAST_ERROR = 0;
		return Value;
	}
	return 0;
}


BOOL PointerIH::SetBaseAddr(PVOID BaseAddr){
	BASE_ADDR = (DWORD)BaseAddr;
	return 1;
}


BOOL HackIH::SolvePointer(PointerIH &hPointer){
	PVOID ReadAddr=0;
	if (ReadPointer(hPointer, &ReadAddr)){
		hPointer = ReadAddr;
		return 1;
	}
	return 0;
	
}


PointerIH::PointerIH(PVOID BaseAddr, DWORD* Offsets,BYTE Amount){
	if (Amount <= 16) OFFS_AMOUNT = Amount;
	BASE_ADDR = (DWORD)BaseAddr;
	memcpy(OFFSETS, Offsets, OFFS_AMOUNT * 4);
	
}


BOOL PointerIH::AddOffset(DWORD Offset){
	if (OFFS_AMOUNT < 16){
		OFFSETS[OFFS_AMOUNT] = Offset;
		OFFS_AMOUNT++;
		return 1;
	}
	return 0;

}


DWORD PointerIH::GetOffsets(DWORD* Out_Offsets){

	if(Out_Offsets) memcpy(Out_Offsets, OFFSETS, OFFS_AMOUNT * 4);
	return OFFS_AMOUNT;
}


BOOL PointerIH::RemoveOffset(){
	if (OFFS_AMOUNT){
		OFFS_AMOUNT--;
		return 1;
	}
	return 0;
}


PointerIH & PointerIH::operator=(const PointerIH &rhs){
	if (this == &rhs) return *this;
	BASE_ADDR = rhs.BASE_ADDR;
	OFFS_AMOUNT = rhs.OFFS_AMOUNT;
	memcpy(OFFSETS, rhs.OFFSETS, rhs.OFFS_AMOUNT * 4);
	return *this;
}


PointerIH & PointerIH::operator=(const int &rhs){
	BASE_ADDR = rhs;
	memset(OFFSETS, 0, OFFS_AMOUNT * 4);
	OFFS_AMOUNT = 0;
	return *this;
}


PointerIH & PointerIH::operator=(const PVOID &rhs){
	return PointerIH::operator=((DWORD&)rhs);
}


PointerIH & PointerIH::operator+=(const PointerIH &rhs){
	if (this == &rhs) return *this;
	BASE_ADDR += rhs.BASE_ADDR;
	OFFS_AMOUNT = max(OFFS_AMOUNT,rhs.OFFS_AMOUNT);
	for (int i = 0; i < OFFS_AMOUNT; i++){
		OFFSETS[i] += rhs.OFFSETS[i];
	}
	return *this;
}


PointerIH & PointerIH::operator+=(const int &rhs){
	BASE_ADDR += rhs;
	return *this;
}


PointerIH & PointerIH::operator+=(const PVOID &rhs){
	return PointerIH::operator+=((DWORD&)rhs);
}


PointerIH & PointerIH::operator-=(const PointerIH &rhs){
	if (this == &rhs) return *this;
	BASE_ADDR -= rhs.BASE_ADDR;
	OFFS_AMOUNT = max(OFFS_AMOUNT, rhs.OFFS_AMOUNT);
	for (int i = 0; i < OFFS_AMOUNT; i++){
		OFFSETS[i] -= rhs.OFFSETS[i];
	}
	return *this;
}


PointerIH & PointerIH::operator-=(const int &rhs){
	BASE_ADDR -= rhs;
	return *this;
}


PointerIH & PointerIH::operator-=(const PVOID &rhs){
	return PointerIH::operator-=((DWORD)rhs);
}


const PointerIH & PointerIH::operator+(const PointerIH &rhs)const {
	return PointerIH(*this) += rhs;
}


const PointerIH & PointerIH::operator+(const int &rhs)const {
	return PointerIH(*this) += rhs;
}


const PointerIH & PointerIH::operator+(const PVOID &rhs)const {
	return PointerIH(*this) += rhs;
}


const PointerIH & PointerIH::operator-(const PointerIH &rhs)const {
	return PointerIH(*this) -= rhs;
}


const PointerIH & PointerIH::operator-(const int &rhs)const {
	return PointerIH(*this) -= rhs;
}


const PointerIH & PointerIH::operator-(const PVOID &rhs)const {
	return PointerIH(*this) -= rhs;
}


PointerIH & PointerIH::operator<<(const int &rhs){
	AddOffset(rhs);
	return *this;
}


PointerIH & PointerIH::operator<<(const PVOID &rhs){
	PointerIH::operator<<((DWORD)rhs);
}


PointerIH::operator bool() const{
	return BASE_ADDR;
}


bool PointerIH::operator!() const{
	return !(bool)*this;
}
