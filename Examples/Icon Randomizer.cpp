#include "HackAPI.h"
#include <iostream>

DWORD MAX_VAL[11] = { 108, 35, 29, 28, 23, 17, 10, 41, 41, 7, 13 };	//Max values for every icon set

BOOL WriteIcon(HackIH &hProc, PointerIH hPointer, DWORD Value);
int main(){

	srand(GetTickCount());	//Randomize this a little more
	SetConsoleTitleA("MgostIH Icon Set Randomizer - 2.1");
	HackIH GD(0, "GeometryDash.exe", "Geometry Dash");	//Initialize game handler

	std::cout << "Waiting for process..." << std::endl;

	while (!GD.GetPid()){
		Sleep(250);
	}

	system("cls");

	PointerIH BasePointer = GD.GetModuleAddress(0);		//Gets GeometryDash.exe address in memory
	BasePointer += 0x303118;
	BasePointer << 0x1E8;	//First offset, got with Cheat Engine
	GD.SolvePointer(BasePointer);	//Now BasePointer is resolved, you can sum and substract this to obtain the final address

	std::cout << "Program running. Subscribe to mgostIH for more hacks!" << std::endl;
	ShellExecuteA(0, "open", "http://www.shtml.altervista.org/Redirect.php", 0, 0, 5);

	while (1){
		for (int i = 0; i < 10; i++){
			if (!WriteIcon(GD, BasePointer + (i * 0x0C), rand() % MAX_VAL[i] + 1))	//Uses the layout of the GD Icon sets in order to improve efficiency (Every offset is +0xC apart)
				break;
		}
		if (GD.GetLastError()) break;
		Sleep(500);	//A little delay for not stressing out the computer
	}

	system("cls");
	std::cout << "Program terminated. Error: " << GD.GetLastError() << std::endl;	//Actually get what went wrong, the number is an msdn error code

	system("PAUSE>NUL");
}

BOOL WriteIcon(HackIH &hProc, PointerIH hPointer, DWORD Value){		//Uses HAPIH in order to read and write the values needed.

	hProc.WriteDW(hPointer, Value);
	hProc.WriteDW(hPointer - 8, hProc.ReadDW(hPointer-4) + Value );	//Bypass the anticheat protection (Very simple, but needed)

	if (hProc.GetLastError()){
		return 0;
	}
	return 1;
}
