#include <conio.h>
#include <windows.h>

void ClearScreen();
void WaitForSart(const char* str, int sec, int pos_x);
void ResizeConsole(int x, int y);
void SetConsoleTextColor(const WORD c);
int WaitForKey();
int PauseAndContinue();