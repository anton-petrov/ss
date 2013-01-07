#ifndef CONSOLE_H

#define CONSOLE_H
#include "Console.h"

#include <conio.h>
#include <stdio.h>


static HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

void gotoxy(int x, int y)
{
	static HANDLE hStdout = NULL;
	COORD wrapper;

	wrapper.X = x;
	wrapper.Y = y;

	if(!hStdout)
	{
		hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	SetConsoleCursorPosition(hStdout,wrapper);
}

void ClearScreen()
{
	    
	static CONSOLE_SCREEN_BUFFER_INFO csbi;
	const COORD startCoords = {0,0};   
	DWORD dummy;

	if(!hStdout)               
	{
		GetConsoleScreenBufferInfo(hStdout,&csbi);
	}

	FillConsoleOutputCharacter(hStdout,
		' ',
		csbi.dwSize.X * csbi.dwSize.Y,
		startCoords,
		&dummy);    
	gotoxy(0,0);
}

void ResizeConsole(int x, int y)
{
	COORD con_size = {x, y};
	SetConsoleTextAttribute(hStdout, 0x07);
    SetConsoleScreenBufferSize(hStdout, con_size);
}

void SetConsoleTextColor(const WORD c)
{
	SetConsoleTextAttribute(hStdout, c);
}

int WaitForKey()
{
	while(!_kbhit()) /* ждем... */;
	return _getche();
}

void WaitForSart(const char* str, int sec, int pos_x)
{
	for(int i=sec*1000; i>0; i-=1000)
	{
		printf("%s: %d ", str, i/1000);
		Sleep(1000);
		COORD pos = {0, pos_x};
        SetConsoleCursorPosition(hStdout, pos);
		if(_kbhit())
		{
			_getche();
			printf("\n");
			break;
		}
	}
}

int PauseAndContinue()
{
	if (_kbhit())
	{
		int c = _getche();
		if (c != 'q' && c != 'Q')
		{
			WaitForKey();
		}
		else
			return 0;
	}
	return 1;
}

#endif



