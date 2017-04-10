#ifndef __HEX
#define __HEX

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

#include "Utils.h"

extern HANDLE File;
extern BOOL LastOpen;

extern WORD bit;
extern int NumberSection;

extern IMAGE_DOS_HEADER Dos;
extern IMAGE_NT_HEADERS32 NT32;
extern IMAGE_NT_HEADERS64 NT64;
extern IMAGE_SECTION_HEADER *Sec;

//Hex �⺻ ȭ��
void HexEditor();

//HexEditor ��� ���
void HexEditor_Manual();

//dwPoint�� ���� �����͸� �̵��� �� dwLine �� ��ŭ ���
void Read_HexEditor(int mode, DWORD dwPoint, DWORD dwLine);

//dwPoint�� ���� �����͸� �̵��� �� dwValue ������ �ٲ�
void Write_HexEditor(int mode, DWORD dwPoint, BYTE dwValue);

#endif