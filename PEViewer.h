#ifndef __PE
#define __PE

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

void PEView_Init();

BOOL SetDosHeader(BOOL First);
BOOL SetNT32Header(BOOL First);
BOOL SetNT64Header(BOOL First);
BOOL SetSectionHeader(BOOL First);

//PE �⺻ ȭ�� 
void PEViewer();

//PE Viewer ��� ��� ���
void PE_Manual();

//File �����ͷ� ���� ������ ������ �׷����� ������
void PE_Graph(TCHAR buf[], BOOL bBody);

//num �� �Է� �� ���� ���� �ش�Ǵ� ������ �����
void PE_Graph_Found(int mode, ULONGLONG num);

//Dos ��� ������ ������
void PE_DosHeader_View();

//NT �ñ״�ó�� FilePointer, OptionPointer �����
void PE_NTHeader_View();

//File ��� ������ ������
void PE_FileHeader_View();

//Option ��� ������ ������
void PE_OptionHeader_View();

//SetIndex ���� ���� ������ �����
void PE_Section_View(int SecIndex);

//option �� �Էµ� ���� ���� str ���ڿ� ����, ������ �ɼ��� ������
void SectionOptionPrint(DWORD option, TCHAR *str);

#endif