#ifndef __PROTECT
#define __PROTECT

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

//������ �����
void Protector_Manual();

//�������� �⺻ ȭ�� ���
void Protector();

//��Ƽ����� ���, �ڵ� ���� ���ڵ� ������ ���ο� ���ǿ� ��������
void PlusAntiDebugging();

#endif