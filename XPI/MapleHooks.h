#ifndef MAPLE_HOOKS_H_
#define MAPLE_HOOKS_H_

#include <Windows.h>

#include "extvars.hpp"

#define PACKETCALL  __fastcall
#define FASTCALL	__fastcall
#define THISCALL	__thiscall
#define NAKED		__declspec(naked)
#define ZArray      unsigned char*

//#define GetXPIWindow() FindWindow(NULL, L"XPI")

#define PACKET_BLANK_OPCODE 0xFFFF

HWND GetXPIWindow();

struct ZFatalSection
{
	LPVOID			m_pTIB;
	unsigned int	m_ref;
};

template<class T>
struct ZSynchronizedHelper
{
	T m_lock;
};

struct CClientSocket
{
	Padding(0x08);
	SOCKET			m_socket;	// 0x08
	Padding(0x08);
	unsigned int	m_uUnknown;	// 0x14
	Padding(0x10);
	sockaddr_in		m_sockaddr;	// 0x24
	Padding(0x18);				// 0x34
	LPVOID			m_lp;		// 0x50
	Padding(0x2C);
	ZFatalSection	m_lock;		// 0x80
	unsigned long	m_uSendSeq;	// 0x88
	unsigned long	m_uRecvSeq;	// 0x8C
	Padding(0x08);
};

struct CWorldSocket
{
	Padding(0x18);
	SOCKET			m_socket;
	Padding(0x08);
	sockaddr_in		m_sockaddr; // 0x10 bytes
	Padding(0x0100);
	unsigned long	m_uSendSeq;
	unsigned long	m_uRecvSeq;
	Padding(0x60);
};

/********************
* SENDING FUNCTIONS *
********************/

struct COutPacket
{
	unsigned int    m_bLoopback;
	unsigned char*  m_aSendBuff;
	unsigned int    m_uLength;
	unsigned int    m_uRawSeq;
	unsigned int    m_uDataLen;
	unsigned int	m_uUnknown;
};

extern VOID(PACKETCALL * _InitPacket)(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType);
extern VOID(PACKETCALL * _Encode1)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in BYTE b);
extern VOID(PACKETCALL * _Encode2)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in WORD w);
extern VOID(PACKETCALL * _Encode4)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in DWORD dw);
extern VOID(PACKETCALL * _Encode8)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in ULONGLONG ull);
extern VOID(PACKETCALL * _EncodeStr)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LPCSTR lpcsz);
extern VOID(PACKETCALL * _EncodeBuffer)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in_bcount(uLength) LPBYTE pb, __in UINT uLength);
extern VOID(PACKETCALL * _SendPacket)(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket);
extern VOID(PACKETCALL * _SendWorldPacket)(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket);

COutPacket* PACKETCALL COutPacket__constructor(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType);
VOID PACKETCALL InitPacket(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType);
VOID PACKETCALL Encode1(__inout COutPacket* oPacket, __in DWORD dwEDX, __in BYTE b);
VOID PACKETCALL Encode2(__inout COutPacket* oPacket, __in DWORD dwEDX, __in WORD w);
VOID PACKETCALL Encode4(__inout COutPacket* oPacket, __in DWORD dwEDX, __in DWORD dw);
VOID PACKETCALL Encode8(__inout COutPacket* oPacket, __in DWORD dwEDX, __in ULONGLONG ull);
VOID PACKETCALL EncodeStr(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LPCSTR lpsz);
VOID PACKETCALL EncodeBuffer(__inout COutPacket* oPacket, __in DWORD dwEDX, __in_bcount(uLength) PBYTE pb, __in UINT uLength);
VOID PACKETCALL SendPacket(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* pPacket);
VOID PACKETCALL SendWorldPacket(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket);

/**********************
* RECIEVING FUNCTIONS *
**********************/

enum { RS_HEADER = 0, RS_DATA, RS_COMPLETED };

struct CInPacket
{
	unsigned int    m_bLoopback;
	unsigned int    m_nState;
	unsigned char*  m_aRecvBuff;
	unsigned int    m_uLength;
	unsigned int    m_uRawSeq;
	unsigned int    m_uDataLen;
	unsigned int    m_uOffset;
};

extern BYTE(PACKETCALL * _Decode1)(__inout CInPacket* inPacket, __in DWORD dwEDX);
extern WORD(PACKETCALL * _Decode2)(__inout CInPacket* inPacket, __in DWORD dwEDX);
extern DWORD(PACKETCALL * _Decode4)(__inout CInPacket* inPacket, __in DWORD dwEDX);
extern ULONGLONG(PACKETCALL * _Decode8)(__inout CInPacket* inPacket, __in DWORD dwEDX);
extern LPCSTR* (PACKETCALL * _DecodeStr)(__inout CInPacket* inPacket, __in DWORD dwEDX, __in LPVOID lpUnknown);
extern VOID(PACKETCALL * _DecodeBuffer)(__inout CInPacket* inPacket, __in DWORD dwEDX, __out_bcount(uLength) PBYTE pb, __in UINT uLength);
extern VOID(PACKETCALL * _ProcessPacket)(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket);
extern VOID(PACKETCALL * _ProcessWorldPacket)(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket);

BYTE PACKETCALL Decode1(__inout CInPacket* inPacket, __in DWORD dwEDX);
WORD PACKETCALL Decode2(__inout CInPacket* inPacket, __in DWORD dwEDX);
DWORD PACKETCALL Decode4(__inout CInPacket* inPacket, __in DWORD dwEDX);
ULONGLONG PACKETCALL Decode8(__inout CInPacket* inPacket, __in DWORD dwEDX);
LPCSTR* PACKETCALL DecodeStr(__inout CInPacket* inPacket, __in DWORD dwEDX, __in LPVOID lpUnknown);
VOID PACKETCALL DecodeBuffer(__inout CInPacket* inPacket, __in DWORD dwEDX, __out_bcount(uLength) PBYTE pb, __in UINT uLength);
VOID PACKETCALL ProcessPacket(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket);
VOID PACKETCALL ProcessWorldPacket(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket);

/************
* FUNCTIONS *
************/

extern VOID(PACKETCALL * _RemoveAll)(__in unsigned char** pArray, __in DWORD dwEDX);
extern VOID(PACKETCALL * _COutPacket)(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType);

/******/

enum OFFTYPE { OFF_NONE = 0, OFF_ADD, OFF_SUB, OFF_PTR, OFF_JMP, OFF_CALL };

typedef struct _MAPLE_FUNCTION
{
	LPCWSTR lpcwszName;
	PVOID   pTarget;
	OFFTYPE OffsetType;
	UINT    uOffset;
	LPCWSTR lpcwszSignature;
} MAPLE_FUNCTION, far *LPMAPLE_FUNCTION, near *PMAPLE_FUNCTION;

typedef struct _MAPLE_HOOK
{
	PVOID           pHook;
	MAPLE_FUNCTION  Function;
} MAPLE_HOOK, far *LPMAPLE_HOOK, near *PMAPLE_HOOK;

const MAPLE_HOOK MapleHooks[] =
{
	// send functions
	{ InitPacket,		{ L"COutPacket::InitPacket",		&_InitPacket,		OFF_NONE,	0,		L"8B 44 24 04 6A 00 6A 00 50 E8" } },
	{ Encode1,			{ L"COutPacket::Encode1",			&_Encode1,			OFF_NONE,	0,		L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 41 3B C8 76" } },
	{ Encode2,			{ L"COutPacket::Encode2",			&_Encode2,			OFF_NONE,	0,		L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 02 3B" } },
	{ Encode4,			{ L"COutPacket::Encode4",			&_Encode4,			OFF_NONE,	0,		L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 04 3B" } },
	{ Encode8,			{ L"COutPacket::Encode8",			&_Encode8,			OFF_NONE,	0,		L"56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 83 C1 08 3B" } },
	{ EncodeBuffer,		{ L"COutPacket::EncodeBuffer",		&_EncodeBuffer,		OFF_NONE,	0,		L"53 56 8B F1 8B 46 04 57 8D 7E 04 85 C0 74 03 8B 40 FC 8B 4E 08 8B 5C 24 14 03" } },
	{ EncodeStr,		{ L"COutPacket::EncodeStr",			&_EncodeStr,		OFF_SUB,	51,		L"74 05 8B 48 FC EB 02 33 C9 8B" } },
	{ SendPacket,		{ L"CClientSocket::SendPacket",		&_SendPacket,		OFF_CALL,	11,		L"8B 0D ?? ?? ?? ?? 8D 44 24 ?? 50 E8 ?? ?? ?? 00 83 BE ?? 00 00 00 00 75" } },
	// recv functions
	{ Decode1,			{ L"CInPacket::Decode1",			&_Decode1,			OFF_SUB,	64,		L"83 F8 01 73 4C" } },
	{ Decode2,			{ L"CInPacket::Decode2",			&_Decode2,			OFF_SUB,	64,		L"83 F8 02 73 4C" } },
	{ Decode4,			{ L"CInPacket::Decode4",			&_Decode4,			OFF_SUB,	64,		L"83 F8 04 73 4C" } },
	{ Decode8,			{ L"CInPacket::Decode8",			&_Decode8,			OFF_SUB,	64,		L"83 F8 08 73 4C" } },
	{ DecodeBuffer,		{ L"CInPacket::DecodeBuffer",		&_DecodeBuffer,		OFF_SUB,	60,		L"2B C1 03 CA C7 45 FC 00 00 00 00 3B C7 73" } },
	{ DecodeStr,		{ L"CInPacket::DecodeStr",			&_DecodeStr,		OFF_SUB,	48,		L"C7 45 EC 00 00 00 00 8B 7D 08 B8 01 00 00 00 89" } },
	{ ProcessPacket,	{ L"CClientSocket::ProcessPacket",	&_ProcessPacket,	OFF_CALL,	0,		L"E8 ?? ?? FF FF 8D 4C 24 ?? C7 44 24 ?? FF FF FF FF E8 ?? ?? ?? ?? 83 7E ?? 00 0F 85" } },

	// world
	{ SendWorldPacket,		{ L"CWorldSocket::SendPacket",		&_SendWorldPacket,		OFF_SUB,	74,		L"E8 ?? ?? ?? ?? B9 01 00 00 00 38 4E ?? 75" } },
	{ ProcessWorldPacket,	{ L"CWorldSocket::ProcessPacket",	&_ProcessWorldPacket,	OFF_NONE,	0,		L"56 57 8B 7C 24 0C 8B F1 8B CF E8 ?? ?? ?? ?? 0F B7 C0 48 83 F8 1B 0F 87" } }
};

const MAPLE_FUNCTION MapleFunctions[] =
{
	{ L"COutPacket::COutPacket",	&_COutPacket,	OFF_SUB,	59,	L"E8 ?? ?? ?? ?? 8B 4C 24 ?? 5? 8B CE C7"},
	{ L"ZArray::RemoveAll",			&_RemoveAll,	OFF_NONE,	0,	L"56 8B F1 8B 06 85 C0 74" },
};



#endif // MAPLE_HOOKS_H_
