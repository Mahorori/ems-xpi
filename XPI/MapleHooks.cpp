#include "MapleHooks.h"

#include "CInstanceManager.hpp"
#include "CMaplePacket.hpp"
#include "XPIUtilities.hpp"

#include <intrin.h>

#pragma  intrinsic(_ReturnAddress)

/********************
* SENDING FUNCTIONS *
********************/

VOID(PACKETCALL * _InitPacket)(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType) = NULL;
VOID(PACKETCALL * _Encode1)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in BYTE b) = NULL;
VOID(PACKETCALL * _Encode2)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in WORD w) = NULL;
VOID(PACKETCALL * _Encode4)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in DWORD dw) = NULL;
VOID(PACKETCALL * _Encode8)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in ULONGLONG ull) = NULL;
VOID(PACKETCALL * _EncodeStr)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LPCSTR lpcsz) = NULL;
VOID(PACKETCALL * _EncodeBuffer)(__inout COutPacket* oPacket, __in DWORD dwEDX, __in_bcount(uLength) LPBYTE pb, __in UINT uLength) = NULL;
VOID(PACKETCALL * _SendPacket)(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket) = NULL;
VOID(PACKETCALL * _SendWorldPacket)(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket) = NULL;

COutPacket* PACKETCALL COutPacket__constructor(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType)
{
	LPBYTE lpbBuffer = new BYTE[256 + 4];

	oPacket->m_aSendBuff = lpbBuffer + 4;
	*(DWORD*)lpbBuffer = 256; // buffer size

	_InitPacket(oPacket, 0, nType);

	return oPacket;
}

VOID PACKETCALL InitPacket(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType)
{
	if (nType != INT_MAX && bLogging)
	{
		if (pInstances->Find(oPacket) == NULL)
		{
			BOOL bBlock = IsOpcodeBlocked((WORD)nType);

			if (bBlock)
				nType = PACKET_BLANK_OPCODE;

			CMAPLEPACKETSTRUCT cmps;

			cmps.pInstance = oPacket;
			cmps.Direction = PACKET_SEND;
			cmps.ulState = bBlock ? PACKET_BLOCKED : 0;
			cmps.lpv = _ReturnAddress();

			pInstances->Add(oPacket, pPacketPool->construct(&cmps));
		}
	}

	_InitPacket(oPacket, dwEDX, nType);
}

VOID PACKETCALL Encode1(__inout COutPacket* oPacket, __in DWORD dwEDX, __in BYTE b)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->Add1(b, _ReturnAddress());
		}
	}

	_Encode1(oPacket, dwEDX, b);
}

VOID PACKETCALL Encode2(__inout COutPacket* oPacket, __in DWORD dwEDX, __in WORD w)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->Add2(w, _ReturnAddress());
		}
	}

	_Encode2(oPacket, dwEDX, w);
}

VOID PACKETCALL Encode4(__inout COutPacket* oPacket, __in DWORD dwEDX, __in DWORD dw)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->Add4(dw, _ReturnAddress());
		}
	}

	_Encode4(oPacket, dwEDX, dw);
}

#include "extvars.hpp"
#include "CLog.hpp"

VOID PACKETCALL Encode8(__inout COutPacket* oPacket, __in DWORD dwEDX, __in ULONGLONG ull)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->Add8(ull, _ReturnAddress());
		}
	}

	_Encode8(oPacket, dwEDX, ull);
}

VOID PACKETCALL EncodeStr(__inout COutPacket* oPacket, __in DWORD dwEDX, __in LPCSTR lpcsz)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->AddString(lpcsz, _ReturnAddress());
		}
	}

	_EncodeStr(oPacket, dwEDX, lpcsz);
}

VOID PACKETCALL EncodeBuffer(__inout COutPacket* oPacket, __in DWORD dwEDX, __in_bcount(uLength) PBYTE pb, __in UINT uLength)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	if (pckt != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			pckt->AddBuffer(pb, uLength, _ReturnAddress());
		}
	}

	_EncodeBuffer(oPacket, dwEDX, pb, uLength);
}

VOID PACKETCALL SendPacket(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	pClientSocket = thisSocket;

	// send message to main window
	HWND hWnd = GetXPIWindow();

	if (hWnd != NULL)
		PostMessage(hWnd, WM_INJECTREADY, pClientSocket != NULL, 0);

	if (pckt != NULL)
	{
		HWND hWnd = GetXPIWindow();

		if (hWnd != NULL)
		{
			if (oPacket->m_uLength > pckt->GetSize())
				pckt->AddBuffer(&oPacket->m_aSendBuff[pckt->GetSize()], oPacket->m_uLength - pckt->GetSize());

			PostMessage(hWnd, WM_ADDPACKET, 0, (LPARAM)pckt);
		}

		pInstances->Remove(oPacket);
	}

	__asm
	{
		push Next
		push oPacket
		push 0x00412457 // lolz
		mov ecx, thisSocket
		jmp _SendPacket
Next:
	}

	// _SendPacket(thisSocket, dwEDX, oPacket);
}

VOID PACKETCALL SendWorldPacket(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in COutPacket* oPacket)
{
	CMaplePacket* pckt = pInstances->Find(oPacket);

	pWorldSocket = thisSocket;

	// send message to main window
	HWND hWnd = GetXPIWindow();

	if (hWnd != NULL)
		PostMessage(hWnd, WM_INJECTREADY, pWorldSocket != NULL, 0);

	if (pckt != NULL)
	{
		pckt->SetState(pckt->GetState() | PACKET_WORLD);

		HWND hWnd = GetXPIWindow();

		if (hWnd != NULL)
			PostMessage(hWnd, WM_ADDPACKET, 0, (LPARAM)pckt);

		pInstances->Remove(oPacket);
	}

	_SendWorldPacket(thisSocket, dwEDX, oPacket);
}

/**********************
* RECIEVING FUNCTIONS *
**********************/

BYTE(PACKETCALL * _Decode1)(__inout CInPacket* inPacket, __in DWORD dwEDX) = NULL;
WORD(PACKETCALL * _Decode2)(__inout CInPacket* inPacket, __in DWORD dwEDX) = NULL;
DWORD(PACKETCALL * _Decode4)(__inout CInPacket* inPacket, __in DWORD dwEDX) = NULL;
ULONGLONG(PACKETCALL * _Decode8)(__inout CInPacket* inPacket, __in DWORD dwEDX) = NULL;
LPCSTR* (PACKETCALL * _DecodeStr)(__inout CInPacket* inPacket, __in DWORD dwEDX, __in LPVOID lpUnknown) = NULL;
VOID(PACKETCALL * _DecodeBuffer)(__inout CInPacket* inPacket, __in DWORD dwEDX, __out_bcount(uLength) PBYTE pb, __in UINT uLength) = NULL;
VOID(PACKETCALL * _ProcessPacket)(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket) = NULL;
VOID(PACKETCALL * _ProcessWorldPacket)(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket) = NULL;

BYTE PACKETCALL Decode1(__inout CInPacket* inPacket, __in DWORD dwEDX)
{
	CMaplePacket* pckt;
	BYTE          b = _Decode1(inPacket, dwEDX);

	if (inPacket->m_nState == RS_COMPLETED)
	{
		if ((pckt = pInstances->Find(inPacket)) != NULL)
		{
			if (bLogging || pckt->GetState() & PACKET_INJECTED)
				pckt->Add1(b, _ReturnAddress());
		}
	}

	return b;
}

WORD PACKETCALL Decode2(__inout CInPacket* inPacket, __in DWORD dwEDX)
{
	CMaplePacket* pckt;
	WORD          w = _Decode2(inPacket, dwEDX);

	if (inPacket->m_nState == RS_COMPLETED)
	{
		if ((pckt = pInstances->Find(inPacket)) == NULL && bLogging)
		{
			BOOL bBlock = IsOpcodeBlocked(w);

			if (bBlock)
				w = PACKET_BLANK_OPCODE;

			// create a new CMaplePacket if one does not already exist
			CMAPLEPACKETSTRUCT cmps;

			cmps.pInstance = inPacket;
			cmps.Direction = PACKET_RECV;
			cmps.ulState = bBlock ? PACKET_BLOCKED : 0;
			cmps.lpv = _ReturnAddress();

			pckt = pPacketPool->construct(&cmps);
			pInstances->Add(inPacket, pckt);
		}

		if (pckt != NULL)
		{
			if (bLogging || pckt->GetState() & PACKET_INJECTED)
				pckt->Add2(w, _ReturnAddress());
		}
	}
	return w;
}

DWORD PACKETCALL Decode4(__inout CInPacket* inPacket, __in DWORD dwEDX)
{
	CMaplePacket* pckt;
	DWORD         dw = _Decode4(inPacket, dwEDX);

	if (inPacket->m_nState == RS_COMPLETED)
	{
		if ((pckt = pInstances->Find(inPacket)) != NULL)
		{
			if (bLogging || pckt->GetState() & PACKET_INJECTED)
				pckt->Add4(dw, _ReturnAddress());
		}
	}

	return dw;
}

ULONGLONG PACKETCALL Decode8(__inout CInPacket* inPacket, __in DWORD dwEDX)
{
	CMaplePacket* pckt;
	ULONGLONG     ull = _Decode8(inPacket, dwEDX);

	if (inPacket->m_nState == RS_COMPLETED)
	{
		if ((pckt = pInstances->Find(inPacket)) != NULL)
		{
			if (bLogging || pckt->GetState() & PACKET_INJECTED)
				pckt->Add8(ull, _ReturnAddress());
		}
	}

	return ull;
}

LPCSTR* PACKETCALL DecodeStr(__inout CInPacket* inPacket, __in DWORD dwEDX, __in LPVOID lpUnknown)
{
	CMaplePacket*   pckt;
	LPCSTR*         lplpcsz = _DecodeStr(inPacket, dwEDX, lpUnknown);

	if (inPacket->m_nState == RS_COMPLETED)
	{
		if ((pckt = pInstances->Find(inPacket)) != NULL)
		{
			if (bLogging || pckt->GetState() & PACKET_INJECTED)
				if (lplpcsz != NULL)
					if (*lplpcsz != NULL)
						pckt->AddString(*lplpcsz, _ReturnAddress());
		}
	}

	return lplpcsz;
}

VOID PACKETCALL DecodeBuffer(__inout CInPacket* inPacket, __in DWORD dwEDX, __out_bcount(uLength) PBYTE pb, __in UINT uLength)
{
	CMaplePacket* pckt;

	_DecodeBuffer(inPacket, dwEDX, pb, uLength);

	if (inPacket->m_nState != RS_COMPLETED)
		return;

	if ((pckt = pInstances->Find(inPacket)) != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
			pckt->AddBuffer(pb, uLength, _ReturnAddress());
	}
}

VOID PACKETCALL ProcessPacket(__in CClientSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket)
{
	CMaplePacket* pckt;

	__asm
	{
		push Next
		push pPacket
		push 0x00412457 // lolz
		mov ecx, thisSocket
		jmp _ProcessPacket
		Next :
	}
	// _ProcessPacket(thisSocket, dwEDX, pPacket);

	if ((pckt = pInstances->Find(pPacket)) != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			HWND hWnd = GetXPIWindow();

			if (hWnd != NULL)
				PostMessage(hWnd, WM_ADDPACKET, 0, (LPARAM)pckt);

			pInstances->Remove(pPacket);
		}
	}
}

VOID PACKETCALL ProcessWorldPacket(__in CWorldSocket* thisSocket, __in DWORD dwEDX, __in CInPacket* pPacket)
{
	CMaplePacket* pckt;

	_ProcessWorldPacket(thisSocket, dwEDX, pPacket);

	if ((pckt = pInstances->Find(pPacket)) != NULL)
	{
		if (bLogging || pckt->GetState() & PACKET_INJECTED)
		{
			pckt->SetState(pckt->GetState() | PACKET_WORLD);

			HWND hWnd = GetXPIWindow();

			if (hWnd != NULL)
				PostMessage(hWnd, WM_ADDPACKET, 0, (LPARAM)pckt);

			pInstances->Remove(pPacket);
		}
	}
}

VOID(PACKETCALL * _COutPacket)(__out COutPacket* oPacket, __in DWORD dwEDX, __in LONG nType) = NULL;
VOID(PACKETCALL * _RemoveAll)(__in unsigned char** pArray, __in DWORD dwEDX) = NULL;

HWND GetXPIWindow()
{
	TCHAR szBuffer[200];
	DWORD dwTemp;

	for (HWND hWnd = GetTopWindow(NULL); hWnd != NULL; hWnd = GetNextWindow(hWnd, GW_HWNDNEXT))
	{
		GetWindowThreadProcessId(hWnd, &dwTemp);

		if (dwTemp != GetCurrentProcessId())
			continue;

		if (!GetWindowText(hWnd, szBuffer, sizeof(szBuffer) / sizeof(TCHAR)))
			continue;

		if (!wcscmp(szBuffer, L"XPI"))
			return hWnd;
	}
	return NULL;
}