#include "FormattedInject.hpp"

#include "CInstanceManager.hpp"
#include "CMaplePacket.hpp"

namespace FormattedInject
{
	VOID DoInitPacket(COutPacket* pckt, BOOL bHidden, WORD w)
	{
		if (!bHidden)
			_COutPacket(pckt, 0, w);
		else
			COutPacket__constructor(pckt, 0, w);
	}

	VOID DoEncode1(COutPacket* pckt, BOOL bHidden, BYTE b)
	{
		if (!bHidden)
			Encode1(pckt, 0, b);
		else
			_Encode1(pckt, 0, b);
	}

	VOID DoEncode2(COutPacket* pckt, BOOL bHidden, WORD w)
	{
		if (!bHidden)
			Encode2(pckt, 0, w);
		else
			_Encode2(pckt, 0, w);
	}

	VOID DoEncode4(COutPacket* pckt, BOOL bHidden, DWORD dw)
	{
		if (!bHidden)
			Encode4(pckt, 0, dw);
		else
			_Encode4(pckt, 0, dw);
	}

	VOID DoEncode8(COutPacket* pckt, BOOL bHidden, ULONGLONG ull)
	{
		if (!bHidden)
			Encode8(pckt, 0, ull);
		else
			_Encode8(pckt, 0, ull);
	}

	VOID DoEncodeString(COutPacket* pckt, BOOL bHidden, std::string& str)
	{
		if (!bHidden)
		{
			CMaplePacket* p = pInstances->Find(pckt);

			if (p != NULL)
				p->AddString(str.c_str(), 0);
		}

		_Encode2(pckt, 0, str.length());
		_EncodeBuffer(pckt, 0, (LPBYTE)str.c_str(), str.length());
	}

	VOID DoEncodeBuffer(COutPacket* pckt, BOOL bHidden, std::vector<BYTE>& vb)
	{
		if (!bHidden)
			EncodeBuffer(pckt, 0, &vb[0], vb.size());
		else
			_EncodeBuffer(pckt, 0, &vb[0], vb.size());
	}
}