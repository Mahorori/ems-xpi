#ifndef CMAPLE_PACKET_HPP_
#define CMAPLE_PACKET_HPP_

#include <windows.h>

#include <boost/pool/pool_alloc.hpp>

#include <string>
#include <vector>
#include <deque>

enum MEMBER_TYPE
{
	MEMBER_STRING,
	MEMBER_BUFFER,
	MEMBER_BYTE,
	MEMBER_WORD,
	MEMBER_DWORD,
	MEMBER_ULONGLONG
};

enum PACKET_DIRECTION
{
	PACKET_SEND,
	PACKET_RECV
};

typedef struct _CALLER_TIME
{
	FILETIME  Time;
	LPVOID    lpCaller;
} CALLER_TIME, far *LPCALLER_TIME, near *PCALLER_TIME;

typedef std::vector<BYTE> PACKET_BUFFER;
typedef std::string PACKET_STRING;

typedef struct _PACKET_MEMBER
{
	CALLER_TIME CallerTime;
	MEMBER_TYPE Type;
	union
	{
		PACKET_BUFFER* buff;
		PACKET_STRING* str;
		BYTE b;
		WORD w;
		DWORD dw;
		ULONGLONG ull;
	} data;
} PACKET_MEMBER, far *LPPACKET_MEMBER, near *PPACKET_MEMBER;

typedef std::deque<PACKET_MEMBER, boost::fast_pool_allocator<PACKET_MEMBER> > PACKET_MEMBERS;

#define PACKET_INJECTED 0x1
#define PACKET_LOOPBACK 0x2
#define PACKET_BLOCKED  0x4
#define PACKET_WORLD	0x8

typedef struct _CMAPLEPACKETSTRUCT
{
	PVOID             pInstance;
	PACKET_DIRECTION  Direction;
	ULONG_PTR         ulState;
	LPVOID            lpv;
} CMAPLEPACKETSTRUCT, far *LPCMAPLEPACKETSTRUCT, near *PCMAPLEPACKETSTRUCT;

extern volatile LONG lPacketCount;

class CMaplePacket
{
private:
	// packet ID
	LONG m_lID;
	// sent or received?
	PACKET_DIRECTION  m_Direction;
	// class instance pointer (&this)
	PVOID m_pInstance;
	// caller & time
	CALLER_TIME m_CallerTime;
	// CS for atomic member adding
	CRITICAL_SECTION m_CriticalSection;
	// injected/loopback/blocked
	ULONG_PTR m_ulState;
	// packet members
	PACKET_MEMBERS m_dqMembers;
	// packet data
	std::vector<BYTE> m_vbData;
	// extra data
	LPARAM  m_lParam;
	WPARAM  m_wParam;
private:
	VOID SetCallerTime(__out LPCALLER_TIME lpCT, __in LPVOID lpv = 0);
public:
	// ctor/dtor
	explicit CMaplePacket(__in LPCMAPLEPACKETSTRUCT lpCMaplePacketStruct);
	~CMaplePacket();
	// adding members
	VOID Add1(__in BYTE b, __in LPVOID lpv = 0);
	VOID Add2(__in WORD w, __in LPVOID lpv = 0);
	VOID Add4(__in DWORD dw, __in LPVOID lpv = 0);
	VOID Add8(__in ULONGLONG ull, __in LPVOID lpv);
	VOID AddString(__in LPCSTR lpcsz, __in LPVOID lpv = 0);
	VOID AddBuffer(__in_bcount(uSize) const PBYTE pcbData, __in UINT uSize, __in LPVOID lpv = 0);
	// copying
	VOID CopyMembersFrom(__in CMaplePacket* pPacket);
	// helpers
	const CALLER_TIME* GetCallerTime() const { return &m_CallerTime; }
	const PACKET_MEMBERS* GetMembers() const { return &m_dqMembers; }
	WORD GetOpcode() const { return (!m_dqMembers.empty() && m_dqMembers[0].Type == MEMBER_WORD) ? m_dqMembers[0].data.w : 0xFFFF; }
	UINT GetSize() const { return m_vbData.size(); }
	UINT GetMemberCount() const { return m_dqMembers.size(); }
	ULONG_PTR GetState() const { return m_ulState; }
	VOID SetState(__in ULONG_PTR ulState) { m_ulState = ulState;  }
	LONG GetID() const { return m_lID; }
	PACKET_DIRECTION GetDirection() const { return m_Direction; }
	std::vector<BYTE>* GetData() { return &m_vbData; }
	LPARAM GetLParam() const { return m_lParam; }
	VOID SetLParam(__in LPARAM lParam) { m_lParam = lParam; }
	WPARAM GetWParam() const { return m_wParam; }
	VOID SetWParam(__in WPARAM wParam) { m_wParam = wParam; }
};

#endif // CMAPLE_PACKET_HPP_
