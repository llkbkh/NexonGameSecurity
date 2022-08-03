#include "CSagaClient.h"
#include <VMProtectSDK.h>
#include <PackWrite.h>
#include "openssl/win32/include/openssl/rc4.h"


#pragma comment(lib,"openssl/win32/lib/libcrypto.lib")
#pragma comment(lib,"openssl/win32/lib/libssl.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"winmm.lib")
#pragma comment(lib,"wldap32.lib")

CSagaClient::CSagaClient()
{
	m_pClient     = nullptr;
	m_pRcfInit    = nullptr;
	m_uPort       = 0;
	m_RC4Key      = xorstr_("99BA5433DF5FA898C8E078B8BA55F251");
	m_SagaVersion = 20220324;
	m_ultimestamp = 0;
}

CSagaClient* CSagaClient::GetInstance()
{
	if (!m_pInstance)
	{
		m_pInstance = new CSagaClient();
	}
	return m_pInstance;
}


VOID CSagaClient::StartThreadRCFInit(ULONG uPort)
{
	VMProtectBegin(__FUNCDNAME__);

	m_uPort = uPort;

	auto ThreadFuns = [&]()->void
	{
		m_pRcfInit = new RCF::RcfInit();
		try
		{
			m_pClient = new RcfClient<I_SagaService>(RCF::TcpEndpoint(xorstr_("127.0.0.1"), m_uPort));

			SagaLogin(xorstr_("admin"), xorstr_("123456"));

		}
		catch (const RCF::Exception& e)
		{
			
		}
	};
	std::thread th(ThreadFuns);
	th.detach();
	VMProtectEnd();
}

BOOL CSagaClient::SagaLogin(std::string User, std::string PassWord)
{
	std::vector<BYTE> VecByte(User.length() + PassWord.length() + 1024);

	auto lPack = std::make_shared<PackWriter>(VecByte);

	lPack->WriteString(User);
	lPack->WriteString(PassWord);

	auto VecEncryptValue = SRC4Encrypt(VecByte);

	BOOL bRet = FALSE;

	try
	{
		bRet = m_pClient->Login(VecEncryptValue);

	}
	catch (const RCF::Exception& e)
	{
		
	}


	if (bRet)
	{
		//解密获取客户端session
		m_ClientSession = (char*)SRC4Decode(VecEncryptValue).data();

		//设置请求用户数据
		m_pClient->getClientStub().setRequestUserData(m_ClientSession);

	}
	
	return bRet;
}
BOOL CSagaClient::SagaCheckVar()
{
	VMProtectBegin(__FUNCTION__);

	BOOL bRet = FALSE;

#if SAGA_CLOUDS
	std::vector<BYTE> VecByte(1024);

	auto lPack = std::make_shared<PackWriter>(VecByte);

	lPack->WriteString(xorstr_("CS_Var_Guid"));

	auto VecEncryptValue = SRC4Encrypt(VecByte);

	try
	{
		std::string Text = m_pClient->GetVar(VecEncryptValue);

		if (Text == xorstr_("99BA5433-DF5F-A898-C8E0-78B8BA55F251"))
		{
			bRet = TRUE;
		}
	}
	catch (const RCF::Exception& e)
	{
		
	}

#else
	return TRUE;
#endif

	VMProtectEnd();

	return bRet;
}


std::vector<BYTE> CSagaClient::SRC4Decode(std::vector<BYTE> CipherByte)
{
	RC4_KEY s_table;
	RC4_set_key(&s_table, m_RC4Key.length(), (unsigned char*)m_RC4Key.c_str());
	std::vector<BYTE>DecodeText(CipherByte.size());
	RC4(&s_table, CipherByte.size(), (unsigned char*)CipherByte.data(), DecodeText.data());     //解密
	return DecodeText;
}

std::vector<BYTE> CSagaClient::SRC4Encrypt(std::vector<BYTE> CipherByte)
{
	RC4_KEY s_table;
	RC4_set_key(&s_table, m_RC4Key.length(), (unsigned char*)m_RC4Key.c_str());
	std::vector<BYTE> Rc4Data(CipherByte.size());
	RC4(&s_table, CipherByte.size(), (unsigned char*)CipherByte.data(), Rc4Data.data());		//加密
	return Rc4Data;
}