#include "CSagaClient.h"
#include <RCF/ProxyEndpoint.hpp>
#include <PackWrite.h>


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
	m_SagaVersion = 20220324;
	m_ultimestamp = 0;
	m_RSAPub = xorstr_(R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx8JqromtSAvoN9xZGLtM
Ib+e+b0vh8LBVCDgPXI00cAzTNggMmYC1mmiHmvtbR1dErRUwUxS2JOd/iqJBPFa
v+62ImeoKdF4XhFnbOz4/UmjGmvj240QU2Sq4Qb9jRwDAPFy9l2oDAggB2GmAN+D
NyL/pe1lBqcI6jVeLLeeQctVbUPFp+qqgvhoCMHHy7+Y6veiL9yEnErDfxg/3cC8
7yVvCpSTygPLWLI/5G2LVSk21AaE863QLmKO/sMgbEyZ8FBynrhcmyr1kTm96g5k
WieDcQwVW1SvfceO28sFhXPQ/CbXXfktTBA+CwmFLqb//WQ3/TYUq02tlTwPTO4u
YwIDAQAB
-----END PUBLIC KEY-----)");
	m_pInstance = this;
}

CSagaClient* CSagaClient::GetInstance()
{
	if (!m_pInstance)
	{
		m_pInstance = new CSagaClient();
	}
	return m_pInstance;
}

SagaProxyClient printService;
VOID CSagaClient::StartThreadRCFInit(ULONG uPort)
{

	m_uPort = uPort;

	CACEHwid HWID;
	m_MAC = HWID.GetActiveNetworkAdapter()->GetAdapterName();

	auto ThreadFuns = [&]()->void
	{
		VMProtectBeginVirtualization(__FUNCTION__);

		m_pRcfInit = new RCF::RcfInit();
		try
		{
#if SAGA_STUDIO

			m_pClient = new RcfClient<I_CsoStdioPipe>(RCF::Win32NamedPipeEndpoint(xorstr_("SagaSvrPipe")));
			//取消自动连接
			m_pClient->getClientStub().setAutoReconnect(false);

			auto Result = m_pClient->Connect();

			auto lPackRead = std::make_shared<PackReader>(Result.get());

			if (lPackRead->ReadChar())
			{
				m_ClientSession = lPackRead->ReadStr();

				//设置请求用户数据
				m_pClient->getClientStub().setRequestUserData(m_ClientSession);
			}
			
#elseif SAGA_CLOUDS
			m_pClient = new RcfClient<I_SagaService>(RCF::TcpEndpoint(xorstr_("127.0.0.1"), m_uPort));

			if (SagaVersion())
			{
				//方便点.代理端就是Session  下一步GUID 来代替
				m_ProxyName = m_ClientSession;
				//验证成功.启动代理
				static RCF::RcfServer server(RCF::ProxyEndpoint(RCF::TcpEndpoint(xorstr_("127.0.0.1"), m_uPort), m_ProxyName));
				server.bind<I_SagaProxy>(printService);
				server.start();

				auto Module = std::make_unique<CACEModule>();

				auto Result = SagaClient(Module->GetModuleInfo()->AppName, xorstr_("5.1.5.2"));

				if (std::get<BOOL>(Result) == FALSE)
				{
					//弹出错误框.
					MessageBoxA(0, std::get<std::string>(Result).data(), 0, MB_ICONSTOP);

					exit(0);

				}
			}

#endif

		}
		catch (const RCF::Exception& e)
		{
			ACEDebugLog("{}", e.getErrorMessage());
		}
		VMProtectEnd();
	};
	std::thread th(ThreadFuns);
	th.detach();
}

BOOL CSagaClient::SagaCheckVar()
{
	VMProtectBegin(__FUNCTION__);
	BOOL bRet = FALSE;
#if SAGA_CLOUDS
	auto Result =  SagaRemoteVar(xorstr_("CS_Var_Guid"));
	if (std::get<0>(Result))
	{
		if (std::get<1>(Result) == xorstr_("99BA5433-DF5F-A898-C8E0-78B8BA55F251"))
		{
			bRet = TRUE;
		}
	}
	ACEDebugFileLog("[{}] Ret:{} Str:{}",__FUNCTION__, std::get<0>(Result), std::get<1>(Result));
#elif SAGA_STUDIO
	return !m_ClientSession.empty();
#else
	
	return TRUE;
#endif
	VMProtectEnd();
	return bRet;
}

void CSagaClient::HeartBeat()
{

#if SAGA_CLOUDS
	auto Result = SagaClientCheck(m_MAC);

	if (std::get<0>(Result) == false)
	{
		

	}
#endif
}



BOOL CSagaClient::SagaVersion()
{
	VMProtectBegin(__FUNCTION__);
	
	BOOL bRet = FALSE;

#if SAGA_CLOUDS
	std::vector<BYTE> VecByte(2048);

	auto lPack = std::make_shared<PackWriter>(VecByte);

	lPack->WriteByte(0x7E);

	lPack->WriteInt(0x89252061);

	CACEUtil Util;

	int Salt = Util.GetUnixTimeStamp();


	lPack->WriteInt(Salt);

	//RSA加密
	auto EncrypText = RsaPubEncrypt(std::string((char*)lPack->GetBytes(), lPack->GetBytesLength()), m_RSAPub);

	if (EncrypText.size() == 0)
	{
		ACEWarningFileLog("[{}] RSA加密失败", __FUNCTION__);
		return FALSE;
	}
	
	try
	{
		bRet = m_pClient->Version(EncrypText);
	}
	catch (const RCF::Exception& e)
	{
		m_ErrStr = e.getErrorMessage();
		ACEDebugLog("[{}] errstr:{}", __FUNCTION__, m_ErrStr);
	}
	if (bRet)
	{
		//解密获取客户端session
		auto Text = RsaPubDecrypt(EncrypText, m_RSAPub);

		if (Text.size() == 0)
		{
			ACEErrorFileLog("[{}] RSA解密失败", __FUNCTION__);
			return FALSE;
		}
		auto lPackReply = std::make_shared<PackReader>(Text);

		if (lPackReply->ReadChar() != 0x7E)
		{
			m_ErrStr = xorstr_("SagaVersion Head fail");
			ACEErrorFileLog("[{}] {}", __FUNCTION__, m_ErrStr);
			return FALSE;
		}

		//效验 salt
		if (lPackReply->ReadInt() != Salt)
		{
			m_ErrStr = xorstr_("SagaVersion salt fail");
			ACEErrorFileLog("[{}] {}", __FUNCTION__, m_ErrStr);
			return FALSE;
		}
		m_ClientSession = lPackReply->ReadStr();
		m_RC4Key = lPackReply->ReadStr();
		//设置请求用户数据
		m_pClient->getClientStub().setRequestUserData(m_ClientSession);
	}
#endif
	
	VMProtectEnd();
	return bRet;
}

std::tuple<BOOL, std::string> CSagaClient::SagaClient(std::string ProcessName, std::string Version)
{
	std::vector<BYTE> VecByte(1024 + ProcessName.length() + Version.length());

	auto lPackWrite = std::make_shared<PackWriter>(VecByte);

	lPackWrite->WriteString(ProcessName);

	lPackWrite->WriteString(Version);

	auto VecEncrypt = SRC4Encrypt(VecByte);

	BOOL bRet = FALSE;
	std::string ResultStr;

#if SAGA_CLOUDS
	try  
	{
		auto  VecDecode = SRC4Decode(m_pClient->ClientInfo(VecEncrypt));
		auto lPackRead  = std::make_shared<PackReader>(VecDecode);
		bRet            = lPackRead->ReadChar();
		ResultStr       = lPackRead->ReadStr();
	}
	catch (const RCF::Exception& e)
	{
		ResultStr = m_ErrStr = e.getErrorMessage();
	
		ACEErrorFileLog("[{}] {}",__FUNCTION__,m_ErrStr);
	}
#endif
	
	return std::make_tuple(bRet, ResultStr);
}

std::tuple<BOOL, std::string> CSagaClient::SagaRemoteVar(std::string VarName)
{
	std::vector<BYTE> VecByte(1024 + VarName.length());

	auto lPackWrite = std::make_shared<PackWriter>(VecByte);

	lPackWrite->WriteString(VarName);

	auto VecEncrypt = SRC4Encrypt(VecByte);

	BOOL bRet = FALSE;
	std::string ResultStr;

#if SAGA_CLOUDS
	try
	{
		auto  VecDecode = SRC4Decode(m_pClient->RemoteVar(VecEncrypt));

		auto lPackRead = std::make_shared<PackReader>(VecDecode);

		bRet = lPackRead->ReadChar();

		ResultStr = lPackRead->ReadStr();

	}
	catch (const RCF::Exception& e)
	{
		ResultStr = m_ErrStr = e.getErrorMessage();

		ACEErrorFileLog("[{}] {}", __FUNCTION__, m_ErrStr);
	}
#endif
	return std::make_tuple(bRet, ResultStr);
}

std::tuple<BOOL, std::string> CSagaClient::SagaClientCheck(std::string Mac)
{
	std::vector<BYTE> VecByte(1024 + Mac.length());
	auto lPackWrite = std::make_shared<PackWriter>(VecByte);
	CACEUtil Util;
	lPackWrite->WriteInt(Util.GetUnixTimeStamp());
	lPackWrite->WriteString(Mac);

	auto VecEncrypt = SRC4Encrypt(VecByte);

	BOOL bRet = FALSE;
	std::string ResultStr;
#if SAGA_CLOUDS
	try
	{
		auto  VecDecode = SRC4Decode(m_pClient->ClientCheck(VecEncrypt));
		auto lPackRead  = std::make_shared<PackReader>(VecDecode);

		bRet          = lPackRead->ReadChar();
		ResultStr     = lPackRead->ReadStr();
		m_ultimestamp = lPackRead->ReadInt();

		ACEDebugFileLog("[{}] Ret:{} Str:{} timestamp:{}",__FUNCTION__, bRet, ResultStr, m_ultimestamp);
	}
	catch (const RCF::Exception& e)
	{
		ResultStr = m_ErrStr = e.getErrorMessage();

		ACEErrorFileLog("[{}] {}", __FUNCTION__, m_ErrStr);
	}
#endif
	return std::make_tuple(bRet, ResultStr);
}

std::vector<BYTE>  CSagaClient::RsaPubDecrypt(std::vector<BYTE>& VecText, std::string& PubKey)
{
	VMProtectBegin(__FUNCTION__);

	std::vector<BYTE> decrypt_text;
	RSA* rsa = RSA_new();
	BIO* keybio = nullptr;
	keybio = BIO_new_mem_buf((unsigned char*)PubKey.c_str(), -1);

	rsa = /*PEM_read_bio_RSAPrivateKey*/PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		char err_msg[1024] = { 0 };
		ERR_error_string(ERR_get_error(), err_msg); // 格式：error:errId:库:函数:原因
		BIO_free_all(keybio);
		return decrypt_text;
	}

	// 获取RSA单次处理的最大长度
	int key_len = RSA_size(rsa);
	std::vector<BYTE> sub_text(key_len);

	int ret = 0;
	int pos = 0;

	// 对密文进行分段解密
	while (pos < VecText.size())
	{
		memset(sub_text.data(), 0, key_len);
		ret = /*RSA_private_decrypt*/RSA_public_decrypt(key_len, (const unsigned char*)VecText.data() + pos, (unsigned char*)sub_text.data(), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
		{
			int Pos = decrypt_text.size();
			decrypt_text.resize(Pos + ret, 0);
			memcpy(decrypt_text.data() + pos, sub_text.data(), ret);
		}
		pos += key_len;
	}
	BIO_free_all(keybio);
	RSA_free(rsa);
	VMProtectEnd();


	return decrypt_text;
}


std::vector<BYTE> CSagaClient::RsaPubEncrypt(std::string& Text, std::string& PubKey)
{
	VMProtectBegin(__FUNCTION__);

	std::vector<BYTE> CipherText;

	BIO* keybio = BIO_new_mem_buf((unsigned char*)PubKey.data(), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		char err_msg[1024] = { 0 };
		ERR_error_string(ERR_get_error(), err_msg);
		BIO_free_all(keybio);
		return CipherText;
	}

	int key_len = RSA_size(rsa);
	int block_len = key_len - 11;

	std::vector<BYTE> VecText(key_len + 1);

	int ret = 0;
	int pos = 0;
	std::string sub_str;

	while (pos < Text.length())
	{
		sub_str = Text.substr(pos, block_len);
		memset(VecText.data(), 0, key_len + 1);
		ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)VecText.data(), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
		{
			int Pos = CipherText.size();
			CipherText.resize(Pos + ret, 0);
			memcpy((CipherText.data() + Pos), VecText.data(), ret);
		}
		pos += block_len;
	}

	BIO_free_all(keybio);
	RSA_free(rsa);

	VMProtectEnd();
	return CipherText;
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


SagaProxyClient::SagaProxyClient()
{

}

std::vector<BYTE> SagaProxyClient::UMSG(std::vector<BYTE>& v)
{
	auto lPackRead = std::make_shared<PackReader>(v);
	lPackRead->ReadChar();
	auto v1 = lPackRead->ReadStr();
	ACEDebugFileLog("{} {}", __FUNCTION__,v1 );

	return std::vector<BYTE>();
}
