#pragma once
#include <RCF/RCF.hpp>
#include "../RCF/RCF007Interface.hpp"
#pragma comment(lib,"RcfDll.lib")
#pragma comment(lib,"imm32.lib")
//传奇云 验证
#define  SAGA_CLOUDS		1

class CSagaClient
{
public:
	CSagaClient();
	static CSagaClient* GetInstance();
	

	// @启动线程初始化
	VOID StartThreadRCFInit(ULONG uPort = 31251);


	// @用户登录
	BOOL SagaLogin(std::string User,std::string PassWord);
	BOOL SagaCheckVar();

	std::vector<BYTE> SRC4Decode(std::vector<BYTE> CipherByte);
	std::vector<BYTE> SRC4Encrypt(std::vector<BYTE> CipherByte);
private:
	RCF::RcfInit*              m_pRcfInit;
	RcfClient<I_SagaService>*  m_pClient;
	static inline CSagaClient* m_pInstance = nullptr;
	ULONG                      m_uPort;
	std::string                m_RC4Key;
	ULONG	                   m_SagaVersion;
	std::string	               m_ClientSession;
	ULONG	                   m_ultimestamp;
};

