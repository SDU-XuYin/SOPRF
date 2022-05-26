#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "OT/OTExtInterface.h"
#include "PSI/SimpleHasher.h"
#include "OT/SSOTReceiver.h"
#include "OT/SSOTSender.h"
#include "Common/poly/Poly.h"
#include "Common/Tools/LinearCode.h"

namespace bOPRF
{


	class BopPsiSender
	{
	public:
		BopPsiSender();
		~BopPsiSender();

		
		u64 mSenderSize, mRecverSize, mStatSecParam;
		const static  u64 Ma_size = (u64)(1.2* setSize);
		//std::vector<SSOtPsiSender> mPsis;

		std::vector<blockBop> mPsiRecvSSOtMessages;


		LinearCode code;
		SimpleHasher mBins;
		BitVector mSSOtChoice;

		block mHashingSeed;

		u64 mNumStash;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, const std::vector<Channel*>& chls, SSOtExtSender& otSender, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, SSOtExtSender& otSender, block seed);
		u64 BopPsiSender::calcurrentstep(std::vector<block>& inputs, u64 cr);
		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);
		void T_sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> Ma, vector<block> Mb);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> Ma, vector<block> Mb);
		u64 BopPsiSender::poww(block a, u64 b);
		u64 BopPsiSender::calPoly(block input, std::vector<u32>& coefficient);

	};

}