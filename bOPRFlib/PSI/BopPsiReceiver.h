#pragma once

#include "Common/Defines.h"
#include "Network/Channel.h"
#include "OT/OTExtInterface.h"
#include "PSI/CuckooHasher.h"
#include "OT/SSOTReceiver.h"
#include "OT/SSOTSender.h"
#include "Common/Tools/LinearCode.h"
#include "Common/poly/Poly.h"
namespace bOPRF
{

	class BopPsiReceiver
	{
	public:
		BopPsiReceiver();
		~BopPsiReceiver();

		u64 mRecverSize,mSenderSize,mStatSecParam;
		const static  u64 Ma_size = (u64)(1.2 * setSize);
		std::vector<u64> mIntersection;
		CuckooHasher mBins;
		LinearCode code;
		block mHashingSeed;
		
		std::vector<std::array<blockBop, 2>> mSSOtMessages; 

		u64 mNumStash;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel& chl0, SSOtExtReceiver& otRecv,  block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, const std::vector<Channel*>& chls, SSOtExtReceiver& otRecv,  block seed);
		void sendInput(std::vector<block>& inputs, Channel& chl);
		u64 BopPsiReceiver::calcurrentstep(std::vector<block>& inputs, u64 cr);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> Ma, vector<block> Mb);
		void T_sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> Ma, vector<block> Mb);
		ZpMersenneLongElement BopPsiReceiver::Lagrange(vector<ZpMersenneLongElement> X, vector<ZpMersenneLongElement> Y, int n, u64 x);
	};




}
