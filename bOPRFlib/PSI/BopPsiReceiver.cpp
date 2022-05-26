#include "BopPsiReceiver.h"
#include <future>
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "PSI/SimpleHasher.h"
#include "Common/Log.h"
#include "OT/Base/naor-pinkas.h"
#include <unordered_map>
#include <type_traits>
#include <typeinfo>
#include <boost/mpl/if.hpp>
#include "Common/Tools/bch511.h"
#include "Common/poly/Poly.h"
namespace mpl = boost::mpl;

namespace bOPRF
{


	std::string hexString(u8* data, u64 length)
	{
		std::stringstream ss;

		for (u64 i = 0; i < length; ++i)
		{

			ss << std::hex << std::setw(2) << std::setfill('0') << (u16)data[i];
		}

		return ss.str();
	}

	BopPsiReceiver::BopPsiReceiver()
	{
	}


	BopPsiReceiver::~BopPsiReceiver()
	{
	}

	void BopPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, SSOtExtReceiver& ots, block seed)
	{
		init(senderSize, recverSize, statSecParam, { &chl0 }, ots, seed);
	}


	void BopPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, const std::vector<Channel*>& chls, SSOtExtReceiver& otRecv, block seed)
	{

		mStatSecParam = statSecParam;
		mSenderSize = senderSize;
		mRecverSize = recverSize;

		mNumStash = get_stash_size(recverSize);

		gTimer.setTimePoint("Init.start");


		PRNG prngHashing(seed);
		block myHashSeeds;
		myHashSeeds = prngHashing.get_block();
		auto& chl0 = *chls[0];


		// we need a random hash function, so both commit to a seed and then decommit later
		chl0.asyncSend(&myHashSeeds, sizeof(block));
		block theirHashingSeeds;
		chl0.asyncRecv(&theirHashingSeeds, sizeof(block));
		//gTimer.setTimePoint("Init.hashSeed");


		// init Cuckoo hash
		mBins.init(mRecverSize, mSenderSize);

		// makes codeword for each bins
		mSSOtMessages.resize(mBins.mBinCount + mNumStash);
		//do base OT
		if (otRecv.hasBaseSSOts() == false)
		{
			//Timer timer;
			gTimer.setTimePoint("Init: BaseSSOT start");
			Log::setThreadName("receiver");
			BaseSSOT baseSSOTs(chl0, OTRole::Sender);
			baseSSOTs.exec_base(prngHashing);
			baseSSOTs.check();
			otRecv.setBaseSSOts(baseSSOTs.sender_inputs);
			gTimer.setTimePoint("Init: BaseSSOT done");
			//	Log::out << gTimer;
		}

		mHashingSeed = myHashSeeds ^ theirHashingSeeds;

		//gTimer.setTimePoint("Init.ExtStart");
		//extend OT
		otRecv.Extend(mBins.mBinCount + mNumStash, mSSOtMessages, chl0);
		std::cout << "receiver 完成 OT extendion 96" << std::endl;
		
		//gTimer.setTimePoint("r Init.Done");
		//	Log::out << gTimer;
	}

	

	struct has_const_member
	{
		const bool x;

		has_const_member(bool x_)
			: x(x_)
		{ }

	};
	u64 BopPsiReceiver::calcurrentstep(std::vector<block>& inputs, u64 cr) {
		
		return cr-(cr%stepSize);
	}
	void BopPsiReceiver::sendInput(std::vector<block>& inputs, Channel& chl)
	{
		sendInput(inputs, { &chl });
	}
	void BopPsiReceiver::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
	{
	}
	void BopPsiReceiver::T_sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls,  vector<block>  ai, vector<block> bi)
	{


		code.load(bch511_binary, sizeof(bch511_binary));
		//const bool leq1 = true;
		//define keysearch of mask based on mask length
//		typedef std::conditional<leq1, u32, u64>::type uMask;

		// check that the number of inputs is as expected.
		if (inputs.size() != mRecverSize)
			throw std::runtime_error("inputs.size() != mN");
		gTimer.setTimePoint("R Online.Start");

		//asign channel
		auto& chl = *chls[0];

		SHA1 sha1;
		u8 hashBuff[SHA1::HashSize];

		//random seed
		PRNG prng(_mm_set_epi32(42534612345, 34557734565, 211234435, 23987045));

		u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte
		u64 maskSize = get_mask_size(mSenderSize, mRecverSize); //by byte
		blockBop codeWord;

		//hash all items, use for: 1) arrage each item to bin using Cuckoo; 
		//                         2) use for psedo-codeword.
		std::array<AES, 4> AESHASH;
		TODO("make real keys seeds");
		for (u64 i = 0; i < AESHASH.size(); ++i)
			AESHASH[i].setKey(_mm_set1_epi64x(i));

		std::array<std::vector<block>, 4> aesHashBuffs;


		aesHashBuffs[0].resize(inputs.size());
		aesHashBuffs[1].resize(inputs.size());
		aesHashBuffs[2].resize(inputs.size());
		aesHashBuffs[3].resize(inputs.size());


		for (u64 i = 0; i < inputs.size(); i += stepSize)
		{
			auto currentStepSize = std::min(stepSize, inputs.size() - i);

			AESHASH[0].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[0].data() + i);

			AESHASH[1].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[1].data() + i);
			AESHASH[2].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[2].data() + i);
			AESHASH[3].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[3].data() + i);

		};

		//insert item to corresponding bin
		mBins.insertItems(aesHashBuffs);
		//mBins.print();

		//we use 4 unordered_maps, we put the mask to the corresponding unordered_map 
		//that indicates of the hash function index 0,1,2. and the last unordered_maps is used for stash bin
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		//store the masks of elements that map to bin by h0
		localMasks.reserve(3 * mBins.mBinCount); //upper bound of # mask
		//store the masks of elements that map to bin by h1


		std::unique_ptr<ByteStream> locaStashlMasks(new ByteStream());
		locaStashlMasks->resize(mNumStash * maskSize);


		//======================Bucket BINs (not stash)==========================

		//pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
		TODO("run in parallel");
		auto binStart = 0;
		auto binEnd = mBins.mBinCount;
		gTimer.setTimePoint("R Online.computeBucketMask start");
		//for each batch
		//trans a+x


		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;
			std::unique_ptr<ByteStream> Mabuff(new ByteStream());
			Mabuff->resize((sizeof(block) * currentStepSize));
			auto xa = Mabuff->getArrayView<block>();
			for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
			{
				auto& item = mBins.mBins[bIdx];
				if (item.isEmpty() == false) {
					xa[i] = ai[bIdx] ^ inputs[item.mIdx];

				}
				else
					xa[i] = ai[bIdx] ^ (prng.get_block());

			}
			chl.asyncSend(std::move(Mabuff));
		}



		vector<block> bibnsum(binEnd);
		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the size of current step & end index.
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// make a buffer for the pseudo-code we need to send
			std::unique_ptr<ByteStream> buff(new ByteStream());
			buff->resize((sizeof(blockBop) * currentStepSize));
			auto myOt = buff->getArrayView<blockBop>();
			// for each bin, do encoding
			for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
			{
				auto& item = mBins.mBins[bIdx];
				block mask(ZeroBlock);

				if (item.isEmpty() == false)
				{
					std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					code.encode(bi[bIdx].m128i_u8, (u8*)lcodebuffs.data());
					memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));


								// encoding will send to the sender.
					myOt[i] =
						codeWord
						^ mSSOtMessages[bIdx][0]
						^ mSSOtMessages[bIdx][1];
					//

						// 0 -》1 应该是b1和a0
						//cout << "recv ele " << item.mIdx << " map ot" << bIdx << " hash " << item.mHashIdx << " sum " << mSSOtMessages[bIdx][0] << "recv suppose ot " << bIdx << " " << myOt[i] << endl;

					//compute my mask
					sha1.Reset();
					//sha1.Update((u8*)&item.mHashIdx, sizeof(u64)); //
					sha1.Update((u8*)&mSSOtMessages[bIdx][0], codeWordSize);
					sha1.Final(hashBuff);
					bibnsum[bIdx] = mSSOtMessages[bIdx][0].elem[0];


					// store the my mask value here					
					memcpy(&mask, hashBuff, maskSize);
					
					//store my mask into corresponding buff at the permuted position
					localMasks.emplace(*(u64*)&mask, std::pair<block, u64>(mask, bIdx));

				}
				else
				{
					// no item for this bin, just use a dummy.
					//myOt[i] = prng.get_block512(codeWordSize);
					std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					code.encode(bi[bIdx].m128i_u8, (u8*)lcodebuffs.data());
					memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));

					/*			codeWord.elem[0] = lcodebuffs[0];
								codeWord.elem[1] = lcodebuffs[1];
								codeWord.elem[2] = lcodebuffs[2];
								codeWord.elem[3] = lcodebuffs[3];*/

								// encoding will send to the sender.
					myOt[i] =
						codeWord
						^ mSSOtMessages[bIdx][0]
						^ mSSOtMessages[bIdx][1];
					//
					sha1.Reset();
					//sha1.Update((u8*)&item.mHashIdx, sizeof(u64)); //
					sha1.Update((u8*)&mSSOtMessages[bIdx][0], codeWordSize);
					sha1.Final(hashBuff);
					memcpy(&mask, hashBuff, maskSize);
					//cout << "stash ele map ot " << bIdx << "  sum " << mSSOtMessages[bIdx][0] << "recv suppose ot " << bIdx << " " << myOt[i] << endl;

					//store my mask into corresponding buff at the permuted position
					localMasks.emplace(*(u64*)&mask, std::pair<block, u64>(mask, bIdx));
				}
			}
			// send the OT correction masks for the current step
			chl.asyncSend(std::move(buff));

		}// Done with compute the masks for the main set of bins. 	

		gTimer.setTimePoint("R Online.sendBucketMask done");
		//receive the sender's marks, we have 3 buffs that corresponding to the mask of elements used hash index 0,1,2
		//cout << " recv 329 finish" << endl;
		ByteStream u0Buff;
		chl.recv(u0Buff);
		ByteStream u1Buff;
		chl.recv(u1Buff);
		ByteStream u2Buff;
		chl.recv(u2Buff);
		ZpMersenneLongElement sec_s=0;
		cout << " recv 332 finish,recv buff" << endl;
		// double check the size. 
		if (u0Buff.size() != 3 * mSenderSize * maskSize )
		{
			Log::out << "recvBuff.size() != expectedSize" << Log::endl;
			throw std::runtime_error("rt error at " LOCATION);
		}
		if (u1Buff.size() != 3 * mSenderSize  * sizeof(ZpMersenneLongElement[1]) )
		{
			Log::out << "recvBuff.size() != expectedSize" << Log::endl;
			throw std::runtime_error("rt error at " LOCATION);
		}		
		if (u2Buff.size() != 3 * mSenderSize  * sizeof(block[1]))
		{
			Log::out << "recvBuff.size() != expectedSize" << Log::endl;
			throw std::runtime_error("rt error at " LOCATION);
		}

		auto theirMasks = u0Buff.data();
		auto u2u64s = u1Buff.getArrayView<ZpMersenneLongElement[1]>();
		auto block3s = u2Buff.getArrayView<block[1]>();
		vector<ZpMersenneLongElement> fin(threshold);
		vector<ZpMersenneLongElement> fout(threshold);
		i64 binhas[Ma_size];
		for (u64 i = 0; i < Ma_size; i++) {
			binhas[i]= -1;
		}
		//loop each mask
		if (maskSize >= 8)
		{
			cout << " >8" << endl;
			//if masksize>=8, we can check 64 bits of key from the map first
			for (u64 i = 0; i < 3 * mSenderSize; ++i)
			{
				auto& msk = *(u64*)(theirMasks);

				// check 64 first bits
				auto match = localMasks.find(msk);

				//if match, check for whole bits
				if (match != localMasks.end())
				{
					if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
					{

						if (binhas[match->second.second]<0) {
							if (mIntersection.size() < threshold) {
								fin[mIntersection.size()] = mSSOtMessages[match->second.second][0].elem[0].m128i_u64[0];
								fout[mIntersection.size()] = u2u64s[i][0];
							}
							mIntersection.push_back(match->second.second);
							binhas[match->second.second] = i;
						}
						//Log::out << "#id: " << match->second.second << Log::endl;
					}
				}

				theirMasks += maskSize;
			}
			cout << "start interp" << endl;
			ZpMersenneLongElement ss = Lagrange(fin, fout, threshold, 0);
			cout<<"s copm "<<ss << endl;
		}
		else
		{
			cout << " <8" << endl;
			for (u64 i = 0; i < 3 * mSenderSize; ++i)
			{
				for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
				{
					if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
					{
						if (!binhas[match->second.second]) {
							if (mIntersection.size() < threshold) {
								fin[mIntersection.size()] = mSSOtMessages[match->second.second][0].elem[0].m128i_u64[0];
								fout[mIntersection.size()] = u2u64s[i][0];//mSSOtMessages[match->second.second][0].elem[0].m128i_u64[0];
								//cout << "recv  X  " << fin[mIntersection.size()] << " recv Y" << fout[mIntersection.size()] << endl;
							}
							mIntersection.push_back(match->second.second);
							binhas[match->second.second] = true;

						//cout << "intserc " << match->second.second << endl;
						}
						//Log::out << "#id: " << match->second.second << Log::endl;
						//cout <<  theirMasks << "  " << match->second.first << endl;

					}
					else {
					}
				}
				theirMasks += maskSize;
			}
			ZpMersenneLongElement ss = Lagrange(fin, fout, threshold, 0);
			cout << "s copm " << ss << endl;
		}

		vector<block> intersect;
		for (u64 i = 0; (i < Ma_size); i++) {
			if(binhas[i]>0){
			sha1.Reset();
			sha1.Update((u8*)&mSSOtMessages[i][0], codeWordSize);
			sha1.Update((u8*)&sec_s, sizeof(u64));
			sha1.Final(hashBuff);
			block bb = ZeroBlock;
			for (int nn = 0; nn < sizeof(hashBuff) / sizeof(hashBuff[0]); nn++) {
				bb = bb << hashBuff[nn];
			}
			cout << " we recv intersec " << intersect.size() << endl;
			intersect.push_back(bb ^ block3s[binhas[i]][0]);
		}
		}
		vector<u64> cotinput;
		//Lagrange(fin, fout, threshold, 0);
		for (u64 i = 0; i < inputs.size(); i++) {
			for (u64 j = 0; j < intersect.size(); j++) {
				if (inputs[i] == intersect[j]) {
					cotinput.push_back(i);
					break;
				}
			}
		}
		cout << " real intersect seize" << cotinput.size()<<endl;
		gTimer.setTimePoint("R Online.Bucket done");

		//======================STASH BIN==========================

		std::unique_ptr<ByteStream> stashBuff(new ByteStream());
		stashBuff->resize((sizeof(blockBop) * mBins.mStash.size()));
		auto myOt = stashBuff->getArrayView<blockBop>();

		cout << "recv 370 finfisdh" << endl;
		gTimer.setTimePoint("R Online.Stash start");
		// compute the encoding for each item in the stash.
		for (u64 i = 0, otIdx = mBins.mBinCount; i < mBins.mStash.size(); ++i, ++otIdx)
		{
			auto& item = mBins.mStash[i];
			block mask(ZeroBlock);

			if (item.isEmpty() == false)
			{
				std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock };
				code.encode((u8*)inputs[item.mIdx].m128i_u8, (u8*)lcodebuffs.data());
				memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));
				//codeWord.elem[0] = lcodebuffs[0];
				//codeWord.elem[1] = lcodebuffs[1];
				//codeWord.elem[2] = lcodebuffs[2];
				//codeWord.elem[3] = lcodebuffs[3];

				myOt[i] =
					codeWord
					^ mSSOtMessages[otIdx][0]
					^ mSSOtMessages[otIdx][1];

				sha1.Reset();
				sha1.Update((u8*)&mSSOtMessages[otIdx][0], codeWordSize);
				sha1.Final(hashBuff);

				memcpy(locaStashlMasks->data() + i * maskSize, hashBuff, maskSize);
			}
			else
			{
				myOt[i] = prng.get_block512(codeWordSize) ^ mSSOtMessages[otIdx][0]
					^ mSSOtMessages[otIdx][1];
			}
		}

		chl.asyncSend(std::move(stashBuff));
		gTimer.setTimePoint("R Online.sendStashMask done");

		//receive masks from the stash
		for (u64 sBuffIdx = 0; sBuffIdx < mNumStash; sBuffIdx++)
		{
			ByteStream recvBuff;
			chl.recv(recvBuff);
			if (mBins.mStash[sBuffIdx].isEmpty() == false)
			{
				// double check the size.
				auto cntMask = mSenderSize;
				gTimer.setTimePoint("Online.MaskReceived from STASH");
				if (recvBuff.size() != cntMask * maskSize)
				{
					Log::out << "recvBuff.size() != expectedSize" << Log::endl;
					throw std::runtime_error("rt error at " LOCATION);
				}

				auto theirMasks = recvBuff.data();
				for (u64 i = 0; i < cntMask; ++i)
				{
					//check stash
					if (memcmp(theirMasks, locaStashlMasks->data() + sBuffIdx * maskSize, maskSize) == 0)
					{
						mIntersection.push_back(mBins.mStash[sBuffIdx].mIdx);
						//Log::out << "#id: " << match->second.second << Log::endl;
					}

					theirMasks += maskSize;
				}
			}
		}

		gTimer.setTimePoint("Online.Done");
		//	Log::out << gTimer << Log::endl;
	}
	void BopPsiReceiver::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> ai, vector<block> bi)
	{


		code.load(bch511_binary, sizeof(bch511_binary));
		//const bool leq1 = true;
		//define keysearch of mask based on mask length
//		typedef std::conditional<leq1, u32, u64>::type uMask;

		// check that the number of inputs is as expected.
		if (inputs.size() != mRecverSize)
			throw std::runtime_error("inputs.size() != mN");
		gTimer.setTimePoint("R Online.Start");

		//asign channel
		auto& chl = *chls[0];

		SHA1 sha1;
		u8 hashBuff[SHA1::HashSize];

		//random seed
		PRNG prng(_mm_set_epi32(42534612345, 34557734565, 211234435, 23987045));

		u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte
		u64 maskSize = get_mask_size(mSenderSize, mRecverSize); //by byte
		blockBop codeWord;

		//hash all items, use for: 1) arrage each item to bin using Cuckoo; 
		//                         2) use for psedo-codeword.
		std::array<AES, 4> AESHASH;
		TODO("make real keys seeds");
		for (u64 i = 0; i < AESHASH.size(); ++i)
			AESHASH[i].setKey(_mm_set1_epi64x(i));

		std::array<std::vector<block>, 4> aesHashBuffs;

		
		aesHashBuffs[0].resize(inputs.size());
		aesHashBuffs[1].resize(inputs.size());
		aesHashBuffs[2].resize(inputs.size());
		aesHashBuffs[3].resize(inputs.size());
		

		for (u64 i = 0; i < inputs.size(); i += stepSize)
		{
			auto currentStepSize = std::min(stepSize, inputs.size() - i);

			AESHASH[0].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[0].data() + i);
			
			AESHASH[1].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[1].data() + i);
			AESHASH[2].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[2].data() + i);
			AESHASH[3].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[3].data() + i);
	
		};

		//insert item to corresponding bin
		mBins.insertItems(aesHashBuffs);
		//mBins.print();

		//we use 4 unordered_maps, we put the mask to the corresponding unordered_map 
		//that indicates of the hash function index 0,1,2. and the last unordered_maps is used for stash bin
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		//store the masks of elements that map to bin by h0
		localMasks.reserve(3*mBins.mBinCount); //upper bound of # mask
		//store the masks of elements that map to bin by h1
	

		std::unique_ptr<ByteStream> locaStashlMasks(new ByteStream());
		locaStashlMasks->resize(mNumStash* maskSize);


		//======================Bucket BINs (not stash)==========================

		//pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
		TODO("run in parallel");
		auto binStart = 0;
		auto binEnd = mBins.mBinCount;
		gTimer.setTimePoint("R Online.computeBucketMask start");
		//for each batch
		//trans a+x

		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;
			std::unique_ptr<ByteStream> Mabuff(new ByteStream());
			Mabuff->resize((sizeof(block) * currentStepSize));
			auto xa = Mabuff->getArrayView<block>();
			for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
			{
				auto& item = mBins.mBins[bIdx];
				if (item.isEmpty() == false) {
				xa[i] = ai[bIdx] ^ inputs[item.mIdx];

			}
		else
				xa[i] = ai[bIdx] ^ (prng.get_block());

				}
			chl.asyncSend(std::move(Mabuff));
			}

		


		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the size of current step & end index.
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// make a buffer for the pseudo-code we need to send
			std::unique_ptr<ByteStream> buff(new ByteStream());
			buff->resize((sizeof(blockBop)*currentStepSize));
			auto myOt = buff->getArrayView<blockBop>();
			// for each bin, do encoding
			for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
			{
				auto& item = mBins.mBins[bIdx];
				block mask(ZeroBlock);

				if (item.isEmpty() == false)
				{
					std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					code.encode(bi[bIdx].m128i_u8, (u8*)lcodebuffs.data());
					memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));

		/*			codeWord.elem[0] = lcodebuffs[0];
					codeWord.elem[1] = lcodebuffs[1];
					codeWord.elem[2] = lcodebuffs[2];
					codeWord.elem[3] = lcodebuffs[3];*/

					// encoding will send to the sender.
					myOt[i] =
						codeWord
						^ mSSOtMessages[bIdx][0]
						^ mSSOtMessages[bIdx][1];
					//

						// 0 -》1 应该是b1和a0
						//cout << "recv ele" << item.mIdx << " map ot" << bIdx << " hash " << item.mHashIdx << " sum " << mSSOtMessages[bIdx][0] << "recv suppose ot " << bIdx << " " << myOt[i] << endl;
					
					//compute my mask
					sha1.Reset();
					//sha1.Update((u8*)&item.mHashIdx, sizeof(u64)); //
					sha1.Update((u8*)&mSSOtMessages[bIdx][0], codeWordSize);
					sha1.Final(hashBuff);


					// store the my mask value here					
					memcpy(&mask, hashBuff, maskSize);

					//store my mask into corresponding buff at the permuted position
					localMasks.emplace(*(u64*)&mask, std::pair<block, u64>(mask, bIdx));

				}
				else
				{
					// no item for this bin, just use a dummy.
					//myOt[i] = prng.get_block512(codeWordSize);
					std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					code.encode(bi[bIdx].m128i_u8, (u8*)lcodebuffs.data());
					memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));

					/*			codeWord.elem[0] = lcodebuffs[0];
								codeWord.elem[1] = lcodebuffs[1];
								codeWord.elem[2] = lcodebuffs[2];
								codeWord.elem[3] = lcodebuffs[3];*/

								// encoding will send to the sender.
					myOt[i] =
						codeWord
						^ mSSOtMessages[bIdx][0]
						^ mSSOtMessages[bIdx][1];
					//
					sha1.Reset();
					//sha1.Update((u8*)&item.mHashIdx, sizeof(u64)); //
					sha1.Update((u8*)&mSSOtMessages[bIdx][0], codeWordSize);
					sha1.Final(hashBuff);
					memcpy(&mask, hashBuff, maskSize);
					//cout << "stash ele map ot " << bIdx << "  sum " << mSSOtMessages[bIdx][0] << "recv suppose ot " << bIdx << " " << myOt[i] << endl;

					//store my mask into corresponding buff at the permuted position
					localMasks.emplace(*(u64*)&mask, std::pair<block, u64>(mask, bIdx));
				}
			}
			// send the OT correction masks for the current step
			chl.asyncSend(std::move(buff));

		}// Done with compute the masks for the main set of bins. 	

		gTimer.setTimePoint("R Online.sendBucketMask done");
		//receive the sender's marks, we have 3 buffs that corresponding to the mask of elements used hash index 0,1,2
		//cout << " recv 329 finish" << endl;
			ByteStream recvBuff;
			chl.recv(recvBuff);
			//cout << " recv 332 finish" << endl;
			// double check the size. 
			if (recvBuff.size() != 3*mSenderSize* maskSize)
			{
				Log::out << "recvBuff.size() != expectedSize" << Log::endl;
				throw std::runtime_error("rt error at " LOCATION);
			}

			auto theirMasks = recvBuff.data();

			//loop each mask
			if (maskSize >= 8)
			{
				cout << " >8" << endl;
				//if masksize>=8, we can check 64 bits of key from the map first
				for (u64 i = 0; i < 3*mSenderSize; ++i)
				{
					auto& msk = *(u64*)(theirMasks);

					// check 64 first bits
						auto match = localMasks.find(msk);

					//if match, check for whole bits
					if (match != localMasks.end())
					{
						if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
						{
							mIntersection.push_back(match->second.second);
							//Log::out << "#id: " << match->second.second << Log::endl;
						}
					}
				
					theirMasks += maskSize;
				}
			}
			else
			{
				cout << " <8" << endl;
				for (u64 i = 0; i < 3*mSenderSize; ++i)
				{
						for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
						{
							if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
							{
								mIntersection.push_back(match->second.second);
								//Log::out << "#id: " << match->second.second << Log::endl;
								//cout <<  theirMasks << "  " << match->second.first << endl;
							}
							else {
							}
						}
					theirMasks += maskSize;
				}
			}
		gTimer.setTimePoint("R Online.Bucket done");

		//======================STASH BIN==========================

		std::unique_ptr<ByteStream> stashBuff(new ByteStream());
		stashBuff->resize((sizeof(blockBop)*mBins.mStash.size()));
		auto myOt = stashBuff->getArrayView<blockBop>();

		cout << "recv 370 finfisdh" << endl;
		gTimer.setTimePoint("R Online.Stash start");
		// compute the encoding for each item in the stash.
		for (u64 i = 0, otIdx = mBins.mBinCount; i < mBins.mStash.size(); ++i, ++otIdx)
		{
			auto& item = mBins.mStash[i];
			block mask(ZeroBlock);

			if (item.isEmpty() == false)
			{
				std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock };
				code.encode((u8*)inputs[item.mIdx].m128i_u8, (u8*)lcodebuffs.data());
				memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));
				//codeWord.elem[0] = lcodebuffs[0];
				//codeWord.elem[1] = lcodebuffs[1];
				//codeWord.elem[2] = lcodebuffs[2];
				//codeWord.elem[3] = lcodebuffs[3];

				myOt[i] =
					codeWord
					^ mSSOtMessages[otIdx][0]
					^ mSSOtMessages[otIdx][1];

				sha1.Reset();
				sha1.Update((u8*)&mSSOtMessages[otIdx][0], codeWordSize);
				sha1.Final(hashBuff);
				
				memcpy(locaStashlMasks->data() + i * maskSize, hashBuff, maskSize);
			}
			else
			{
				myOt[i] = prng.get_block512(codeWordSize) ^ mSSOtMessages[otIdx][0]
					^ mSSOtMessages[otIdx][1];
			}
		}

		chl.asyncSend(std::move(stashBuff));
		gTimer.setTimePoint("R Online.sendStashMask done");

		//receive masks from the stash
		for (u64 sBuffIdx = 0; sBuffIdx < mNumStash; sBuffIdx++)
		{
			ByteStream recvBuff;
			chl.recv(recvBuff);
			if (mBins.mStash[sBuffIdx].isEmpty()== false)
			{
				// double check the size.
				auto cntMask = mSenderSize;
				gTimer.setTimePoint("Online.MaskReceived from STASH");
				if (recvBuff.size() != cntMask* maskSize)
				{
					Log::out << "recvBuff.size() != expectedSize" << Log::endl;
					throw std::runtime_error("rt error at " LOCATION);
				}

				auto theirMasks = recvBuff.data();
					for (u64 i = 0; i < cntMask; ++i)
					{
						//check stash
							if (memcmp(theirMasks, locaStashlMasks->data()+ sBuffIdx*maskSize, maskSize) == 0) 
							{
								mIntersection.push_back(mBins.mStash[sBuffIdx].mIdx);
								//Log::out << "#id: " << match->second.second << Log::endl;
							}
						
						theirMasks += maskSize;
					}				
			}
		}

	gTimer.setTimePoint("Online.Done");
	//	Log::out << gTimer << Log::endl;
}
	ZpMersenneLongElement BopPsiReceiver::Lagrange(vector<ZpMersenneLongElement> X, vector<ZpMersenneLongElement> Y, int n, u64 x)//采用Lagrange插值方法，分别表示，长度，深度，数组数目和所需要计算点的值
{
		vector<ZpMersenneLongElement> coefficient(threshold);
		ZpMersenneLongElement result;

		result = Poly::evalMe0(X, Y, 0);
		cout << " result2 " << result << endl;
	return result;
}
}