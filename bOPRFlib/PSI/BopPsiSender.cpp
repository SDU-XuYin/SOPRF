#include "BopPsiSender.h"
#include "Crypto/Commit.h"
#include "Common/Log.h"
#include "Common/Timer.h"
#include "OT/Base/naor-pinkas.h"
#include "Common/Tools/bch511.h"
#include "Common/poly/Poly.h"

namespace bOPRF
{

	BopPsiSender::BopPsiSender()
	{
	}

	BopPsiSender::~BopPsiSender()
	{
	}
	extern std::string hexString(u8* data, u64 length);

	void BopPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, Channel & chl0, SSOtExtSender& ots, block seed)
	{
		init(senderSize, recverSize, statSec, { &chl0 }, ots, seed);
	}

	void BopPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, const std::vector<Channel*>& chls, SSOtExtSender& otSend, block seed)
	{
		mStatSecParam = statSec;
		mSenderSize = senderSize;
		mRecverSize = recverSize;
		mNumStash = get_stash_size(recverSize);

		// we need a random hash function, so both commit to a seed and then decommit later
		PRNG prngHashing(seed);
		block myHashSeeds;
		myHashSeeds = prngHashing.get_block();
		auto& chl0 = *chls[0];
		chl0.asyncSend(&myHashSeeds, sizeof(block));


		block theirHashingSeeds;
		chl0.asyncRecv(&theirHashingSeeds, sizeof(block));

		// init Simple hash
		mBins.init(mRecverSize, mSenderSize);

		mPsiRecvSSOtMessages.resize(mBins.mBinCount + mNumStash);
		//std::cout << "sender init start base ot " << endl;
		//do base OT
		if (otSend.hasBaseSSOts() == false)
		{
			//Timer timer;
			BaseSSOT baseSSOTs(chl0, OTRole::Receiver);
			baseSSOTs.exec_base(prngHashing);
			baseSSOTs.check();
			otSend.setBaseSSOts(baseSSOTs.receiver_outputs, baseSSOTs.receiver_inputs);
			//	gTimer.setTimePoint("s baseDOne");
			mSSOtChoice = baseSSOTs.receiver_inputs;
			//Log::out << gTimer;
		}
		mHashingSeed = myHashSeeds ^ theirHashingSeeds;

		otSend.Extend(mBins.mBinCount + mNumStash, mPsiRecvSSOtMessages, chl0);

		std::cout << "sender 完成 OT extendion 64" << std::endl;
		gTimer.setTimePoint("s InitS.extFinished");
	}


	u64 BopPsiSender::calcurrentstep(std::vector<block>& inputs, u64 cr) {
		return cr - (cr % stepSize);
	}
	void BopPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
	{

		//sendInput(inputs, { &chl });
	}
	void BopPsiSender::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
	{
	 }
	void BopPsiSender::T_sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> ai, vector<block> bi)
	{

		code.load(bch511_binary, sizeof(bch511_binary));
		if (inputs.size() != mSenderSize)
			throw std::runtime_error("rt error at " LOCATION);
		vector<u64> shuffle_x(Ma_size);
		vector<u64> shuffle_y(Ma_size);
		for (u64 i = 0; i < Ma_size; i++) {
			shuffle_x[i] = i;
			shuffle_y[i] = i;
		}

		//gTimer.setTimePoint("OnlineS.start");
		PRNG prng(ZeroBlock);
		std::shuffle(shuffle_x.begin(), shuffle_x.end(), prng);
		for (u64 i = 0; i < Ma_size; i++) {
			shuffle_y[shuffle_x[i]] = i;
		}
		auto& chl = *chls[0];
		SHA1 sha1;
		u8 hashBuff[SHA1::HashSize];
		u64 maskSize = get_mask_size(mSenderSize, mRecverSize); //by byte
		u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte

		//compute PRC

		gTimer.setTimePoint("S Online.PRC start");
		std::array<AES, 4> AESHASH;
		TODO("make real keys seeds");
		for (u64 i = 0; i < AESHASH.size(); ++i)
			AESHASH[i].setKey(_mm_set1_epi64x(i));

		std::array<std::vector<block>, 4> aesHashBuffs;

		aesHashBuffs[0].resize(inputs.size());
		aesHashBuffs[1].resize(inputs.size());
		aesHashBuffs[2].resize(inputs.size());
		aesHashBuffs[3].resize(inputs.size());

		//		for (u64 i = 0; i <16; i++)
			//		std::cout << "sender 109   " << i <<"   " << inputs[i] << endl;
		for (u64 i = 0; i < inputs.size(); i += stepSize)
		{

			auto currentStepSize = std::min(stepSize, inputs.size() - i);
			AESHASH[0].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[0].data() + i);

			AESHASH[1].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[1].data() + i);
			AESHASH[2].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[2].data() + i);
			AESHASH[3].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[3].data() + i);

		}

		gTimer.setTimePoint("S Online.PRC done");

		//insert element into bin
		mBins.insertItems(aesHashBuffs);
		//mBins.print();

		//OT value from office phasing	
		auto& blk448Choice = mSSOtChoice.getArrayView<blockBop>()[0];
		blockBop codeWord, elecodeword;

		//======================Bucket BINs (not stash)==========================

		auto binStart = 0;
		auto binEnd = mBins.mBinCount;
		u64 binmax = mBins.mMaxBinSize;
		ZpMersenneLongElement sec_s = prng.get_u64();
		cout << "Sender sec s : " << sec_s << endl;
		//trans a+x

		vector<block> delt(Ma_size);
		vector<block> sharei(Ma_size);

		vector<block> xPa(Ma_size);

		vector<blockBop> cxpi(Ma_size);
		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the  size of the current step and the end index
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// receive their  OT correction mask values.
			ByteStream MaBuff;
			chl.recv(MaBuff);

			// check the size
			if (MaBuff.size() != sizeof(block) * currentStepSize)
				throw std::runtime_error("rt error at " LOCATION);

			auto x_a = MaBuff.getArrayView<block>();

			// loop all the bins in this step.
			for (u64 bIdx = stepIdx, j = 0; bIdx < stepEnd; ++bIdx, ++j)
			{
				//delta=pi(a)^b
				delt[bIdx] = ai[shuffle_x[bIdx]] ^ bi[bIdx];
				xPa[bIdx] = x_a[j];
			}
		}



		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the  size of the current step and the end index
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// receive their  OT correction mask values.
			ByteStream MaBuff;
			chl.recv(MaBuff);

			// check the size
			if (MaBuff.size() != sizeof(blockBop) * currentStepSize)
				throw std::runtime_error("rt error at " LOCATION);

			auto x_a = MaBuff.getArrayView<blockBop>();

			// loop all the bins in this step.
			for (u64 bIdx = stepIdx, j = 0; bIdx < stepEnd; ++bIdx, ++j)
			{
				//delta=pi(a)^b
				cxpi[bIdx] = x_a[j];
			}



			//sharei[shuffle_y[bIdx]] = x_a[j] ^ delt[shuffle_y[bIdx]];

		}




		for (u64 i = 0; i < Ma_size; i++) {
			sharei[i] = xPa[shuffle_y[i]] ^ delt[i];
		}



		cout << "send 224 "<< endl; 
		//u64 cntMask = mBins.mN;
		std::unique_ptr<ByteStream> u0Buff(new ByteStream());
		std::unique_ptr<ByteStream> u1Buff(new ByteStream());
		std::unique_ptr<ByteStream> u2Buff(new ByteStream());
		u0Buff->resize(3 * mSenderSize * maskSize );
		u1Buff->resize(3 * mSenderSize * sizeof(ZpMersenneLongElement) );
		u2Buff->resize(3 * mSenderSize * sizeof(block[1]));
		ZpMersenneLongElement pBuff[1];
		vector<ZpMersenneLongElement> coefficient(threshold);
		coefficient[0] = sec_s;
		for (u64 i = 1; i < coefficient.size(); i++) {
			coefficient[i] = prng.get_u32();
		}


		//create permute array to add my mask in the permuted positions
		std::vector<u64> permute;
		u64 idxPermuteDone;
	
			//permute.resize(mBins.mMaxBinSize * mBins.mBinCount);
		permute.resize(3 * mSenderSize);
			for (u64 i = 0; i < 3 * mSenderSize; i++)
			{
				permute[i] = i;
			}
			//permute position
			std::shuffle(permute.begin(), permute.end(), prng);
			idxPermuteDone = 0; //count the number of permutation that is done.
		

		//pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
		TODO("run in parallel");

		bool deb = false;
		for (u64 bIdx = binStart; bIdx < binEnd; bIdx++)
		{


			// current bin
			if (deb)
			cout << "send 260 "<<shuffle_x[bIdx] << endl; 
			auto bin = mBins.mBins[shuffle_x[bIdx]];
			if (deb)
			cout << "send 261 " << endl;
			// for each item, hash it, encode then hash it again. 
			//cout << "send 249 finfisdh" << endl;
			for (u64 i = 0; i < mBins.mBinSizes[shuffle_x[bIdx]]; ++i)
			{
				
				//if(i< mBins.mBinSizes[shuffle_x[bIdx]]){
				std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
				block shares = xPa[shuffle_x[bIdx]] ^ bi[bIdx] ^ ai[shuffle_x[bIdx]];
				code.encode(shares.m128i_u8, (u8*)lcodebuffs.data());
				memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));
				//code.encode(inputs[bin[i].mIdx].m128i_u8, (u8*)lcodebuffs.data());
				std::array<block, 10>  lcodebuffsx = { ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
				code.encode(inputs[bin[i].mIdx].m128i_u8, (u8*)lcodebuffsx.data());
				if (deb) cout << "send 273" << endl;
				memcpy(elecodeword.elem, lcodebuffsx.data(), 4 * sizeof(block));

				auto sum = mPsiRecvSSOtMessages[bIdx] ^ ((cxpi[bIdx] ^ codeWord ^ elecodeword) & blk448Choice);
				if (deb) cout << "send 277" << endl;
				sha1.Reset();
				//sha1.Update((u8*)&bin[i].mHashIdx, sizeof(u64)); //add hash index
				sha1.Update((u8*)&sum, codeWordSize);
				sha1.Final(hashBuff);
				memcpy(u0Buff->data() + permute[idxPermuteDone] * maskSize, hashBuff, maskSize);
				//cout << "sum of ele" << bin[i].mIdx<<"in bin"<<bIdx << " " << sum << endl;
				ZpMersenneLongElement X((sum.elem[0].m128i_u64[0]));
				Poly::evalMersenne(pBuff[0], coefficient, X);
				//cout << "Mersen ne cal poly "<<X << endl;
				int MeLongsize = sizeof(ZpMersenneLongElement[1]);
				memcpy(u1Buff->data() + permute[idxPermuteDone] * MeLongsize, pBuff, MeLongsize);
				if (deb) cout << "send 296" << endl;
				sha1.Reset();
				sha1.Update((u8*)&sum, codeWordSize);
				sha1.Update((u8*)&sec_s, sizeof(u64)); 
				sha1.Final(hashBuff);
				block bb = ZeroBlock;
				for (int nn = 0; nn < sizeof(hashBuff) / sizeof(hashBuff[0]); nn++) {
				bb = bb << hashBuff[nn];
				}
				block sendblock[1];
				sendblock[0] = inputs[bin[i].mIdx] ^ bb;
				u64 blocksz = sizeof(block[1]);
				//cout << "X " << pBuff[0]<< " Y "<<v3[0] << endl;
				memcpy(u2Buff->data() + permute[idxPermuteDone] * blocksz, sendblock, blocksz);
			
				//else {
				//	//if (deb) cout << "send 311" << endl;
				//	auto sum = mPsiRecvSSOtMessages[bIdx];
				//	//if (deb) cout << "send 313" << endl;
				//	sha1.Reset();
				//	sha1.Update((u8*)&sum, codeWordSize);
				//	sha1.Final(hashBuff);
				//	block bBuff[1];
				//	bBuff[0]=_mm_loadu_si128(((__m128i*)hashBuff));
				//	//if (deb) cout << "send 319" << endl;
				//	int blocksz = sizeof(block);
				//	memcpy(u0Buff->data() + permute[idxPermuteDone] * blocksz, bBuff, blocksz);
				//	if (deb) cout << "send 319" << endl;
				//	pBuff[0] = calPoly(sum.elem[0], coefficient);
				//	memcpy(u1Buff->data() + permute[idxPermuteDone] * sizeof(u64), pBuff, sizeof(u64));
				//	if (deb) cout << "send 319" << endl;
				//	memcpy(u2Buff->data() + permute[idxPermuteDone] * maskSize, hashBuff, maskSize);
				//	//cout << "send 320" << endl;
				//	
				//}
			idxPermuteDone++;
			//cout << "send 292" << endl;
		}
		
		}
		//cout << "send 306 finish" << endl;
		gTimer.setTimePoint("S Online.computeBucketMask done");

		chl.asyncSend(std::move(u0Buff));
		chl.asyncSend(std::move(u1Buff));
		chl.asyncSend(std::move(u2Buff));
		gTimer.setTimePoint("S Online.sendBucketMask done");

		//cout << "send 304 finfisdh" << endl;
		//======================STASH BIN==========================


		//receive theirStashCorrOTMasksBuff
		ByteStream theirStashCorrOTMasksBuff;
		chl.recv(theirStashCorrOTMasksBuff);
		auto theirStashCorrOT = theirStashCorrOTMasksBuff.getArrayView<blockBop>();
		if (theirStashCorrOT.size() != mNumStash)
			throw std::runtime_error("rt error at " LOCATION);

		// now compute mask for each of the stash elements
		for (u64 stashIdx = 0, otIdx = mBins.mBinCount; stashIdx < mNumStash; ++stashIdx, ++otIdx)
		{
			std::unique_ptr<ByteStream> myStashMasksBuff(new ByteStream());
			myStashMasksBuff->resize(mSenderSize * maskSize);

			//cntMask = mSenderSize;
			std::vector<u64> stashPermute(mSenderSize);
			int idxStashDone = 0;
			for (u64 i = 0; i < mSenderSize; i++)
				stashPermute[i] = i;

			//permute position
			std::shuffle(stashPermute.begin(), stashPermute.end(), prng);

			//compute mask
			for (u64 i = 0; i < inputs.size(); ++i)
			{
				std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock };
				code.encode(inputs[i].m128i_u8, (u8*)lcodebuffs.data());
				memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));
				//codeWord.elem[0] = lcodebuffs[0];
				//codeWord.elem[1] = lcodebuffs[1];
				//codeWord.elem[2] = lcodebuffs[2];
				//codeWord.elem[3] = lcodebuffs[3];

				codeWord = mPsiRecvSSOtMessages[otIdx] ^ ((theirStashCorrOT[stashIdx] ^ codeWord) & blk448Choice);


				sha1.Reset();
				sha1.Update((u8*)&codeWord, codeWordSize);
				sha1.Final(hashBuff);

				// copy mask into the buffer in permuted pos
				memcpy(myStashMasksBuff->data() + stashPermute[idxStashDone++] * maskSize, hashBuff, maskSize);
			}

			//check the size of mask
			if (mSenderSize != myStashMasksBuff->size() / maskSize)
			{
				Log::out << "myMaskByteIter != myMaskBuff->data() + myMaskBuff->size()" << Log::endl;
				throw std::runtime_error("rt error at " LOCATION);
			}
			chl.asyncSend(std::move(myStashMasksBuff));
		}
	}
	void BopPsiSender::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls, vector<block> ai, vector<block> bi)
	{
	
		code.load(bch511_binary, sizeof(bch511_binary));
		if (inputs.size() != mSenderSize)
			throw std::runtime_error("rt error at " LOCATION);
		vector<u64> shuffle_x(Ma_size);
		vector<u64> shuffle_y(Ma_size);
		for (u64 i = 0; i < Ma_size;i++) {
			shuffle_x[i] = i;
			shuffle_y[i] = i;
		}

		//gTimer.setTimePoint("OnlineS.start");
		PRNG prng(ZeroBlock);
		std::shuffle(shuffle_x.begin(), shuffle_x.end(), prng);
		for (u64 i = 0; i < Ma_size; i++) {
			shuffle_y[shuffle_x[i]] = i;
		}
		auto& chl = *chls[0];
		SHA1 sha1;
		u8 hashBuff[SHA1::HashSize];
		u64 maskSize = get_mask_size(mSenderSize, mRecverSize); //by byte
		u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte

		//compute PRC

		gTimer.setTimePoint("S Online.PRC start");
		std::array<AES, 4> AESHASH;
		TODO("make real keys seeds");
		for (u64 i = 0; i < AESHASH.size(); ++i)
			AESHASH[i].setKey(_mm_set1_epi64x(i));

		std::array<std::vector<block>, 4> aesHashBuffs;

		aesHashBuffs[0].resize(inputs.size());
		aesHashBuffs[1].resize(inputs.size());
		aesHashBuffs[2].resize(inputs.size());
		aesHashBuffs[3].resize(inputs.size());

//		for (u64 i = 0; i <16; i++)
	//		std::cout << "sender 109   " << i <<"   " << inputs[i] << endl;
		for (u64 i = 0; i < inputs.size(); i += stepSize)
		{
			
			auto currentStepSize = std::min(stepSize, inputs.size() - i);
			AESHASH[0].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[0].data() + i);

			AESHASH[1].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[1].data() + i);
			AESHASH[2].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[2].data() + i);
			AESHASH[3].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[3].data() + i);

		}

		gTimer.setTimePoint("S Online.PRC done");

		//insert element into bin
		mBins.insertItems(aesHashBuffs);
		//mBins.print();

		//OT value from office phasing	
		auto& blk448Choice = mSSOtChoice.getArrayView<blockBop>()[0];
		blockBop codeWord,elecodeword;

		//======================Bucket BINs (not stash)==========================

		auto binStart = 0;
		auto binEnd = mBins.mBinCount;
		//trans a+x
		vector<block> delt(Ma_size);
		vector<block> sharei(Ma_size);

		vector<block> xPa(Ma_size);

		vector<blockBop> cxpi(Ma_size);

		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the  size of the current step and the end index
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// receive their  OT correction mask values.
			ByteStream MaBuff;
			chl.recv(MaBuff);

			// check the size
			if (MaBuff.size() != sizeof(block) * currentStepSize)
				throw std::runtime_error("rt error at " LOCATION);

			auto x_a = MaBuff.getArrayView<block>();

			// loop all the bins in this step.
			for (u64 bIdx = stepIdx, j = 0; bIdx < stepEnd; ++bIdx, ++j)
			{
				//delta=pi(a)^b
				delt[bIdx] = ai[shuffle_x[bIdx]] ^ bi[bIdx];
				xPa[bIdx] = x_a[j];
			}
		}
		


		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
			{
				// compute the  size of the current step and the end index
				auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
				auto stepEnd = stepIdx + currentStepSize;

				// receive their  OT correction mask values.
				ByteStream MaBuff;
				chl.recv(MaBuff);

				// check the size
				if (MaBuff.size() != sizeof(blockBop) * currentStepSize)
					throw std::runtime_error("rt error at " LOCATION);

				auto x_a = MaBuff.getArrayView<blockBop>();

				// loop all the bins in this step.
				for (u64 bIdx = stepIdx, j = 0; bIdx < stepEnd; ++bIdx, ++j)
				{
					//delta=pi(a)^b
					cxpi[bIdx] = x_a[j];
				}
				//sharei[shuffle_y[bIdx]] = x_a[j] ^ delt[shuffle_y[bIdx]];

		}




		for (u64 i = 0; i < Ma_size; i++) {
			sharei[i] = xPa[shuffle_y[i]] ^ delt[i];
		}



		//u64 cntMask = mBins.mN;
		std::unique_ptr<ByteStream> myMaskBuff1(new ByteStream());
		myMaskBuff1->resize(mSenderSize* maskSize*3);

		//create permute array to add my mask in the permuted positions
		std::array<std::vector<u64>, 3>permute;
		int idxPermuteDone[3];
		for (u64 j = 0; j < 3; j++)
		{
			permute[j].resize(3*mSenderSize);
			for (u64 i = 0; i < 3*mSenderSize; i++)
			{
				permute[j][i] = i;
			}
			//permute position
			std::shuffle(permute[j].begin(), permute[j].end(), prng);
			idxPermuteDone[j] = 0; //count the number of permutation that is done.
		}

		//pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
		TODO("run in parallel");


		for (u64 bIdx = binStart; bIdx < binEnd; bIdx ++)
		{

			
				// current bin
			//cout << "send 260 "<<shuffle_x[bIdx] << endl; 
				auto bin = mBins.mBins[shuffle_x[bIdx]];
				//cout << "send 261 " << endl;
				// for each item, hash it, encode then hash it again. 
				//cout << "send 249 finfisdh" << endl;
				for (u64 i = 0; i < mBins.mBinSizes[shuffle_x[bIdx]]; ++i)
				{
					//cout << "send 266" << endl;
					std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					block shares = xPa[shuffle_x[bIdx]]^bi[bIdx]^ai[shuffle_x[bIdx]];
					code.encode(shares.m128i_u8, (u8*)lcodebuffs.data());
					memcpy(codeWord.elem,lcodebuffs.data(),4*sizeof(block));
					//code.encode(inputs[bin[i].mIdx].m128i_u8, (u8*)lcodebuffs.data());
					std::array<block, 10>  lcodebuffsx = { ZeroBlock,ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock,ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
					code.encode(inputs[bin[i].mIdx].m128i_u8, (u8*)lcodebuffsx.data());
					//cout << "send 273" << endl;
					memcpy(elecodeword.elem, lcodebuffsx.data(), 4 * sizeof(block));

					auto sum = mPsiRecvSSOtMessages[bIdx] ^ ((cxpi[bIdx] ^ codeWord^elecodeword) & blk448Choice);//必须是同一个元素
					//cout << "send 277" << endl;
					sha1.Reset();
					//sha1.Update((u8*)&bin[i].mHashIdx, sizeof(u64)); //add hash index
					sha1.Update((u8*)&sum, codeWordSize);
					sha1.Final(hashBuff);

					//put the mask into corresponding buff at the permuted position
					//if (bin[i].mHashIdx == 0) 	//buff 1 for hash index 0	
					//cout << "send 284" << endl;
					memcpy(myMaskBuff1->data() + permute[0][idxPermuteDone[0]++] * maskSize, hashBuff, maskSize);
					//cout << "send 286" << endl;
					//else if (bin[i].mHashIdx == 1)//buff 2 for hash index 1		
					//	memcpy(myMaskBuff2->data() + permute[1][idxPermuteDone[1]++] * maskSize, hashBuff, maskSize);
					//else if (bin[i].mHashIdx == 2)//buff 3 for hash index 2
					//	memcpy(myMaskBuff3->data() + permute[2][idxPermuteDone[2]++] * maskSize, hashBuff, maskSize);
				}
				//cout << "send 292" << endl;
			
		}
		//cout << "send 306 finish" << endl;
		gTimer.setTimePoint("S Online.computeBucketMask done");
		//double-check
		//if (cntMask != myMaskBuff1->size() / maskSize
		//	|| cntMask != myMaskBuff2->size() / maskSize
		//	|| cntMask != myMaskBuff3->size() / maskSize)
		//{
		//	Log::out << "myMaskByteIter != myMaskBuff->data() + myMaskBuff->size()" << Log::endl;
		//	throw std::runtime_error("rt error at " LOCATION);
		//}
		chl.asyncSend(std::move(myMaskBuff1));
		//chl.asyncSend(std::move(myMaskBuff2));
		//chl.asyncSend(std::move(myMaskBuff3));
		gTimer.setTimePoint("S Online.sendBucketMask done");

		//cout << "send 304 finfisdh" << endl;
		//======================STASH BIN==========================


		//receive theirStashCorrOTMasksBuff
		ByteStream theirStashCorrOTMasksBuff;
		chl.recv(theirStashCorrOTMasksBuff);
		auto theirStashCorrOT = theirStashCorrOTMasksBuff.getArrayView<blockBop>();
		if (theirStashCorrOT.size() != mNumStash)
			throw std::runtime_error("rt error at " LOCATION);

		// now compute mask for each of the stash elements
		for (u64 stashIdx = 0, otIdx = mBins.mBinCount; stashIdx < mNumStash; ++stashIdx, ++otIdx)
		{
			std::unique_ptr<ByteStream> myStashMasksBuff(new ByteStream());
			myStashMasksBuff->resize(mSenderSize* maskSize);

			//cntMask = mSenderSize;
			std::vector<u64> stashPermute(mSenderSize);
			int idxStashDone = 0;
			for (u64 i = 0; i < mSenderSize; i++)
				stashPermute[i] = i;

			//permute position
			std::shuffle(stashPermute.begin(), stashPermute.end(), prng);

			//compute mask
			for (u64 i = 0; i < inputs.size(); ++i)
			{
				std::array<block, 10>  lcodebuffs = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock };
				code.encode(inputs[i].m128i_u8, (u8*)lcodebuffs.data());
				memcpy(codeWord.elem, lcodebuffs.data(), 4 * sizeof(block));
				//codeWord.elem[0] = lcodebuffs[0];
				//codeWord.elem[1] = lcodebuffs[1];
				//codeWord.elem[2] = lcodebuffs[2];
				//codeWord.elem[3] = lcodebuffs[3];

				codeWord = mPsiRecvSSOtMessages[otIdx] ^ ((theirStashCorrOT[stashIdx] ^ codeWord) & blk448Choice);


				sha1.Reset();
				sha1.Update((u8*)&codeWord, codeWordSize);
				sha1.Final(hashBuff);

				// copy mask into the buffer in permuted pos
				memcpy(myStashMasksBuff->data() + stashPermute[idxStashDone++] * maskSize, hashBuff, maskSize);
			}

			//check the size of mask
			if (mSenderSize != myStashMasksBuff->size() / maskSize)
			{
				Log::out << "myMaskByteIter != myMaskBuff->data() + myMaskBuff->size()" << Log::endl;
				throw std::runtime_error("rt error at " LOCATION);
			}
			chl.asyncSend(std::move(myStashMasksBuff));
		}
	}
	u64 BopPsiSender::calPoly(block input, std::vector<u32>& coefficient) {
		u64 num = 0;
		for (u64 i = 1; i < coefficient.size(); i++) {
			num += ((coefficient[i]*poww(input, i)));
		}

		return (num);
	}
	u64 BopPsiSender::poww(block a, u64 b) { // return a ^ b
		u64 ans = 1, base =a.m128i_u64[0];
		while (b != 0) {
			if ((b & 1) != 0) ans *= (base );
			base *= (base );
			b >>= 1;
		}
		cout << "poly " << ans << endl;
		return (ans);
	}
}


