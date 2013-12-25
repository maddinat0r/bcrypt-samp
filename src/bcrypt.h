#pragma once
#ifndef INC_BCRYPT_H
#define INC_BCRYPT_H


#include <set>
#include <queue>
#include <string>
#include <stack>
#include <boost/thread/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/atomic/atomic.hpp>

using std::set;
using std::queue;
using std::string;
using std::stack;
using boost::thread;
namespace this_thread = boost::this_thread;
using boost::lockfree::spsc_queue;
using boost::atomic;

#include "main.h"


class CBcrypt
{
public:
	enum class Task
	{
		NONE,
		HASH,
		CHECK
	};

	static CBcrypt *Create(string key, unsigned char cost, Task task, string hash = string());
	void Destroy();

	inline void EnableCallback(string name, const char *format, AMX *amx, cell *params, const unsigned int param_offset)
	{
		Callback.Enable(name, format, amx, params, param_offset);
	}

private:
	struct
	{
		string Key;
		unsigned char Cost;
		string Hash;
		bool Equal;

		Task Task;
	} Crypt;

	class m_CallbackType
	{
	private:
		enum class Datatype
		{
			NONE,
			CELL,
			STRING
		};
		
		string Name;

		struct ParamType
		{
			cell Cell;
			string String;
			Datatype Type;

			ParamType(Datatype type, cell cell_val) : 
				Type(type),
				Cell(cell_val)
			{}
			ParamType(Datatype type, string str_val) :
				Type(type),
				String(str_val)
			{}
		};
		stack<ParamType> Params;

		friend class CPlugin;
	public:
		void Enable(string name, const char *format, AMX *amx, cell *params, const unsigned int param_offset);
	} Callback;

	friend class CPlugin;
};


class CPlugin
{
public:
	static inline CPlugin *Get()
	{
		return m_Instance;
	}

	static void Initialize();
	void Destroy();


	inline void AddAmxInstance(AMX *instance)
	{
		m_AmxList.insert(instance);
	}
	inline void RemoveAmxInstance(AMX *instance)
	{
		m_AmxList.erase(instance);
	}


	inline void QueueCrypt(CBcrypt *crypt)
	{
		m_CryptQueue.push(crypt);
	}
	void ProcessCryptQueue();
	void ProcessCallbackQueue();


	inline string &GetActiveHash()
	{
		return m_ActiveResult.Hash;
	}
	inline bool IsActiveEqual() const
	{
		return m_ActiveResult.Equal;
	}

private:
	static CPlugin *m_Instance;


	struct
	{
		string Hash;
		bool Equal;
	} m_ActiveResult;


	set<AMX *> m_AmxList;
	spsc_queue<
			CBcrypt*,
			boost::lockfree::fixed_sized<true>,
			boost::lockfree::capacity<4096>
		> 
		m_CryptQueue,
		m_CallbackQueue;

	thread m_ProcessCryptThread;
	atomic<bool> m_ProcessCryptThreadRunning;


	CPlugin() :
		m_ProcessCryptThreadRunning(true),
		m_ProcessCryptThread(boost::bind(&CPlugin::ProcessCryptQueue, this))
	{}
};


#endif // INC_BCRYPT_H
