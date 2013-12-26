#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/chrono.hpp>

#include "bcrypt.h"
#include "crypt_blowfish/ow-crypt.h"


CPlugin *CPlugin::m_Instance = NULL;


CBcrypt *CBcrypt::Create(string key, unsigned char cost, TaskType task, string hash /*= string()*/)
{
	CBcrypt *crypt = new CBcrypt;
	crypt->Crypt.Key = key;
	crypt->Crypt.Task = task;
	if (task == TaskType::CHECK)
		crypt->Crypt.Hash = hash;
	else
		crypt->Crypt.Cost = cost;

	return crypt;
}

void CBcrypt::Destroy()
{
	delete this;
}


void CBcrypt::EnableCallback(string name, const char *format, AMX *amx, cell *params, const unsigned int param_offset)
{
	Callback.Name = name;
	
	cell *addr_ptr = NULL;
	unsigned int param_idx = 1;

	do
	{
		char *str_buf = NULL;
		switch (*format)
		{
			case 'd':
			case 'i':
			case 'f':
				amx_GetAddr(amx, params[param_offset + param_idx++], &addr_ptr);
				Callback.Params.push(*addr_ptr);
				break;
			case 's':
				amx_StrParam(amx, params[param_offset + param_idx++], str_buf);
				Callback.Params.push(str_buf == NULL ? string() : string(str_buf));
				break;
		}
	} while (*(++format));
}


void CPlugin::ProcessCryptQueue()
{
	m_ProcessCryptThreadRunning = true;
	while (m_ProcessCryptThreadRunning)
	{
		CBcrypt *crypt_instance = NULL;
		while (m_CryptQueue.pop(crypt_instance))
		{
			switch (crypt_instance->Crypt.Task)
			{
				case CBcrypt::TaskType::HASH:
				{
					string 
						chars(
							"abcdefghijklmnopqrstuvwxyz"
							"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
							"1234567890"),
						raw_salt;
					//generate random salt
					boost::random::random_device rand_num_gen;
					boost::random::uniform_int_distribution<> idx_dist(0, chars.size() - 1);
					for (size_t i = 0; i < 21; ++i)
						raw_salt.push_back(chars.at(idx_dist(rand_num_gen)));

					char salt[61];
					crypt_gensalt_rn("$2a$", crypt_instance->Crypt.Cost, raw_salt.c_str(), 21, salt, 61);
					crypt_instance->Crypt.Hash.assign(crypt(crypt_instance->Crypt.Key.c_str(), salt));
				} break;

				case CBcrypt::TaskType::CHECK:
				{
					string hash2(crypt(crypt_instance->Crypt.Key.c_str(), crypt_instance->Crypt.Hash.c_str()));
					crypt_instance->Crypt.Equal = crypt_instance->Crypt.Hash == hash2;
				} break;
			}

			m_CallbackQueue.push(crypt_instance);
		}
		this_thread::sleep_for(boost::chrono::milliseconds(5));
	}
}

void CPlugin::ProcessCallbackQueue()
{
	CBcrypt *crypt_instance = NULL;
	while (m_CallbackQueue.pop(crypt_instance))
	{
		for (set<AMX *>::iterator i = m_AmxList.begin(), end = m_AmxList.end(); i != end; ++i)
		{
			AMX *amx = (*i);
			cell amx_idx = 0;
			if (amx_FindPublic(amx, crypt_instance->Callback.Name.c_str(), &amx_idx) == AMX_ERR_NONE)
			{
				cell amx_addr = -1;

				while (!crypt_instance->Callback.Params.empty())
				{
					variant<cell, string> &param = crypt_instance->Callback.Params.top();

					if (param.type() == typeid(cell))
						amx_Push(amx, boost::get<cell>(param));
					else
					{
						cell tmp_addr;
						amx_PushString(amx, &tmp_addr, NULL, boost::get<string>(param).c_str(), 0, 0);
						if (amx_addr < NULL)
							amx_addr = tmp_addr;
					}

					crypt_instance->Callback.Params.pop();
				}

				m_ActiveResult.Hash = crypt_instance->Crypt.Hash;
				m_ActiveResult.Equal = crypt_instance->Crypt.Equal;


				cell amx_ret;
				amx_Exec(amx, &amx_ret, amx_idx);

				if (amx_addr >= NULL)
					amx_Release(amx, amx_addr);


				m_ActiveResult.Hash.clear();
				m_ActiveResult.Equal = false;

				break;
			}
		}
		crypt_instance->Destroy();
	}
}


void CPlugin::Initialize()
{
	m_Instance = new CPlugin;
}

void CPlugin::Destroy()
{
	m_ProcessCryptThreadRunning = false;
	m_ProcessCryptThread.join();

	CBcrypt *crypt_instance = NULL;
	while (m_CryptQueue.pop(crypt_instance))
		crypt_instance->Destroy();
	while (m_CallbackQueue.pop(crypt_instance))
		crypt_instance->Destroy();
}