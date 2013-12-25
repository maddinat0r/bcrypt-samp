#include "main.h"
#include "bcrypt.h"


logprintf_t logprintf;
extern void *pAMXFunctions;


// native bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);
cell AMX_NATIVE_CALL bcrypt_hash(AMX* amx, cell* params)
{
	if (params[0] < 3 * sizeof(cell))
		return 0;

	char *key = NULL;
	unsigned char cost = static_cast<unsigned char>(params[2]);
	char 
		*cb_name = NULL,
		*cb_format = NULL;

	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[3], cb_name);
	amx_StrParam(amx, params[4], cb_format);

	if (key == NULL || cb_name == NULL)
		return 0; //makes no sense to hash something and then not use the hash itself

	if (cost < 4 || cost > 31)
		return 0;

	
	CBcrypt *Crypt = CBcrypt::Create(key, cost, CBcrypt::Task::HASH);
	Crypt->EnableCallback(cb_name, cb_format, amx, params, 4);

	CPlugin::Get()->QueueCrypt(Crypt);

	return 1;
}


// native bcrypt_get_hash(dest[]);
cell AMX_NATIVE_CALL bcrypt_get_hash(AMX* amx, cell* params)
{
	if (params[0] != sizeof(cell))
		return 0;

	cell *amx_dest_addr = NULL;
	string &hash = CPlugin::Get()->GetActiveHash();

	amx_GetAddr(amx, params[1], &amx_dest_addr);
	amx_SetString(amx_dest_addr, hash.c_str(), 0, 0, 61);
	return 1;
}


// native bcrypt_check(key[], hash[], callback_name[], callback_format[], {Float, _}:...);
cell AMX_NATIVE_CALL bcrypt_check(AMX* amx, cell* params)
{
	if (params[0] < 3 * sizeof(cell))
		return 0;

	char
		*key = NULL,
		*hash = NULL,
		*cb_name = NULL,
		*cb_format = NULL;

	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[2], hash);
	amx_StrParam(amx, params[3], cb_name);
	amx_StrParam(amx, params[4], cb_format);

	if (key == NULL || hash == NULL || cb_name == NULL)
		return 0;


	CBcrypt *Crypt = CBcrypt::Create(key, 0, CBcrypt::Task::CHECK, hash);
	Crypt->EnableCallback(cb_name, cb_format, amx, params, 4);

	CPlugin::Get()->QueueCrypt(Crypt);

	return 1;
}


// native bool:bcrypt_is_equal();
cell AMX_NATIVE_CALL bcrypt_is_equal(AMX* amx, cell* params)
{
	return static_cast<cell>(CPlugin::Get()->IsActiveEqual());
}



PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_PROCESS_TICK | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t) ppData[PLUGIN_DATA_LOGPRINTF];

	CPlugin::Initialize();

	logprintf(" >> plugin.bcrypt: v2.0 successfully loaded.");
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	CPlugin::Get()->Destroy();
	logprintf("plugin.bcrypt: Plugin unloaded.");
}


AMX_NATIVE_INFO PluginNatives[] =
{
	AMX_ADD_NATIVE(bcrypt_hash)
	AMX_ADD_NATIVE(bcrypt_get_hash)
	AMX_ADD_NATIVE(bcrypt_check)
	AMX_ADD_NATIVE(bcrypt_is_equal)
	{ 0, 0 }
};


PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	CPlugin::Get()->ProcessCallbackQueue();
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	CPlugin::Get()->AddAmxInstance(amx);
	return amx_Register(amx, PluginNatives, -1);
}


PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	CPlugin::Get()->RemoveAmxInstance(amx);
	return AMX_ERR_NONE;
}
