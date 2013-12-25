#if defined bcrypt_included
	#endinput
#endif
#define bcrypt_included

native bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);
native bcrypt_get_hash(dest[]);
native bcrypt_check(key[], hash[], callback_name[], callback_format[], {Float, _}:...);
native bool:bcrypt_is_equal();
