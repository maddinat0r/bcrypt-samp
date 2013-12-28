# Bcrypt for SA-MP

An implementation of the bcrypt hashing algorithm for PAWN written in C++.

## Benefits of bcrypt

* All passwords are automatically salted
* Bcrypt is slow, which makes offline bruteforce attacks very hard (depends on the work factor)
* The work factor can be increased as the computers become more powerful 

## Functions
* `bcrypt_hash(key[], cost, callback_name[], callback_format[], {Float, _}:...);`
* `bcrypt_get_hash(dest[]);`
* `bcrypt_check(key[], hash[], callback_name[], callback_format[], {Float, _}:...);`
* `bool:bcrypt_is_equal();`

## Usage
* Copy the include and plugin file to their appropriate directories
* Use `bcrypt_hash` if you want to hash user input (e.g. passwords, or when updating the work factor). Once the hash is calculated, the specified callback is called and the hash can be accessed with the function `bcrypt_get_hash`.

* Use `bcrypt_check` if you want to verify whether or not user input matches a given hash (e.g. on login). Once the verification is done, the specified callback will be called. The function `bcrypt_is_equal` returns true or false whether or not the password matched the hash.

## Example
```
#include <a_samp>
#include <bcrypt>


// Hashing a password
bcrypt_hash("MyPassword", 12, "OnPlayerRegister", "d", playerid);

forward public OnPlayerRegister(playerid);
public OnPlayerRegister(playerid)
{
	new hash[61]; //the hash length is always 60
	bcrypt_get_hash(hash);
	
	printf("Password hashed for playerid %d: %s (registration)", playerid, hash);
	// Could print for instance:
	//    "Password hashed for playerid 32: $2a$12$izP1Fy.pZxOjDOCVma0UneQoQ3sUX3HxfmyibOLPcafDSL8Pj.Ety (registration)"
	// The hash will be different every time even for the same input due to the random salt
    return 1;
}

// Checking a password
bcrypt_check(inputtext, hash, "OnPlayerLogin", "d", playerid);

forward public OnPlayerLogin(playerid);
public OnPlayerLogin(playerid)
{
	printf("Password checked for playerid %d: %s (login)", playerid, (bcrypt_is_equal()) ? ("Correct password") : ("Incorrect password"));

    return 1;
}
```