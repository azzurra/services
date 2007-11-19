/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* crypt_userhost.h - Mascheramento hostname utenti
* 
*/


#ifndef SRV_CRYPTUSERHOST_H
#define SRV_CRYPTUSERHOST_H


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void crypt_init();
extern void crypt_done();

extern BOOL crypt_change_key(CSTR newKey);
extern BOOL crypt_load_key();
extern BOOL crypt_save_key();
extern void handle_cryptkey(CSTR source, User *callerUser, ServiceCommandData *data);

extern STR crypt_userhost(CSTR real, HOST_TYPE htype, short int dotsCount);

extern long crypt_hash_FNV(CSTR string, size_t size);
extern long crypt_hash_SHA1(CSTR string, size_t size, STR buffer, size_t bufferSize);

extern STR user_hidehost(CSTR real);

extern void crypt_ds_dump(CSTR sourceNick, const User *callerUser, STR request);


#endif /* SRV_CRYPTUSERHOST_H */
