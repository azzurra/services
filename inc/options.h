/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* options.h - Various configuration options
* 
*/

#ifndef SRV_OPTIONS_H
#define SRV_OPTIONS_H


/*********************************************************
 * Se definito eventuali spazi presenti nelle password   *
 * di nick e canali verranno sostituiti con '_' al       *
 * caricamento dei database.                             *
 *********************************************************/

//#define FIX_PASSWORD_SPACE
#undef FIX_PASSWORD_SPACE


/*********************************************************
 * Se definito imposta il campo real_founder di tutti i  *
 * canali registrati, se vuoto, al caricamento dei       *
 * database.							                 *
 *********************************************************/

//#define FIX_RF
#undef FIX_RF


/*********************************************************
 * Rimette a posto le E-Mail di tutti i nick registrati  *
 * al caricamento dei database. Da utilizzare una sola   *
 * volta.                                                *
 *********************************************************/

//#define FIX_NS_REGMAIL_DB
#undef FIX_NS_REGMAIL_DB


/*********************************************************
 * Azzera e ricalcola il numero di canali a cui ogni     *
 * nick registrato ha accesso al caricamento dei         *
 * database.                                             *
 *********************************************************/

//#define FIX_NICKNAME_ACCESS_COUNT
#undef FIX_NICKNAME_ACCESS_COUNT


/*********************************************************
 * Rimuove le flag obsolete da tutti i nick e i canali   *
 * al caricamento dei database.                          *
 *********************************************************/

//#define FIX_FLAGS
#undef FIX_FLAGS


/*********************************************************
 * Imposta il bantype di tutti i canali registrati al    *
 * default al caricamento dei database.                  *
 *********************************************************/

//#define FIX_BANTYPE
#undef FIX_BANTYPE


/*********************************************************
 * Reimposta il tipo di accesso (mask o nick) di ogni    *
 * entry di ogni canale registrato al caricamento dei    *
 * database.                                             *
 *********************************************************/

//#define FIX_CHANNEL_ACCESS_TYPE
#undef FIX_CHANNEL_ACCESS_TYPE


/*********************************************************
 * Abilita i comandi di debug in DebugServ.              *
 *********************************************************/

//#define ENABLE_DEBUG_COMMANDS
#undef ENABLE_DEBUG_COMMANDS


/*********************************************************
 * Abilita il trace.                                     *
 *********************************************************/

#define ENABLE_TRACE
//#undef ENABLE_TRACE


/*********************************************************
 * Utilizza il nuovo socket per la connessione e la      *
 * ricezione di dati dall'hub.                           *
 *********************************************************/

#define NEW_SOCK
//#undef NEW_SOCK


/*********************************************************
 * Abilita la gestione di memoria tramite i memory       *
 * pools.                                                *
 *********************************************************/

#define FIX_USE_MPOOL
//#undef FIX_USE_MPOOL


/*********************************************************
 * Abilita i CAPAB da inviare al connect.                *
 *********************************************************/

#define ENABLE_CAPAB_TS3
#define ENABLE_CAPAB_NOQUIT
#define ENABLE_CAPAB_SSJOIN
#define ENABLE_CAPAB_BURST
#define ENABLE_CAPAB_UNCONNECT
#undef ENABLE_CAPAB_ZIP
#define ENABLE_CAPAB_NICKIP
#undef ENABLE_CAPAB_TSMODE
#undef ENABLE_CAPAB_DKEY

#endif /* SRV_OPTIONS_H */
