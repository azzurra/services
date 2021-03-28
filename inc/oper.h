/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* oper.h - For secure oper access structures
* 
*/

#ifndef SRV_OPER_H
#define SRV_OPER_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "strings.h"
#include "messages.h"
#include "users.h"
#include "cidr.h"


/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	OPER_DB_CURRENT_VERSION		11
#define OPER_DB_SUPPORTED_VERSION	"10 11"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _OperAccess_V10	OperAccess_V10;
struct _OperAccess_V10 {

	OperAccess_V10	*next;

	char			*name;		/* Holds username or hostname in ascii format. */

	CIDR_IP			cidr;		/* Holds CIDR information, if any. */

	Creator			creator;
	flags_t			flags;
};

// Current structs version
#define	OperAccess	OperAccess_V10


typedef struct _Oper_V10	Oper_V10;
struct _Oper_V10 {

	Oper_V10		*prev, *next;

	char			*nick;

	OperAccess		*userList;
	unsigned char	userCount;

	OperAccess		*hostList;
	unsigned char 	hostCount;

	Creator			creator;
	time_t			lastUpdate;

	flags_t			flags;					/* OPER_* defined below. */
	int				level;					/* Oper's access level to services (ULEVEL_*) */
};


typedef struct _Oper_V11	Oper_V11;
struct _Oper_V11 {

	Oper_V11		*prev, *next;

	char			*nick;

	Creator			creator;
	time_t			lastUpdate;

	flags_t			flags;					/* OPER_* defined below. */
	int				level;					/* Oper's access level to services (ULEVEL_*) */
};

// Current structs version
#define	Oper	Oper_V11


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Oper.flags
#define OPER_FLAG_ENABLED	0x00000001


// Livelli di accesso ai comandi
#define	CMDLEVEL_USER				0x00000001
#define	CMDLEVEL_OPER				0x00000002
#define	CMDLEVEL_AGENT				0x00000004
#define	CMDLEVEL_HOP				0x00000008
#define	CMDLEVEL_SOP				0x00000020
#define	CMDLEVEL_SA					0x00000040
#define	CMDLEVEL_SRA				0x00000080
#define	CMDLEVEL_CODER				0x00000100
#define	CMDLEVEL_MASTER				0x00000200

#define	CMDLEVEL_DISABLED			0x10000000
#define	CMDLEVEL_CANT_BE_DISABLED	0x08000000

// Livelli utenti standard
#define ULEVEL_NOACCESS			0x00000000
#define ULEVEL_USER				CMDLEVEL_USER
#define ULEVEL_OPER				(ULEVEL_USER  | CMDLEVEL_OPER)
#define ULEVEL_AGENT			(ULEVEL_USER  | CMDLEVEL_AGENT)
#define ULEVEL_HOP				(ULEVEL_USER  | CMDLEVEL_HOP)
#define ULEVEL_SOP				(ULEVEL_AGENT | CMDLEVEL_HOP | CMDLEVEL_OPER | CMDLEVEL_SOP)
#define ULEVEL_SA				(ULEVEL_SOP   | CMDLEVEL_SA)
#define ULEVEL_SRA				(ULEVEL_SA    | CMDLEVEL_SRA)
#define ULEVEL_CODER			(ULEVEL_SRA   | CMDLEVEL_CODER)
#define ULEVEL_MASTER			(ULEVEL_CODER | CMDLEVEL_MASTER)



/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern ServiceCommand	*nickserv_commands[26];
extern ServiceCommand	*chanserv_commands[26];
extern ServiceCommand	*memoserv_commands[26];
extern ServiceCommand	*operserv_commands[26];
extern ServiceCommand	*rootserv_commands[26];
extern ServiceCommand	*helpserv_commands[26];
extern ServiceCommand	*statserv_commands[26];
extern ServiceCommand	*seenserv_commands[26];
extern ServiceCommand	*debugserv_commands[26];


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void handle_count(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_oper(CSTR source, User *callerUser, ServiceCommandData *data);

extern BOOL oper_db_load(void);
extern BOOL oper_db_save(void);

extern void oper_remove_nick(CSTR nick);
extern int check_oper(User *user, CSTR nick, CSTR pass);

extern __inline__ BOOL is_services_master(const User *user);
extern __inline__ BOOL is_services_coder(const User *user);
extern __inline__ BOOL is_services_root(const User *user);
extern __inline__ BOOL is_services_admin(const User *user);
extern __inline__ BOOL is_services_oper(const User *user);
extern __inline__ BOOL is_services_helpop(const User *user);
extern __inline__ BOOL is_services_valid_oper(const User *user);

extern int get_services_access(const User *user, CSTR nick);


// Command handling

#define CheckOperAccess(userLevel, accessRequired)	(((userLevel) & (accessRequired)) == (accessRequired))

extern void oper_invoke_agent_command(char *cmd, ServiceCommand *commands[], User *callerUser, const Agent *agent);

extern CSTR oper_get_agent_name(agentid_t id);
extern agentid_t oper_get_agentid(CSTR agentNickname, BOOL performMatch);
extern ServiceCommand **oper_get_agent_command_map(agentid_t agentID);
extern ServiceCommand *oper_get_command_table(char *cmd, ServiceCommand *commands[]);

extern result_t oper_enable_command(char *cmd, ServiceCommand *commands[], BOOL enable);
extern void oper_send_disabled_command_list(ServiceCommand *commands[], CSTR agentChecked, User *callerUser, CSTR agentNickname);

extern void oper_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int oper_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_OPER_H */
