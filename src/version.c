/*
*
* Azzurra IRC Services
* 
* version.c - version info
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/version.h"
#include "../inc/users.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/logging.h"
#include "../inc/main.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

STDSTR	s_vers_name		= "\2Azzurra\2 IRC Services";
STDSTR	s_vers_build_name	= VERS_BUILDNAME;
STDSTR	s_vers_buildtime	= " " __DATE__ " " __TIME__;
STDSTR	s_vers_codedby		= "\2Shaka\2, \2Gastaman\2, \2Sonic\2, \2morph\2, \2Scorpion\2";
STDSTR	s_vers_version		= "\2" VERS_MAJOR "." VERS_MINOR "." VERS_REVISION "\2 " VERS_IRCD "+" VERS_CP_TS3 VERS_CP_NOQUIT VERS_CP_SSJOIN VERS_CP_BURST VERS_CP_UNCONNECT VERS_CP_ZIP VERS_CP_NICKIP VERS_CP_TSMODE VERS_CP_DKEY "-" VERS_BF_LANG VERS_BF_POOL VERS_BF_DEBUG VERS_BF_TRACE "-" BRANCH_NAME_SHORT " [ \2" VERS_CODENAME "\2 ]";


/*********************************************************
 * Public code                                           *
 *********************************************************/

void handle_version(const char *source, User *callerUser, ServiceCommandData *data) {

	if (data->operMatch)
		LOG_SNOOP(data->agent->nick, "%s V -- by %s (%s@%s)", data->agent->shortNick, source, callerUser->username, callerUser->host);
	else
		LOG_SNOOP(data->agent->nick, "%s V -- by %s (%s@%s) through %s", data->agent->shortNick, source, callerUser->username, callerUser->host, data->operName);

	send_notice_to_user(data->agent->nick, callerUser, "*** Version Info ***");
	send_notice_to_user(data->agent->nick, callerUser, "%s - \2%s\2", s_vers_name, s_vers_build_name);
	send_notice_to_user(data->agent->nick, callerUser, "Version: %s", s_vers_version);
	send_notice_to_user(data->agent->nick, callerUser, "Build time: %s", s_vers_buildtime);	
	send_notice_to_user(data->agent->nick, callerUser, "Coded by: %s", s_vers_codedby);
	send_notice_to_user(data->agent->nick, callerUser, "*** \2End of Version\2 ***");
}
