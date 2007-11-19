/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* branch.h
* 
*/


#ifndef SRV_BRANCH_H
#define SRV_BRANCH_H


#define BRANCH_STABLE	1
#define BRANCH_DEVEL	2



/* The current compile branch */
#define BRANCH	BRANCH_DEVEL



#if BRANCH == BRANCH_STABLE
	#define BRANCH_NAME			"STABLE"
	#define BRANCH_NAME_SHORT	"STB"
#else
	#define BRANCH_NAME			"DEVEL"
	#define BRANCH_NAME_SHORT	"DEV"
#endif


#endif /* SRV_BRANCH_H */
