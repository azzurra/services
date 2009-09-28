/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* sockutil.c - Socket utility routines
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/timeout.h"
#include "../inc/memory.h"
#include "../inc/sockutil.h"

#ifdef USE_SOCKSMONITOR
#include "../inc/conf.h"
#endif


/* Socket used when connecting to our uplink. */
static int SERVER_SOCKET = -1;


#ifdef NEW_SOCK

/////////////// NEW CODE ///////////////////////////////////////////////////////////


/* Maximum amount of data from/to the network to buffer (bytes). */
#define NET_BUFSIZE	665536

int ReadTimeout = 5;

/* Read from a socket with buffering. */

static char read_netbuf[NET_BUFSIZE];
static char *read_curpos = read_netbuf; /* Next byte to return */
static char *read_bufend = read_netbuf; /* Next position for data from socket */
static char * const read_buftop = read_netbuf + NET_BUFSIZE;
unsigned long long int total_read = 0;



/* Return amount of data in read buffer. */
int read_buffer_len() {

	return (read_bufend >= read_curpos) ? (read_bufend - read_curpos) : (read_bufend + NET_BUFSIZE) - read_curpos;
}

/* Optimized version of the buffered_read() for reading a single character;
   returns the character in an int or EOF, like fgetc(). */

static int buffered_read_one(void) {

	int nread, selected;
	fd_set fds;
	static struct timeval tv = {0,0};
	char c;
	struct timeval *tvptr;
	int errno_save;

/*
	if (fd < 0) {

		errno = EBADF;
		return EOF;
	}
*/

	/* Handle the normal case first. This duplicates the code below, but
	* we do it anyway for speed. */
	if (read_curpos != read_bufend) {

		c = *read_curpos++;

		if (read_curpos == read_buftop)
			read_curpos = read_netbuf;

		++total_read;

		return (int)c & 0xFF;
	}

	/* We need to read more data. */
	errno_save = errno;

	tvptr = NULL;

	FD_ZERO(&fds);
	FD_SET(SERVER_SOCKET, &fds);

	do {

		selected = -1;

		while ((read_bufend != (read_curpos - 1))
			&& ((read_curpos != read_netbuf) || (read_bufend != (read_buftop - 1)))
			&& ((selected = select(SERVER_SOCKET + 1, &fds, 0, 0, tvptr)) == 1) ) {

			int maxread;

			if (read_bufend < read_curpos)	/* wrapped around? */
				maxread = (read_curpos-1) - read_bufend;

			else if (read_curpos == read_netbuf)
				maxread = read_buftop - read_bufend - 1;

			else
				maxread = read_buftop - read_bufend;
				
			do {

				errno = 0;
				nread = read(SERVER_SOCKET, read_bufend, maxread);
			} while ((nread <= 0) && (errno == EINTR));
				
			tvptr = &tv;			/* don't wait next time */
			errno_save = errno;

			if (nread <= 0)
				break;

			read_bufend += nread;

			if (read_bufend == read_buftop)
				read_bufend = read_netbuf;
		}

	} while ((selected == -1) && (errno == EINTR));

	if (read_curpos == read_bufend) {	/* No more data on socket */

		errno = errno_save;
		return EOF;
	}

	c = *read_curpos++;

	if (read_curpos == read_buftop)
		read_curpos = read_netbuf;

	++total_read;

	return (int)c & 0xFF;
}

/*********************************************************/

/* Write to a socket with buffering. Note that this assumes only one socket. */

static char write_netbuf[NET_BUFSIZE];
static char *write_curpos = write_netbuf; /* Next byte to write to socket */
static char *write_bufend = write_netbuf; /* Next position for data to socket */
static char * const write_buftop = write_netbuf + NET_BUFSIZE;
static int write_fd = -1;
unsigned long long int total_written;


/* Return amount of data in write buffer. */
int write_buffer_len() {

	if (write_bufend >= write_curpos)
		return write_bufend - write_curpos;
	else
		return (write_bufend+NET_BUFSIZE) - write_curpos;
}


/* Helper routine to try and write up to one chunk of data from
   the buffer to the socket. Return how much was written. */

static int flush_write_buffer(int wait) {

	fd_set fds;
	struct timeval tv = {0,0};
	int errno_save = errno;

	if ((write_bufend == write_curpos) || (write_fd == -1))
		return 0;

	FD_ZERO(&fds);
	FD_SET(write_fd, &fds);

	if (select(write_fd + 1, 0, &fds, 0, wait ? NULL : &tv) == 1) {

		int maxwrite, nwritten;

		if (write_curpos > write_bufend)	/* wrapped around? */
			maxwrite = write_buftop - write_curpos;
		else
			maxwrite = write_bufend - write_curpos;

		nwritten = write(write_fd, write_curpos, maxwrite);
		errno_save = errno;

		if (nwritten > 0) {

			write_curpos += nwritten;

			if (write_curpos == write_buftop)
				write_curpos = write_netbuf;

			total_written += nwritten;

			return nwritten;
		}
	}

	errno = errno_save;
	return 0;
}


/* Write data. */
static int buffered_write(char *buf, int len) {

	int nwritten, left = len;
	int errno_save = errno;

/*
	if (fd < 0) {

		errno = EBADF;
		return -1;
	}
*/

	write_fd = SERVER_SOCKET;

	while (left > 0) {

		/* Don't try putting anything in the buffer if it's full. */
		if ((write_curpos != (write_bufend + 1)) &&
			((write_curpos != write_netbuf) || (write_bufend != (write_buftop - 1)))) {

			/* See if we need to write up to the end of the buffer. */
			if (((write_bufend + left) >= write_buftop) && (write_curpos <= write_bufend)) {

				nwritten = (write_buftop - write_bufend);

				memcpy(write_bufend, buf, nwritten);
				buf += nwritten;
				left -= nwritten;
				write_bufend = write_netbuf;
			}

			/* Now we can copy a single chunk to write_bufend. */
			if ((write_curpos > write_bufend) && ((write_curpos - write_bufend - 1) < left))
				nwritten = (write_curpos - write_bufend - 1);
			else
				nwritten = left;

			if (nwritten) {

				memcpy(write_bufend, buf, nwritten);
				buf += nwritten;
				left -= nwritten;
				write_bufend += nwritten;
			}
		}

		/* Now write to the socket as much as we can. */
		if ((write_curpos == (write_bufend + 1)) ||
			((write_curpos == write_netbuf) && (write_bufend == (write_buftop - 1))))
			flush_write_buffer(TRUE);
		else
			flush_write_buffer(FALSE);

		errno_save = errno;

		if ((write_curpos == (write_bufend + 1)) ||
			((write_curpos == write_netbuf) && (write_bufend == (write_buftop - 1)))) {

			/* Write failed on full buffer */
			break;
		}
	}

	errno = errno_save;
	return (len - left);
}


/*********************************************************
 * Public code.                                          *
 *********************************************************/

/*********************************************************
 * socket_read()                                         *
 *                                                       *
 * Read data from our socket and fill in the buffer.     *
 * Return -1 if connection was broken, or an error       *
 *   occurred.                                           *
 * Return 0 if the read timed out (no data to be read).  *
 * Return 1 if the buffer was filled successfully.       *
 *********************************************************/

SOCKET_RESULT socket_read(char *buffer, long int len) {

	int 			c, selected = 1;
	struct timeval	tv;
	fd_set			fds;
	char			*ptr;


	FD_ZERO(&fds);
	FD_SET(SERVER_SOCKET, &fds);

	tv.tv_sec = ReadTimeout;
	tv.tv_usec = 0;

	while ((read_buffer_len() == 0) && ((selected = select(SERVER_SOCKET + 1, &fds, NULL, NULL, &tv)) < 0)) {

		if (errno != EINTR)
			break;
	}

	/* select() returned nothing to read on our socket. Ignore and continue. */
	if (selected == 0)
		return socketTimeout;

	/* select() returned an error. */
	if (selected < 0)
		return socketError;

	ptr = buffer;

	while (((c = buffered_read_one()) >= 0) && (--len > 0) && (c != '\n'))
		*ptr++ = c;

	/* Something's not right... error out. */
	if (c < 0)
		return socketError;

	if (*(ptr - 1) == '\r')
		--ptr;

	*ptr = 0;

	/* If the buffer is empty, return error. */
	if (buffer[0] == 0)
		return socketError;

	return socketSuccess;
}

/*********************************************************/

__inline__ void socket_write(char *text, size_t length) {

	buffered_write(text, length);
}

/*********************************************************/

#if 0

static int lastchar = EOF;

static int buffered_read(int fd, char *buf, int len) {

	int nread, left = len;
	fd_set fds;
	static struct timeval tv = {0,0};
	int errno_save = errno;

	if (fd < 0) {

		errno = EBADF;
		return -1;
	}

	while (left > 0) {

		struct timeval *tvptr = (read_bufend == read_curpos ? NULL : &tv);

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		while (read_bufend != read_curpos-1 && !(read_curpos == read_netbuf && read_bufend == read_buftop-1)
			&& select(fd+1, &fds, 0, 0, tvptr) == 1) {

			int maxread;

			if (read_bufend < read_curpos)	/* wrapped around? */
				maxread = (read_curpos-1) - read_bufend;

			else if (read_curpos == read_netbuf)
				maxread = read_buftop - read_bufend - 1;

			else
				maxread = read_buftop - read_bufend;

			do {
				errno = 0;
				nread = read(fd, read_bufend, maxread);
			} while (nread <= 0 && errno == EINTR);

			tvptr = &tv;			/* don't wait next time */
			errno_save = errno;

			if (nread <= 0)
				break;

			read_bufend += nread;

			if (read_bufend == read_buftop)
				read_bufend = read_netbuf;
		}

		if (read_curpos == read_bufend)		/* No more data on socket */
			break;

		/* See if we can gobble up the rest of the buffer. */
		if (read_curpos+left >= read_buftop && read_bufend < read_curpos) {

			nread = read_buftop-read_curpos;
			memcpy(buf, read_curpos, nread);
			buf += nread;
			left -= nread;
			read_curpos = read_netbuf;
		}

		/* Now everything we need is in a single chunk at read_curpos. */
		if (read_bufend > read_curpos && read_bufend-read_curpos < left)
			nread = read_bufend-read_curpos;
		else
			nread = left;

		if (nread) {

			memcpy(buf, read_curpos, nread);
			buf += nread;
			left -= nread;
			read_curpos += nread;
		}
	}

	total_read += len - left;

	errno = errno_save;
	return len - left;
}

/*********************************************************/

/* Optimized version of the buffered_write() for writing a single character;
   returns the character in an int or EOF, like fputc(). */

static int buffered_write_one(int c, int fd) {

	struct timeval tv = {0,0};

	if (fd < 0) {

		errno = EBADF;
		return -1;
	}
	write_fd = fd;

	/* Try to flush the buffer if it's full. */
	if (write_curpos == write_bufend+1 ||
		(write_curpos == write_netbuf && write_bufend == write_buftop-1)) {

		flush_write_buffer(1);

		if (write_curpos == write_bufend+1 ||
			(write_curpos == write_netbuf && write_bufend == write_buftop-1)) {

			/* Write failed */
			if (SET_DEBUG)
				log("debug: buffered_write_one(%d) returning %d", fd, EOF);

			return EOF;
		}
	}

	/* Write the character. */
	*write_bufend++ = c;

	if (write_bufend == write_buftop)
		write_bufend = write_netbuf;

	/* Move it to the socket if we can. */
	flush_write_buffer(0);

	if (SET_DEBUG)
		log("debug: buffered_write_one(%d) returning %d", fd, c);

	return (int)c & 0xFF;
}

/*********************************************************/

/* Read from a socket. (Use this instead of read() because it has buffering.) */
int sread(int s, char *buf, int len) {

	return buffered_read(s, buf, len);
}

/*********************************************************/

int sputs(char *str, int s) {

	return buffered_write(s, str, strlen(str));
}

/*********************************************************/

static int sgetc(int s) {

	int c;

	if (lastchar != EOF) {

		c = lastchar;
		lastchar = EOF;
		return c;
	}

	return buffered_read_one(s);
}

/*********************************************************/

int sungetc(int c, int s) {

	return lastchar = c;
}
#endif

/////////////// fine NEW CODE ///////////////////////////////////////////////////////////

#else // NEW_SOCK

FILE **files = NULL;	/* Array of FILE *'s; files[s] = fdopen(s, "r+") */
int filescnt = 0;		/* Size of files array */
static int lastchar = EOF;


/*********************************************************/

int sgetc(int s) {

	unsigned char c;

	if (lastchar != EOF) {

		c = lastchar;
		lastchar = EOF;
		return c;
	}

	if (read(s, &c, 1) <= 0)
		return EOF;

	return c;
}

/*********************************************************/

/* If connection was broken, return NULL. If the read timed out, return (char *)-1. */

char *sgets(char *buf, unsigned int len, int s) {

	int c;
	char *ptr = buf;

	if (len == 0)
		return NULL;

	c = sgetc(s);

	while (--len && (*ptr++ = c) != '\n' && (c = sgetc(s)) >= 0)
		;

	if (c < 0)
		return NULL;

	*ptr = 0;

	return buf;
}

/*********************************************************/

/* sgets2: Read a line of text from a socket, and strip newline and
 *         carriage return characters from the end of the line.
 */

char *sgets2(char *buf, long size, int sock) {

	char *s = sgets(buf, size, sock);

	if (!s || s == (char *)-1)
		return s;

	if (buf[str_len(buf)-1] == '\n')
		buf[str_len(buf)-1] = 0;

	if (buf[str_len(buf)-1] == '\r')
		buf[str_len(buf)-1] = 0;

	return buf;
}

/*********************************************************/

int inline sputs(char *str, int s) {

	return write(s, str, str_len(str));
}

int sockprintf(int s, char *fmt, ...) {

	va_list args;
	va_start(args, fmt);

	if (s >= filescnt) {

		int oldcnt = filescnt;
		filescnt *= 2;

		if (filescnt <= s)
			filescnt = s+1;

		files = mem_realloc(files, sizeof(FILE *) * filescnt);

		if (!files) {

			filescnt = 0;
			errno = ENOMEM;
			return 0;
		}

		memset(files+oldcnt, 0, sizeof(FILE *) * (filescnt - oldcnt));
	}

	if (IS_NULL(files))
		return 0;

	if (!files[s]) {

		if (!(files[s] = fdopen(s, "r+")))
			return 0;

		setbuf(files[s], NULL);
	}

	return vfprintf(files[s], fmt, args);
}

#endif /* NEW_SOCK */

/*********************************************************/

BOOL socket_connect(CSTR host, const unsigned short port) {

	struct hostent *hp;
	struct sockaddr_in sa;
	int sock;


	if (IS_NULL(host) || (port <= 0))
		return FALSE;

	if (IS_NULL(hp = gethostbyname(host)))
		return FALSE;

	memset(&sa, 0, sizeof(sa));

	memcpy((char *)&sa.sin_addr, hp->h_addr, hp->h_length);

	sa.sin_family = hp->h_addrtype;
	sa.sin_port = htons(port);

	if ((sock = socket(sa.sin_family, SOCK_STREAM, 0)) < 0)
		return FALSE;

#ifndef NEW_SOCK
	if (filescnt <= sock) {

		int oldcnt = filescnt;
		filescnt *= 2;

		if (filescnt <= sock)
			filescnt = sock+1;

		files = mem_realloc(files, sizeof(FILE *) * filescnt);

		if (!files) {

			filescnt = 0;
			shutdown(sock, SHUT_RDWR);
			close(sock);
			errno = ENOMEM;
			return -1;
		}

		memset(files+oldcnt, 0, sizeof(FILE *) * (filescnt - oldcnt));
	}

	if (!(files[sock] = fdopen(sock, "r+"))) {

		int errno_save = errno;
		shutdown(sock, SHUT_RDWR);
		close(sock);
		errno = errno_save;
		return -1;
	}

	setbuf(files[sock], NULL);
#endif

#ifdef USE_SOCKSMONITOR
	if ((CONF_MONITOR_LOCAL_HOST) && bind(sock, (struct sockaddr *)&MONITOR_LOCAL_ADDRESS, sizeof(MONITOR_LOCAL_ADDRESS)) < 0) {

		int errno_save = errno;

		shutdown(sock, SHUT_RDWR);

		#ifndef NEW_SOCK
		fclose(files[sock]);
		#endif

		close(sock);
		errno = errno_save;
		return -1;
	}
#endif

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {

		int errno_save = errno;

		shutdown(sock, SHUT_RDWR);

		#ifndef NEW_SOCK
		fclose(files[sock]);
		#endif

		close(sock);
		errno = errno_save;
		return FALSE;
	}

	SERVER_SOCKET = sock;

	return TRUE;
}

void socket_disconnect(void) {

	shutdown(SERVER_SOCKET, SHUT_RDWR);

#ifndef NEW_SOCK
	if (SERVER_SOCKET < filescnt)
		fclose(files[SERVER_SOCKET]);
	else
#endif
		close(SERVER_SOCKET);
}
