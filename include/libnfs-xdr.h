/*
   Copyright (C) 2012 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/*
 * This file contains definitions for the built in XDR implementation.
 * This is a very limited XDR subset that can only marshal to/from a momory buffer,
 * i.e. xdrmem_create() buffers.
 * It aims to be compatible with normal rpcgen generated functions.
 */

#include "config.h"

#ifdef USE_LOCAL_XDR

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/rpc_msg.h>

#else

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>

#define _RPC_RPC_H 1
#define _RPC_XDR_H 1
#define _RPC_AUTH_H 1

/* we dont need these */
typedef void CLIENT;
struct svc_req {
};
typedef void SVCXPRT;





#define XDR_INLINE(...) NULL
#define IXDR_PUT_U_LONG(...)		assert(0)
#define IXDR_GET_U_LONG(...)		(assert(0), 0)
#define IXDR_PUT_LONG(...)		assert(0)
#define IXDR_GET_LONG(...)		(assert(0), 0)
#define IXDR_PUT_BOOL(...)		assert(0)
#define IXDR_GET_BOOL(...)		(assert(0), 0)

#define TRUE		1
#define FALSE		0

enum xdr_op {
	XDR_ENCODE = 0,
	XDR_DECODE = 1
};

struct xdr_mem {
       struct xdr_mem *next;
       caddr_t buf;
       uint32_t size;
};

struct XDR {
	enum xdr_op x_op;
	caddr_t buf;
	int size;
	int pos;
	struct xdr_mem *mem;
};
typedef struct XDR XDR;


typedef uint32_t u_int;
typedef uint32_t enum_t;
typedef int bool_t;

typedef int (*xdrproc_t) (XDR *, void *,...);

/* XXX find out what we can get rid of */

#define AUTH_NONE 0
#define AUTH_NULL 0
#define AUTH_UNIX 1
struct opaque_auth {
	uint32_t oa_flavor;
	caddr_t  oa_base;
	uint32_t oa_length;
};
extern struct opaque_auth _null_auth;


typedef struct {
	struct opaque_auth	ah_cred;
	struct opaque_auth	ah_verf;
	caddr_t ah_private;
} AUTH;

enum msg_type {
	CALL=0,
	REPLY=1
};

#define RPC_MSG_VERSION	2

struct call_body {
	uint32_t cb_rpcvers;
	uint32_t cb_prog;
	uint32_t cb_vers;
	uint32_t cb_proc;
	struct opaque_auth cb_cred;
	struct opaque_auth cb_verf;
};

enum accept_stat {
	SUCCESS=0,
	PROG_UNAVAIL=1,
	PROG_MISMATCH=2,
	PROC_UNAVAIL=3,
	GARBAGE_ARGS=4,
	SYSTEM_ERR=5
};

struct accepted_reply {
	struct opaque_auth	ar_verf;
	uint32_t		ar_stat;
	union {
		struct {
			u_long	low;
			u_long	high;
		} AR_versions;
		struct {
			caddr_t	where;
			xdrproc_t proc;
		} AR_results;
		/* and many other null cases */
	} ru;
#define	ar_results	ru.AR_results
#define	ar_vers		ru.AR_versions
};

enum reject_stat {
	RPC_MISMATCH=0,
	AUTH_ERROR=1
};

enum auth_stat {
	AUTH_OK=0,
	/*
	 * failed at remote end
	 */
	AUTH_BADCRED=1,			/* bogus credentials (seal broken) */
	AUTH_REJECTEDCRED=2,		/* client should begin new session */
	AUTH_BADVERF=3,			/* bogus verifier (seal broken) */
	AUTH_REJECTEDVERF=4,		/* verifier expired or was replayed */
	AUTH_TOOWEAK=5,			/* rejected due to security reasons */
	/*
	 * failed locally
	*/
	AUTH_INVALIDRESP=6,		/* bogus response verifier */
	AUTH_FAILED=7			/* some unknown reason */
};

struct rejected_reply {
	enum reject_stat rj_stat;
	union {
		struct {
			u_long low;
			u_long high;
		} RJ_versions;
		enum auth_stat RJ_why;  /* why authentication did not work */
	} ru;
#define	rj_vers	ru.RJ_versions
#define	rj_why	ru.RJ_why
};

#define MSG_ACCEPTED 0
#define MSG_DENIED 1

struct reply_body {
	uint32_t rp_stat;
	union {
		struct accepted_reply RP_ar;
		struct rejected_reply RP_dr;
	} ru;
#define	rp_acpt	ru.RP_ar
#define	rp_rjct	ru.RP_dr
};

struct rpc_msg {
	uint32_t		rm_xid;

	uint32_t		rm_direction;
	union {
		struct call_body RM_cmb;
		struct reply_body RM_rmb;
	} ru;
#define	rm_call		ru.RM_cmb
#define	rm_reply	ru.RM_rmb
};
#define	acpted_rply	ru.RM_rmb.ru.RP_ar
#define	rjcted_rply	ru.RM_rmb.ru.RP_dr



#define xdrmem_create libnfs_xdrmem_create
void libnfs_xdrmem_create(XDR *xdrs, const caddr_t addr, uint32_t size, enum xdr_op xop);

#define xdr_destroy libnfs_xdr_destroy
void libnfs_xdr_destroy(XDR *xdrs);

#define xdr_bytes libnfs_xdr_bytes
bool_t libnfs_xdr_bytes(XDR *xdrs, char **bufp, uint32_t *size, uint32_t *maxsize);

#define xdr_u_int libnfs_xdr_u_int
bool_t libnfs_xdr_u_int(XDR *xdrs, uint32_t *u);

#define xdr_int libnfs_xdr_int
bool_t libnfs_xdr_int(XDR *xdrs, int32_t *i);

#define xdr_void libnfs_xdr_void
bool_t libnfs_xdr_void(void);

#define xdr_setpos libnfs_xdr_setpos
bool_t libnfs_xdr_setpos(XDR *xdrs, uint32_t pos);

#define xdr_getpos libnfs_xdr_getpos
uint32_t libnfs_xdr_getpos(XDR *xdrs);

#define xdr_free libnfs_xdr_free
void libnfs_xdr_free(xdrproc_t proc, char *objp);

#define xdr_callmsg libnfs_xdr_callmsg
bool_t libnfs_xdr_callmsg(XDR *xdrs, struct rpc_msg *msg);

#define xdr_replymsg libnfs_xdr_replymsg
bool_t libnfs_xdr_replymsg(XDR *xdrs, struct rpc_msg *msg);

#define auth_destroy libnfs_auth_destroy
void libnfs_auth_destroy(AUTH *auth);


#endif
