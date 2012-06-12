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

#include <stdlib.h>
#include <string.h>
#include "libnfs-xdr.h"

struct opaque_auth _null_auth;

bool_t libnfs_xdr_setpos(XDR *xdrs, uint32_t pos)
{
	xdrs->pos = pos;
}

uint32_t libnfs_xdr_getpos(XDR *xdrs)
{
	return xdrs->pos;
}

void libnfs_xdrmem_create(XDR *xdrs, const caddr_t addr, uint32_t size, enum xdr_op xop)
{
	xdrs->x_op = xop;
	xdrs->buf  = addr;
	xdrs->size = size;
	xdrs->pos  = 0;
	xdrs->mem = NULL;
}

static void *xdr_malloc(XDR *xdrs, uint32_t size)
{
	struct xdr_mem *mem;

	mem = malloc(sizeof(struct xdr_mem));
	mem->next = xdrs->mem;
	mem->size = size;
	mem->buf  = malloc(mem->size);
	xdrs->mem = mem;

	return mem->buf;
}
	
void libnfs_xdr_destroy(XDR *xdrs)
{
	while (xdrs->mem != NULL) {
		struct xdr_mem *mem = xdrs->mem->next;
		free(xdrs->mem->buf);
		free(xdrs->mem);
		xdrs->mem = mem;
	}
}

bool_t libnfs_xdr_u_int(XDR *xdrs, uint32_t *u)
{
	if (xdrs->pos + 4 > xdrs->size) {
		return FALSE;
	}

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		*(uint32_t *)&xdrs->buf[xdrs->pos] = htonl(*u);
		xdrs->pos += 4;
		return TRUE;
		break;
	case XDR_DECODE:
		*u = ntohl(*(uint32_t *)&xdrs->buf[xdrs->pos]);
		xdrs->pos += 4;
		return TRUE;
		break;
	}

	return FALSE;
}

bool_t libnfs_xdr_bytes(XDR *xdrs, char **bufp, uint32_t *size, uint32_t *maxsize)
{
	if (!libnfs_xdr_u_int(xdrs, size)) {
		return FALSE;
	}

	if (xdrs->pos + *size > xdrs->size) {
		return FALSE;
	}

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		memcpy(&xdrs->buf[xdrs->pos], *bufp, *size);
		xdrs->pos += *size;
		xdrs->pos = (xdrs->pos + 3) & ~3;
		return TRUE;
	case XDR_DECODE:
		if (*bufp == NULL) {
			*bufp = xdr_malloc(xdrs, *size);
		}
		memcpy(*bufp, &xdrs->buf[xdrs->pos], *size);
		xdrs->pos += *size;
		xdrs->pos = (xdrs->pos + 3) & ~3;
		return TRUE;
	}

	return FALSE;
}


bool_t libnfs_xdr_int(XDR *xdrs, int32_t *i)
{
	return libnfs_xdr_u_int(xdrs, (uint32_t *)i);
}

bool_t libnfs_xdr_enum(XDR *xdrs, int32_t *e)
{
	return libnfs_xdr_u_int(xdrs, (uint32_t *)e);
}

bool_t libnfs_xdr_bool(XDR *xdrs, bool_t *b)
{
	return libnfs_xdr_u_int(xdrs, (uint32_t *)b);
}

bool_t libnfs_xdr_void(void)
{
	return TRUE;
}

void libnfs_xdr_free(xdrproc_t proc, char *objp)
{
}

static bool_t libnfs_opaque_auth(XDR *xdrs, struct opaque_auth *auth)
{
	if (!libnfs_xdr_u_int(xdrs, &auth->oa_flavor)) {
		return FALSE;
	}

	if (!libnfs_xdr_bytes(xdrs, &auth->oa_base, &auth->oa_length, &auth->oa_length)) {
		return FALSE;
	}

	return TRUE;
}

static bool_t libnfs_rpc_call_body(XDR *xdrs, struct call_body *cmb)
{
	if (!libnfs_xdr_u_int(xdrs, &cmb->cb_rpcvers)) {
		return FALSE;
	}

	if (!libnfs_xdr_u_int(xdrs, &cmb->cb_prog)) {
		return FALSE;
	}

	if (!libnfs_xdr_u_int(xdrs, &cmb->cb_vers)) {
		return FALSE;
	}

	if (!libnfs_xdr_u_int(xdrs, &cmb->cb_proc)) {
		return FALSE;
	}

	if (!libnfs_opaque_auth(xdrs, &cmb->cb_cred)) {
		return FALSE;
	}

	if (!libnfs_opaque_auth(xdrs, &cmb->cb_verf)) {
		return FALSE;
	}
}

static bool_t libnfs_accepted_reply(XDR *xdrs, struct accepted_reply *ar)
{
	if (!libnfs_opaque_auth(xdrs, &ar->ar_verf)) {
		return FALSE;
	}

	if (!libnfs_xdr_u_int(xdrs, &ar->ar_stat)) {
		return FALSE;
	}

	switch (ar->ar_stat) {
	case SUCCESS:
		if (!ar->ar_results.proc(xdrs, ar->ar_results.where)) {
			return FALSE;
		}
		return TRUE;
	case PROG_MISMATCH:
		if (!libnfs_xdr_u_int(xdrs, &ar->ar_vers.low)) {
			return FALSE;
		}
		if (!libnfs_xdr_u_int(xdrs, &ar->ar_vers.high)) {
			return FALSE;
		}
		return TRUE;
	default:
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rejected_reply(XDR *xdrs, struct rejected_reply *RP_dr)
{
printf("rejected reply\n");
exit(10);
}

static bool_t libnfs_rpc_reply_body(XDR *xdrs, struct reply_body *rmb)
{
	if (!libnfs_xdr_u_int(xdrs, &rmb->rp_stat)) {
		return FALSE;
	}

	switch (rmb->rp_stat) {
	case MSG_ACCEPTED:
		if (!libnfs_accepted_reply(xdrs, &rmb->rp_acpt)) {
			return FALSE;
		}
		return TRUE;
	case MSG_DENIED:
		if (!libnfs_rejected_reply(xdrs, &rmb->rp_rjct)) {
			return FALSE;
		}
		return TRUE;
	}

	return FALSE;
}

static bool_t libnfs_rpc_msg(XDR *xdrs, struct rpc_msg *msg)
{
	if (!libnfs_xdr_u_int(xdrs, &msg->rm_xid)) {
		return FALSE;
	}

	if (!libnfs_xdr_u_int(xdrs, &msg->rm_direction)) {
		return FALSE;
	}

	switch (msg->rm_direction) {
	case CALL:
		return libnfs_rpc_call_body(xdrs, &msg->ru.RM_cmb);
		break;
	case REPLY:
		return libnfs_rpc_reply_body(xdrs, &msg->ru.RM_rmb);
		break;
	default:
		return FALSE;
	}
}

bool_t libnfs_xdr_callmsg(XDR *xdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(xdrs, msg);
}

bool_t libnfs_xdr_replymsg(XDR *xdrs, struct rpc_msg *msg)
{
	return libnfs_rpc_msg(xdrs, msg);
}

AUTH *authnone_create(void)
{
	AUTH *auth;

	auth = malloc(sizeof(AUTH));

	auth->ah_cred.oa_flavor = AUTH_NONE;
	auth->ah_cred.oa_length = 0;
	auth->ah_cred.oa_base = NULL;

	auth->ah_verf.oa_flavor = AUTH_NONE;
	auth->ah_verf.oa_length = 0;
	auth->ah_verf.oa_base = NULL;

	auth->ah_private = NULL;

	return auth;
}

AUTH *libnfs_authunix_create(char *host, uint32_t uid, uint32_t gid, uint32_t len, uint32_t *groups)
{
	AUTH *auth;
	int size;
	uint32_t *buf;
	int idx;

	size = 4 + 4 + ((strlen(host) + 3) & ~3) + 4 + 4 + 4 + len * 4;
	auth = malloc(sizeof(AUTH));
	auth->ah_cred.oa_flavor = AUTH_UNIX;
	auth->ah_cred.oa_length = size;
	auth->ah_cred.oa_base = malloc(size);

	buf = auth->ah_cred.oa_base;
	idx = 0;
	buf[idx++] = htonl(time(NULL));
	buf[idx++] = htonl(strlen(host));
	memcpy(&buf[2], host, strlen(host));

	idx += (strlen(host) + 3) >> 2;	
	buf[idx++] = htonl(uid);
	buf[idx++] = htonl(gid);
	buf[idx++] = htonl(len);
	while (len-- > 0) {
		buf[idx++] = htonl(*groups++);
	}

	auth->ah_verf.oa_flavor = AUTH_NONE;
	auth->ah_verf.oa_length = 0;
	auth->ah_verf.oa_base = NULL;

	auth->ah_private = NULL;

	return auth;
}

AUTH *libnfs_authunix_create_default(void)
{
	return libnfs_authunix_create("libnfs", getuid(), -1, 0, NULL);
}

void libnfs_auth_destroy(AUTH *auth)
{
	if (auth->ah_cred.oa_base) {
		free(auth->ah_cred.oa_base);
	}
	if (auth->ah_verf.oa_base) {
		free(auth->ah_verf.oa_base);
	}
	free(auth);
}

