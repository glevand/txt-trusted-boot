/*	$OpenBSD: cmac.h,v 1.1 2008/08/12 15:43:00 damien Exp $	*/

/*-
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _CMAC_H_
#define _CMAC_H_


#define AES_CMAC_KEY_LENGTH	16
#define AES_CMAC_DIGEST_LENGTH	16

/* begin added for tboot */
#define u_int      unsigned int
#define u_int8_t   uint8_t

typedef uint8_t cmac_t[AES_CMAC_DIGEST_LENGTH];

#define __BEGIN_DECLS
#define __END_DECLS

#include <rijndael.h>
/* end added for tboot */

typedef struct _AES_CMAC_CTX {
	rijndael_ctx	rijndael;
	u_int8_t	X[16];
	u_int8_t	M_last[16];
	u_int		M_n;
} AES_CMAC_CTX;

//#include <sys/cdefs.h>

__BEGIN_DECLS
void	 AES_CMAC_Init(AES_CMAC_CTX *);
void	 AES_CMAC_SetKey(AES_CMAC_CTX *, const u_int8_t [AES_CMAC_KEY_LENGTH]);
void	 AES_CMAC_Update(AES_CMAC_CTX *, const u_int8_t *, u_int);
//		__attribute__((__bounded__(__string__,2,3)));
void	 AES_CMAC_Final(u_int8_t [AES_CMAC_DIGEST_LENGTH], AES_CMAC_CTX *);
//		__attribute__((__bounded__(__minbytes__,1,AES_CMAC_DIGEST_LENGTH)));
__END_DECLS

#endif /* _CMAC_H_ */