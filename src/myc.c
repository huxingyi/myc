#include "myc.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define CLIENT_LONG_PASSWORD    1       /* new more secure passwords */
#define CLIENT_LONG_FLAG        4       /* Get all column flags */
#define CLIENT_PROTOCOL_41      512     /* New 4.1 protocol */
#define CLIENT_SECURE_CONNECTION 32768  /* New 4.1 authentication */

#define SCRAMBLE_LENGTH_323 8

#define PROTOCOL_VERSION                10

typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long long ulonglong;

#define uint2korr(A)    (uint16) (((uint16) ((uchar) (A)[0])) +\
                                  ((uint16) ((uchar) (A)[1]) << 8))
#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16))
#define uint4korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24))
#define uint5korr(A)    ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                    (((uint32) ((uchar) (A)[1])) << 8) +\
                                    (((uint32) ((uchar) (A)[2])) << 16) +\
                                    (((uint32) ((uchar) (A)[3])) << 24)) +\
                                    (((ulonglong) ((uchar) (A)[4])) << 32))
#define uint6korr(A)    ((ulonglong)(((uint32)    ((uchar) (A)[0]))          + \
                                     (((uint32)    ((uchar) (A)[1])) << 8)   + \
                                     (((uint32)    ((uchar) (A)[2])) << 16)  + \
                                     (((uint32)    ((uchar) (A)[3])) << 24)) + \
                         (((ulonglong) ((uchar) (A)[4])) << 32) +       \
                         (((ulonglong) ((uchar) (A)[5])) << 40))
#define uint8korr(A)    ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                    (((uint32) ((uchar) (A)[1])) << 8) +\
                                    (((uint32) ((uchar) (A)[2])) << 16) +\
                                    (((uint32) ((uchar) (A)[3])) << 24)) +\
                        (((ulonglong) (((uint32) ((uchar) (A)[4])) +\
                                    (((uint32) ((uchar) (A)[5])) << 8) +\
                                    (((uint32) ((uchar) (A)[6])) << 16) +\
                                    (((uint32) ((uchar) (A)[7])) << 24))) <<\
                                    32))

enum mysql_commands {
  COM_SLEEP = 0,
  COM_QUIT,
  COM_INIT_DB,
  COM_QUERY
};

static inline void to_my_2(int value, unsigned char *m) 
{
        m[1] = value >> 8;
        m[0] = value;
}

static inline void to_my_3(int value, unsigned char *m) 
{
        m[2] = value >> 16;
        m[1] = value >> 8;
        m[0] = value;
}

static inline void to_my_4(int value, unsigned char *m) 
{
        m[3] = value >> 24;
        m[2] = value >> 16;
        m[1] = value >> 8;
        m[0] = value;
}

static inline void to_my_8(long long value, unsigned char *m) 
{
        m[7] = value >> 56;
        m[6] = value >> 48;
        m[5] = value >> 40;
        m[4] = value >> 32;
        m[3] = value >> 24;
        m[2] = value >> 16;
        m[1] = value >> 8;
        m[0] = value;
}

/* length coded binary
  0-250        0           = value of first byte
  251          0           column value = NULL
                                only appropriate in a Row Data Packet
  252          2           = value of following 16-bit word
  253          3           = value of following 24-bit word
  254          8           = value of following 64-bit word

  fichier mysql: source mysql: sql/pack.c
*/
static inline int my_lcb_ll(const unsigned char *m, unsigned long long *r, char *nul, int len) {
        if (len < 1)
                return -1;
        switch ((unsigned char)m[0]) {

        case 251: /* fb : 1 octet */
                *r = 0;
                *nul=1;
                return 1;

        case 252: /* fc : 2 octets */
                if (len < 3)
                        return -1;
                *r = uint2korr(&m[1]);
                *nul=0;
                return 3;

        case 253: /* fd : 3 octets */
                if (len < 4)
                        return -1;
                *r = uint3korr(&m[1]);
                *nul=0;
                return 4;

        case 254: /* fe */
                if (len < 9)
                        return -1;
                *r = uint8korr(&m[1]);
                *nul=0;
                return 9;

        default:
                *r = (unsigned char)m[0];
                *nul=0;
                return 1;
        }
}

// https://github.com/drewlesueur/node-app/raw/34bd5f7c1ae264fdc7c538aeae70e46be17921b1/vendor/node-mysql/test/fixture/libmysql_password.c

typedef unsigned long ulong;
typedef unsigned int uint;
typedef unsigned char uchar;

struct rand_struct {
  unsigned long seed1,seed2,max_value;
  double max_value_dbl;
};

void hash_password(ulong *result, const char *password, uint password_len)
{
  register ulong nr=1345345333L, add=7, nr2=0x12345671L;
  ulong tmp;
  const char *password_end= password + password_len;
  for (; password < password_end; password++)
  {
    if (*password == ' ' || *password == '\t')
      continue;                                 /* skip space in password */
    tmp= (ulong) (uchar) *password;
    nr^= (((nr & 63)+add)*tmp)+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=tmp;
  }
  result[0]=nr & (((ulong) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
  result[1]=nr2 & (((ulong) 1L << 31) -1L);
}

void randominit(struct rand_struct *rand_st, ulong seed1, ulong seed2)
{                                               /* For mysql 3.21.# */
#ifdef HAVE_purify
  bzero((char*) rand_st,sizeof(*rand_st));      /* Avoid UMC varnings */
#endif
  rand_st->max_value= 0x3FFFFFFFL;
  rand_st->max_value_dbl=(double) rand_st->max_value;
  rand_st->seed1=seed1%rand_st->max_value ;
  rand_st->seed2=seed2%rand_st->max_value;
}

double my_rnd(struct rand_struct *rand_st)
{
  rand_st->seed1=(rand_st->seed1*3+rand_st->seed2) % rand_st->max_value;
  rand_st->seed2=(rand_st->seed1+rand_st->seed2+33) % rand_st->max_value;
  return (((double) rand_st->seed1)/rand_st->max_value_dbl);
}

void scramble_323(char *to, const char *message, const char *password)
{
  struct rand_struct rand_st;
  ulong hash_pass[2], hash_message[2];

  if (password && password[0])
  {
    char extra, *to_start=to;
    const char *message_end= message + SCRAMBLE_LENGTH_323;
    hash_password(hash_pass,password, (uint) strlen(password));
    hash_password(hash_message, message, SCRAMBLE_LENGTH_323);
    randominit(&rand_st,hash_pass[0] ^ hash_message[0],
               hash_pass[1] ^ hash_message[1]);
    for (; message < message_end; message++)
      *to++= (char) (floor(my_rnd(&rand_st)*31)+64);
    extra=(char) (floor(my_rnd(&rand_st)*31));
    while (to_start != to)
      *(to_start++)^=extra;
  }
  *to= 0;
}

/*
 * Genererate a new message based on message and password
 * The same thing is done in client and server and the results are checked.
 */

/* scramble for 4.1 servers
 * Code based on php_nysqlnd_scramble function from PHP's mysqlnd extension,
 * written by Andrey Hristov (andrey@php.net)
 * License: PHP License 3.0
 */
void my_crypt(unsigned char *buffer, const unsigned char *s1, const unsigned char *s2, size_t len)
{
        const unsigned char *s1_end= s1 + len;
        while (s1 < s1_end) {
                *buffer++= *s1++ ^ *s2++;
        }
}

////////////////////////////////////////////////////////////////////////////
/****************************************************************************
   Copyright (C) 2012 Monty Program AB
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA
*****************************************************************************/

#define SHA1_MAX_LENGTH 20

/* SHA1 context. */
typedef struct {
        uint32 state[5];                /* state (ABCD) */
        uint32 count[2];                /* number of bits, modulo 2^64 (lsb first) */
        unsigned char buffer[64];       /* input buffer */
} MYSQL_SHA1_CTX;

/* This code came from the PHP project, initially written by
   Stefan Esser */

/* This code is heavily based on the PHP md5 implementation */ 


static void SHA1Transform(uint32[5], const unsigned char[64]);
static void SHA1Encode(unsigned char *, uint32 *, unsigned int);
static void SHA1Decode(uint32 *, const unsigned char *, unsigned int);

static unsigned char PADDING[64] =
{
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic SHA1 functions.
 */
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((x) ^ (y) ^ (z))
#define H(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define I(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* W[i]
 */
#define W(i) ( tmp=x[(i-3)&15]^x[(i-8)&15]^x[(i-14)&15]^x[i&15], \
        (x[i&15]=ROTATE_LEFT(tmp, 1)) )  

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 */
#define FF(a, b, c, d, e, w) { \
 (e) += F ((b), (c), (d)) + (w) + (uint32)(0x5A827999); \
 (e) += ROTATE_LEFT ((a), 5); \
 (b) = ROTATE_LEFT((b), 30); \
  }
#define GG(a, b, c, d, e, w) { \
 (e) += G ((b), (c), (d)) + (w) + (uint32)(0x6ED9EBA1); \
 (e) += ROTATE_LEFT ((a), 5); \
 (b) = ROTATE_LEFT((b), 30); \
  }
#define HH(a, b, c, d, e, w) { \
 (e) += H ((b), (c), (d)) + (w) + (uint32)(0x8F1BBCDC); \
 (e) += ROTATE_LEFT ((a), 5); \
 (b) = ROTATE_LEFT((b), 30); \
  }
#define II(a, b, c, d, e, w) { \
 (e) += I ((b), (c), (d)) + (w) + (uint32)(0xCA62C1D6); \
 (e) += ROTATE_LEFT ((a), 5); \
 (b) = ROTATE_LEFT((b), 30); \
  }
                                            

/* {{{ MYSQL_SHA1Init
 * SHA1 initialization. Begins an SHA1 operation, writing a new context.
 */
void MYSQL_SHA1Init(MYSQL_SHA1_CTX * context)
{
        context->count[0] = context->count[1] = 0;
        /* Load magic initialization constants.
         */
        context->state[0] = 0x67452301;
        context->state[1] = 0xefcdab89;
        context->state[2] = 0x98badcfe;
        context->state[3] = 0x10325476;
        context->state[4] = 0xc3d2e1f0;
}
/* }}} */

/* {{{ MYSQL_SHA1Update
   SHA1 block update operation. Continues an SHA1 message-digest
   operation, processing another message block, and updating the
   context.
 */
void MYSQL_SHA1Update(MYSQL_SHA1_CTX * context, const unsigned char *input,
                           size_t inputLen)
{
        unsigned int i, index, partLen;

        /* Compute number of bytes mod 64 */
        index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

        /* Update number of bits */
        if ((context->count[0] += ((uint32) inputLen << 3))
                < ((uint32) inputLen << 3))
                context->count[1]++;
        context->count[1] += ((uint32) inputLen >> 29);

        partLen = 64 - index;

        /* Transform as many times as possible.
         */
        if (inputLen >= partLen) {
                memcpy
                        ((unsigned char*) & context->buffer[index], (unsigned char*) input, partLen);
                SHA1Transform(context->state, context->buffer);

                for (i = partLen; i + 63 < inputLen; i += 64)
                        SHA1Transform(context->state, &input[i]);

                index = 0;
        } else
                i = 0;

        /* Buffer remaining input */
        memcpy
                ((unsigned char*) & context->buffer[index], (unsigned char*) & input[i],
                 inputLen - i);
}
/* }}} */

/* {{{ MYSQL_SHA1Final
   SHA1 finalization. Ends an SHA1 message-digest operation, writing the
   the message digest and zeroizing the context.
 */
void MYSQL_SHA1Final(unsigned char digest[20], MYSQL_SHA1_CTX * context)
{
        unsigned char bits[8];
        unsigned int index, padLen;

        /* Save number of bits */
        bits[7] = context->count[0] & 0xFF;
        bits[6] = (context->count[0] >> 8) & 0xFF;
        bits[5] = (context->count[0] >> 16) & 0xFF;
        bits[4] = (context->count[0] >> 24) & 0xFF;
        bits[3] = context->count[1] & 0xFF;
        bits[2] = (context->count[1] >> 8) & 0xFF;
        bits[1] = (context->count[1] >> 16) & 0xFF;
        bits[0] = (context->count[1] >> 24) & 0xFF;
        
        /* Pad out to 56 mod 64.
         */
        index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
        padLen = (index < 56) ? (56 - index) : (120 - index);
        MYSQL_SHA1Update(context, PADDING, padLen);

        /* Append length (before padding) */
        MYSQL_SHA1Update(context, bits, 8);

        /* Store state in digest */
        SHA1Encode(digest, context->state, 20);

        /* Zeroize sensitive information.
         */
        memset((unsigned char*) context, 0, sizeof(*context));
}
/* }}} */

/* {{{ SHA1Transform
 * SHA1 basic transformation. Transforms state based on block.
 */
static void SHA1Transform(uint32 state[5], const unsigned char block[64])
{
        uint32 a = state[0], b = state[1], c = state[2];
        uint32 d = state[3], e = state[4], x[16], tmp;

        SHA1Decode(x, block, 64);

        /* Round 1 */
        FF(a, b, c, d, e, x[0]);   /* 1 */
        FF(e, a, b, c, d, x[1]);   /* 2 */
        FF(d, e, a, b, c, x[2]);   /* 3 */
        FF(c, d, e, a, b, x[3]);   /* 4 */
        FF(b, c, d, e, a, x[4]);   /* 5 */
        FF(a, b, c, d, e, x[5]);   /* 6 */
        FF(e, a, b, c, d, x[6]);   /* 7 */
        FF(d, e, a, b, c, x[7]);   /* 8 */
        FF(c, d, e, a, b, x[8]);   /* 9 */
        FF(b, c, d, e, a, x[9]);   /* 10 */
        FF(a, b, c, d, e, x[10]);  /* 11 */
        FF(e, a, b, c, d, x[11]);  /* 12 */
        FF(d, e, a, b, c, x[12]);  /* 13 */
        FF(c, d, e, a, b, x[13]);  /* 14 */
        FF(b, c, d, e, a, x[14]);  /* 15 */
        FF(a, b, c, d, e, x[15]);  /* 16 */
        FF(e, a, b, c, d, W(16));  /* 17 */
        FF(d, e, a, b, c, W(17));  /* 18 */
        FF(c, d, e, a, b, W(18));  /* 19 */
        FF(b, c, d, e, a, W(19));  /* 20 */

        /* Round 2 */
        GG(a, b, c, d, e, W(20));  /* 21 */
        GG(e, a, b, c, d, W(21));  /* 22 */
        GG(d, e, a, b, c, W(22));  /* 23 */
        GG(c, d, e, a, b, W(23));  /* 24 */
        GG(b, c, d, e, a, W(24));  /* 25 */
        GG(a, b, c, d, e, W(25));  /* 26 */
        GG(e, a, b, c, d, W(26));  /* 27 */
        GG(d, e, a, b, c, W(27));  /* 28 */
        GG(c, d, e, a, b, W(28));  /* 29 */
        GG(b, c, d, e, a, W(29));  /* 30 */
        GG(a, b, c, d, e, W(30));  /* 31 */
        GG(e, a, b, c, d, W(31));  /* 32 */
        GG(d, e, a, b, c, W(32));  /* 33 */
        GG(c, d, e, a, b, W(33));  /* 34 */
        GG(b, c, d, e, a, W(34));  /* 35 */
        GG(a, b, c, d, e, W(35));  /* 36 */
        GG(e, a, b, c, d, W(36));  /* 37 */
        GG(d, e, a, b, c, W(37));  /* 38 */
        GG(c, d, e, a, b, W(38));  /* 39 */
        GG(b, c, d, e, a, W(39));  /* 40 */

        /* Round 3 */
        HH(a, b, c, d, e, W(40));  /* 41 */
        HH(e, a, b, c, d, W(41));  /* 42 */
        HH(d, e, a, b, c, W(42));  /* 43 */
        HH(c, d, e, a, b, W(43));  /* 44 */
        HH(b, c, d, e, a, W(44));  /* 45 */
        HH(a, b, c, d, e, W(45));  /* 46 */
        HH(e, a, b, c, d, W(46));  /* 47 */
        HH(d, e, a, b, c, W(47));  /* 48 */
        HH(c, d, e, a, b, W(48));  /* 49 */
        HH(b, c, d, e, a, W(49));  /* 50 */
        HH(a, b, c, d, e, W(50));  /* 51 */
        HH(e, a, b, c, d, W(51));  /* 52 */
        HH(d, e, a, b, c, W(52));  /* 53 */
        HH(c, d, e, a, b, W(53));  /* 54 */
        HH(b, c, d, e, a, W(54));  /* 55 */
        HH(a, b, c, d, e, W(55));  /* 56 */
        HH(e, a, b, c, d, W(56));  /* 57 */
        HH(d, e, a, b, c, W(57));  /* 58 */
        HH(c, d, e, a, b, W(58));  /* 59 */
        HH(b, c, d, e, a, W(59));  /* 60 */

        /* Round 4 */
        II(a, b, c, d, e, W(60));  /* 61 */
        II(e, a, b, c, d, W(61));  /* 62 */
        II(d, e, a, b, c, W(62));  /* 63 */
        II(c, d, e, a, b, W(63));  /* 64 */
        II(b, c, d, e, a, W(64));  /* 65 */
        II(a, b, c, d, e, W(65));  /* 66 */
        II(e, a, b, c, d, W(66));  /* 67 */
        II(d, e, a, b, c, W(67));  /* 68 */
        II(c, d, e, a, b, W(68));  /* 69 */
        II(b, c, d, e, a, W(69));  /* 70 */
        II(a, b, c, d, e, W(70));  /* 71 */
        II(e, a, b, c, d, W(71));  /* 72 */
        II(d, e, a, b, c, W(72));  /* 73 */
        II(c, d, e, a, b, W(73));  /* 74 */
        II(b, c, d, e, a, W(74));  /* 75 */
        II(a, b, c, d, e, W(75));  /* 76 */
        II(e, a, b, c, d, W(76));  /* 77 */
        II(d, e, a, b, c, W(77));  /* 78 */
        II(c, d, e, a, b, W(78));  /* 79 */
        II(b, c, d, e, a, W(79));  /* 80 */

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;

        /* Zeroize sensitive information. */
        memset((unsigned char*) x, 0, sizeof(x));
}
/* }}} */

/* {{{ SHA1Encode
   Encodes input (uint32) into output (unsigned char). Assumes len is
   a multiple of 4.
 */
static void SHA1Encode(unsigned char *output, uint32 *input, unsigned int len)
{
        unsigned int i, j;

        for (i = 0, j = 0; j < len; i++, j += 4) {
                output[j] = (unsigned char) ((input[i] >> 24) & 0xff);
                output[j + 1] = (unsigned char) ((input[i] >> 16) & 0xff);
                output[j + 2] = (unsigned char) ((input[i] >> 8) & 0xff);
                output[j + 3] = (unsigned char) (input[i] & 0xff);
        }
}
/* }}} */

/* {{{ SHA1Decode
   Decodes input (unsigned char) into output (uint32). Assumes len is
   a multiple of 4.
 */
static void SHA1Decode(uint32 *output, const unsigned char * input, unsigned int len)
{
        unsigned int i, j;

        for (i = 0, j = 0; j < len; i++, j += 4)
                output[i] = ((uint32) input[j + 3]) | (((uint32) input[j + 2]) << 8) |
                        (((uint32) input[j + 1]) << 16) | (((uint32) input[j]) << 24);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
////////////////////////////////////////////////////////////////////////////

void
scramble(const unsigned char *buffer, const char *scramble, const char *password)
{
        MYSQL_SHA1_CTX context;
        unsigned char sha1[SHA1_MAX_LENGTH];
        unsigned char sha2[SHA1_MAX_LENGTH];
        

        /* Phase 1: hash password */
        MYSQL_SHA1Init(&context);
        MYSQL_SHA1Update(&context, (unsigned char *)password, strlen((char *)password));
        MYSQL_SHA1Final(sha1, &context);

        /* Phase 2: hash sha1 */
        MYSQL_SHA1Init(&context);
        MYSQL_SHA1Update(&context, (unsigned char*)sha1, SHA1_MAX_LENGTH);
        MYSQL_SHA1Final(sha2, &context);

        /* Phase 3: hash scramble + sha2 */
        MYSQL_SHA1Init(&context);
        MYSQL_SHA1Update(&context, (unsigned char *)scramble, SCRAMBLE_LENGTH);
        MYSQL_SHA1Update(&context, (unsigned char*)sha2, SHA1_MAX_LENGTH);
        MYSQL_SHA1Final((unsigned char *)buffer, &context);

        /* let's crypt buffer now */
        my_crypt((uchar *)buffer, (const unsigned char *)buffer, (const unsigned  char *)sha1, SHA1_MAX_LENGTH);
}

static int threebytelen(unsigned char *buf) {
  int len = buf[0];
  if (buf[1]) {
    len |= ((int)(buf[1])) << 8;
  }
  if (buf[2]) {
    len |= ((int)(buf[2])) << 16;
  }
  return len;
}

///////////////////////////////////////////////////////////////////////////////

#define PACKET_TYPE_UNKNOWN                0
#define PACKET_TYPE_INITIAL_HANDSHAKE      1
#define PACKET_TYPE_LOGIN_RESULT           2
#define PACKET_TYPE_INIT_DB                3
#define PACKET_TYPE_EXECUTE_RESULT         4
#define PACKET_TYPE_SELECT_RESULT          5

#define SELECT_STATE_WANT_FIELD_COUNT   1
#define SELECT_STATE_WANT_FIELD_ITEM    2
#define SELECT_STATE_WANT_FIELD_EOF     3
#define SELECT_STATE_WANT_ROW_ITEM      4

#define ANALYZE_STATE_INIT          0
#define ANALYZE_STATE_WANT_PAYLOAD  1

#ifndef mycMin
#define mycMin(a,b) (((a) < (b)) ? (a) : (b))
#endif

static int mycPulse(myc *conn) {
  return 0;
}

static int mycSend(myc *conn, int size) {
  if (conn->isSending) {
    return -1;
  }
  to_my_3(size, conn->sendBuf);
  conn->sendBuf[3] = conn->packetNumber;
  conn->wantWriteSize = 4 + size;
  conn->isSending = 1;
  return 0;
}

static int mycFinishReq(myc *conn, int status) {
  if (conn->executeCb) {
    conn->executeCb(conn, status);
  }
  return 0;
}

int mycIsIdle(myc *conn) {
  if (!conn->logined) {
    return 0;
  }
  if (conn->isSending) {
    return 0;
  }
  if (conn->wantPacketType != PACKET_TYPE_UNKNOWN) {
    return 0;
  }
  return 1;
}

int mycQueryLimit1000(myc *conn, const char *sql, int sqlLen, mycCb cb) {
  unsigned char *payload = conn->sendBuf + 4;
  int offset = 0;
  if (!mycIsIdle(conn)) {
    return -1;
  }
  if (-1 == sqlLen) {
    sqlLen = strlen(sql);
  }
  conn->fieldCount = 0;
  conn->affectedRows = 0;
  conn->insertId = 0;
  conn->fieldIndex = 0;
  conn->rowCount = 0;
  conn->resOffset = 0;
  conn->selectState = SELECT_STATE_WANT_FIELD_COUNT;
  conn->wantPacketType = PACKET_TYPE_SELECT_RESULT;
  payload[offset] = COM_QUERY;
  offset += 1;
  assert(sqlLen <= sizeof(conn->sendBuf) - 4 - 1);
  memcpy(payload + offset, sql, sqlLen);
  offset += sqlLen;
  conn->packetNumber = 0;
  conn->executeCb = cb;
  return mycSend(conn, offset);
}

int mycExecute(myc *conn, const char *sql, int sqlLen, mycCb cb) {
  unsigned char *payload = conn->sendBuf + 4;
  int offset = 0;
  if (!mycIsIdle(conn)) {
    return -1;
  }
  if (-1 == sqlLen) {
    sqlLen = strlen(sql);
  }
  conn->wantPacketType = PACKET_TYPE_EXECUTE_RESULT;
  payload[offset] = COM_QUERY;
  offset += 1;
  assert(sqlLen <= sizeof(conn->sendBuf) - 4 - 1);
  memcpy(payload + offset, sql, sqlLen);
  offset += sqlLen;
  conn->packetNumber = 0;
  conn->executeCb = cb;
  return mycSend(conn, offset);
}

static int mycSendHandshakeRespPacket(myc *conn) {
  unsigned char *payload = conn->sendBuf + 4;
  unsigned short flags = 0;
  unsigned short extendedFlags = 0;
  unsigned int maxSendSize = sizeof(conn->sendBuf);
  unsigned char charset = conn->charset;
  int loginNameLen = strlen(conn->username);
  int dbNameLen = strlen(conn->dbname);
  int offset = 0;
  
  if (conn->isSending) {
    return -1;
  }
  
  if (conn->options & CLIENT_LONG_PASSWORD) {
    flags |= CLIENT_LONG_PASSWORD;
  }
  flags |= CLIENT_LONG_FLAG | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
  to_my_2(flags, &payload[offset]);
  offset += 2;
  
  to_my_2(extendedFlags, &payload[offset]);
  offset += 2;
  
  to_my_4(maxSendSize, &payload[offset]);
  offset += 4;
  
  payload[offset] = charset;
  offset += 1;
  
  memset(payload + offset, 0, 23);
  offset += 23;
  
  memcpy(payload + offset, conn->username, 
      loginNameLen + 1);
  offset += loginNameLen + 1;
  
  if (conn->options & CLIENT_SECURE_CONNECTION) {
    payload[offset] = SCRAMBLE_LENGTH;
    offset += 1;
    
    scramble((char *)&payload[offset], conn->salt, conn->password);
    offset += SCRAMBLE_LENGTH;
  } else {
    scramble_323((char *)&payload[offset], conn->salt, conn->password);
    offset += SCRAMBLE_LENGTH_323 + 1;
  }
  
  memcpy(payload + offset, conn->dbname, 
      dbNameLen + 1);
  offset += dbNameLen + 1;

  return mycSend(conn, offset);
}

static int mycReadErrorInfo(myc *conn, const unsigned char *payload, 
    int payloadLen, int offset) {
    int errLen = 0;
  conn->mysqlErrCode = uint2korr(&payload[offset]);
  offset += 2;
  
  offset += 1;
  
  offset += 5;

  if (offset < payloadLen) {
    int errLen = mycMin((payloadLen - offset - 1), 
        sizeof(conn->mysqlErrMsg) - 1);
    if (errLen < 0) {
      errLen = 0;
    }
    memcpy(conn->mysqlErrMsg, payload + offset, errLen);
  }
  conn->mysqlErrMsg[errLen] = '\0';
  return offset;
}

static int mycSendOldScrambledPassword(myc *conn) {
  unsigned char *payload = conn->sendBuf + 4;
  int offset = 0;
  
  if (conn->isSending) {
    return -1;
  }
  
  scramble_323((char *)&payload[offset], conn->salt, conn->password);
  offset += SCRAMBLE_LENGTH_323 + 1;
  
  return mycSend(conn, offset);
}

static int mycSendInitDbPacket(myc *conn) {
  unsigned char *payload = conn->sendBuf + 4;
  int offset = 0;
  int dbnameLen = strlen(conn->dbname);
  
  if (conn->isSending) {
    return -1;
  }
  
  payload[offset] = COM_INIT_DB;
  offset += 1;
  
  assert(dbnameLen <= sizeof(conn->sendBuf) - 4 - 1);
  memcpy(payload + offset, conn->dbname, dbnameLen);
  offset += dbnameLen;
  
  conn->packetNumber = 0;
  
  return mycSend(conn, offset);
}

static int mycProcessPacket(myc *conn, unsigned char seqId,
    const unsigned char *payload, int payloadLen) {
  conn->packetNumber = seqId + 1;
  switch (conn->wantPacketType) {
    case PACKET_TYPE_INITIAL_HANDSHAKE: {
        const char *version;
        int offset = 0;
        unsigned int threadId;
        unsigned short highOptions;
        
        if (payloadLen < 1) {
          fprintf(stderr, "%s: <PACKET_TYPE_INITIAL_HANDSHAKE> payloadLen < 1, payloadLen:%d\n",
              __FUNCTION__, payloadLen);
          return -1;
        }
        
        conn->protocol = payload[offset];
        if (PROTOCOL_VERSION != conn->protocol) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_INITIAL_HANDSHAKE> PROTOCOL_VERSION != conn->protocol, conn->protocol:%d\n",
              __FUNCTION__, conn->protocol);
          return -1;
        }
        offset += 1;
        
        version = (char *)payload + offset;
        offset += strlen(version) + 1;
        
        threadId = uint4korr(&payload[offset]);
        offset += 4;
        
        memcpy(conn->salt, payload + offset, SCRAMBLE_LENGTH_323);
        conn->salt[SCRAMBLE_LENGTH_323] = '\0';
        offset += SCRAMBLE_LENGTH_323;
        
        offset += 1;
        
        conn->options = uint2korr(&payload[offset]);
        offset += 2;
        
        conn->charset = payload[offset];
        offset += 1;
        
        conn->status = uint2korr(&payload[offset]);
        offset += 2;
        
        highOptions = uint2korr(&payload[offset]);
        offset += 2;
        
        offset += 1;
        
        offset += 10;
        
        memcpy(conn->salt + SCRAMBLE_LENGTH_323, 
            payload + offset, SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323);
        conn->salt[SCRAMBLE_LENGTH] = '\0';
        offset += SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323;
        
        if (0 != mycSendHandshakeRespPacket(conn)) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_INITIAL_HANDSHAKE> 0 != mycSendHandshakeRespPacket\n",
              __FUNCTION__);
          return -1;
        }
        
        fprintf(stderr, 
            "%s: <PACKET_TYPE_INITIAL_HANDSHAKE>\n",
            __FUNCTION__);
        
        conn->wantPacketType = PACKET_TYPE_LOGIN_RESULT;
        
        return 0;
      } break;
    case PACKET_TYPE_INIT_DB: {
        int offset = 0;
        unsigned char result;
        
        if (payloadLen < 1) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_INIT_DB> payloadLen < 1, payloadLen:%d\n",
              __FUNCTION__, payloadLen);
          return -1;
        }
        
        conn->mysqlErrCode = 0;
        conn->mysqlErrMsg[0] = '\0';
        
        result = payload[offset];
        offset += 1;

        if (0xff == result) {
          offset = mycReadErrorInfo(conn, payload, payloadLen, offset);
        }
        
        if (0x00 != result) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_INIT_DB> 0x00 != result, result:%d mysqlErrCode:%d mysqlErMsg:%s\n",
              __FUNCTION__, result, conn->mysqlErrCode, conn->mysqlErrMsg);
          return -1;
        }
        
        fprintf(stderr, 
            "%s: <PACKET_TYPE_INIT_DB>\n",
            __FUNCTION__);
        
        conn->logined = 1;
        conn->wantPacketType = PACKET_TYPE_UNKNOWN;
        return mycPulse(conn);
      } break;
    case PACKET_TYPE_LOGIN_RESULT: {
        int offset = 0;
        unsigned char result;
        
        if (payloadLen < 1) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_LOGIN_RESULT> payloadLen < 1, payloadLen:%d\n",
              __FUNCTION__, payloadLen);
          return -1;
        }
        
        conn->mysqlErrCode = 0;
        conn->mysqlErrMsg[0] = '\0';
        
        result = payload[offset];
        offset += 1;
            
        if (1 == payloadLen && 0xfe == result) {
          if (CLIENT_SECURE_CONNECTION & conn->options) {
            if (0 != mycSendOldScrambledPassword(conn)) {
              return -1;
            }
            return 0;
          }
        }
        
        if (0xff == result) {
          offset = mycReadErrorInfo(conn, payload, payloadLen, offset);
        }
          
        if (0x00 != result) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_LOGIN_RESULT> 0x00 != result, result:%d mysqlErrCode:%d mysqlErMsg:%s\n",
              __FUNCTION__, result, conn->mysqlErrCode, conn->mysqlErrMsg);
          return -1;
        }
        
        if (0 != mycSendInitDbPacket(conn)) {
          return -1;
        }
        
        fprintf(stderr, 
            "%s: <PACKET_TYPE_LOGIN_RESULT>\n",
            __FUNCTION__);
        
        conn->wantPacketType = PACKET_TYPE_INIT_DB;
        
        return mycPulse(conn);
      } break;
    case PACKET_TYPE_EXECUTE_RESULT: {
        int offset = 0;
        unsigned char result;
        
        if (payloadLen < 1) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_EXECUTE_RESULT> payloadLen < 1, payloadLen:%d\n",
              __FUNCTION__, payloadLen);
          return -1;
        }
        
        conn->mysqlErrCode = 0;
        conn->mysqlErrMsg[0] = '\0';
        
        conn->affectedRows = 0;
        conn->insertId = 0;
        
        result = payload[offset];
        offset += 1;
        
        if (0xff == result) {
          offset = mycReadErrorInfo(conn, payload, payloadLen, offset);
        }
        
        fprintf(stderr, 
            "%s: <PACKET_TYPE_EXECUTE_RESULT>\n",
            __FUNCTION__);
        
        if (0x00 == result) {
          char nul;
          int consumeLen;
          
          consumeLen = my_lcb_ll(&payload[offset], 
              &conn->affectedRows, &nul, payloadLen - offset);
          if (consumeLen < 0) {
            fprintf(stderr, 
                "%s: <PACKET_TYPE_EXECUTE_RESULT> my_lcb_ll affectedRows consumeLen < 0\n",
                __FUNCTION__);
            return -1;
          }
          offset += consumeLen;
          
          consumeLen = my_lcb_ll(&payload[offset], 
              &conn->insertId, &nul, payloadLen - offset);
          if (consumeLen < 0) {
            fprintf(stderr, 
                "%s: <PACKET_TYPE_EXECUTE_RESULT> my_lcb_ll insertId consumeLen < 0\n",
                __FUNCTION__);
            return -1;
          }
          offset += consumeLen;
        }
        
        conn->wantPacketType = PACKET_TYPE_UNKNOWN;
        return mycFinishReq(conn, 0);
      } break;
    case PACKET_TYPE_SELECT_RESULT: {
        int offset = 0;
        unsigned char result;
        
        if (payloadLen < 1) {
          fprintf(stderr, 
              "%s: <PACKET_TYPE_EXECUTE_RESULT> payloadLen < 1, payloadLen:%d\n",
              __FUNCTION__, payloadLen);
          return -1;
        }
        
        conn->mysqlErrCode = 0;
        conn->mysqlErrMsg[0] = '\0';

        result = payload[offset];
        offset += 1;
        
        if (0xff == result) {
          offset = mycReadErrorInfo(conn, payload, payloadLen, offset);
          conn->wantPacketType = PACKET_TYPE_UNKNOWN;
          return mycFinishReq(conn, -1);
        }
        
        fprintf(stderr, 
            "%s: <PACKET_TYPE_SELECT_RESULT>\n",
            __FUNCTION__);
        
        switch (conn->selectState) {
          case SELECT_STATE_WANT_FIELD_COUNT: {
              if (0x00 == result) {
                conn->wantPacketType = PACKET_TYPE_UNKNOWN;
                return mycFinishReq(conn, 0);
              } else {
                char nul;
                int consumeLen;
                unsigned long long bigint = 0;
                
                offset -= 1;
                
                consumeLen = my_lcb_ll(&payload[offset], 
                    &bigint, &nul, payloadLen - offset);
                if (consumeLen < 0) {
                  fprintf(stderr, 
                      "%s: <SELECT_STATE_WANT_FIELD_COUNT> my_lcb_ll fieldCount consumeLen < 0\n",
                      __FUNCTION__);
                  return -1;
                }
                
                conn->fieldCount = (int)bigint;
                conn->selectState = SELECT_STATE_WANT_FIELD_ITEM;
                    
                return 0;
              }
            } break;
          case SELECT_STATE_WANT_FIELD_ITEM: {
              if (conn->fieldIndex < conn->fieldCount) {
                ++conn->fieldIndex;
                if (conn->fieldIndex == conn->fieldCount) {
                  conn->selectState = SELECT_STATE_WANT_FIELD_EOF;
                  return 0;
                }
                return 0;
              }
              fprintf(stderr, 
                  "%s: <SELECT_STATE_WANT_FIELD_ITEM> fieldIndex >= fieldCount, fieldIndex:%d fieldCount:%d\n",
                  __FUNCTION__, conn->fieldIndex, conn->fieldCount);
              return -1;
            } break;
          case SELECT_STATE_WANT_FIELD_EOF: {
              if (0xfe == result) {
                conn->selectState = SELECT_STATE_WANT_ROW_ITEM;
                return 0;
              }
              fprintf(stderr, 
                  "%s: <SELECT_STATE_WANT_FIELD_EOF> want field eof but result:%u\n",
                  __FUNCTION__, result);
              return -1;
            } break;
          case SELECT_STATE_WANT_ROW_ITEM: {
              int col;
              if (0xfe == result) {
                conn->wantPacketType = PACKET_TYPE_UNKNOWN;
                return mycFinishReq(conn, 0);
              }
              offset -= 1;
              if (conn->rowCount + 1 > MYC_MAX_ROW) {
                fprintf(stderr, 
                  "%s: <SELECT_STATE_WANT_ROW_ITEM> rows exceeded\n",
                  __FUNCTION__);
                return -1;
              }
              for (col = 0; col < conn->fieldCount && col < MYC_MAX_COL; ++col) {
                char nul;
                int consumeLen;
                unsigned long long rowStrLen = 0;
                if (offset >= payloadLen) {
                  fprintf(stderr, 
                    "%s: <SELECT_STATE_WANT_ROW_ITEM> col(%d) offset(%d) >= payloadLen(%d)\n",
                    __FUNCTION__, col, offset, payloadLen);
                  return -1;
                }
                consumeLen = my_lcb_ll(&payload[offset], 
                    &rowStrLen, &nul, payloadLen - offset);
                if (consumeLen < 0) {
                  fprintf(stderr, 
                    "%s: <SELECT_STATE_WANT_ROW_ITEM> read col(%d) failed\n",
                    __FUNCTION__, col);
                  return -1;
                }
                offset += consumeLen;
                if (nul) {
                  conn->rows[conn->rowCount][col] = 0;
                } else {
                  if (conn->resOffset + (int)rowStrLen + 1 > 
                      sizeof(conn->resBuf)) {
                    fprintf(stderr, 
                        "%s: <SELECT_STATE_WANT_ROW_ITEM> resBuf exceeded\n",
                        __FUNCTION__);
                    return -1;
                  }
                  conn->rows[conn->rowCount][col] = &conn->resBuf[conn->resOffset];
                  
                  memcpy(&conn->resBuf[conn->resOffset],
                      (char *)payload + offset,
                      (int)rowStrLen);
                  conn->resOffset += (int)rowStrLen;
                  
                  conn->resBuf[conn->resOffset] = '\0';
                  conn->resOffset += 1;
                  
                  offset += (int)rowStrLen;
                }
              }
              ++conn->rowCount;
              return 0;
            } break;
          default: {
              fprintf(stderr, 
                  "%s: <SELECT_STATE_WANT_ROW_ITEM> unknown selectState(%d)\n",
                  __FUNCTION__, conn->selectState);
              return -1;
            }
        }
      } break;
  default: {
        fprintf(stderr, 
            "%s: unknown wantPacketType(%d)\n",
            __FUNCTION__, conn->wantPacketType);
        return -1;
      }
  }
  assert(0);
}

void mycInit(myc *conn, unsigned char charset, const char *username,
    const char *password, const char *dbname) {
  void *data = conn->data;
  memset(conn, 0, sizeof(myc));
  conn->data = data;
  conn->charset = charset;
  strcpy(conn->username, username);
  strcpy(conn->password, password);
  strcpy(conn->dbname, dbname);
  conn->wantPacketType = PACKET_TYPE_INITIAL_HANDSHAKE;
}

void mycReset(myc *conn) {
  void *data;
  int ignoreSize = (char *)&conn->mysqlErrCode - (char *)conn;
  data = conn->data;
  memset((char *)conn + ignoreSize, 0, sizeof(myc) - ignoreSize);
  conn->data = data;
}

int mycRead(myc *conn, char *data, int size) {
  if (conn->recvOffset + size > sizeof(conn->recvBuf)) {
    fprintf(stderr, 
        "%s: conn->recvOffset(%d) + size(%d) > sizeof(conn->recvBuf)",
        __FUNCTION__, conn->recvOffset, size);
    return -1;
  }
  memcpy(conn->recvBuf + conn->recvOffset, data, size);
  conn->recvOffset += size;
  while (conn->recvOffset - conn->analyzeOffset) {
    switch (conn->analyzeState) {
      case ANALYZE_STATE_INIT: {
          if ((conn->recvOffset - conn->analyzeOffset) >= 4) {
            conn->payloadLen = threebytelen(conn->recvBuf + 
                                    conn->analyzeOffset);
            conn->payloadReadOffset = 0;
            conn->seqId = conn->recvBuf[3];
            conn->analyzeOffset += 4;
            conn->analyzeState = ANALYZE_STATE_WANT_PAYLOAD;
          } else {
            return 0;
          }
        } break;
      case ANALYZE_STATE_WANT_PAYLOAD: {
          int once = mycMin((conn->payloadLen - conn->payloadReadOffset),
              (conn->recvOffset - conn->analyzeOffset));
          conn->payloadReadOffset += once;
          conn->analyzeOffset += once;
          
          if (conn->payloadReadOffset == conn->payloadLen) {
            if (0 != mycProcessPacket(conn, conn->seqId, conn->recvBuf + 4,
                conn->payloadLen)) {
              return -1;
            }
            conn->analyzeState = ANALYZE_STATE_INIT;
            if (conn->analyzeOffset > 0) {
              if (conn->recvOffset - conn->analyzeOffset > 0) {
                memmove(conn->recvBuf,
                    conn->recvBuf + conn->analyzeOffset,
                    conn->recvOffset - conn->analyzeOffset);
              }
              conn->recvOffset -= conn->analyzeOffset;
              conn->analyzeOffset = 0;
            }
          }
        } break;
      default: {
          return 0;
        }
    }
  }
  return 0;
}

int mycWantWriteSize(myc *conn) {
  if (!conn->isSending) {
    return 0;
  }
  return conn->wantWriteSize;
}

char *mycWantWriteData(myc *conn) {
  return (char *)conn->sendBuf;
}

int mycFinishWrite(myc *conn) {
  conn->isSending = 0;
  conn->wantWriteSize = 0;
  return mycPulse(conn);
}

int mycGetFieldCount(myc *conn) {
  return conn->fieldCount;
}

int mycGetRowCount(myc *conn) {
  return conn->rowCount;
}

long long mycGetRowNumber(myc *conn, int row, int column) {
  const char *val = mycGetRowString(conn, row, column);
  return strtoll(val, 0, 10);
}
    
const char *mycGetRowString(myc *conn, int row, int column) {
  const char *val;
  assert(row >= 0 && row < conn->rowCount);
  assert(column < conn->fieldCount && column < MYC_MAX_COL);
  val = conn->rows[row][column];
  if (val) {
    return val;
  }
  return "";
}

unsigned long long mycGetInsertId(myc *conn) {
  return conn->insertId;
}
    
unsigned long long mycGetAffectedRows(myc *conn) {
  return conn->affectedRows;
}

const char *mycGetMysqlErrMsg(myc *conn) {
  return conn->mysqlErrMsg;
}

int mycGetMysqlErrCode(myc *conn) {
  return conn->mysqlErrCode;
}

