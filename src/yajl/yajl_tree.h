/*
 * Copyright (c) 2010-2011  Florian Forster  <ff at octo.it>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

/**
 * Parses JSON data and returns the data in tree form.
 *
 * Writtan by Florian Forster
 *
 * August 2010
 *
 * This interface makes quick parsing and extraction of smallish JSON docs
 * trivial, as shown in the following example:
 *
 * +html+ <a href="../../example/parse_config.c.html#file">example/parse_config.c</a><br>
 * +html+ <hr>
 **/

#ifndef YAJL_TREE_H
#define YAJL_TREE_H 1

#include <yajl/yajl_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*+ an optional hook to allow use of custom yajl_alloc_funcs with yajl_tree_parse() +*/
extern YAJL_API yajl_alloc_funcs *yajl_tree_parse_afs;

/*+ possible data types that a yajl_val_s can hold +*/
typedef enum {
    yajl_t_string = 1,
    yajl_t_number = 2,
    yajl_t_object = 3,
    yajl_t_array = 4,
    yajl_t_true = 5,
    yajl_t_false = 6,
    yajl_t_null = 7,
    /*+
     * The <any> type isn't valid for yajl_val_s.type, but can be
     * used as an argument to routines like yajl_tree_get().
     +*/
    yajl_t_any = 8
} yajl_type;

#define YAJL_NUMBER_INT_VALID    0x01
#define YAJL_NUMBER_DOUBLE_VALID 0x02

/*+ A pointer to a node in the parse tree +*/
typedef struct yajl_val_s * yajl_val;

/*+
 * A JSON value representation capable of holding one of the seven types above.
 * For "string", "number", "object", and "array" additional data is available in
 * the union.  The "YAJL_IS_*" and "YAJL_GET_*" macros below allow type checking
 * and convenient value extraction.
 +*/
struct yajl_val_s
{
    /*+
     * Type of the value contained. Use the "YAJL_IS_*" macros to check for a
     * specific type.
     +*/
    yajl_type type;
    /*+
     * Type-specific data. You may use the "YAJL_GET_*" macros to access these
     * members.
     +*/
    union
    {
        char *string;
        /*+
         * Integers and doubles are combined into one representation as a
         * yajl_t_number, while also keeping the original string form available.
         *
         * While there are some advantages to this amalgamation, it does
         * complicate extracting the values.
         *
         * Normally every integer will also be available as a double, provided
         * it is within the range of integers representable by a double.
         *
         * However care must be taken to always check if the desired value is
         * valid by examining the flags field.
         +*/
        struct {
            long long i; /*+ integer value, if representable. +*/
            double  d;   /*+ double value, if representable. +*/
            char   *r;   /*+ unparsed number in string form. +*/
            /*+
             * Signals whether the .i and .d members are valid.  See
             * YAJL_NUMBER_INT_VALID() and YAJL_NUMBER_DOUBLE_VALID().
             +*/
            unsigned int flags;
        } number;
        struct {
            const char **keys; /*+ Array of keys +*/
            yajl_val *values; /*+ Array of values. +*/
            size_t len; /*+ Number of key-value-pairs. +*/
        } object;
        struct {
            yajl_val *values; /*+ Array of elements. +*/
            size_t len; /*+ Number of elements. +*/
        } array;
    } u;
};

YAJL_API yajl_val yajl_tree_parse (const char *input,
                                   char *error_buffer, size_t error_buffer_size);
YAJL_API void yajl_tree_free (yajl_val v);
YAJL_API yajl_val yajl_tree_get(yajl_val parent, const char ** path, yajl_type type);

/* Various convenience macros to check the type of a `yajl_val` */
#define YAJL_IS_STRING(v) (((v) != NULL) && ((v)->type == yajl_t_string))
#define YAJL_IS_NUMBER(v) (((v) != NULL) && ((v)->type == yajl_t_number))
#define YAJL_IS_INTEGER(v) (YAJL_IS_NUMBER(v) && ((v)->u.number.flags & YAJL_NUMBER_INT_VALID))
#define YAJL_IS_DOUBLE(v) (YAJL_IS_NUMBER(v) && ((v)->u.number.flags & YAJL_NUMBER_DOUBLE_VALID))
#define YAJL_IS_OBJECT(v) (((v) != NULL) && ((v)->type == yajl_t_object))
#define YAJL_IS_ARRAY(v)  (((v) != NULL) && ((v)->type == yajl_t_array ))
#define YAJL_IS_TRUE(v)   (((v) != NULL) && ((v)->type == yajl_t_true  ))
#define YAJL_IS_FALSE(v)  (((v) != NULL) && ((v)->type == yajl_t_false ))
#define YAJL_IS_NULL(v)   (((v) != NULL) && ((v)->type == yajl_t_null  ))

/*+ Given a yajl_val_string return a ptr to the bare string it contains,
 *  or NULL if the value is not a string. +*/
#define YAJL_GET_STRING(v) (YAJL_IS_STRING(v) ? (v)->u.string : NULL)

/*+ Get the string representation of a number.  You should check type first,
 *  perhaps using YAJL_IS_NUMBER +*/
#define YAJL_GET_NUMBER(v) ((v)->u.number.r)

/*+ Get the double representation of a number.  You should check type first,
 *  perhaps using YAJL_IS_DOUBLE +*/
#define YAJL_GET_DOUBLE(v) ((v)->u.number.d)

/*+ Get the 64bit (long long) integer representation of a number.  You should
 *  check type first, perhaps using YAJL_IS_INTEGER +*/
#define YAJL_GET_INTEGER(v) ((v)->u.number.i)

/*+ Get a pointer to a yajl_val_object or NULL if the value is not an object. +*/
#define YAJL_GET_OBJECT(v) (YAJL_IS_OBJECT(v) ? &(v)->u.object : NULL)

/*+ Get a pointer to a yajl_val_array or NULL if the value is not an object. +*/
#define YAJL_GET_ARRAY(v)  (YAJL_IS_ARRAY(v)  ? &(v)->u.array  : NULL)

#ifdef __cplusplus
}
#endif

#endif /* YAJL_TREE_H */
