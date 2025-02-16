/*
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
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

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(DBL_DIG)
# if defined(__DBL_DIG__)
#  define DBL_DIG	__DBL_DIG__
# else
#  define DBL_DIG	15		/* assumes binary64 IEEE 754 double */
# endif
#endif

/* memory debugging routines and other context */
typedef struct
{
    unsigned int do_printfs:1;
    unsigned int numFrees;
    unsigned int numMallocs;
    /* XXX: we really need a hash table here with per-allocation
     *      information */
} yajlTestMemoryContext;

/* cast void * into context */
#define TEST_CTX(vptr) ((yajlTestMemoryContext *) (vptr))

static void
yajlTestFree(void *ctx,
             void *ptr)
{
    assert(ptr != NULL);
    TEST_CTX(ctx)->numFrees++;
    free(ptr);
}

static void *
yajlTestMalloc(void *ctx,
               size_t sz)
{
    assert(sz != 0);
    TEST_CTX(ctx)->numMallocs++;
    return malloc(sz);
}

static void *
yajlTestRealloc(void *ctx,
                void *ptr,
                size_t sz)
{
    if (ptr == NULL) {
        assert(sz != 0);
        TEST_CTX(ctx)->numMallocs++;
    } else if (sz == 0) {
        TEST_CTX(ctx)->numFrees++;
    }

    return realloc(ptr, sz);
}


/* begin parsing callback routines */

static int
test_yajl_null(void *ctx)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("null\n");
    }
    return 1;
}

static int
test_yajl_boolean(void *ctx,
                  int boolVal)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("bool: %s\n", boolVal ? "true" : "false");
    }
    return 1;
}

static int
test_yajl_integer(void *ctx,
                  long long integerVal)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("integer: %lld\n", integerVal);
    }
    return 1;
}

static int
test_yajl_double(void *ctx,
                 double doubleVal)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("double: %.*g\n", DBL_DIG, doubleVal);
    }
    return 1;
}

static int
test_yajl_string(void *ctx,
                 const unsigned char *stringVal,
                 size_t stringLen)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("string: '");
        fwrite(stringVal, (size_t) 1, stringLen, stdout);
        printf("'\n");
    }
    return 1;
}

static int
test_yajl_map_key(void *ctx,
                  const unsigned char *stringVal,
                  size_t stringLen)
{
    if (TEST_CTX(ctx)->do_printfs) {
        char * str = (char *) malloc(stringLen + 1);
        str[stringLen] = 0;
        memcpy(str, stringVal, stringLen);
        printf("key: '%s'\n", str);
        free(str);
    }
    return 1;
}

static int
test_yajl_start_map(void *ctx)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("map open '{'\n");
    }
    return 1;
}


static int
test_yajl_end_map(void *ctx)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("map close '}'\n");
    }
    return 1;
}

static int
test_yajl_start_array(void *ctx)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("array open '['\n");
    }
    return 1;
}

static int
test_yajl_end_array(void *ctx)
{
    if (TEST_CTX(ctx)->do_printfs) {
        printf("array close ']'\n");
    }
    return 1;
}

static yajl_callbacks callbacks = {
    test_yajl_null,
    test_yajl_boolean,
    test_yajl_integer,
    test_yajl_double,
    NULL,
    test_yajl_string,
    test_yajl_start_map,
    test_yajl_map_key,
    test_yajl_end_map,
    test_yajl_start_array,
    test_yajl_end_array
};

#ifndef EXIT_USAGE
# define EXIT_USAGE	2
#endif

static void
usage(const char *progname)
{
    fprintf(stderr,
            "usage:  %s [options] [file.json]\n"
            "Parse input from stdin as JSON and ouput parsing details "
                                                          "to stdout\n"
            "   -b  set the read buffer size\n"
            "   -c  allow comments\n"
            "   -g  allow garbage after valid JSON text\n"
            "   -m  allow the parser to consume multiple JSON values\n"
            "       from a single stream separated by whitespace\n"
            "   -N  do not print tokens or values\n"
            "   -p  partial JSON documents should not cause errors\n",
            progname);
    exit(EXIT_USAGE);
}

int
main(int argc, char **argv)
{
    yajl_handle hand;
    const char *fileName = NULL;
    static unsigned char *fileData = NULL;
    FILE *file;
    size_t bufSize = BUFSIZ;
    yajl_status stat;
    size_t rd;
    int i, j;
    bool set_allow_comments = false;
    bool set_allow_garbage = false;
    bool set_allow_multi = false;
    bool set_allow_partial = false;

    /* memory allocation debugging: allocate a structure which holds
     * allocation routines */
    yajl_alloc_funcs allocFuncs = {
        yajlTestMalloc,
        yajlTestRealloc,
        yajlTestFree,
        (void *) NULL
    };

    /* memory allocation debugging: allocate a structure which collects
     * statistics */
    yajlTestMemoryContext memCtx;

    memCtx.do_printfs = 1;
    memCtx.numMallocs = 0;
    memCtx.numFrees = 0;

    allocFuncs.ctx = (void *) &memCtx;

    /* check arguments... so lame... xxx convert to getopt() */
    for (i = 1; i < argc; i++) {
        if (!strcmp("-D", argv[i])) {
            memCtx.do_printfs = true;
        } else if (!strcmp("-c", argv[i])) {
            set_allow_comments = true;
        } else if (!strcmp("-b", argv[i])) {
            if (++i >= argc) {
                usage(argv[0]);
            }

            /* validate integer */
            for (j=0;j<(int)strlen(argv[i]);j++) {
                if (argv[i][j] <= '9' && argv[i][j] >= '0') continue;
                fprintf(stderr, "-b requires an integer argument.  '%s' "
                        "is invalid\n", argv[i]);
                usage(argv[0]);
            }

            bufSize = (size_t) atoi(argv[i]);
            if (!bufSize) {
                fprintf(stderr, "%zu is an invalid buffer size\n",
                        bufSize);
            }
        } else if (!strcmp("-g", argv[i])) {
            set_allow_garbage = true;
        } else if (!strcmp("-m", argv[i])) {
            set_allow_multi = true;
        } else if (!strcmp("-p", argv[i])) {
            set_allow_partial = true;
        } else {
            fileName = argv[i];
            break;
        }
    }

    /* allocate a parser */
    hand = yajl_alloc(&callbacks, &allocFuncs, (void *) &memCtx);

    /* configure the parser */
    if (set_allow_comments) {
        yajl_config(hand, yajl_allow_comments, 1);
    }
    if (set_allow_garbage) {
        yajl_config(hand, yajl_allow_trailing_garbage, 1);
    }
    if (set_allow_multi) {
        yajl_config(hand, yajl_allow_multiple_values, 1);
    }
    if (set_allow_partial) {
        yajl_config(hand, yajl_allow_partial_values, 1);
    }

    fileData = (unsigned char *) malloc(bufSize + 1);
    if (fileData == NULL) {
        fprintf(stderr,
                "failed to allocate read buffer of %zu bytes, exiting.",
                bufSize);
        exit(EXIT_FAILURE);
    }

    if (fileName) {
        file = fopen(fileName, "r");
        if (file == NULL) {
            fprintf(stderr, "error opening '%s': %s\n",
                    fileName, strerror(errno));
            exit(EXIT_FAILURE);
        }
    } else {
        file = stdin;
        fileName = "stdin";
    }
    for (;;) {
        rd = fread(fileData, (size_t) 1, bufSize, file);
        if (rd == 0) {
            if (ferror(file)) {
                fprintf(stderr, "%s: error encountered: %s\n",
                        fileName, strerror(errno));
                exit(EXIT_FAILURE);
            } else if (!feof(file)) {
                fprintf(stderr, "%s: error before EOF: %s\n",
                        fileName, strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;
        }
        fileData[rd] = '\0';

        /* read file data, now pass to parser */
        stat = yajl_parse(hand, fileData, rd);

        if (stat != yajl_status_ok) {
            break;
        }
    }
    if (stat == yajl_status_ok) {
        stat = yajl_complete_parse(hand);
    }
    if (stat != yajl_status_ok) {
        unsigned char *str = yajl_get_error(hand, 0, fileData, rd);

        fflush(stdout);
        fprintf(stderr, "%s", (char *) str);
        yajl_free_error(hand, str);
        /*
         * n.b.:  the error text is in the expected output (the "*.gold" file),
         * so we don't need to also set a non-zero exit code -- the test
         * succeeds so long as there are no spurious system errors or memory
         * leaks -- expected parsing errors are OK.
         */
    }

    yajl_free(hand);
    free(fileData);

    if (file != stdin) {
        fclose(file);
    }
    fflush(stderr);
    fflush(stdout);
    /*
     * (lth) only print leaks here, as allocations and frees may vary depending
     *       on read buffer size, causing false failures.
     *
     */
    printf("memory leaks:\t%u\n", memCtx.numMallocs - memCtx.numFrees);

    exit(memCtx.numMallocs - memCtx.numFrees ? EXIT_FAILURE : EXIT_SUCCESS);
    /* NOTREACHED */
}

/*
 * Local Variables:
 * eval: (make-local-variable 'compile-command)
 * compile-command: (concat "MAKEOBJDIRPREFIX=../../build " (default-value 'compile-command))
 * End:
 */
