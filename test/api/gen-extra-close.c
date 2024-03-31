/* ensure that if we try to generate an extra closing brace
 * we get the expected error */

#include <yajl/yajl_gen.h>

#include <stdio.h>
#include <stdlib.h>

#define CHK(x) if (x != yajl_gen_status_ok) {                           \
        fprintf(stderr, "intermediate step failed!");                   \
        exit(2);                                                        \
    }


int
main(void)
{
    yajl_gen yg;
    yajl_gen_status s;

    yg = yajl_gen_alloc(NULL);
    CHK(yajl_gen_map_open(yg));
    CHK(yajl_gen_map_close(yg));
    s = yajl_gen_map_close(yg);

    if (yajl_gen_generation_complete == s) {
        exit(0);
    }
    fprintf(stderr, "s = %d (should be: %d)\n", s, yajl_gen_generation_complete);

    exit(1);
}
