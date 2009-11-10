
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

struct {
    int count;
    int delay;
    int counter;
} var =
{
    .count = 1,
    .delay = 1,
};

void *do_count(void *arg)
{
    for (;;)
    {
        int counter = ++var.counter;
        int count   = var.count;

        printf("count %d of %d\n", counter, count);

        if (counter >= count)
            break;

        int delay = var.delay;

        sleep(delay);
    }

    printf("done\n");

    return 0;
}

void usage(FILE *fp, int status)
{
    fprintf( fp,
        "usage: counter [-c count] [-d dealy]\n"
        );
    exit(status);
}

int main(int argc, char *argv[])
{
    pthread_t thread_id;
    int status;
    void *result;
    int opt;

    while ((opt = getopt(argc, argv, "c:d:h")) != -1)
    {
        switch (opt) {
        case 'c':
            var.count = atoi(optarg);
            break;
        case 'd':
            var.delay = atoi(optarg);
            break;
        case 'h':
            usage(stdout, EXIT_SUCCESS);
            break;
        default:
            usage(stderr, EXIT_FAILURE);
        }
    }

    sleep(var.delay);

    status = pthread_create(&thread_id, NULL, do_count, NULL);

    status = pthread_join(thread_id, &result);

    return status || result;

    return 0;
}

