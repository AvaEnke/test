#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <crypt.h>

struct thread_input {
    char *target;
    char *salt;
    int keysize;
    unsigned long start;
    unsigned long end;
    int *flag_pass; // Changed variable name
};

void *crack_pass(void *arg) {
    struct thread_input *thread_args = (struct thread_input *)arg;
    struct crypt_data data = {0}; // Ensure that the crypt_data structure is initialized
    char test_p[thread_args->keysize + 1];
    memset(test_p, 'a', thread_args->keysize);
    test_p[thread_args->keysize] = '\0';

    for (unsigned long current = thread_args->start; current <= thread_args->end && !(*thread_args->flag_pass); ++current) {
        unsigned long temp = current;
        for (int i = 0; i < thread_args->keysize; i++) {
            test_p[i] = 'a' + (temp % 26);
            temp /= 26;
        }
        test_p[thread_args->keysize] = '\0';

        char *hashed = crypt_r(test_p, thread_args->salt, &data);
        if (strcmp(thread_args->target, hashed) == 0) {
            *(thread_args->flag_pass) = 1; // Set the value of flag_pass to 1
            char *result = strdup(test_p); // Dynamically allocate memory for the found password
            return result; // Return the found password
        }
    }
    return NULL; // Return NULL if the password was not found
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        // Change the error message
        fprintf(stderr, "Usage: crack <threads> <keysize> <target>\n");
        return 1;
    }

    int threads = atoi(argv[1]);
    int keysize_m = atoi(argv[2]);
    char *target_m = argv[3];
    char salt[3];
    strncpy(salt, target_m, 2);
    salt[2] = '\0';

    pthread_t thread_ids[threads];
    struct thread_input thread_args[threads];

    unsigned long range = 1;
    for (int i = 0; i < keysize_m; i++) {
        range *= 26;
    }

    unsigned long portion = range / threads;
    unsigned long start = 0;
    unsigned long extra = range % threads;

    void *thread_result;
    char *found_pass = NULL;

    int flag_pass = 0; // Changed variable name

    for (int i = 0; i < threads; i++) {
        unsigned long end = start + portion - 1 + (i < extra);
        thread_args[i] = (struct thread_input){target_m, salt, keysize_m, start, end, &flag_pass}; // Pass the address of flag_pass
        pthread_create(&thread_ids[i], NULL, crack_pass, &thread_args[i]);
        start = end + 1;
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], &thread_result);
        if (thread_result != NULL) {
            found_pass = (char *)thread_result;
            break;
        }
    }

    if (found_pass) {
        printf("Password found: %s\n", found_pass);
        free(found_pass); // Free the dynamically allocated memory
    } else {
        printf("Password not found.\n");
    }

    return 0;
}
