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
    int *flag_pass; 
};

void *crack_pass(void *arg) {
    struct thread_input *thread_args = (struct thread_input *)arg;
    struct crypt_data data = {0}; // intialize crypt data --> for crypt calls
    char test_p[thread_args->keysize + 1];//password to be tested against crypt 
    memset(test_p, 'a', thread_args->keysize);//initialzing password with a's 
    test_p[thread_args->keysize] = '\0';//null terminating pasword 


    //iterating through the temp pass combinations in the threads start and end range
    for (unsigned long current = thread_args->start; current <= thread_args->end; current++) {
        //check if password is flagged 
        if (*thread_args->flag_pass) {
            break; // password has been found 
        }

        unsigned long curr_index = current;//determines character in each position

        // Generate the password based on the current index
        for (int i = 0; i < thread_args->keysize; i++) {
            test_p[i] = 'a' + (curr_index % 26);//convert index to lowercase
            curr_index /= 26;//moving to next character position
        }
    
        // test_p[thread_args->keysize] = '\0'; see if need twice 

        //getting hash of the generated pasword 
        char *hashed = crypt_r(test_p, thread_args->salt, &data);
        if (strcmp(thread_args->target, hashed) == 0) {//password has been found
            *(thread_args->flag_pass) = 1;
            char *result = strdup(test_p); //memory for password and return it
            return result;
        }
    }
        return NULL; 
}
    


int main(int argc, char* argv[]) {
    if (argc != 4) {//check number of command line arguments
        perror("Too many or too little arguments, expected: crack <threads> <keysize> <target>");
        return 1;
    }

    //getting input from command line args 
    int threads = atoi(argv[1]);
    int keysize_m = atoi(argv[2]);
    char *target_m = argv[3];
    char salt[3];
    strncpy(salt, target_m, 2);
    salt[2] = '\0';

    pthread_t thread_ids[threads];
    struct thread_input thread_args[threads];

    //calculate total range of password combinations
    unsigned long range = 1;
    for (int i = 0; i < keysize_m; i++) {
        range *= 26;
    }

    //calculating the portion of range needed for each thread
    unsigned long portion = range / threads;
    unsigned long start = 0;
    unsigned long extra = range % threads;

    void *thread_result;
    char *found_pass = NULL;

    int flag_pass = 0; //flag to inidcate if password has been found

    //create threads and search for password
    for (int i = 0; i < threads; i++) {
        unsigned long end = start + portion - 1 + (i < extra);
        thread_args[i] = (struct thread_input){target_m, salt, keysize_m, start, end, &flag_pass}; // Pass the address of flag_pass
        pthread_create(&thread_ids[i], NULL, crack_pass, &thread_args[i]);
        start = end + 1;
    }

    //waiting for threads to finish execution
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], &thread_result);
        if (thread_result != NULL) {
            found_pass = (char *)thread_result;
            break;
        }
    }

    //displaying result
    if (found_pass) {
        printf("Password found: %s\n", found_pass);
        free(found_pass); // Free the dynamically allocated memory
    } else {
        printf("Password not found.\n");
    }

    return 0;
}
