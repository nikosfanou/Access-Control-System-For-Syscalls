#include <stdio.h>
#include <time.h>

/* Syscalls at start: 11, 45, 33, 192, 33, 5, 197, 192, 6, 33, 5, 3,
197, 192, 192, 192, 6, 192, 243, 125, 125, 91, 197, 192 */

/* Syscalls of program: 4, 45, 45, 5, 197, 192, 4, 6, 91, 15, 13, 4 */

int main(){
    FILE* fp;
    const char* file = "text.txt";
    char *buf = "Some data for test.txt";
    size_t written_bytes, read_bytes;
    time_t seconds;

    printf("Hi im input_exec!\n"); //write
    fp = fopen(file, "w+"); //open
    if(!fp){
        printf("Couldn't open file\n"); //write
        return -1;
    }
    written_bytes = fwrite(buf , 1 , strlen(buf) , fp ); //write
    fclose(fp); //close
    chmod(file, 0666); //chmod

    seconds = time(NULL); //time
    printf("Hours since January 1, 1970 = %ld\n", seconds/3600); //write

    return 0;
}