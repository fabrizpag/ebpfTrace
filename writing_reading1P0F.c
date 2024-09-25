#include <stdio.h> /* for convenience */
#include <stdlib.h> /* for convenience */
#include <stddef.h> /* for offsetof */
#include <string.h> /* for convenience */
#include <unistd.h> /* for convenience */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "mystring.h"

int main(){
    // Apertura file di scrittura
    int fd = open("txt3", O_RDWR , S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("Errore nell'apertura del file di scrittura");
        exit(EXIT_FAILURE);
    }

    // Apertura file di lettura
    int fd_read = open("txt", O_RDONLY);
    if (fd_read == -1) {
        perror("Errore nell'apertura del file di lettura");
        close(fd);
        exit(EXIT_FAILURE);
    }

    off_t offset = 0;
    char *data;
    char buffer[1]; // Buffer per le letture di un byte

    // Scritture
    for(int i = 0; i < 100; i++){
        if(i < 10){
            data = string4B; // 10 volte 4B
        } else if(i >= 10 && i < 20){
            data = string8961B; // 10 volte 8961B
        } else if(i >= 20 && i < 30){
            data = string62721B; // 10 volte 62721B
        } else {
            data = string3135B; // 10 volte 3135B
        }

        ssize_t bytes_written = pwrite(fd, data, strlen(data), offset);
        if (bytes_written == -1) {
            perror("Errore durante la scrittura nel file");
            close(fd);
            close(fd_read);
            exit(EXIT_FAILURE);
        }

        offset += 1;
    }

    // Letture: leggi un byte alla volta dal file antaniDaleggere.txt
    offset = 0;
    for (int i = 0; i < 100; i++) {
        ssize_t bytes_read = pread(fd_read, buffer, 1, offset);
        if (bytes_read == -1) {
            perror("Errore durante la lettura del file");
            close(fd);
            close(fd_read);
            exit(EXIT_FAILURE);
        }
        
        offset += 1;
    }

    close(fd);
    close(fd_read);
    return 0;
}