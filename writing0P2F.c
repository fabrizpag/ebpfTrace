#include <stdio.h> /* for convenience */
#include <stdlib.h> /* for convenience */
#include <stddef.h> /* for offsetof */
#include <string.h> /* for convenience */
#include <unistd.h> /* for convenience */
#include <signal.h> /* for SIG_ERR */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "mystring.h"

int main(){

    pid_t pid = fork();
    
    if (pid < 0) {
        // Errore nella creazione del primo processo figlio
        fprintf(stderr, "Errore nella creazione del primo processo figlio\n");
        return 1;
    } else if (pid == 0) {
        //////////////////// Codice eseguito dal primo processo figlio
        //////////////////// SCRITTURA SU FILE string2B,string1092B,string114B,string3135B
        for(int i = 0;i<5000;i++){
			i++;
			i--;
		}
        int fd = open("txt2", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        off_t offset = 0;
        char *data;
        for(int i = 0; i < 4000; i++){
            if(i < 10){
                data = string4B;     // 10 volte 4B
            } else if(i >= 10 && i < 20){
                data = string8961B;   // 10 volte 114B
            } else if(i >= 20 && i < 30){
                data = string62721B;  // 10 volte 1092B
            } else {
                data = string3135B;  // 10 volte 3135B
            }
            ssize_t bytes_written = pwrite(fd, data, strlen(data), offset);
            if (bytes_written == -1) {
                perror("Errore durante la scrittura nel file");
                close(fd);
                exit(EXIT_FAILURE);
            }
            offset = offset + 1;
        }
        close(fd);
        for(int i = 0;i<1000;i++){
			i++;
			i--;
		}
        exit(0);

    } else {
        // Codice eseguito dal processo padre
        pid_t pid2 = fork();
        if (pid2 < 0){
            // Errore nella creazione del secondo processo figlio
            fprintf(stderr, "Errore nella creazione del secondo processo figlio\n");
            return 1;
        } else if (pid2 == 0){
            //////////////////// Codice eseguito dal secondo processo figlio
            //////////////////// SCRITTURA SU FILE string2B,string1092B,string114B,string3135B
            int fd = open("txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            off_t offset = 0;
            char *data;
            for(int i = 0; i < 4000; i++){
                if(i < 10){
                    data = string4B;     // 10 volte 4B
                } else if(i >= 10 && i < 20){
                    data = string8961B;   // 10 volte 114B
                } else if(i >= 20 && i < 30){
                    data = string62721B;  // 10 volte 1092B
                } else {
                    data = string3135B;  // 10 volte 3135B
                }
                ssize_t bytes_written = pwrite(fd, data, strlen(data), offset);
                if (bytes_written == -1) {
                    perror("Errore durante la scrittura nel file");
                    close(fd);
                    exit(EXIT_FAILURE);
                }
                offset = offset + 1;
            }
            close(fd);
            for(int i = 0;i<1000;i++){
                i++;
                i--;
		    }
            exit(0);

        } else {
            // Codice eseguito dal processo padre
            int status;
            waitpid(pid, &status, 0); // Attendi la terminazione del primo figlio
            waitpid(pid2, &status, 0); // Attendi la terminazione del secondo figlio
            for(int i = 0;i<8000;i++){
                i++;
                i--;
		    }
        }
    }

    return 0;
}