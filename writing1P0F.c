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
    int fd = open("txt3", O_RDWR , S_IRUSR|S_IWUSR);
		off_t offset = 0;
		char *data;
		
		for(int i = 0;i<1000;i++){
			i++;
			i--;
		}

		for(int i = 0;i<40000;i++){
			if(i<10){
				data = string4B;     //10 volte 4B
			}else if(i >=10 && i<20){
				data = string8961B;   //10 volte 8961B
			}else if(i >=20 && i<30){
				data = string62721B;	 //10 volte 62721B
			}else{
				data = string3135B;  //10 volte 3135B
			}
			ssize_t bytes_written = pwrite(fd, data, strlen(data), offset);
			//("%d scritto\n",i+1);
			//fflush(stdout); // Forza la stampa del buffer
			if (bytes_written == -1) {
				perror("Errore durante la scrittura nel file");
				close(fd);
				exit(EXIT_FAILURE);
			}
			offset=offset+1;
		}

		for(int i = 0;i<1000000;i++){
			i++;
			i--;
		}

		for(int i = 0;i<40;i++){
			if(i<10){
				data = string4B;     //10 volte 4B
			}else if(i >=10 && i<20){
				data = string8961B;   //10 volte 114B
			}else if(i >=20 && i<30){
				data = string62721B;	 //10 volte 1092B
			}else{
				data = string3135B;  //10 volte 3135B
			}
			ssize_t bytes_written = pwrite(fd, data, strlen(data), offset);
			//("%d scritto\n",i+1);
			//fflush(stdout); // Forza la stampa del buffer
			if (bytes_written == -1) {
				perror("Errore durante la scrittura nel file");
				close(fd);
				exit(EXIT_FAILURE);
			}
			offset=offset+1;
		}
		for(int i = 0;i<1000;i++){
			i++;
			i--;
		}

        exit(0);
    return 0;
}
