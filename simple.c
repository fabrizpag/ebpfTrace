////////////////     ##MY PROG##
// ./simple /home/enrico/Desktop/bpfwrite7/writing1P0F
// ./simple /home/enrico/Desktop/bpfwrite7/writing0P2F
// ./simple /home/enrico/Desktop/bpfwrite7/wr1P0F

////////////////     ##GZIP##
// ./simple /bin/gzip /home/enrico/Desktop/daComprimere.txt
// ./simple /bin/gzip /home/enrico/Desktop/book.pdf

#include <sys/resource.h>
#include "simple.skel.h"
#include <bpf/bpf.h>
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
//maxEntriestimer:200, maxEntriesCSwitching:200, maxEntriesPIDs:100
#define MAX_PER_MAP 500

char* fromPathToName(const char* stringa);
//void StampaFile(int timerFDenter,int timerFDexit, int PidFDmap);
void StampaFile2(int timerFDenter,int timerFDexit, int PidFDmap, int fileDescr);
void StampaCS(int CSfd,int fileDescr);
bool checkFullMap(int timer_fd_enter, unsigned int fullNum );
void block_wait( int Semaphore_fd, int utility_fd, int PidFDmap);
void removeBlock (int utility_fd, int timerFDenter, int timerFDexit,int Semaphore_fd);
void cancel100elem (int timer_fd_enter, int timer_fd_exit);

typedef struct{
    unsigned long long int timer;
    unsigned int PID;
    unsigned int syscallType;
} mapTimerStruct;

typedef struct  {
    unsigned long long int timer;
    unsigned int PIDprec;
    unsigned int PIDpost;
} mapCSwitchStruct;

typedef struct{
    unsigned int internalBlock;
    unsigned int queue;
}semaforo;

typedef struct {
    unsigned int PID;
    bool stop;
} pidStop;

static void bump_memlock_rlimit(void)
{		
	// alloco più memoria possibile per il nostro bpf
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "failed to increase rlimit_memlock limit \n");
		exit(1);
	}
}
int main(int argc, char *argv[])
{	
	bump_memlock_rlimit();
	struct simple *skel = simple__open();
	simple__load(skel);
	simple__attach(skel);
	//aprima il bpf, lo carichiamo e lo attacchiamo ad un hook

	// carico le mappe
	
	struct bpf_map *timer_map_enter = skel->maps.timer_map_enter;
	struct bpf_map *timer_map_exit = skel->maps.timer_map_exit;
	struct bpf_map *PIDs_map = skel->maps.PIDs_map;
	struct bpf_map *utility_map = skel->maps.utility_map;
	struct bpf_map *Semaphore_map = skel->maps.Semaphore_map;
	struct bpf_map *CS_map = skel->maps.Context_Switch_Map;
	int timer_fd_enter = bpf_map__fd(timer_map_enter);
	int timer_fd_exit = bpf_map__fd(timer_map_exit);
	int PIDs_fd = bpf_map__fd(PIDs_map);
	int utility_fd = bpf_map__fd(utility_map);
	int Semaphore_fd = bpf_map__fd(Semaphore_map);
	int CS_fd = bpf_map__fd(CS_map);

	int fd = open("output.txt", O_WRONLY | O_APPEND | O_CREAT, 0644); // Apre il file in modalità scrittura
	int fd2 = open("output2.txt", O_WRONLY | O_APPEND | O_CREAT, 0644); // Apre il file in modalità scrittura

	if(argc == 1){
		//non stai tracciando alcun processo
		;
	}else{
		//  
		unsigned int processPid,mapPid0=0,mapPid1=1;
		int isOK;
		char *progName, *path;
		pid_t pid,processPidpt;
        pidStop pidStruct;
		processPidpt = getpid();
		processPid = (unsigned int)processPidpt;
		printf("\npid  di simple.c %u",processPid);
		fflush(stdout);
		
			//codice per l'esecuzione del programma da tracciare
		pid = fork();
		if(pid<0){
			//error
			return 1;
		}else if(pid == 0) {
			/////////////////////////////////// codice figlio

			//righe per la corretta esecuzione di execlp
			path = argv[1];
			progName = fromPathToName(path);

			processPidpt = getpid();
			processPid = (unsigned int)processPidpt;
			printf("\npid  del figlio di simple.c %u\n",processPid);
			fflush(stdout);

			//aggiungo il pid del figlio di simple.c in utility_map[0]
			bpf_map_update_elem(utility_fd,&mapPid0,&processPid,BPF_ADD);

			//eseguo il set up di PIDs_map
			pidStruct.PID = 1;
            pidStruct.stop = (unsigned int)1;
			bpf_map_update_elem(PIDs_fd,&mapPid0,&pidStruct,BPF_ADD);
            pidStruct.PID = processPid;
            pidStruct.stop = (unsigned int)1;
			bpf_map_update_elem(PIDs_fd,&mapPid1,&pidStruct,BPF_ADD);

			if(argc == 2){
				// sto eseguendo un programma senza opzioni o argomenti
				isOK = execlp(argv[1],progName,NULL);
				if(isOK == -1){return 1;}
			}else{
				// sto eseguendo un programma con opzioni o argomenti
				isOK = execlp(argv[1],progName,argv[2],NULL);
			}
		}//fine codice figlio
		else{

			///////////////////////////////////// codice padre
			//wait(NULL);
			
			int status;
			pid_t result;
			bool t = false,alreadyPrinted = false;
			int tempcont = 0;
			while(true){
				
				result = waitpid(pid, &status, WNOHANG); // Non bloccante
				if(result == 0) {
					printf("\ntempcont: %d\n",tempcont);
					tempcont++;
					printf("Il figlio non ha ancora terminato.\n");

					//usleep(500); //0.0005 sec (entrano dentro circa 100 syscall se sono di fila)
					usleep(50);
					t = checkFullMap( timer_fd_enter, MAX_PER_MAP );
					if(t == true){
						printf("la mappa è piena\n");
						block_wait( Semaphore_fd, utility_fd, PIDs_fd);
						if (fd == -1) {
							perror("Impossibile aprire il file");
							return 1;
						}
						
						StampaFile2(timer_fd_enter,timer_fd_exit, PIDs_fd,fd);
						StampaCS(CS_fd,fd2);
						alreadyPrinted = true;

						//CANCELLA I PRIMI 100 POSTI DI ENTRAMBE LE MAPPE PER SICUREZZA
						cancel100elem (timer_fd_enter, timer_fd_exit);
						removeBlock(utility_fd,timer_fd_enter,timer_fd_exit,Semaphore_fd);
						
					}

				} else if(result == -1) {
					printf ("errore sul waitpid ");
					break;

				} else {
					// Il figlio è terminato
					break;
				}
			}

			// questa stampa viene effettuata per liberare gli ultimi dati rimasti nelle mappe che non sono stati stampati
			StampaFile2(timer_fd_enter,timer_fd_exit, PIDs_fd,fd);
			StampaCS(CS_fd,fd2);

			printf("Il figlio ha terminato con successo.\n");
			printf("\n\n inizia la stampa fuori dal ciclo\n\n");
			
			/***** vecchia stampa   ******/
			
			printf("\n\n\n\n vecchia stampa: \n");
			unsigned long long int diff;
			unsigned int chiave_enter,chiave_exit;
			int try_enter,try_exit;
			mapTimerStruct map_enter,map_exit;

			for(int i=0;;i++){
				if(i==10){printf("\nfine i = 10\n");break;}
				chiave_enter = i;
                pidStop pidStopBuffer;
				try_enter = bpf_map_lookup_elem(PIDs_fd, &chiave_enter, &pidStopBuffer);
				if(try_enter == -1){
					printf("fine\n");
					break;
				}else{
					printf("key[%u] : %u, stop:%u\n",chiave_enter,pidStopBuffer.PID,pidStopBuffer.stop);
				}
			}
			chiave_enter = 0;
			try_enter = bpf_map_lookup_elem(utility_fd, &chiave_enter, &chiave_exit);
			if(try_enter != 1){
				printf("\n questo è utility: k[0] : %u\n",chiave_exit);
			}
			/*****                  *****/
			   
		} // fine codice padre
	}
	return 0;
}

char* fromPathToName(const char* stringa) {
    // Trova l'ultima occorrenza dello slash nella stringa
    const char* ultima_barra = strrchr(stringa, '/');
    
    // Se non è stata trovata alcuna barra, restituisci la stringa originale
    if (ultima_barra == NULL) {
        return strdup(stringa); // duplica la stringa originale
    } else {
        // Restituisci la sottostringa dopo l'ultima barra
        return strdup(ultima_barra + 1);
    }
}

bool checkFullMap(int timer_fd_enter, unsigned int fullNum ){
	printf("sono dentro checkFullMap\n");
	fflush(stdout);
	unsigned int key0 = 0;
	int try_enter;
	mapTimerStruct tempBuffer;
	try_enter = bpf_map_lookup_elem(timer_fd_enter,&key0,&tempBuffer);
	if(try_enter != -1){
		printf("sono dentro checkFullMap e questo è il conter dell'enter%llu\n",tempBuffer.timer);
		fflush(stdout);
		if(tempBuffer.timer >= fullNum){
			// raggiunto il limite
			printf("\n raggiunto il limite current index: %llu, fullNum : %u\n", tempBuffer.timer,fullNum);
			fflush(stdout);
			return true;
		}else{
			return false;
		}
	}else{
		return false;
	}

}

void block_wait( int Semaphore_fd, int utility_fd, int PidFDmap){
	printf("dentro block_wait\n");
	fflush(stdout);
	int try_general,try_general2;
	semaforo semBuffer;
	unsigned int UI_1=1,key0 = 0, externalBlock = 1,index;
    pidStop psBuffer;

    // blocco externblock utility_map
	for(int i = 1;i<2;i++){
		bpf_map_update_elem(utility_fd,&i,&externalBlock,BPF_ANY); 
	}
    // imposto a 1 tutti i pidStop->stop
	printf("imposto a 1 tutti i pidStop\n");
	fflush(stdout);
    try_general = bpf_map_lookup_elem(PidFDmap,&key0,&psBuffer);
    if(try_general != -1){
        index = psBuffer.PID;
        for(int i = 1;i<=index;i++){
            try_general2 = bpf_map_lookup_elem(PidFDmap,&i,&psBuffer);
			printf("questo era il pidStop PID:%u stop:%u\n",psBuffer.PID,psBuffer.stop);
            if(try_general2 != -1){
                psBuffer.stop = UI_1;
                bpf_map_update_elem(PidFDmap,&i,&psBuffer,BPF_ANY); 
            }
			try_general2 = bpf_map_lookup_elem(PidFDmap,&i,&psBuffer);
			if(try_general2 != -1){
				printf("questo è il pidStop dopo la modifica PID:%u stop:%u\n\n",psBuffer.PID,psBuffer.stop);
			}
        }
    }
    // qui ci stava la wait, aspettavi di pareggiare tra enter e exit ma ora non è più necessario
	
}

void removeBlock (int utility_fd,int timerFDenter, int timerFDexit, int Semaphore_fd){
	printf("dentro removeBlock\n");
	fflush(stdout);
	// da rimuovere
	int try_general;
	//

	unsigned int externalBlock = 0,count = 1;
	mapTimerStruct tempBuffer;
	tempBuffer.PID = 0;
	tempBuffer.syscallType = 0;
	tempBuffer.timer = 0;
	//for(int i=0;i<2;i++){
	//	bpf_map_update_elem(Semaphore_fd,&i,&externalBlock,BPF_ANY);
	//}
	for(;count<2;count++){
		bpf_map_update_elem(utility_fd,&count,&externalBlock,BPF_ANY);  //sblocco externblock utility_map
	}
	bpf_map_update_elem(timerFDenter,&externalBlock,&tempBuffer,BPF_ANY); 
	bpf_map_update_elem(timerFDexit,&externalBlock,&tempBuffer,BPF_ANY);
	
	//azzero i primi 20 elementi per compatibilità con il check del pidStop
	count = 1;
	for(;count<20;count++){
		bpf_map_update_elem(timerFDenter,&count,&tempBuffer,BPF_ANY); 
		bpf_map_update_elem(timerFDexit,&count,&tempBuffer,BPF_ANY);
	}



	
}
			
void StampaFile2(int timerFDenter,int timerFDexit, int PidFDmap, int fileDescr){

	int try_enter,try_exit,try_pid,   varEnterIndex=1,varExitIndex=1;
	unsigned int key0=0, key1=1, pidIndex;
	unsigned long long int EnterIndex, ExitIndex;
	mapTimerStruct MTSbufferEnter,MTSbufferExit;
    pidStop PSBuffer; 

	try_pid = bpf_map_lookup_elem(PidFDmap, &key0, &PSBuffer);
	try_enter = bpf_map_lookup_elem(timerFDenter, &key0, &MTSbufferEnter);
	try_exit = bpf_map_lookup_elem(timerFDexit, &key0, &MTSbufferExit);

	if( (try_enter!= -1)&&(try_exit!= -1) ){
		EnterIndex = MTSbufferEnter.timer;
		ExitIndex = MTSbufferExit.timer;
		printf("dentro StampaFile2 questi sono gli indice  enter:%llu exit:%llu",EnterIndex, ExitIndex);
		fflush(stdout);
	}

	if(try_pid != -1){
		if(PSBuffer.PID == 1){
			// solo il processo principale ha attivato le sonde
            
            // pareggio eventuali irregolarità
            if(EnterIndex > ExitIndex){
                EnterIndex = ExitIndex;
            }else{
                ExitIndex = EnterIndex;
            }
			try_pid = bpf_map_lookup_elem(PidFDmap, &key1, &PSBuffer);
			if(try_pid != -1){

				for(int i=0;i<=EnterIndex;i++){
					if(i == 0){
						try_enter = bpf_map_lookup_elem(timerFDenter, &i, &MTSbufferEnter);
						try_exit = bpf_map_lookup_elem(timerFDexit, &i, &MTSbufferExit);
						if((try_enter!= -1)&&(try_exit!= -1)){
							//primo elemento della mappa
							dprintf(fileDescr,"PID: %u   syscall: %u   k_enter: %u   time: %llu || ",MTSbufferEnter.PID,MTSbufferEnter.syscallType,i,MTSbufferEnter.timer);
							dprintf(fileDescr, "PID: %u   syscall: %u   k_exit: %u   time: %llu\n",MTSbufferExit.PID, MTSbufferExit.syscallType,i,MTSbufferExit.timer);
						}
					}else{
						try_enter = bpf_map_lookup_elem(timerFDenter, &i, &MTSbufferEnter);
						try_exit = bpf_map_lookup_elem(timerFDexit, &i, &MTSbufferExit);
						if((try_enter!= -1)&&(try_exit!= -1)){
							dprintf(fileDescr,"PID: %u   syscall: %u   k_enter: %u   time: %llu || ",MTSbufferEnter.PID,MTSbufferEnter.syscallType,i,MTSbufferEnter.timer);
							dprintf(fileDescr, "PID: %u   syscall: %u   k_exit: %u   time: %llu || differenza: %llu\n",MTSbufferExit.PID, MTSbufferExit.syscallType,i,MTSbufferExit.timer, MTSbufferExit.timer - MTSbufferEnter.timer);
						}
					}
            	}
			}

        }
        else{
            // più processi hanno attivato le sonde
            
            // pareggio eventuali irregolarità
            if(EnterIndex > ExitIndex){
                EnterIndex = ExitIndex;
            }else{
                ExitIndex = EnterIndex;
            }

			try_pid = bpf_map_lookup_elem(PidFDmap, &key0, &PSBuffer);
			if((try_pid != -1)&&(PSBuffer.PID != 0)){
                pidIndex = PSBuffer.PID;
				dprintf(fileDescr,"\n\n%u processi hanno attivato le sonde\n",pidIndex);
                
                //scorro i PID
                for(int k=1;k<=pidIndex;k++){
                    try_pid = bpf_map_lookup_elem(PidFDmap, &k, &PSBuffer);
					if(try_pid != -1){
						dprintf(fileDescr,"\ndati del processo con PID: %u\n",PSBuffer.PID);
					}
					varEnterIndex = 1;
					varExitIndex = 1;
                    while(true){
						
						//scorro l'enter partendo da varEnterIndex(ti fermi quando raggiungi EnterIndex)
                        //se trovo un PID corrispondente  salvo la posizione dell'enter in varEnterIndex, esci dal ciclo
                        //else esci dal ciclo e esci dal while true
						while(varEnterIndex<=EnterIndex){
							try_enter = bpf_map_lookup_elem(timerFDenter, &varEnterIndex, &MTSbufferEnter);
							//dprintf(fileDescr,"dentro while Enter, questo è il valore di varEi:%d, questo EnterIndex:%llu\n",varEnterIndex,EnterIndex);
							if((try_pid != -1)&&(try_enter != -1)){
								//dprintf(fileDescr,"dentro while Enter, PSBuffer.PID:%u MTSbufferEnter.PID:%u",PSBuffer.PID,MTSbufferEnter.PID);
								if(PSBuffer.PID == MTSbufferEnter.PID){
									break;
								}
							}
							varEnterIndex++;
						}
						if(varEnterIndex > EnterIndex){
							break;
						}

                        //scorro l'exit partendo da varExitIndex(ti fermi quando raggiungi ExitIndex)
                        //se trovo un PID corrispondente   salvo la posizione dell'enter in varEnterIndex, esci dal ciclo
                        //else esci dal ciclo e esci dal while true
						while(varExitIndex<=ExitIndex){
							try_exit = bpf_map_lookup_elem(timerFDexit, &varExitIndex, &MTSbufferExit);
							if((try_pid != -1)&&(try_exit != -1)){
								if(PSBuffer.PID == MTSbufferExit.PID){
									break;
								}
							}
							varExitIndex++;
						}
						if(varExitIndex > ExitIndex){
							break;
						}

                        //esegui la stampa
						dprintf(fileDescr,"PID: %u   syscall: %u   k_enter: %u   time: %llu || ",MTSbufferEnter.PID,MTSbufferEnter.syscallType,varEnterIndex,MTSbufferEnter.timer);
                    	dprintf(fileDescr, "PID: %u   syscall: %u   k_exit: %u   time: %llu || differenza: %llu\n",MTSbufferExit.PID, MTSbufferExit.syscallType,varExitIndex,MTSbufferExit.timer, MTSbufferExit.timer - MTSbufferEnter.timer);
						varEnterIndex += 1;
						varExitIndex += 1;
					}
                }
            }
			dprintf(fileDescr,"##################################\n");

        }
    }
    return;

}
void StampaCS(int CSfd,int fileDescr){
	int try_general;
	mapCSwitchStruct mcsBuffer;
	unsigned int mapIndex,key0=0;
	try_general = bpf_map_lookup_elem(CSfd, &key0, &mcsBuffer);
	if(try_general != -1){
		mapIndex = (unsigned int)mcsBuffer.timer;
	}
	for(unsigned int i = 0;i <=mapIndex;i++){
		try_general = bpf_map_lookup_elem(CSfd, &i, &mcsBuffer);
		if(i == 0){
			dprintf(fileDescr,"\n$$$$$$$$$$$$$$$$$$$$$$$$\n");
			dprintf(fileDescr,"questo è l'indice: %llu\n",mcsBuffer.timer);
		}else{
			dprintf(fileDescr,"pid switchato da :%u a :%u nel tempo:%llu\n",mcsBuffer.PIDprec,mcsBuffer.PIDpost,mcsBuffer.timer);
		}
	}
	dprintf(fileDescr,"fine\n");

	return;
}

void cancel100elem (int timer_fd_enter, int timer_fd_exit){
	mapTimerStruct m;
	m.PID = 0;
	m.timer = 0;
	m.syscallType =0;
	for(int i = 0; i< 100; i++){
		//bpf_map_update_elem(utility_fd,&count,&externalBlock,BPF_ANY);  //sblocco externblock utility_map
		bpf_map_update_elem(timer_fd_enter,&i,&m,BPF_ANY);
		bpf_map_update_elem(timer_fd_exit,&i,&m,BPF_ANY);
	}
}
