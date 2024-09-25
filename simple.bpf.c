#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SYS_TYPE_KEY 0
#define SYS_TYPE_PWRITE64 1
#define SYS_TYPE_PREAD64 2
#define SYS_TYPE_SOCKET 3
#define SYS_TYPE_WRITE 4
#define SYS_TYPE_READ 5

// bpf_ktime_get_ns() in nanosecondi 
// tutti bpf_repeat(100)

char LICENSE[] SEC("license") = "GPL";
//definisco la LICENSE GPL che ci permette di utilizzare il codice GPL del kernel
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
}semaforo;

typedef struct {
    unsigned int PID;
    unsigned int stop;   //     0:continua   1:stop
} pidStop;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, mapTimerStruct);
    __uint(max_entries, 2000);
} timer_map_enter SEC(".maps"),timer_map_exit SEC(".maps");
// [0] mapTimerStruct.timer = indice corrente dell'array   mapTimerStruct.PID=0   mapTimerStruct.syscallType=SYS_TYPE_KEY

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, mapCSwitchStruct);
    __uint(max_entries, 2000);
} Context_Switch_Map SEC(".maps");
// [0] mapCSwitchStruct.timer = indice corrente dell'array   mapCSwitchStruct.PIDprec=0   mapCSwitchStruct.PIDpost=0

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, pidStop);
    __uint(max_entries, 100);
} PIDs_map SEC(".maps");
// [0] indice corrente dell'array

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, unsigned int);
    __uint(max_entries, 10);
} utility_map SEC(".maps");
// [0] PID del processo figlio di simple.c
// [1] externBlock write


struct {
     __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, unsigned int);
    __type(value, semaforo);
    __uint(max_entries, 10);
} Semaphore_map SEC(".maps");
// i semafori servono per la concorrenza
// [0] semaforo enter write
// [1] semaforo exit write
// [2] semaforo Context Switch
SEC("tp/syscalls/sys_enter_pwrite64")  
int handle_sys_enter_pwrite64(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2;
    unsigned int tempPIDkey=0;
    bool trovato = false;
    semaforo *sem; 
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1); //utility_map[1] externBlock write

    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0) ||(externBlock == NULL) || (*externBlock == 1)  ){
        ;      // mappa vuota / errore / extern block   
    }else{
        // cerco se il PID è presente nella PIDs_map
        tempPIDkey=1;
        bpf_repeat(100){
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if((tempPIDelem == NULL)||(tempPIDelem->PID == 0)){
                break;
            }else if(tempPIDelem->PID == pid){
                trovato = true;
                break;
            }
            tempPIDkey++;
        }
        
    }

    if(trovato == true){
        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns();
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0)){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PWRITE64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&tkey1,&mts2,BPF_ANY);
            u32 keyToPrint = (u32)tkey1;

            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PWRITE64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&newIndex,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

            
        }

        //unlock
        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0);
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey0,sem,BPF_ANY); //Semaphore_map[0] semaforo enter write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_exit_pwrite64")
int handle_sys_exit_pwrite64(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2, tkey3=3;
    unsigned int tempPIDkey =1;
    bool trovato = false,pidStop_1=false;
    semaforo *sem;
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1);
    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0)||(externBlock == NULL) || (*externBlock == 1) ){
        ;      // mappa vuota / errore
    }else{
        // cerco se il PID è presente nella PIDs_map
        bpf_repeat(10){
            
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if(tempPIDelem != NULL){
                if(tempPIDelem->PID == 0){
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop == 0)){
                    trovato = true;
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop != 0)){
                    pidStop_1 = true;
                    break;
                }
                tempPIDkey++;
            }
        }

    }

    if(pidStop_1 == true){
        const char a0[] = "nuovo check";
        bpf_trace_printk(a0, sizeof(a0));
        //il pidStop è impostato a 1, questo significa che è la prima exit del PID
        //controllo se per lo stesso PID esiste una entry corrispondente nella enter
        mapTimerStruct *structElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        if(structElem != NULL){

            //se il primo elemento della enter è stato già inserito
            if(structElem->timer != 0){
                unsigned int tempCount=1;
                //cerco elementi nella enter fino a trovarne uno che abbia il pid corrispondente
                bpf_repeat(20){
                    structElem = bpf_map_lookup_elem(&timer_map_enter,&tempCount);
                    if(structElem != NULL){
                        if(structElem->timer == 0){
                            break;
                        }
                        if(structElem->PID == pid){
                            trovato = true;
                        }
                    }
                }
                //trovato = true;
                //settaggio stop del pidStop a 0 
                tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
                if(tempPIDelem != NULL){
                    if(tempPIDelem->stop != 0){
                        const char a1[] = "dentro enter settaggio del pidstop da 1 a 0";
                        bpf_trace_printk(a1, sizeof(a1));
                        pidStop psBuffer;
                        psBuffer.PID=tempPIDelem->PID;
                        psBuffer.stop=0;
                        bpf_map_update_elem(&PIDs_map,&tempPIDkey,&psBuffer,BPF_ANY);

                    }
                }
            }
        }

    }
    if(trovato == true){

        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns()- timestampdiff;
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_exit,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0) ){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PWRITE64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&tkey1,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)tkey1;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);  
            
        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PWRITE64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&newIndex,&mts2,BPF_ANY);

            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }

        //unlock

        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey1,sem,BPF_ANY); //Semaphore_map[1] semaforo exit write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_enter_pread64")  
int handle_sys_enter_pread64(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2;
    unsigned int tempPIDkey=0;
    bool trovato = false;
    semaforo *sem; 
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1); //utility_map[1] externBlock write

    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0) ||(externBlock == NULL) || (*externBlock == 1)  ){
        ;      // mappa vuota / errore / extern block   
    }else{
        // cerco se il PID è presente nella PIDs_map
        tempPIDkey=1;
        bpf_repeat(100){
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if((tempPIDelem == NULL)||(tempPIDelem->PID == 0)){
                break;
            }else if(tempPIDelem->PID == pid){
                trovato = true;
                break;
            }
            tempPIDkey++;
        }
        
    }

    if(trovato == true){
        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns();
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0)){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PREAD64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&tkey1,&mts2,BPF_ANY);
            u32 keyToPrint = (u32)tkey1;

            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PREAD64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&newIndex,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

            
        }

        //unlock
        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0);
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey0,sem,BPF_ANY); //Semaphore_map[0] semaforo enter write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_exit_pread64")
int handle_sys_exit_pread64(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2, tkey3=3;
    unsigned int tempPIDkey =1;
    bool trovato = false,pidStop_1=false;
    semaforo *sem;
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1);
    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0)||(externBlock == NULL) || (*externBlock == 1) ){
        ;      // mappa vuota / errore
    }else{
        // cerco se il PID è presente nella PIDs_map
        bpf_repeat(10){
            
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if(tempPIDelem != NULL){
                if(tempPIDelem->PID == 0){
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop == 0)){
                    trovato = true;
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop != 0)){
                    pidStop_1 = true;
                    break;
                }
                tempPIDkey++;
            }
        }

    }

    if(pidStop_1 == true){
        const char a0[] = "nuovo check";
        bpf_trace_printk(a0, sizeof(a0));
        //il pidStop è impostato a 1, questo significa che è la prima exit del PID
        //controllo se per lo stesso PID esiste una entry corrispondente nella enter
        mapTimerStruct *structElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        if(structElem != NULL){

            //se il primo elemento della enter è stato già inserito
            if(structElem->timer != 0){
                unsigned int tempCount=1;
                //cerco elementi nella enter fino a trovarne uno che abbia il pid corrispondente
                bpf_repeat(20){
                    structElem = bpf_map_lookup_elem(&timer_map_enter,&tempCount);
                    if(structElem != NULL){
                        if(structElem->timer == 0){
                            break;
                        }
                        if(structElem->PID == pid){
                            trovato = true;
                        }
                    }
                }
                //trovato = true;
                //settaggio stop del pidStop a 0 
                tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
                if(tempPIDelem != NULL){
                    if(tempPIDelem->stop != 0){
                        const char a1[] = "dentro enter settaggio del pidstop da 1 a 0";
                        bpf_trace_printk(a1, sizeof(a1));
                        pidStop psBuffer;
                        psBuffer.PID=tempPIDelem->PID;
                        psBuffer.stop=0;
                        bpf_map_update_elem(&PIDs_map,&tempPIDkey,&psBuffer,BPF_ANY);

                    }
                }
            }
        }

    }
    if(trovato == true){

        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns()- timestampdiff;
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_exit,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0) ){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PREAD64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&tkey1,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)tkey1;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);  
            
        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_PREAD64;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&newIndex,&mts2,BPF_ANY);

            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }

        //unlock

        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey1,sem,BPF_ANY); //Semaphore_map[1] semaforo exit write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_enter_write")  
int handle_sys_enter_write(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2;
    unsigned int tempPIDkey=0;
    bool trovato = false;
    semaforo *sem; 
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1); //utility_map[1] externBlock write

    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0) ||(externBlock == NULL) || (*externBlock == 1)  ){
        ;      // mappa vuota / errore / extern block   
    }else{
        // cerco se il PID è presente nella PIDs_map
        tempPIDkey=1;
        bpf_repeat(100){
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if((tempPIDelem == NULL)||(tempPIDelem->PID == 0)){
                break;
            }else if(tempPIDelem->PID == pid){
                trovato = true;
                break;
            }
            tempPIDkey++;
        }
        
    }

    if(trovato == true){
        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns();
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0)){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_WRITE;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&tkey1,&mts2,BPF_ANY);
            u32 keyToPrint = (u32)tkey1;

            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_WRITE;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&newIndex,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

            
        }

        //unlock
        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0);
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey0,sem,BPF_ANY); //Semaphore_map[0] semaforo enter write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_exit_write")
int handle_sys_exit_write(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2, tkey3=3;
    unsigned int tempPIDkey =1;
    bool trovato = false,pidStop_1=false;
    semaforo *sem;
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1);
    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0)||(externBlock == NULL) || (*externBlock == 1) ){
        ;      // mappa vuota / errore
    }else{
        // cerco se il PID è presente nella PIDs_map
        bpf_repeat(10){
            
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if(tempPIDelem != NULL){
                if(tempPIDelem->PID == 0){
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop == 0)){
                    trovato = true;
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop != 0)){
                    pidStop_1 = true;
                    break;
                }
                tempPIDkey++;
            }
        }

    }

    if(pidStop_1 == true){
        const char a0[] = "nuovo check";
        bpf_trace_printk(a0, sizeof(a0));
        //il pidStop è impostato a 1, questo significa che è la prima exit del PID
        //controllo se per lo stesso PID esiste una entry corrispondente nella enter
        mapTimerStruct *structElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        if(structElem != NULL){

            //se il primo elemento della enter è stato già inserito
            if(structElem->timer != 0){
                unsigned int tempCount=1;
                //cerco elementi nella enter fino a trovarne uno che abbia il pid corrispondente
                bpf_repeat(20){
                    structElem = bpf_map_lookup_elem(&timer_map_enter,&tempCount);
                    if(structElem != NULL){
                        if(structElem->timer == 0){
                            break;
                        }
                        if(structElem->PID == pid){
                            trovato = true;
                        }
                    }
                }
                //trovato = true;
                //settaggio stop del pidStop a 0 
                tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
                if(tempPIDelem != NULL){
                    if(tempPIDelem->stop != 0){
                        const char a1[] = "dentro enter settaggio del pidstop da 1 a 0";
                        bpf_trace_printk(a1, sizeof(a1));
                        pidStop psBuffer;
                        psBuffer.PID=tempPIDelem->PID;
                        psBuffer.stop=0;
                        bpf_map_update_elem(&PIDs_map,&tempPIDkey,&psBuffer,BPF_ANY);

                    }
                }
            }
        }

    }
    if(trovato == true){

        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns()- timestampdiff;
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_exit,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0) ){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_WRITE;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&tkey1,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)tkey1;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);  
            
        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_WRITE;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&newIndex,&mts2,BPF_ANY);

            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }

        //unlock

        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey1,sem,BPF_ANY); //Semaphore_map[1] semaforo exit write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_enter_read")  
int handle_sys_enter_read(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2;
    unsigned int tempPIDkey=0;
    bool trovato = false;
    semaforo *sem; 
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1); //utility_map[1] externBlock write

    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0) ||(externBlock == NULL) || (*externBlock == 1)  ){
        ;      // mappa vuota / errore / extern block   
    }else{
        // cerco se il PID è presente nella PIDs_map
        tempPIDkey=1;
        bpf_repeat(100){
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if((tempPIDelem == NULL)||(tempPIDelem->PID == 0)){
                break;
            }else if(tempPIDelem->PID == pid){
                trovato = true;
                break;
            }
            tempPIDkey++;
        }
        
    }

    if(trovato == true){
        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0); //Semaphore_map[0] semaforo enter write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey0,&newSem,BPF_ANY); //Semaphore_map[0] semaforo enter write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns();
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0)){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_READ;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&tkey1,&mts2,BPF_ANY);
            u32 keyToPrint = (u32)tkey1;

            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_enter,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_READ;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_enter,&newIndex,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro enter write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

            
        }

        //unlock
        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey0);
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey0,sem,BPF_ANY); //Semaphore_map[0] semaforo enter write
        }
        
    }

    return 0;
}
SEC("tp/syscalls/sys_exit_read")
int handle_sys_exit_read(void *params)
{
    u64 timestamp1 = bpf_ktime_get_ns();
    unsigned int tkey0 = 0, tkey1 = 1, tkey2=2, tkey3=3;
    unsigned int tempPIDkey =1;
    bool trovato = false,pidStop_1=false;
    semaforo *sem;
    semaforo newSem;
    newSem.internalBlock=1;
    pidStop *tempPIDelem;

    // il filtraggio dei PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pidu32 = pid_tgid & 0xFFFFFFFF;
    unsigned int pid = (unsigned int)pidu32;
    pidStop *firstPIDelem = bpf_map_lookup_elem(&PIDs_map, &tkey0);
    unsigned int *externBlock = bpf_map_lookup_elem(&utility_map,&tkey1);
    if( (firstPIDelem == NULL) || (firstPIDelem->PID == 0)||(externBlock == NULL) || (*externBlock == 1) ){
        ;      // mappa vuota / errore
    }else{
        // cerco se il PID è presente nella PIDs_map
        bpf_repeat(10){
            
            tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
            if(tempPIDelem != NULL){
                if(tempPIDelem->PID == 0){
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop == 0)){
                    trovato = true;
                    break;
                }
                if((tempPIDelem->PID == pid)&&(tempPIDelem->stop != 0)){
                    pidStop_1 = true;
                    break;
                }
                tempPIDkey++;
            }
        }

    }

    if(pidStop_1 == true){
        const char a0[] = "nuovo check";
        bpf_trace_printk(a0, sizeof(a0));
        //il pidStop è impostato a 1, questo significa che è la prima exit del PID
        //controllo se per lo stesso PID esiste una entry corrispondente nella enter
        mapTimerStruct *structElem = bpf_map_lookup_elem(&timer_map_enter,&tkey0); 
        if(structElem != NULL){

            //se il primo elemento della enter è stato già inserito
            if(structElem->timer != 0){
                unsigned int tempCount=1;
                //cerco elementi nella enter fino a trovarne uno che abbia il pid corrispondente
                bpf_repeat(20){
                    structElem = bpf_map_lookup_elem(&timer_map_enter,&tempCount);
                    if(structElem != NULL){
                        if(structElem->timer == 0){
                            break;
                        }
                        if(structElem->PID == pid){
                            trovato = true;
                        }
                    }
                }
                //trovato = true;
                //settaggio stop del pidStop a 0 
                tempPIDelem = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
                if(tempPIDelem != NULL){
                    if(tempPIDelem->stop != 0){
                        const char a1[] = "dentro enter settaggio del pidstop da 1 a 0";
                        bpf_trace_printk(a1, sizeof(a1));
                        pidStop psBuffer;
                        psBuffer.PID=tempPIDelem->PID;
                        psBuffer.stop=0;
                        bpf_map_update_elem(&PIDs_map,&tempPIDkey,&psBuffer,BPF_ANY);

                    }
                }
            }
        }

    }
    if(trovato == true){

        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&tkey1,&newSem,BPF_ANY); //Semaphore_map[1] semaforo exit write
                            break;
                        }
                    }
                    
                }
            }
        }

        u64 timestamp2 = bpf_ktime_get_ns();
        u64 timestampdiff = timestamp2 - timestamp1;
        u64 timestampu64 = bpf_ktime_get_ns()- timestampdiff;
        unsigned long long int timestamp = (unsigned long long int) timestampu64;

        mapTimerStruct *firstStructElem = bpf_map_lookup_elem(&timer_map_exit,&tkey0); 
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0) ){
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType= SYS_TYPE_KEY;
            mts.timer=1;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_READ;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&tkey1,&mts2,BPF_ANY);
            
            u32 keyToPrint = (u32)tkey1;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);  
            
        }else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            newIndex++;
            mapTimerStruct mts,mts2;
            mts.PID=0;
            mts.syscallType=SYS_TYPE_KEY;
            mts.timer=newIndex;
            bpf_map_update_elem(&timer_map_exit,&tkey0,&mts,BPF_ANY);

            mts2.PID=pid;
            mts2.syscallType=SYS_TYPE_READ;
            mts2.timer=timestamp;
            bpf_map_update_elem(&timer_map_exit,&newIndex,&mts2,BPF_ANY);

            u32 keyToPrint = (u32)newIndex;
            //const char fmt_str1[] = "dentro exit write, pid:%u key:%u";
            //bpf_trace_printk(fmt_str1, sizeof(fmt_str1),pidu32,keyToPrint);

        }

        //unlock

        //azzera l'internal block
        sem = bpf_map_lookup_elem(&Semaphore_map, &tkey1); //Semaphore_map[1] semaforo exit write
        if(sem != NULL){
            sem->internalBlock =0;
            bpf_map_update_elem(&Semaphore_map,&tkey1,sem,BPF_ANY); //Semaphore_map[1] semaforo exit write
        }
        
    }

    return 0;
}
SEC("tp/sched/sched_process_fork")   // trace point attivato appena dopo che il processo figlio è stato creato
int handle_sched_process_fork(void *params)
{   
    struct trace_event_raw_sched_process_fork *ctx = params;
    unsigned int pidParent = ctx->parent_pid;
    unsigned int pidChild = ctx->child_pid;
    unsigned int key0=0;
    bool trovato = false;
    pidStop *pidStruct,newPidStruct;

    // cerco se il pidParent è presente nella lista dei pid, altrimenti non fare nulla
    unsigned int tempPIDkey=1;
    bpf_repeat(5){
        pidStruct = bpf_map_lookup_elem(&PIDs_map,&tempPIDkey);
        if((pidStruct == NULL)||(pidStruct->PID == 0)){
            break;
        }else if(pidStruct->PID == pidParent){
            trovato = true;
            break;
        }
        tempPIDkey++;
    }

    // se pidParent è stato trovato allora aggiungo il figlio nella mappa PIDs
    if(trovato == true){
        pidStruct = bpf_map_lookup_elem(&PIDs_map,&key0);
        if(pidStruct != NULL){
            unsigned int newIndex = pidStruct->PID + 1;
            unsigned int newPID =  pidChild;
            newPidStruct.stop = 1;
            newPidStruct.PID = newIndex;
            bpf_map_update_elem(&PIDs_map,&key0,&newPidStruct,BPF_ANY);
            newPidStruct.stop = 0;
            newPidStruct.PID = newPID;
            bpf_map_update_elem(&PIDs_map,&newIndex,&newPidStruct,BPF_ANY);
        }
        
    }
    return 0;
    
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(void *ctx)
{
    u64 timestampu64 = bpf_ktime_get_ns();
    unsigned long long int timestamp = (unsigned long long int) timestampu64;

    struct trace_event_raw_sched_switch *args = ctx;
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    unsigned int PIDprec= (unsigned int)prev_pid;
    unsigned int PIDpost= (unsigned int)next_pid;
    
    unsigned int key0=0,key1=1,key2=2;
    bool prevTrovato=false,postTrovato=false;
    semaforo *sem,newSem;
    newSem.internalBlock=1;
    pidStop *tempPID;
    
    //check se il processo switchato era presente nella lista dei pid
    bpf_repeat(100){
        tempPID = bpf_map_lookup_elem(&PIDs_map,&key0);
        if((tempPID!=NULL)&&(tempPID->PID!=0)){
            if(tempPID->PID == PIDprec){
                prevTrovato = true;
                break;
            }
            key0++;
        }
    }
    key0=0;
    //check se il processo in entrata è presente nella lista dei pid
    bpf_repeat(100){
        tempPID = bpf_map_lookup_elem(&PIDs_map,&key0);
        if((tempPID!=NULL)&&(tempPID->PID!=0)){
            if(tempPID->PID == PIDpost){
                postTrovato = true;
                break;
            }
            key0++;
        }
    }
    key0=0;

    if(prevTrovato || postTrovato){
        //const char fmt_str[] = "Context switch: PID %u -> PID %u";
        //bpf_trace_printk(fmt_str, sizeof(fmt_str), prev_pid, next_pid);

        // semaforo
        sem = bpf_map_lookup_elem(&Semaphore_map, &key2); //Semaphore_map[2] semaforo CS
        if(sem != NULL){
            if(sem->internalBlock == 0){
                bpf_map_update_elem(&Semaphore_map,&key2,&newSem,BPF_ANY); //Semaphore_map[2] CS
            }else{
                bpf_repeat(10000){
                    sem = bpf_map_lookup_elem(&Semaphore_map, &key2); //Semaphore_map[2] CS
                    if(sem != NULL){
                        if(sem->internalBlock == 0){
                            newSem.internalBlock = 1;
                            bpf_map_update_elem(&Semaphore_map,&key2,&newSem,BPF_ANY); //Semaphore_map[2] CS
                            break;
                        }
                    }
                    
                }
            }
        }
        mapCSwitchStruct *firstStructElem = bpf_map_lookup_elem(&Context_Switch_Map,&key0);
        //caso in cui la mappa è vuota
        if((firstStructElem != NULL) && (firstStructElem->timer==0) ){
            mapCSwitchStruct mcs,mcs2;
            mcs.timer = 1;
            mcs.PIDpost = 0;
            mcs.PIDprec = 0;
            bpf_map_update_elem(&Context_Switch_Map,&key0,&mcs,BPF_ANY);

            mcs2.timer=timestamp;
            mcs2.PIDprec=PIDprec;
            mcs2.PIDpost=PIDpost;
            bpf_map_update_elem(&Context_Switch_Map,&key1,&mcs2,BPF_ANY);
            
        }
        // la mappa non è vuota
        else if((firstStructElem != NULL) && (firstStructElem->timer!=0)){
            unsigned long long int newIndex = firstStructElem->timer;
            newIndex++;
            mapCSwitchStruct mcs,mcs2;
            mcs.PIDpost = 0;
            mcs.PIDprec = 0;
            mcs.timer=newIndex;
            bpf_map_update_elem(&Context_Switch_Map,&key0,&mcs,BPF_ANY);

            mcs2.PIDpost = PIDpost;
            mcs2.PIDprec = PIDprec;
            mcs2.timer=timestamp;
            bpf_map_update_elem(&Context_Switch_Map,&newIndex,&mcs2,BPF_ANY);


        }

        //unlock
        //azzera l'internal block
        newSem.internalBlock =0;
        bpf_map_update_elem(&Semaphore_map,&key2,&newSem,BPF_ANY); //Semaphore_map[2] semaforo context Switch
        
        
    }
    
    
   return 0;
}




