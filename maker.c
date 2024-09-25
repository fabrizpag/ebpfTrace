#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_SYSCALLS 8

void append_to_file(const char* destination, const char* source) {
    FILE *src, *dest;
    char buffer[1024];

    src = fopen(source, "r");
    if (src == NULL) {
        perror("Errore durante l'apertura del file sorgente");
        exit(EXIT_FAILURE);
    }

    dest = fopen(destination, "a");
    if (dest == NULL) {
        perror("Errore durante l'apertura del file di destinazione");
        fclose(src);
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), src) != NULL) {
        fputs(buffer, dest);
    }
    fclose(src);
    fclose(dest);
}

void parse_input(const char *input, int result[]) {
    // Inizializza tutti i valori di result a 0
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        result[i] = 0;
    }
    
    // Copia la stringa di input per poterla tokenizzare
    char *input_copy = strdup(input);
    if (!input_copy) {
        perror("strdup");
        exit(1);
    }
    
    char *token = strtok(input_copy, ";");
    while (token != NULL) {
        int index = atoi(token);
        if (index >= 0 && index < MAX_SYSCALLS) {
            result[index] = 1;
        }
        token = strtok(NULL, ";");
    }
    
    free(input_copy);
}

// Funzione per cercare e sostituire tutte le occorrenze di una stringa con un'altra
char *replace_all(const char *str, const char *old_word, const char *new_word) {
    char *result;
    int i, count = 0;
    int new_len = strlen(new_word);
    int old_len = strlen(old_word);

    // Conta il numero di occorrenze della vecchia parola
    for (i = 0; str[i] != '\0'; i++) {
        if (strstr(&str[i], old_word) == &str[i]) {
            count++;
            i += old_len - 1;
        }
    }

    // Allocare spazio per la nuova stringa
    result = (char *)malloc(i + count * (new_len - old_len) + 1);

    if (result == NULL) {
        printf("Errore di allocazione memoria\n");
        exit(1);
    }

    i = 0;
    while (*str) {
        if (strstr(str, old_word) == str) {
            strcpy(&result[i], new_word);
            i += new_len;
            str += old_len;
        } else {
            result[i++] = *str++;
        }
    }

    result[i] = '\0';
    return result;
}

void copy_and_replace(const char *input_file, const char *output_file, int sysType) {
    FILE *file1 = fopen(input_file, "r");
    if (file1 == NULL) {
        printf("Impossibile aprire il file %s\n", input_file);
        return;
    }

    // Leggi il contenuto del file di input in memoria
    fseek(file1, 0, SEEK_END);
    long file_size = ftell(file1);
    fseek(file1, 0, SEEK_SET);

    char *file_content = (char *)malloc(file_size + 1);
    if (file_content == NULL) {
        printf("Errore di allocazione memoria\n");
        fclose(file1);
        return;
    }

    fread(file_content, 1, file_size, file1);
    file_content[file_size] = '\0';
    fclose(file1);

    char *modified_content;
    char *modified_content2;
    char *final_content;
    switch (sysType) {
        case 1:
            // sysType 1 SYS_TYPE_PWRITE64
            modified_content = replace_all(file_content, "$%%", "sys_enter_pwrite64");
            modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_PWRITE64");
            final_content = replace_all(modified_content2, "%%$", "sys_exit_pwrite64");
            break; 
        case 2:
            // sysType 2 SYS_TYPE_PREAD64
            modified_content = replace_all(file_content, "$%%", "sys_enter_pread64");
            modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_PREAD64");
            final_content = replace_all(modified_content2, "%%$", "sys_exit_pread64");
            break;
        case 3:
            // sysType 3 SYS_TYPE_SOCKET
            modified_content = replace_all(file_content, "$%%", "sys_enter_socket");
            modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_SOCKET");
            final_content = replace_all(modified_content2, "%%$", "sys_exit_socket");
            break;
        case 4:
            // sysType 3 SYS_TYPE_SOCKET
            modified_content = replace_all(file_content, "$%%", "sys_enter_write");
            modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_WRITE");
            final_content = replace_all(modified_content2, "%%$", "sys_exit_write");
            break;
        case 5:
            // sysType 3 SYS_TYPE_SOCKET
            modified_content = replace_all(file_content, "$%%", "sys_enter_read");
            modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_READ");
            final_content = replace_all(modified_content2, "%%$", "sys_exit_read");
            break;
    }

    free(modified_content);
    free(modified_content2);

    // Apri il file di output in modalità append
    FILE *file2 = fopen(output_file, "a"); // "a" per appendere senza sovrascrivere
    if (file2 == NULL) {
        printf("Impossibile aprire il file %s\n", output_file);
        free(file_content);
        return;
    }

    // Scrivi solo il contenuto modificato in file2.c
    fputs(final_content, file2);
    fclose(file2);

    free(file_content);
    free(final_content);

    printf("Operazione completata con successo.\n");
}

int main() {
    
    const char* destination = "simple.bpf.c";
    char input[256];
    int result[MAX_SYSCALLS];


    printf("Scrivere le system call che si vogliono tracciare\n");
    printf("Questa è la legenda:\n");
    printf("pwrite = 0;\n");
    printf("pread = 1;\n");
    printf("socket = 2;\n");
    printf("write = 3;\n");
    printf("read = 4;\n");
    printf("Per esempio per tracciare write, read e socket bisogna scrivere: 0;1;2;\n");
    printf("Un uso scorretto delle regole non porterà ad alcun risultato.\n");
    // Legge l'input dell'utente
    if (scanf("%255s", input) != 1) {
        fprintf(stderr, "Errore nella lettura dell'input\n");
        return 1;
    }
    
    parse_input(input, result);
    
    //scorri array result per la scrittura di enter e exit
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        // posizionamento: [0]write [1]read [2]socket
        if(result[i] == 0){
        }
        else{
            printf("chiamo copy_and_replace su indice: %d ricorda 0w 1r 2s", i);
            copy_and_replace("Template_enter_exit.txt", "sostituzione.txt", i+1);
        }
    }
    
    //scrivi simple.bpf.c
    append_to_file(destination, "Template_dichiarazioni.txt");
    append_to_file(destination, "sostituzione.txt");
    append_to_file(destination, "Template_end.txt");
    
    return 0;
}
