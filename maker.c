#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POSITION_WRITE 0
#define POSITION_READ 1
#define POSITION_OPEN 2
#define POSITION_EXECVE 3
#define POSITION_DUP 4
#define POSITION_LINK 5
#define POSITION_LSEEK 6
#define POSITION_PIPE 7
#define MAX_SYSCALLS 8

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

    switch (sysType) {
        case 1:
            printf("Il numero è 1.\n");
            break; // Uscita dal case
        case 2:
            printf("Il numero è 2.\n");
            break;
    }
    // Esegui direttamente le sostituzioni sul contenuto di file1.txt
    char *modified_content = replace_all(file_content, "$%%", "sys_enter_pwrite64");
    char *modified_content2 = replace_all(modified_content, "%$%", "SYS_TYPE_PWRITE64");
    char *final_content = replace_all(modified_content2, "%%$", "sys_exit_pwrite64");

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
    printf("Scrivere le system call che si vogliono tracciare\n");
    printf("Questa è la legenda:\n");
    printf("write = 1;\n");
    printf("read = 2;\n");
    printf("open = 3;\n");
    printf("execve = 4;\n");
    printf("dup = 5;\n");
    printf("link = 6;\n");
    printf("lseek = 7;\n");
    printf("pipe = 8;\n");
    printf("Per esempio per tracciare write, open e dup bisogna scrivere: 0;2;4;\n");
    printf("Un uso scorretto delle regole non porterà ad alcun risultato.\n");
    
    char input[256];
    int result[MAX_SYSCALLS];
    
    // Legge l'input dell'utente
    if (scanf("%255s", input) != 1) {
        fprintf(stderr, "Errore nella lettura dell'input\n");
        return 1;
    }
    
    // Processa l'input per ottenere i valori dell'array result
    parse_input(input, result);
    
    // Stampa l'array result per verifica
    printf("Array result:\n");
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        printf("%d ", result[i]);
    }
    printf("\n");
    copy_and_replace("Template_enter_exit.txt", "sostituzione.txt");
    
    return 0;
}
