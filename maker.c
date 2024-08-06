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

int main() {
    printf("Scrivere le system call che si vogliono tracciare\n");
    printf("Questa è la legenda:\n");
    printf("write = 0;\n");
    printf("read = 1;\n");
    printf("open = 2;\n");
    printf("execve = 3;\n");
    printf("dup = 4;\n");
    printf("link = 5;\n");
    printf("lseek = 6;\n");
    printf("pipe = 7;\n");
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
    
    return 0;
}