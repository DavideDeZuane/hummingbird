#include "../common_include.h" // IWYU pragma: keep
#include <stdio.h>
#include <sys/random.h>

// la keyword che viene utilizzata in fase di configurazione
typedef struct {
    char *keyword;
    char *name;
} Node;

typedef struct {
    size_t size;
    size_t num;
    Node **table;
} CipherTable;

//la funizone di hash deve essere scelta tra una famiglia random all'inzio di ogni esecuzione

/*
char tmp[32];
getrandom(tmp, 32, GRND_NONBLOCK);
*/