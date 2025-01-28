#include "crypto.h" // IWYU pragma: keep
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

uint64_t generate_spi() {
    uint64_t spi;

    // Utilizza getrandom per leggere 8 byte casuali
    if (getrandom(&spi, sizeof(spi), 0) != sizeof(spi)) {
        perror("Errore nella generazione dei numeri casuali con getrandom");
        exit(EXIT_FAILURE);
    }

    return spi;
}