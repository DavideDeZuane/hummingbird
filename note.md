# TO-DO

- [ ] Implementare il meccanismo di ritrasmissione
- [ ] La ritrasmissione va fatta fino a quando non si riceve una risposta oppure si supera il numero di tentativi
- [ ] I messaggi IKE devono essere al più 1280 byte
- [ ] Nello scambio IKE AUTH l'initiator deve aggiugnere il payload N(INITIAL_CONTAT) in modo da istruire il responder ad eliminare delle possibili IKE SA residue senza inviare delle notifiche  



RFC 7619
The NULL Authentication Method in the Internet Key Exchange Protocol Version 2 (IKEv2)






    //THIS EXCHANGE IS NECESSARY BECAUSE STRONGSWAN USE COOKIE AS DDOS PREVENTION
    //SO BEFORE GENERATING THE SKEYSEED AND OTHER THINGS HE WAIT THE IKE_AUTH_INIT 

# Setup 

Nella cartella src è presente il codice dell'implementazione di minimal ike.
Mentre nella cartella srv è presente la configurazione docker per creare un server strongswan con cui far comunicare la nostra istanza per vedere se tutto sta andando correttamente.

## Minimal IKE

Campi extra che sono presenti nell'SA init 

|             Campo             | Dimensione (Byte) |    Opzione Strongswan    | Value |    RFC   |
|:-----------------------------:|-------------------|:------------------------:|-------|:--------:|
| VENDOR\_ID                     |         20        |           send\_vendor\_id |    no |     7296 |
| MULTIPLE\_AUTH\_SUPPORTED       |         8         |  multiple\_authentication |    no |     4739 |
| SIGNATURE\_HASH\_ALGORITHMS     |         16        | signature\_authentication |    no |     7427 |
| REDIRECT\_SUPPORTED            |         8         |           flow\_redirects |    no |     5685 |
| NAT\_DETECTION\_SOURCE\_IP       |         28        |                        - |     - |     4306 |
| NAT\_DETECTION\_DESTIONATION\_IP |         28        |                        - |     - |     4306 |
|                               |                   |                          |       |          |
|        TOTALE OVERHEAD        |        108        |                          |       |          |

## Dependencies

- `libinih`: per eseguire il parsing della configurazione

- `log.c`: per eseguire il logging ([link](https://github.com/rxi/log.c))

- `libossl`: per le primitive crittografiche classiche

- `liboqs`: per le primitive crittografiche post-quantum

Un altra libreria per la configurazione carina è [libconfig](https://www.hyperrealm.com/libconfig/libconfig_manual.html)

### libssl 

EVP stands for `EnVeloPE` API, which is the API used from applications to access Openssl cryptography.

## RFC

RFC di riferimento per l'implementazione

- RFC 7296: IKEv2
- RFC 7815: Minimal IKE
- RFC 7670: Generic Raw Public-Key Support for IKEv2

I parametri di IKEv2 sono disponibili qui https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

## Socket 

### Blocking

Dato che send e recv (così come le altre varianti) sono chiamate bloccanti è bene specificare il tempo massimo oltre il quale la chiamata termina con un errore se non è stato ricevuto o inviato nulla. Il codice di errore che viene ritornato nel caso in cui scada il timer è `EAGAIN`, che sta per "Error Again" indica che l'operazione richiesta (come una lettura o scrittura su un socket) non può essere completata in quel momento, ma potrebbe avere successo se riprovata più tardi.

### UDP 

Per creare un socket UDP che utilizzi porte effimere per collegarsi ad un altro socket, nella struttura `sockaddr_in` va specificata la porta `0`, in questo 
modo stiamo dicendo al kernel lui di assegnarne una. Se si vuole inviare un messaggio e basta si può anche non fare la bind, tuttavia se si vuole controllare
quale porta effimera viene assegnata occorre fare il bind.

#### Ephemeral port 
    //passiamo come porta 0 in modo tale che sia il kernel a gestire l'assegnamento di una porta effimera
    //questo è molto meglio anche per motivi di sicurezza dato che ad ogni volta cambia


The allocation of an ephemeral port is temporary and only valid for the duration of the communication session. After completion of the session, the port is destroyed and the port number becomes available for reuse, but many implementations simply increment the last used port number until the ephemeral port range is exhausted, when the numbers roll over. 

Range of ephemeral ports: `32768–60999`.



Per vedere come aggiungere una policy ipsec guardare 

```strongswan/src/libcharon/kernel/kernel_ipsec.h```


### Overload in C

#define foo(X) _Generic((X), int: foo_int, char*: foo_char)(X)

void foo_int(int a){
    printf("%d\n", a);
}
 
void foo_char(char* d){
    printf("Print di un char\n");
}


### Endianess 

. Le CPU eseguono le operazioni aritmetiche nel formato nativo (host endian, che in un sistema little-endian è little-endian). Quindi, se vuoi ottenere il risultato corretto, devi assicurarti che gli operandi siano convertiti nel formato host prima dell’operazione e, se necessario, convertire il risultato in big-endian dopo l’operazione.
Quindi la soluzione migliore è convertire i dati prima di inviarli se necessario altrimenti mantenerli in memoria sulla base dell'host

## Docker

Quando facciamo il dockerfile abbiamo una cosa da considerare. Quando facciamo un comando Dockerfile RUN, ogni comando è eseguito in una nuova shell se facciamo ./configure ma prima non facciamo un cd o lo specifichiamo correttamente il file otteniamo l'erroe not found 


