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

Dat oche send e recv (così come le altre varianti) sono chiamate bloccanti è bene specificare il tempo massimo oltre il quale la chiamata termina con un errore se non è stato ricevuto o inviato nulla. Il codice di errore che viene ritornato nel caso in cui scada il timer è `EAGAIN`, che sta per "Error Again" indica che l'operazione richiesta (come una lettura o scrittura su un socket) non può essere completata in quel momento, ma potrebbe avere successo se riprovata più tardi.

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




