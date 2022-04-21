#ifndef _IP_PLOT_LIST_
#define _IP_PLOT_LIST_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Estructura de datos de lista para almacenar y clasificar las macs así como las tramas que les pertenecen.
*/

typedef struct _Nodo{
    char ip[17];
    int received;
    int sent;
    struct _Nodo *sig;
    struct _Nodo *anterior;
} Nodo;

Nodo * crear(char * ip, int received, int sent){

    Nodo * nuevo;

    nuevo = (Nodo *) malloc(sizeof(Nodo));
    nuevo->received = received;
    nuevo->sent = sent;

    for(int i = 0; i < 17; i++){
        nuevo->ip[i]= ip[i];
    }
    
    nuevo->sig= NULL;

    return nuevo;

}

int detNumElem(Nodo * inicio){
    int num = 0;
    
    if(inicio == NULL){
        num = 0;
    }
    else{
        while(inicio != NULL){
            num++;
            inicio = inicio->sig;
        }
    }

    return num;
}

Nodo * insertarFinal(char * ip, int received, int sent, Nodo *inicio){
    Nodo * nuevo;
    Nodo * aux;
    nuevo = crear(ip, received, sent);

    if(inicio == NULL){
        inicio = nuevo;
    }else{
        aux = inicio;
        while(aux->sig != NULL){
            aux = aux ->sig;
        }

        nuevo->anterior = aux;
        aux->sig = nuevo;
    }

    return inicio;
}

/*
    Método para incrementar de uno en uno los paquetes por dirección MAC.
*/

int actualizarMasUnoReceived(Nodo * inicio, char * llave){
    Nodo * aux = inicio;
    int i = 0;
    int longitudLista = detNumElem(inicio);
    int validador = 0;
    while(longitudLista != 0){
        for(int i = 0; i < 17; i++){
            if(aux->ip[i] == llave[i]){
                validador = 1;
            }
            else{
                validador = 0;
                break;
            }
        }

        if(validador == 1){
            aux->received = aux->received + 1;
            break;
        }

        aux = aux->sig;
        longitudLista--;

    }

    if(longitudLista == 0){
        return 0;
    }
    else if(validador == 1){
        return 1;
    }
}

int actualizarMasUnoSent(Nodo * inicio, char * llave){
    Nodo * aux = inicio;
    int i = 0;
    int longitudLista = detNumElem(inicio);
    int validador = 0;
    while(longitudLista != 0){
        for(int i = 0; i < 17; i++){
            if(aux->ip[i] == llave[i]){
                validador = 1;
            }
            else{
                validador = 0;
                break;
            }
        }

        if(validador == 1){
            aux->sent = aux->sent + 1;
            break;
        }

        aux = aux->sig;
        longitudLista--;

    }

    if(longitudLista == 0){
        return 0;
    }
    else if(validador == 1){
        return 1;
    }
}

/*
    Aquí se despliega la información de la lista.
*/

void desplegarInformacion(Nodo *inicio, FILE * fp){
    if(inicio == NULL){
        printf("La lista esta vacía");
    }
    else{
        while(inicio != NULL){
            int i = 0;
            printf("\nIP: ");
            fprintf(fp, "\nIP: ");
            printf("%s", inicio->ip);
            fprintf(fp,"%s", inicio->ip);


            printf("\t Recibidos: %i\t", inicio->received);
            fprintf(fp, "\t Recibidos: %i\t", inicio->received);

            printf("\t Enviados: %i\n", inicio->sent);
            fprintf(fp, "\t Enviados: %i\n", inicio->sent);

            inicio = inicio->sig;
        }
    }
}



#endif // IP_PLOT_LIST_