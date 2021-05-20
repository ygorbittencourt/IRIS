# IRI(S) - Inspeção de Rede Instantânea(Sniffer)
# Autor: Ygor Bittencourt
# Versão: 1.5
# 2016-2021
# MIT for you! :) 
#
#   - Sniffer de rede baseado no tshark e na biblioteca pyshark.
#   - Filtros similares ao wireshark (Ex: ip and src 10.0.0.1,Ex: tcp port 80, Ex: src 192.168.0.1, Ex: dst 10.0.0.1, Ex: port 21)
#
#   Requirements:
#   #sudo apt install tshark
#   #sudo pip install netifaces
#   #sudo pip install pyshark
#   
#   Uso:
#   sudo python3 iris.py
#
#
#   Enjoy

from datetime import datetime
import pyshark
import netifaces
import sys
sys.tracebacklimit=0

while True:
    try:
        print ('-----------------------\n')
        print ('  __(¬▂¬)__\n')
        print (' IRI(S) - Inspeção de Rede Instantânea(Sniffer)')
        

        label = datetime.now()
        agora = str(label.strftime("%H.%M.%S.%f"))
        log_saida = str('sniffer.captura.'+agora+'.txt')
        if_disponiveis = netifaces.interfaces()
        if_selecionada = str(input("\nQual interface escutar? " + str(if_disponiveis) + " ==> ") or "lo")
        print ('\nAtivando escuta na interface: {}'.format(if_selecionada))
        filtro = input("Qual o filtro(ou NADA para TUDO!)? (Ex: tcp port 80, Ex: src 192.168.0.1, Ex: dst 10.0.0.1, Ex: port 21) ==> ")
        print ('\nExibindo Captura em 5 segundos e salvando automaticamente no arquivo: ' + log_saida)
        print ('Utilize CTRL+C para terminar a captura.')
        
        cap = pyshark.LiveCapture(interface=if_selecionada, bpf_filter=filtro)
        cap.sniff(timeout=5)
        for pacotes in cap:
            arquivo = open(log_saida, 'a') 
            arquivo.write(str(pacotes)) 
            arquivo.close()
            print(pacotes)  
    except KeyboardInterrupt:
        print ('\n\n############################################################################################################## ')
        print ('\nCaptura finalizada, tudo foi salvo no arquivo ==> '+log_saida)
        print ('\n############################################################################################################## ')
        sys.exit()
