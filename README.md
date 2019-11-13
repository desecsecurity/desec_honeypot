# desec_honeypot

[![Python 3.5.3](https://img.shields.io/badge/python-3.5.3-blue.svg)](https://www.python.org/downloads/release/python-353/)

Honeypot para captura de dados de intrusão.

  - Banco de dados sqlite3.
  - Armazenamento de IP, porta, mensagens, data e horário de acesso.
  - Consultas em SQL.
  - Suporte a COUNT (contagem de registros).
  - Bloqueio por IPs de origem através de comandos SQL.
  - Bloqueio de Portas através de comandos SQL.

### Argumentos

Modo de usar:

usage: honeypot.py [-h] [-i IPADDR] [-p PORTS [PORTS ...]] [-q QUERY] [-e] [-v]

-h, --help show this help message and exit
-i IPADDR, --ipaddr IPADDR (IP address server)
-p PORTS [PORTS ...], --ports PORTS [PORTS ...] (List of ports to open)
-q QUERY, --query QUERY (SQL query for search in logs)
-e, --examples (Examples of SQL query)
-v, --version  (show program's version number and exit)

### Estrutura do banco de dados

Nome: logs.db

Nome das tabelas: logs, info, ports

Colunas na tabela logs:
                        log_id (integer)   - Log ID
                        ip_orig (string)   - Origin IP
                        port_orig (string) - Origin Port
                        ip_dst (string)    - Destination IP
                        port_dst (string)  - Destination Port
                        created (datetime) - format: %Y-%m-%d %H:%M:%S
                        banned (boolean)   - false = 0 | true = 1

Colunas na tabela info:
                        info_id (integer)   - Info ID
                        msg (string)        - Message from client
                        log_fk (integer)    - Logs foreign key

Colunas na tabela ports:
                        port_id (integer)   - Port ID
                        port (integer)      - Port number
                        blocked (boolean)   - false = 0 | true = 1


Mostrar ajuda:
```sh
$ python3 honeypot.py -h
```

Antes de executar o Honeypot verifique o IP da máquina local.
Usando o comando ifconfig no Linux e obtendo o IP da interface de rede (eth0, eth1, enp4s0):
```sh
$ sudo ifconfig
```

Exemplo de execução do Honeypot ouvindo as portas 2222, 3333 e 5555:
```sh
$ python3 honeypot.py -i 192.168.1.6 -p 2222 3333 5555
```

Conectando ao Honeypot com netcat na porta 2222:
```sh
$ nc -v 192.168.1.6 2222
```

### Exemplos de comandos SQL através do parâmetro [-q] [--query]

Listando todos os registros da tabela logs:
```sh
-q "SELECT * FROM logs;"
```

Listando todos os registros da tabela ports:
```sh
-q "SELECT * FROM ports;"
```

Listando os cinco últimos registros de um determinado IP ordenado por ordem de criação:
```sh
-q "SELECT * FROM logs WHERE ip_orig='192.168.1.132' ORDER BY created DESC LIMIT 5;"
```

Selecionando IP e porta de destino cujas portas estejam entre 22 e 80:
```sh
-q "SELECT ip_orig, port_dst FROM logs WHERE port_orig BETWEEN 2200 AND 2500;"
```

Selecionando IP e porta de destino que tenham sido registrados entre duas datas específicas:
```sh
-q "SELECT ip_orig, port_dst FROM logs WHERE created BETWEEN '2019-10-01 12:00:00' AND '2019-10-05 12:00:00';"
```

Selecionando IP de origem e mensagens pela ID de um registro:
```sh
-q "SELECT ip_orig, msg FROM logs INNER JOIN info WHERE log_id=1 AND log_id=log_fk;"
```

Bloqueando a conexão a um IP de origem:
```sh
-q "UPDATE logs SET banned=1 WHERE ip_orig='192.168.120.132';"
```

Bloqueando uma porta de destino específica no servidor:
```sh
-q "INSERT INTO ports (port, blocked) VALUES (3500, 1);"
```

Desbloqueando uma porta de destino específica no servidor:
```sh
-q "UPDATE ports SET blocked=0 WHERE port=3500;"
```

Bloqueando uma lista de portas no servidor:
```sh
-q "INSERT INTO ports (port, blocked) VALUES (2000, 1), (3000, 1), (4000, 1), (5000, 1);"
```

Desbloqueando uma lista de portas no servidor:
```sh
-q "UPDATE ports SET blocked=0 WHERE port IN (2000, 3000, 4000, 5000);"
```

### Screenshots

[![Desec Honeypot](https://i.imgur.com/eXoW50e.png)](https://github.com/desecsecurity/desec_honeypot/)

[![Desec Honeypot](https://i.imgur.com/me4nzIv.png)](https://github.com/desecsecurity/desec_honeypot/)

[![Desec Honeypot](https://i.imgur.com/gcfH62J.png)](https://github.com/desecsecurity/desec_honeypot/)