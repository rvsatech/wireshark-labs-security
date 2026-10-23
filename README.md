# Wireshark Labs: Aprendendo Análise de Redes e Segurança 🛡️

Este repositório foi criado para documentar meus laboratórios práticos com o **Wireshark**. O objetivo principal é fixar o aprendizado sobre o funcionamento da internet por baixo dos panos, entendendo como os pacotes trafegam, como analisar fluxos de dados e como utilizar a linguagem **Lua** para automatizar tarefas.

---

## 🧭 A Jornada de Aprendizado (Como tudo começou)

### 1. Entendendo o Tráfego e Limpando o Ruído
No início, ao abrir o Wireshark e selecionar a placa de Wi-Fi, a quantidade de dados na tela assustou. Parecia uma "Matrix" com milhares de linhas subindo sem parar. A maior parte eram mensagens de "bastidores" da rede e confirmações de conexão do protocolo TCP (mensagens do tipo *"tá aí? tô sim"*).

Para conseguir ler os dados de forma humanamente aceitável, comecei a aplicar filtros na barra verde superior do programa:

* **Foco no meu dispositivo:** Isolei apenas o tráfego que saía ou entrava na minha máquina:
  ```text
  ip.addr == 192.168.15.6
  ```
* **Eliminando o ruído:** Para sumir com as mensagens repetitivas de confirmação que não carregavam conteúdo real, combinei filtros para mostrar apenas pacotes com tamanho maior que zero:
  ```text
  ip.addr == 192.168.15.6 and tcp.len > 0
  ```

### 2. Rastreando um Site Real (O Teste com o GitHub)
Para ver a mágica acontecer, fiz um teste prático acessando o **GitHub**. Como o site usa criptografia moderna (HTTPS/TLSv1.3), o conteúdo das páginas e senhas viaja trancado em pacotes ilegíveis. Porém, descobri que no primeiríssimo pacote de conexão (o *Client Hello*), o computador precisa dizer em texto puro para onde quer ir. 

Usei o filtro abaixo para flagrar exatamente o momento em que meu computador revelou o destino através do campo **SNI (Server Name Indication)**:
```text
tls.handshake.extensions_server_name == "github.com"
```
Com isso, consegui isolar o IP exato do servidor do GitHub e entender como o navegador faz o "aperto de mão" com o servidor antes de blindar a conversa.

---

## 💡 O Insight: "Como usar isso no dia a dia? Dá para automatizar!"

Ao perceber que analisar pacotes linha por linha manualmente em arquivos grandes seria exaustivo, veio o pensamento: *E se eu puder automatizar essa busca?* 

Descobri que o Wireshark possui um interpretador nativo da linguagem **Lua**. Em vez de digitar filtros na barra toda hora, criei um script separado chamado `main.lua` que roda direto na memória do programa, monitora o tráfego e gera um relatório consolidado de forma inteligente.

O script foi desenhado para fazer uma auditoria automática na captura de rede em busca de duas situações importantes:
1. **Tráfego Inseguro:** Conta quantos pacotes estão rodando via HTTP puro (sem criptografia), onde os dados ficam expostos.
2. **Varredura de Portas (Port Scanning):** Detecta se algum IP suspeito está tentando "forçar a entrada" em várias portas do meu computador ao mesmo tempo.

---

## 🚀 Como testei e coloquei na Inicialização

Para deixar o laboratório ainda mais prático e integrado, configurei o Wireshark para carregar o `main.lua` de forma 100% automática sempre que o programa é aberto. 

1. Abri a pasta de configurações locais do Wireshark no Windows usando o atalho `Windows + R` e digitando:
   ```text
   %APPDATA%\Wireshark
   ```
2. Criei uma pasta chamada `plugins` (caso não existisse).
3. Salvei o arquivo `main.lua` diretamente dentro dela.

Agora, o script funciona como uma extensão nativa do meu Wireshark. Sempre que altero o código no VS Code, basta ir na tela do Wireshark e pressionar **`Ctrl + Shift + L`** para recarregar as modificações instantaneamente sem precisar fechar o aplicativo.

### 🧪 Executando o Teste Prático
Para forçar o gatilho de tráfego inseguro no script e validar o laboratório, acessei o site de testes sem criptografia:
👉 `http://neverssl.com`

Após rodar o script no tráfego capturado, o console do Wireshark exibiu com sucesso o relatório com os alertas mapeados automaticamente:

![Resultado do Console no Wireshark](console_wireshark.png)

---
*Laboratório focado no entendimento prático de protocolos de redes, análise de pacotes e automação defensiva.*
