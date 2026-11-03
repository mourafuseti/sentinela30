# Sentinela 3.0 — monitoramento de rede

Dashboard local em Python/Streamlit para inventário de ativos, verificações autorizadas, gestão de usuários e auditoria.

## Executar no Windows

No PowerShell, dentro da pasta do projeto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

O Streamlit abrirá o dashboard no navegador. Os ativos, as redes, os usuários e as verificações ficam no arquivo local `netwatch.db`.

## Acesso e perfis

- No primeiro uso, entre com **usuário `admin` e senha `admin`**. A troca da senha é obrigatória antes de acessar o painel.
- A senha nova deve ter no mínimo 12 caracteres e incluir pelo menos três grupos entre minúsculas, maiúsculas, números e símbolos.
- Administradores podem cadastrar contas com perfil **Administrador** ou **Visitante**, redefinir senhas temporárias, alterar perfis e desativar contas.
- Visitantes têm acesso somente para consulta. Verificações, importações e alterações ficam restritas a administradores.
- Senhas são armazenadas como hashes PBKDF2-SHA256 com salt individual. Após cinco falhas de login, novas tentativas ficam bloqueadas por 15 minutos.
- A seção **Auditoria** registra autenticações e ações administrativas, sem registrar senhas.
- O banco de dados contém inventário e histórico. Faça cópias de segurança controladas do arquivo `netwatch.db`.

**Limite de segurança:** este projeto é uma aplicação acadêmica local, não um serviço de autenticação pronto para exposição pública. Não encaminhe a porta do Streamlit à Internet nem o disponibilize em redes não confiáveis. Para uso multiusuário real, adicione HTTPS, gestão segura de sessões e segredos, proteção de cookies, testes de autorização e armazenamento de auditoria protegido contra alteração.

O servidor está configurado para escutar somente em `127.0.0.1`. Para acesso por outros computadores, não remova essa proteção sem antes planejar autenticação de produção, HTTPS e controles de rede.

## Como funciona

- **IPs:** cadastre somente o endereço; a porta fica sem configuração inicial. Opcionalmente, configure uma porta TCP específica na edição do ativo.
- **Sites:** teste HTTP/HTTPS; redirecionamentos não são seguidos.
- **Monitoramento ao vivo:** na **Visão geral**, administradores verificam automaticamente a cada 3 segundos somente sites habilitados e IPs com porta TCP configurada. O monitoramento roda enquanto a sessão está aberta nessa tela; não executa Nmap nem varre sub-redes.
- **Latência e disponibilidade:** a tabela e o gráfico da **Visão geral** se atualizam a cada ciclo. Uma amostra histórica é persistida no máximo a cada 60 segundos por ativo para evitar crescimento excessivo do banco; a leitura de status permanece em tempo real.
- **Alarme:** se um ativo habilitado ficar offline, uma sirene em loop aparece na **Visão geral** e para quando todos voltarem online. O navegador pode bloquear reprodução automática; nesse caso, use o controle de áudio exibido.
- **Verificação manual:** o botão **Verificar agora** continua disponível fora da **Visão geral**, com timeout de 3 segundos por ativo.
- **Redes /24:** cadastra faixas IPv4 para organizar e limitar os resultados importados ao inventário correto.
- **Importação de Nmap:** abra **Redes /24**, selecione a faixa e envie o relatório XML da verificação autorizada. O app importa os hosts IPv4 ativos da faixa selecionada, os nomes de host e as portas/serviços que o arquivo reporta como abertos. O arquivo fica limitado a 5 MB.
- **Verificação manual com Nmap:** disponível em **Redes /24**. Selecione explicitamente até 8 IPs privados já cadastrados e confirme a autorização. Verifica somente TCP nas portas 22, 53, 80, 443, 445, 3389 e 8080, com detecção leve de serviço. Não percorre automaticamente a faixa inteira nem todas as portas. Os resultados aparecem em **Equipamentos e portas reportados** e no inventário de **Ativos**.
- **Requisito do Nmap:** instale o Nmap oficial para Windows e deixe `nmap.exe` no `PATH`; depois reinicie o Sentinela. Download: [nmap.org/download.html](https://nmap.org/download.html#windows).
- **Limite da importação:** relatórios XML são filtrados pela rede selecionada. Portas ausentes em um relatório não são marcadas como fechadas.
- **IP importado:** recebe o hostname do relatório quando disponível; sem hostname, recebe o nome provisório `Dispositivo <IP>`. IPs cadastrados sem porta não são sondados pelo botão **Verificar agora**. As portas/serviços descobertos no relatório XML também aparecem no inventário de **Ativos**. Cadastre manualmente IPs da lista do roteador pelo campo expansível da tela **Redes /24**.
- **Redes:** edite o nome ou CIDR, ou exclua a faixa pela seção **Redes /24**. Excluir a faixa não apaga os IPs do inventário nem seus históricos.
- **Atualização das outras telas:** Ativos, Redes /24, Histórico, Usuários e Auditoria são recarregados a cada 30 segundos. Só a Visão geral executa verificações automáticas.
- **Dados:** cadastros e histórico persistidos localmente em SQLite.

Verifique apenas endereços que você administra ou tem autorização para monitorar. Um teste TCP confirma acesso à porta, não a disponibilidade de todos os serviços do equipamento. O intervalo de 3 segundos gera tráfego contínuo para cada ativo configurado; use-o apenas em ativos autorizados e reduza a frequência se isso sobrecarregar a rede ou os serviços.

## Opções de evolução para o projeto de graduação

1. **Autenticação mais forte:** TOTP/MFA, política de sessão e recuperação segura de conta.
2. **RBAC granular:** permissões separadas para inventário, monitoramento, importação e gestão de contas.
3. **Alertas defensivos:** notificações de indisponibilidade, mudança de serviço ou novo ativo, com regras configuráveis.
4. **Auditoria robusta:** exportação, retenção configurável e envio para um SIEM/syslog com controles de integridade.
5. **Inventário enriquecido:** proprietário, criticidade, sistema operacional, localização, tags e ciclo de vida.
6. **Hardening e qualidade:** HTTPS, backup/restauração, testes automatizados de autorização, validação de entradas e análise estática.
7. **Relatórios acadêmicos:** métricas de disponibilidade, ativos sem responsável e mudanças observadas, com escopo e autorização documentados.

Mantenha verificações de rede manuais e limitadas aos ativos autorizados. Não transforme importações de inventário em varreduras automáticas abrangentes.
