# Sentinela 3.0 — monitoramento de rede

Dashboard local em Python/Streamlit para inventário de ativos, verificações autorizadas, gestão de usuários e auditoria.

## Executar no Windows

No PowerShell, dentro da pasta do projeto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Inicie o painel:

```powershell
streamlit run app.py
```

Os ativos, as redes, os usuários e as verificações ficam no arquivo local `netwatch.db`.

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
- **Inventário:** os ativos aceitam responsável, criticidade, ambiente, localização, tags e observações, além de nome, endereço e porta de verificação.
- **Monitoramento ao vivo:** em **Operação**, escolha o intervalo de 5, 15, 30 ou 60 segundos e o modo Painel, Processo separado ou Desativado. No modo Painel, a Visão geral atualiza a tela a cada 5 segundos e executa verificações no intervalo configurado; somente sites habilitados e IPs com porta TCP configurada são sondados. Não executa Nmap nem varre sub-redes.
- **Processo separado:** selecione o modo de processo separado em **Operação** e execute `python monitor_worker.py` para manter o monitor rodando. `python monitor_worker.py --once` executa um ciclo e encerra, para uso com o Agendador de Tarefas do Windows. O processo lê o mesmo SQLite e respeita o modo e o intervalo configurados; não execute várias instâncias simultâneas.
- **Latência e disponibilidade:** a tabela e o gráfico da **Visão geral** se atualizam a cada ciclo. Uma amostra histórica é persistida no máximo a cada 60 segundos por ativo para evitar crescimento excessivo do banco; a leitura de status permanece em tempo real.
- **Análises:** a seção **Análises** apresenta disponibilidade observada, contagens online/offline e latência média, com filtros por ativo e por período. No gráfico **Verificações online e offline**, escolha 12 horas, 24 horas, 7 dias ou 30 dias; os períodos de até 24 horas são agregados em intervalos de cinco minutos e os maiores em intervalos de uma hora.
- **Alertas:** um ativo gera alerta após duas falhas consecutivas. A sirene em loop aparece na Visão geral até a recuperação; pode ser silenciada por 30 minutos, 1, 4 ou 8 horas na seção **Operação**. O navegador pode bloquear reprodução automática; nesse caso, use o controle de áudio exibido.
- **Manutenção:** edite um ativo para agendar uma janela de manutenção; o monitor deixa de sondá-lo e não toca sirene até o horário final.
- **Relatórios e backup:** a seção **Operação** exporta o histórico de até 30 dias em CSV e PDF. Também permite baixar o backup SQLite e restaurar um arquivo validado; antes de restaurar, uma cópia do banco atual é preservada ao lado do banco.
- **Verificação manual:** o botão **Verificar agora** continua disponível fora da **Visão geral**, com timeout de 3 segundos por ativo.
- **Redes /24:** cadastra faixas IPv4 para organizar e limitar os resultados importados ao inventário correto.
- **Importação de Nmap:** abra **Redes /24**, selecione a faixa e envie o relatório XML da verificação autorizada. O app importa os hosts IPv4 ativos da faixa selecionada, os nomes de host e as portas/serviços que o arquivo reporta como abertos. O arquivo fica limitado a 5 MB.
- **Verificação manual com Nmap:** disponível em **Redes /24**. Selecione explicitamente até 8 IPs privados já cadastrados e confirme a autorização. Verifica somente TCP nas portas 22, 53, 80, 443, 445, 3389 e 8080, com detecção leve de serviço. Não percorre automaticamente a faixa inteira nem todas as portas. Os resultados aparecem em **Equipamentos e portas reportados** e no inventário de **Ativos**.
- **Requisito do Nmap:** instale o Nmap oficial para Windows e deixe `nmap.exe` no `PATH`; depois reinicie o Sentinela. Download: [nmap.org/download.html](https://nmap.org/download.html#windows).
- **Limite da importação:** relatórios XML são filtrados pela rede selecionada. Portas ausentes em um relatório não são marcadas como fechadas.
- **IP importado:** recebe o hostname do relatório quando disponível; sem hostname, recebe o nome provisório `Dispositivo <IP>`. IPs cadastrados sem porta não são sondados pelo botão **Verificar agora**. As portas/serviços descobertos no relatório XML também aparecem no inventário de **Ativos**. Cadastre manualmente IPs da lista do roteador pelo campo expansível da tela **Redes /24**.
- **Redes:** edite o nome ou CIDR, ou exclua a faixa pela seção **Redes /24**. Excluir a faixa não apaga os IPs do inventário nem seus históricos.
- **Atualização das outras telas:** Ativos, Redes /24, Histórico, Usuários, Operação e Auditoria são recarregados a cada 30 segundos. Só o modo Painel na Visão geral executa verificações automáticas.
- **Dados:** cadastros e histórico persistidos localmente em SQLite.

Verifique apenas endereços que você administra ou tem autorização para monitorar. Um teste TCP confirma acesso à porta, não a disponibilidade de todos os serviços do equipamento. Ajuste o intervalo conforme a capacidade da rede e dos serviços.

## Próximas melhorias possíveis

O projeto inclui perfis Administrador/Visitante, metadados de inventário, manutenção, alertas, relatórios CSV/PDF e backup/restauração. Como próximos passos, considere testes automatizados de autorização e migrações, RBAC mais granular, políticas de retenção e exportação controlada de auditoria, além de HTTPS e gestão de sessão antes de qualquer implantação multiusuário.

Mantenha verificações de rede manuais e limitadas aos ativos autorizados. Não transforme importações de inventário em varreduras automáticas abrangentes.
