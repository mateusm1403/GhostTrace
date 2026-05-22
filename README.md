# GhostTrace

GhostTrace é uma plataforma local de Deception Technology desenvolvida para geração de HoneyTokens, captura de tentativas de acesso suspeitas e análise comportamental de atividades potencialmente maliciosas.

O projeto foi criado com foco em laboratórios de segurança, estudos de Blue Team, simulações defensivas e demonstrações internas, oferecendo uma experiência totalmente plug-and-play sem depender de Redis, Kafka, Elasticsearch, serviços em nuvem ou APIs pagas.

A proposta do GhostTrace é simples: criar iscas controladas capazes de identificar movimentações suspeitas, scanners automatizados, enumeração de diretórios e comportamentos comuns de reconhecimento em ambientes web.

---

## Visão Geral

O GhostTrace permite:

- Gerar endpoints falsos e HoneyTokens únicos
- Criar arquivos de configuração falsos para detecção de acesso indevido
- Monitorar acessos suspeitos em tempo real
- Detectar padrões de brute force, fuzzing e scanners automatizados
- Aplicar threat scoring baseado em comportamento
- Gerar alertas estruturados e relatórios JSON
- Simular ataques comuns para validação do ambiente

---

# Dashboard

<img width="1544" height="759" alt="image" src="https://github.com/user-attachments/assets/69e3aae6-030d-41d2-98d2-fb9e8b38525a" />
<img width="1540" height="746" alt="image" src="https://github.com/user-attachments/assets/8dca8e8f-fb77-412f-95f1-6366eb44ce75" />
<img width="1544" height="759" alt="image" src="https://github.com/user-attachments/assets/3e470d40-1aec-4fcb-a138-bcd294740ba1" />



---

# Logs e Eventos em Tempo Real

<img width="1377" height="833" alt="image" src="https://github.com/user-attachments/assets/fc565e45-83f1-4c26-bd15-bbd52328a0b4" />

---

## Principais Recursos

### HoneyTokens e Deception

- Geração de URLs falsas exclusivas
- Fake API Tokens
- Arquivos de configuração falsos estilo produção
- Endpoints isca para detecção de recon

### Captura de Eventos

A aplicação captura automaticamente:

- IP de origem
- Timestamp
- Headers HTTP
- Método da requisição
- User-Agent
- Path acessado
- Query parameters
- Código de resposta
- Token relacionado ao evento

### Analytics e Detecção

O GhostTrace utiliza `pandas` e regras heurísticas para identificar:

- Assinaturas de scanners como Nikto e Dirbuster
- Alto volume de requisições
- Repetição de erros `404`
- Tentativas usando `HEAD` e `OPTIONS`
- Enumeração de diretórios
- Paths sensíveis ou suspeitos
- Comportamentos de brute force
- Acessos a HoneyTokens

### Dashboard Web

Interface leve utilizando:

- FastAPI
- Jinja2
- HTMX

O dashboard exibe:

- Eventos recentes
- Alertas ativos
- Top IPs suspeitos
- User-Agents detectados
- Threat score
- Timeline de eventos

### Alertas e Relatórios

- Alertas estruturados em console
- Relatórios JSON automáticos
- Integração opcional com Discord Webhook

---

## Arquitetura do Projeto

```text
ghosttrace/
├── app/
│   ├── api/          # Rotas da API, dashboard e simulações
│   ├── analyzers/    # Engine de analytics e threat scoring
│   ├── core/         # Configurações, scheduler e logging
│   ├── db/           # Engine SQLAlchemy e inicialização do banco
│   ├── models/       # Modelos de dados
│   ├── services/     # Captura, geração de tokens e alertas
│   ├── templates/    # Templates Jinja2
│   ├── static/       # CSS e assets locais
│   └── main.py       # Aplicação FastAPI
│
├── honeypots/        # Arquivos falsos gerados
├── reports/          # Relatórios JSON e snapshots
├── tests/
├── .env.example
├── requirements.txt
├── docker-compose.yml
└── run.py
```

---

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seuusuario/ghosttrace.git
cd ghosttrace
```

### 2. Crie a virtualenv

```bash
python -m venv venv
```

### 3. Ative a virtualenv

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/macOS

```bash
source venv/bin/activate
```

### 4. Instale as dependências

```bash
pip install -r requirements.txt
```

### 5. Execute a aplicação

```bash
python run.py
```

---

## Acesso

Após iniciar a aplicação:

```text
http://127.0.0.1:8000
```

---

## Configuração Opcional

Você pode copiar o arquivo:

```text
.env.example
```

para:

```text
.env
```

e personalizar parâmetros como Webhook do Discord.

---

## Uso Básico

### Gerar HoneyTokens

#### URL Token

```bash
curl -X POST http://127.0.0.1:8000/tokens/url
```

#### API Token

```bash
curl -X POST http://127.0.0.1:8000/tokens/api
```

#### Config Token

```bash
curl -X POST http://127.0.0.1:8000/tokens/config
```

---

## Simular Acesso a uma Isca

```bash
curl http://127.0.0.1:8000/t/<identifier>
```

---

## Simular Uso de API Token

```bash
curl -H "Authorization: Bearer <generated-api-token>" \
http://127.0.0.1:8000/api/events
```

---

## Gerar Relatório

```bash
curl http://127.0.0.1:8000/reports/latest
```

---

# Simulações de Ataque

O GhostTrace possui rotas internas para simulação segura de comportamentos maliciosos comuns.

Essas simulações geram eventos sintéticos realistas para validar:
- analytics
- scoring
- alertas
- dashboard
- relatórios

### Simulação Nikto

```bash
curl http://127.0.0.1:8000/simulate/nikto
```

### Simulação Dirbuster

```bash
curl http://127.0.0.1:8000/simulate/dirbuster
```

### Simulação de Brute Force

```bash
curl http://127.0.0.1:8000/simulate/bruteforce
```

---

# Threat Scoring

O sistema utiliza um modelo simples de pontuação ponderada baseado em comportamento.

## Indicadores analisados

- Assinatura Nikto
- Assinatura Dirbuster
- Alto volume de requisições
- Múltiplos `404`
- Uso suspeito de `HEAD` e `OPTIONS`
- Paths sensíveis
- Enumeração de diretórios
- Brute force
- Acesso a HoneyTokens

## Níveis de ameaça

| Nível | Score |
|---|---|
| LOW | 0 - 29 |
| MEDIUM | 30 - 59 |
| HIGH | 60 - 89 |
| CRITICAL | 90 - 100 |

---

# Alertas

Os alertas são:

- exibidos em console
- registrados em JSON
- armazenados localmente
- opcionais via Discord Webhook

Para ativar integração Discord:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

A integração é opcional. O projeto funciona completamente offline.

---

# Docker (Opcional)

```bash
docker compose up --build
```

O fluxo principal recomendado continua sendo a execução local via Python.

---

# Roadmap

## Melhorias futuras

- Exportação CSV de eventos
- Ajuste de regras via dashboard
- Página individual por HoneyToken
- Workflow de acknowledgement de alertas
- Tags estilo MITRE ATT&CK
- Novos perfis de simulação
- GeoIP enrichment
- Export Sigma-like
- Heatmaps de ameaça

---

# Objetivo do Projeto

O GhostTrace foi desenvolvido como um laboratório defensivo simples, transparente e fácil de executar localmente.

A ideia não é substituir soluções enterprise de Deception Technology, mas servir como:
- ambiente educacional
- laboratório Blue Team
- ferramenta de demonstração
- projeto de portfólio
- base para futuras integrações SOC/SIEM

---

# Aviso Ético

GhostTrace é uma ferramenta defensiva voltada para estudos, monitoramento e treinamento em segurança ofensiva/defensiva.

Utilize apenas em ambientes próprios ou explicitamente autorizados.

Não utilize o projeto para monitorar, enganar ou coletar informações de terceiros sem permissão formal.
