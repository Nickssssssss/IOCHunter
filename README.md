# Plataforma de Threat Intelligence com IA

Esta plataforma é uma solução completa para análise de Indicadores de Comprometimento (IOCs), como IPs, domínios, hashes e URLs. O objetivo é fornecer contexto relevante para analistas de segurança, integrando múltiplas fontes públicas e privadas, além de recursos de IA para enriquecer a investigação.

---

## 📦 Estrutura do Projeto

```
threat_intel_platform/
├── app.py              # Aplicação principal Streamlit (interface e lógica)
├── utils.py            # Funções utilitárias para análise de IOCs e integração com APIs
├── rag.py              # Sistema RAG (Retrieval-Augmented Generation) para análise com IA
├── requirements.txt    # Lista de dependências do projeto
├── .env                # Variáveis de ambiente (chaves de API)
├── db/
│   └── GeoLite2-City.mmdb  # Banco de dados de geolocalização MaxMind
└── README.md           # Este arquivo de documentação
```

---

## 🚀 Funcionalidades

- **Análise de múltiplos tipos de IOC:** IPs, domínios, hashes (MD5, SHA1, SHA256) e URLs.
- **Integração com diversas fontes:**
  - Whois (IP e Domínio)
  - DNS (nslookup passivo)
  - Certificados SSL
  - Geolocalização (GeoIP)
  - VirusTotal (reputação e análise)
  - Shodan (exposição e serviços)
  - AbuseIPDB (reputação de IP)
  - ThreatFox (ameaças recentes)
  - DNSDumpster (enumeração passiva)
- **Visualização geográfica:** Mapa interativo com Plotly para localização de IPs.
- **Histórico de buscas:** Armazena e exibe pesquisas recentes.
- **Exportação de relatórios:** Markdown, TXT e JSON.
- **Análise com IA:** Sistema RAG (Retrieval-Augmented Generation) para responder perguntas sobre os IOCs analisados.
- **Reconhecimento Passivo e OSINT:**
  - Subdomínios via crt.sh
  - Histórico de domínios (Wayback Machine)
  - Motores OSINT: DuckDuckGo, GitHub, Hunter.io, URLScan.io
  - Extração de e-mails públicos e vazamentos relacionados
- **Verificações de Segurança:**
  - Headers HTTP de segurança
  - Fingerprinting de tecnologias (BuiltWith)
  - Análise de conteúdo HTML

---

## 🛠️ Requisitos

- Python 3.8 ou superior
- Dependências listadas em [`requirements.txt`](requirements.txt)
- Chaves de API (opcionais, mas recomendadas para acesso total):
  - VirusTotal
  - Shodan
  - AbuseIPDB
  - ThreatFox
  - OpenAI (para IA/RAG)
  - Hunter.io (para busca de e-mails)
  - URLScan.io (para análise de URLs)
  - GitHub Token (para busca de códigos)

---

## ⚙️ Instalação

1. **Clone o repositório ou extraia os arquivos:**

   ```bash
   git clone https://github.com/Nickssssssss/IOCHunter.git
   cd IOCHunter
   ```

2. **Instale as dependências:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure as variáveis de ambiente para as chaves de API (opcional, mas recomendado):**

   Você pode definir as variáveis no terminal:

   ```bash
   export VIRUSTOTAL_API_KEY=sua_chave_aqui
   export SHODAN_API_KEY=sua_chave_aqui
   export ABUSEIPDB_API_KEY=sua_chave_aqui
   export THREATFOX_API_KEY=sua_chave_aqui
   export OPENAI_API_KEY=sua_chave_aqui
   export HUNTER_API_KEY=sua_chave_aqui
   export URLSCAN_API_KEY=sua_chave_aqui
   export GITHUB_TOKEN=sua_chave_aqui
   ```

   Ou criar um arquivo `.env` no diretório do projeto com o seguinte conteúdo:

   ```
   VIRUSTOTAL_API_KEY='...'
   SHODAN_API_KEY='...'
   ABUSEIPDB_API_KEY='...'
   THREATFOX_API_KEY='...'
   OPENAI_API_KEY='...'
   HUNTER_API_KEY='...'
   URLSCAN_API_KEY='...'
   GITHUB_TOKEN='...'
   ```

4. **Banco de dados GeoLite2:**
   - O arquivo `GeoLite2-City.mmdb` precisa ser colocado na pasta `db/`. Caso precise atualizar, baixe em https://dev.maxmind.com/geoip/geolite2-free-geolocation-data.

---

## ▶️ Execução

Execute a aplicação com Streamlit:

```bash
streamlit run app.py
```

Acesse no navegador: [http://localhost:8501](http://localhost:8501)

---

## 💡 Uso

1. **Insira um IOC** (IP, domínio, hash ou URL) no campo de entrada.
2. **Clique em "Analisar IOC"** para iniciar a análise.
3. **Navegue pelas abas** para visualizar resultados detalhados:
   - Visão Geral
   - Detalhes Técnicos
   - Geolocalização
   - Fontes Externas (APIs)
   - Análise de Conteúdo Web
   - Análise com IA (RAG)
   - Histórico
   - Exportar
4. **Faça perguntas na aba "Análise com IA"** para obter respostas contextuais sobre o IOC.
5. **Exporte os resultados** em Markdown, TXT ou JSON na aba "Exportar".

---

## 🔗 Ferramentas e APIs Integradas

- **Whois:** Consulta de informações de registro de IPs e domínios.
- **DNS:** Resolução passiva de registros A, MX, NS, TXT, etc.
- **SSL:** Coleta de informações de certificados digitais.
- **GeoIP:** Localização geográfica de IPs usando MaxMind.
- **VirusTotal:** Análise de reputação e detecção de ameaças.
- **Shodan:** Exposição de serviços e portas abertas.
- **AbuseIPDB:** Reputação de IPs baseada em denúncias.
- **ThreatFox:** Dados de ameaças recentes.
- **DNSDumpster:** Enumeração passiva de subdomínios.
- **crt.sh:** Enumeração de subdomínios via certificados públicos.
- **Wayback Machine:** Histórico de snapshots de domínios.
- **DuckDuckGo:** Busca OSINT passiva.
- **GitHub:** Busca de códigos relacionados ao IOC.
- **Hunter.io:** Busca de e-mails públicos do domínio.
- **URLScan.io:** Análise detalhada de URLs.
- **BuiltWith:** Fingerprinting de tecnologias web.
- **Headers de Segurança:** Verificação de headers HTTP importantes.

---

## 🧠 Arquitetura Técnica

O projeto utiliza o modelo de IA com RAG (Retrieval-Augmented Generation), onde os dados coletados sobre um IOC são convertidos em documentos vetorizados com `OpenAIEmbeddings`, armazenados localmente com `FAISS`, e utilizados como contexto em consultas com IA (OpenAI GPT). Isso permite respostas inteligentes e contextuais sem acúmulo de memória entre análises.

Além disso, todas as fontes são consultadas com foco em passividade, evitando ações que possam ser interpretadas como ataques ativos.

---

## 📤 Exportação

- Relatórios completos em Markdown (`.md`), texto puro (`.txt`) e JSON (`.json`).
- Exportação do histórico de buscas e conversas com IA.

---

## 📚 Limitações

- **Chaves de API:** Sem as chaves, algumas funcionalidades terão resultados simulados ou limitados.
- **IA (RAG):** Requer chave de API da OpenAI.
- **Limites de requisição:** Algumas APIs possuem limites em suas versões gratuitas.
- **Reconhecimento passivo:** O projeto evita técnicas de ataque ativo para não gerar tráfego suspeito ao alvo.
- **Banco GeoLite2:** Para geolocalização, é necessário manter o arquivo atualizado.

---

## 📝 Observações

- O projeto é focado em **reconhecimento passivo** e não realiza ações ofensivas.
- Recomenda-se o uso responsável e ético, respeitando as políticas das APIs utilizadas.
- Para dúvidas ou sugestões, consulte o código-fonte ou abra uma issue no repositório.

# Security Notice

Este projeto foi desenvolvido para fins **educacionais e pessoais**. Não é mantido com foco em produção ou uso comercial.

- Nenhum suporte oficial é oferecido.
- Não aceitamos relatórios de vulnerabilidade.
- O uso de chaves de API e credenciais deve ser feito de forma segura pelo usuário final.

**Uso para fins maliciosos é estritamente proibido.**

---

## 👨‍💻 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

---
