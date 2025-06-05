import os
from langchain_community.vectorstores.faiss import FAISS
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableParallel, RunnablePassthrough
import json
from datetime import datetime

INITIAL_VECTORSTORE_TEXT = "Contexto inicial da Plataforma de Threat Intelligence."
EMBEDDING_MODEL = "text-embedding-3-small"
LLM_MODEL = 'gpt-4.1-nano-2025-04-14'
RETRIEVER_SEARCH_TYPE = 'mmr' 
RETRIEVER_K = 5 
RETRIEVER_FETCH_K = 20 

def convert_datetime(obj):
    if isinstance(obj, dict):
        return {k: convert_datetime(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj

class ThreatIntelRAG:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.vectorstore = None
        self.chain = None
        self.ioc_data = {}
        self.embeddings = None

        if not self.api_key:
            print("Aviso: Chave da API OpenAI não encontrada. O RAG não funcionará corretamente.")
            return

        self._initialize_rag()

    def _initialize_rag(self):
        if not self.api_key:
            return

        try:
            self.embeddings = OpenAIEmbeddings(api_key=self.api_key, model=EMBEDDING_MODEL)

            self.vectorstore = FAISS.from_texts(
                texts=[INITIAL_VECTORSTORE_TEXT],
                embedding=self.embeddings
            )

            prompt = ChatPromptTemplate.from_template(
                ''' Você é um analista de segurança cibernética especializado em Threat Intelligence e investigação de IOCs (Indicadores de Comprometimento).
                Baseie suas respostas exclusivamente no **contexto fornecido** a seguir. Esse contexto inclui dados coletados sobre um IOC, como informações Whois, DNS, reputação, localização, entre outros.

                Contexto: {contexto}

                Pergunta: {pergunta}

                Forneça uma resposta detalhada, técnica e precisa, baseada apenas nas informações do contexto e do IOC que foi passado atualmente para você e que esta sendo analisada.
                Se o contexto não contiver informações suficientes para responder à pergunta, 
                indique claramente o que falta e sugira como obter essas informações.'''
            )

            retriever = self.vectorstore.as_retriever(
                search_type=RETRIEVER_SEARCH_TYPE,
                search_kwargs={'k': RETRIEVER_K, 'fetch_k': RETRIEVER_FETCH_K}
            )

            def join_documents(input_dict):
                input_dict['contexto'] = '\n\n'.join([c.page_content for c in input_dict['contexto']])
                return input_dict

            setup = RunnableParallel({
                'pergunta': RunnablePassthrough(),
                'contexto': retriever
            }) | join_documents

            llm = ChatOpenAI(api_key=self.api_key, model=LLM_MODEL)

            self.chain = setup | prompt | llm
            return True
        except Exception as e:
            print(f"Erro ao inicializar o RAG: {str(e)}")
            return False

    def add_ioc_data(self, ioc, ioc_type, data):
        if not self.vectorstore or not self.api_key:
            return False

        try:
            data = convert_datetime(data)
            self.ioc_data[ioc] = {
                'type': ioc_type,
                'data': data
            }

            texts = [f"IOC: {ioc}\nTipo: {ioc_type}\n"]

            for section, section_data in data.items():
                if section in ["ioc", "ioc_type", "timestamp"]:
                    continue

                section_text = f"Seção: {section.upper()}\n"

                # VIRUSTOTAL - Adicionar o máximo de informações possíveis
                if section == "virustotal":
                    vt_data = section_data.get("data", {})
                    attr = vt_data.get("attributes", {})

                    # Estatísticas gerais
                    section_text += "=== Estatísticas Gerais ===\n"
                    stats = attr.get("last_analysis_stats", {})
                    for k, v in stats.items():
                        section_text += f"- {k.capitalize()}: {v}\n"

                    # Datas importantes
                    section_text += "\n=== Datas Importantes ===\n"
                    for date_field in ["first_submission_date", "last_submission_date", "last_analysis_date", "creation_date"]:
                        if attr.get(date_field):
                            try:
                                dt = datetime.fromtimestamp(attr[date_field])
                                section_text += f"- {date_field.replace('_', ' ').capitalize()}: {dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
                            except Exception:
                                section_text += f"- {date_field.replace('_', ' ').capitalize()}: {attr[date_field]}\n"

                    # Tamanho, tipo de arquivo, nome, magic, etc.
                    for meta_field in ["size", "type_description", "type_tag", "md5", "sha1", "sha256", "magic", "meaningful_name", "file_type", "file_type_extension"]:
                        if attr.get(meta_field):
                            section_text += f"- {meta_field.replace('_', ' ').capitalize()}: {attr[meta_field]}\n"

                    # Detecções detalhadas por antivírus
                    vt_results = attr.get("last_analysis_results", {})
                    if vt_results:
                        section_text += "\n=== Detecções por Antivírus ===\n"
                        for engine, result in vt_results.items():
                            section_text += (
                                f"- {engine}: "
                                f"Resultado: {result.get('result', 'N/A')}, "
                                f"Categoria: {result.get('category', 'N/A')}, "
                                f"Engine versão: {result.get('engine_version', 'N/A')}, "
                                f"Definição: {result.get('engine_update', 'N/A')}\n"
                            )

                    # Links úteis
                    if vt_data.get("links", {}).get("self"):
                        section_text += f"\n- Link para análise completa: {vt_data['links']['self']}\n"

                # SHODAN - Adicionar o máximo de informações possíveis
                elif section == "shodan":
                    if "error" in section_data:
                        section_text += f"Erro: {section_data['error']}\n"
                    else:
                        # Para IPs
                        for key in ["ip_str", "hostnames", "domains", "org", "isp", "asn", "os", "country_name", "city", "region_code", "latitude", "longitude"]:
                            if section_data.get(key):
                                section_text += f"- {key.replace('_', ' ').capitalize()}: {section_data[key]}\n"
                        # Portas abertas e serviços
                        if "data" in section_data and isinstance(section_data["data"], list):
                            section_text += "\n=== Serviços Encontrados ===\n"
                            for service in section_data["data"]:
                                port = service.get("port", "N/A")
                                product = service.get("product", "N/A")
                                version = service.get("version", "N/A")
                                banner = service.get("data", "")[:200].replace('\n', ' ')
                                section_text += f"- Porta: {port}, Produto: {product}, Versão: {version}, Banner: {banner}\n"
                        # Vulns
                        if "vulns" in section_data:
                            section_text += "\n=== Vulnerabilidades ===\n"
                            for vuln in section_data["vulns"]:
                                section_text += f"- {vuln}\n"

                # WEB CONTENT - Adicionar o máximo de informações possíveis
                elif section == "web_content":
                    section_text += "=== Análise de Conteúdo Web ===\n"

                    if "title" in section_data:
                        section_text += f"- Título da Página: {section_data['title']}\n"

                    if "status_code" in section_data:
                        section_text += f"- Código de Status HTTP: {section_data['status_code']}\n"

                    if "final_url" in section_data and section_data["final_url"] != ioc:
                        section_text += f"- Redirecionamento Detectado: {section_data['final_url']}\n"

                    if "headers" in section_data and isinstance(section_data["headers"], dict):
                        section_text += "\n--- Headers HTTP ---\n"
                        for hname, hval in section_data["headers"].items():
                            section_text += f"- {hname}: {hval}\n"

                    if section_data.get("forms"):
                        section_text += "\n--- Formulários Detectados ---\n"
                        for form in section_data["forms"]:
                            section_text += f"- Action: {form}\n"
                    else:
                        section_text += "\n- Nenhum formulário detectado\n"

                    if section_data.get("scripts"):
                        section_text += "\n--- Scripts Externos ---\n"
                        for script in section_data["scripts"]:
                            section_text += f"- {script}\n"
                    else:
                        section_text += "\n- Nenhum script externo detectado\n"

                    if section_data.get("iframes"):
                        section_text += "\n--- Iframes Detectados ---\n"
                        for iframe in section_data["iframes"]:
                            section_text += f"- {iframe}\n"
                    else:
                        section_text += "\n- Nenhum iframe detectado\n"

                # SubDOMAINS - Adicionar o máximo de informações possíveis
                elif section == "subdomains":
                    section_text += "=== Subdomínios Detectados (via crt.sh) ===\n"

                    if isinstance(section_data, list) and section_data:
                        for sub in section_data:
                            section_text += f"- {sub}\n"
                    else:
                        section_text += "- Nenhum subdomínio encontrado ou resposta inválida.\n"

                # Fingerprint de Tecnologias - Adicionar o máximo de informações possíveis
                elif section == "tech_fingerprint":
                    section_text += "=== Tecnologias Detectadas (via builtwith) ===\n"
                    if isinstance(section_data, dict):
                        for category, techs in section_data.items():
                            section_text += f"\n-- {category.upper()} --\n"
                            for tech in techs:
                                section_text += f"- {tech}\n"
                    else:
                        section_text += "- Nenhuma tecnologia detectada.\n"

                    if "server" in section_data:
                        section_text += f"- Servidor Web: {section_data['server']}\n"

                # Histórico de Domínio - Adicionar o máximo de informações possíveis
                elif section == "domain_history":
                    section_text += "=== Histórico de Domínio (Wayback Machine) ===\n"
                    for item in section_data:
                        section_text += f"- {item['date']}: {item['url']}\n"

                # Email-s e Vazamentos - Adicionar o máximo de informações possíveis
                elif section == "email_osint":
                    section_text += "=== E-mails Detectados no HTML da Página ===\n"
                    for email in section_data.get("emails", []):
                        section_text += f"- {email}\n"

                # Headers de Segurança - Adicionar o máximo de informações possíveis
                elif section == "security_headers":
                    section_text += "=== Análise de Headers de Segurança HTTP ===\n"
                    for hname, hinfo in section_data.items():
                        status = "PRESENTE" if hinfo["present"] else "AUSENTE"
                        section_text += f"- {hname}: {status} — {hinfo['description']}\n"
                        if hinfo["present"] and hinfo.get("value"):
                            section_text += f"  • Valor: {hinfo['value']}\n"

                elif section == "osint_engines":
                    section_text += "=== OSINT: Dados encontrados em motores externos ===\n"

                    # 🔍 DuckDuckGo
                    duck = section_data.get("duckduckgo")
                    if duck:
                        section_text += "\n-- DuckDuckGo --\n"
                        for r in duck:
                            section_text += f"- {r.get('title', 'Sem título')}: {r.get('url')}\n"

                    # 📂 GitHub
                    github = section_data.get("github")
                    if github:
                        section_text += "\n-- GitHub Code Search --\n"
                        for g in github:
                            section_text += f"- {g.get('name')} ({g.get('language', 'N/A')}): {g.get('html_url')}\n"

                    # 🔎 Hunter.io
                    hunter = section_data.get("hunter")
                    if hunter:
                        section_text += "\n-- Hunter.io (E-mails Públicos) --\n"
                        for h in hunter:
                            section_text += f"- {h.get('value')} ({h.get('type')}), fonte: {h.get('source')}\n"

                    # 🌍 URLScan detalhado
                    scan = section_data.get("urlscan_detailed")
                    if scan:
                        section_text += "\n-- URLScan.io (Detalhado) --\n"
                        section_text += f"- Título: {scan.get('title')}\n"
                        section_text += f"- URL: {scan.get('url')}\n"
                        section_text += f"- IP: {scan.get('ip')} — ASN: {scan.get('asn')}\n"
                        section_text += f"- Servidor: {scan.get('server')}\n"
                        section_text += f"- Malicioso? {'SIM' if scan.get('malicious') else 'NÃO'}\n"

                        if scan.get("resources"):
                            section_text += "- Recursos Carregados Sensíveis:\n"
                            for r in scan["resources"]:
                                section_text += f"  • {r}\n"

                        if scan.get("external_domains"):
                            section_text += "- Domínios Externos Carregados:\n"
                            for d in scan["external_domains"]:
                                section_text += f"  • {d}\n"



                # ABUSEIPDB - Adicionar o máximo de informações possíveis
                elif section == "abuseipdb":
                    abuse_data = section_data.get("data", {})
                    for key, value in abuse_data.items():
                        if isinstance(value, (str, int, float)) and value:
                            section_text += f"- {key.replace('_', ' ').capitalize()}: {value}\n"
                        elif isinstance(value, list):
                            section_text += f"- {key.replace('_', ' ').capitalize()}:\n"
                            for item in value:
                                section_text += f"    - {item}\n"
                        elif isinstance(value, dict):
                            section_text += f"- {key.replace('_', ' ').capitalize()}:\n"
                            for k2, v2 in value.items():
                                section_text += f"    - {k2}: {v2}\n"

                # THREATFOX - Adicionar o máximo de informações possíveis
                elif section == "threatfox":
                    tf_data = section_data.get("data", [])
                    if isinstance(tf_data, list):
                        for obj in tf_data:
                            if isinstance(obj, dict):
                                for k, v in obj.items():
                                    section_text += f"- {k.replace('_', ' ').Capitalize()}: {v}\n"
                                section_text += "\n"
                    elif isinstance(tf_data, dict):
                        for k, v in tf_data.items():
                            section_text += f"- {k.replace('_', ' ').Capitalize()}: {v}\n"

                # DEMAIS SEÇÕES (GENÉRICO)
                else:
                    if isinstance(section_data, dict):
                        if "error" in section_data:
                            section_text += f"Erro: {section_data['error']}\n"
                        else:
                            for key, value in section_data.items():
                                if isinstance(value, (dict, list)):
                                    section_text += f"{key}:\n{json.dumps(value, indent=2, ensure_ascii=False)}\n"
                                else:
                                    section_text += f"{key}: {value}\n"
                    elif isinstance(section_data, list):
                        for item in section_data:
                            section_text += f"- {item}\n"
                    else:
                        section_text += f"{section_data}\n"

                texts.append(section_text)

            self.vectorstore.add_texts(texts)
            return True

        except Exception as e:
            print(f"Erro ao adicionar dados do IOC ao RAG: {str(e)}")
            return False

    def query(self, question):
        if not self.chain or not self.api_key:
            return "Sistema RAG não inicializado. Verifique se a chave da API OpenAI está configurada."

        try:
            response = self.chain.invoke(question)
            return response.content
        except Exception as e:
            return f"Erro ao consultar o RAG: {str(e)}"
    
    def clear_vectorstore(self):
        # Verifica se há embeddings e API key para recriar o vector store
        if self.embeddings and self.api_key:
            try:
                # Cria uma nova instância FAISS com o texto inicial
                self.vectorstore = FAISS.from_texts(
                    texts=[INITIAL_VECTORSTORE_TEXT],
                    embedding=self.embeddings
                )
                # Limpa os dados brutos armazenados
                self._current_ioc_raw_data = {}
                print("DEBUG: Vector Store e dados do IOC atual foram limpos.")
            except Exception as e:
                 print(f"ERRO ao tentar limpar/reinicializar o vector store: {str(e)}")
        else:
            print("AVISO: Não é possível limpar o vector store pois o RAG não foi inicializado corretamente.")