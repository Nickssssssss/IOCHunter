import streamlit as st
import pandas as pd
import plotly.express as px
import socket
import json
import os
import ipaddress
from datetime import datetime
from dotenv import load_dotenv
import tldextract
from urllib.parse import urlparse
import random

# Importar módulos personalizados
from utils import *
from rag import ThreatIntelRAG

# Carregar variáveis de ambiente (para chaves de API)
load_dotenv()

st.set_page_config(
    page_title="IOC Hunter - Plataforma de Threat Intelligence", # Título da aba do navegador
    page_icon="💻", # Ícone da aba
    layout="wide", # Usa layout largo para melhor aproveitamento do espaço
    initial_sidebar_state="expanded" # Mantém a sidebar aberta por padrão (se houver sidebar)
)
history_file = "history.json"

def initialize_session_state():
    """Inicializa as variáveis necessárias no estado da sessão do Streamlit."""
    # Flag para controlar a exibição do histórico inicial
    if 'show_initial_history' not in st.session_state:
        st.session_state.show_initial_history = True

    # Carrega o histórico de pesquisas do arquivo JSON, se existir
    if 'history' not in st.session_state:
        if os.path.exists(history_file):
            try:
                with open(history_file, "r", encoding='utf-8') as f:
                    st.session_state.history = json.load(f)
                # Garante que o histórico carregado é uma lista
                if not isinstance(st.session_state.history, list):
                    st.session_state.history = []
            except (json.JSONDecodeError, IOError) as e:
                print(f"Aviso: Não foi possível carregar o histórico de '{history_file}': {e}")
                st.session_state.history = []
        else:
            st.session_state.history = []

    # Variáveis para armazenar os dados da análise atual
    if 'analyzed_ioc' not in st.session_state:
        st.session_state.analyzed_ioc = None # O IOC que foi analisado
    if 'analyzed_type' not in st.session_state:
        st.session_state.analyzed_type = None # O tipo do IOC analisado
    if 'analyzed_results' not in st.session_state:
        st.session_state.analyzed_results = None # Dicionário com todos os resultados

    # Controle da aba ativa e triggers de ação
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "Visão Geral" # Nome da aba ativa
    if 'trigger_analysis' not in st.session_state:
        st.session_state.trigger_analysis = False # Flag para iniciar análise automaticamente
    if 'reanalyze_ioc' not in st.session_state:
        st.session_state.reanalyze_ioc = None # Guarda o IOC a ser reanalisado

    # Histórico do chat com a IA
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = [] # Lista de mensagens {role: 'user'/'assistant', content: '...'} 

# Chama a função de inicialização
initialize_session_state()

st.title("Bem-Vindo ao IOC Hunter!💻")
st.caption("Análise de IOCs (IPs, Domínios, Hashes, URLs) com múltiplas fontes e IA")
st.info("ℹ️ **Dica:** Para garantir análises com dados sempre atualizados e evitar conflitos de cache entre diferentes IOCs, recomenda-se recarregar o streamlit antes de analisar um novo indicador.")

# Histórico de pesquisas recentes
if st.session_state.show_initial_history:
    st.subheader("🕘 Histórico de Pesquisas Recentes")
    if st.session_state.history:
        for i, entry in enumerate(st.session_state.history[:5]):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**{entry['ioc']}** ({entry['ioc_type'].upper()}) — {datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
            with col2:
                if st.button("Reanalisar", key=f"reanalyze_top_{i}"):
                    st.session_state.reanalyze_ioc = entry['ioc']
                    st.session_state.auto_trigger_analysis = True
                    st.session_state.show_initial_history = False
                    st.session_state.active_tab = 0
                    st.rerun()
    else:
        st.info("Nenhuma pesquisa recente disponível.")

@st.cache_resource
def get_rag_system():
    return ThreatIntelRAG()

rag_system = get_rag_system()

if st.session_state.get("auto_trigger_analysis"):
    ioc_input = st.session_state.reanalyze_ioc
    st.session_state.auto_trigger_analysis = False
    st.session_state.reanalyze_ioc = None
    st.session_state["trigger_analysis"] = True
else:
    st.session_state["trigger_analysis"] = False

col1, col2 = st.columns([3, 1])
with col1:
    # Campo de texto para o usuário inserir o IOC
    ioc_input = st.text_input(
        "Insira o Indicador de Comprometimento (IP, Domínio, Hash, URL):",
        placeholder="Ex: 8.8.8.8, google.com, <hash>, https://exemplo.com/malware",
        key="ioc_input_field", # Chave para referenciar o widget
        label_visibility="collapsed" # Oculta o label principal, já que temos o placeholder
    )
with col2:
    # Botão para iniciar a análise
    analyze_button_pressed = st.button("Analisar IOC", type="primary", use_container_width=True)

if analyze_button_pressed or st.session_state.get("trigger_analysis"):
    st.session_state.show_initial_history = False
    if ioc_input:
        ioc_type, normalized_ioc = detect_ioc_type(ioc_input)
        if ioc_type == "unknown":
            st.error(f"Não foi possível determinar o tipo do IOC: {ioc_input}")
        else:
            results = {}
            results["ioc"] = normalized_ioc
            results["ioc_type"] = ioc_type
            results["timestamp"] = datetime.now().isoformat()
            
            # Coletar informações básicas
            if ioc_type in ["ip", "domain"]:
                if results.get("whois"):
                    whois_info = results["whois"]
                else:
                    whois_info = get_whois_info(normalized_ioc, ioc_type)
                    results["whois"] = whois_info
            # Armazenar no session state
            st.session_state.analyzed_ioc = normalized_ioc
            st.session_state.analyzed_type = ioc_type
            st.session_state.analyzed_results = results

            # Atualizar RAG e limpar chat
            rag_system.add_ioc_data(normalized_ioc, ioc_type, results)
            if "chat_history" in st.session_state:
                st.session_state.chat_history = []
            st.session_state.active_tab = 0
    else:
        st.warning("Por favor, insira um IOC para análise.")

if st.session_state.analyzed_results:
    results = st.session_state.analyzed_results.copy()  # Trabalhar com uma cópia
    normalized_ioc = st.session_state.analyzed_ioc
    ioc_type = st.session_state.analyzed_type

    st.success(f"Exibindo resultados para: **{normalized_ioc}** (Tipo: **{ioc_type.upper()}**)")

    tab_overview, tab_technical, tab_geo, tab_apis, tab_webcontent, tab_ai, tab_history, tab_export = st.tabs(
        [
            "Visão Geral",
            "Detalhes Técnicos", 
            "Geolocalização",
            "Fontes Externas (APIs)",
            "Análise de Conteúdo Web",
            "Análise com IA",
            "Histórico",
            "Exportar"
        ]
    )

    with tab_overview:
        st.session_state.active_tab = 0
        st.header("📊 Resumo da Análise")

        st.write(f"**IOC:** `{normalized_ioc}`")
        st.write(f"**Tipo:** `{ioc_type.upper()}`")
        st.write(f"**Data/Hora da Análise:** {datetime.fromisoformat(results['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        st.markdown("---")

                # Seção de Reputação (baseada nos dados já coletados ou a coletar)
        st.subheader("💡 Status de Reputação")
        with st.spinner("Verificando reputação em fontes chave..."):
            reputation_flags = []
            # Verifica VirusTotal (coleta se não tiver)
            if "virustotal" not in results:
                results["virustotal"] = query_virustotal(normalized_ioc, ioc_type)
            vt_data = results.get("virustotal", {}).get("data", {})
            vt_stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
            vt_malicious = vt_stats.get("malicious", 0)
            vt_suspicious = vt_stats.get("suspicious", 0)
            if vt_malicious > 0:
                reputation_flags.append(f"🛑 **VirusTotal:** {vt_malicious} detecções maliciosas.")
            elif vt_suspicious > 0:
                 reputation_flags.append(f"⚠️ **VirusTotal:** {vt_suspicious} detecções suspeitas.")

            # Verifica AbuseIPDB (apenas para IP, coleta se não tiver)
            if ioc_type == "ip":
                if "abuseipdb" not in results:
                    results["abuseipdb"] = query_abuseipdb(normalized_ioc)
                abuse_data = results.get("abuseipdb", {}).get("data", {})
                abuse_score = abuse_data.get("abuseConfidenceScore", 0)
                if abuse_score >= 75:
                    reputation_flags.append(f"🛑 **AbuseIPDB:** Score de abuso {abuse_score}% (Alto). Relatórios: {abuse_data.get('totalReports', 0)}.")
                elif abuse_score >= 25:
                    reputation_flags.append(f"⚠️ **AbuseIPDB:** Score de abuso {abuse_score}% (Médio). Relatórios: {abuse_data.get('totalReports', 0)}.")

            # Verifica ThreatFox (coleta se não tiver)
            if "threatfox" not in results:
                 results["threatfox"] = query_threatfox(normalized_ioc, ioc_type)
            tf_data = results.get("threatfox", {})
            if tf_data.get("query_status") == "ok" and tf_data.get("data"):
                 threat_type = tf_data["data"][0].get("threat_type_desc", "Ameaça Indefinida")
                 reputation_flags.append(f"🦊 **ThreatFox:** Encontrado! Associado a: {threat_type}.")

            # Exibe o resumo da reputação
            if reputation_flags:
                st.error("**Alerta de Reputação Negativa!**", icon="🚨")
                for flag in reputation_flags:
                    st.markdown(f"- {flag}")
            else:
                st.success("✅ Nenhuma atividade maliciosa significativa detectada nas fontes de reputação consultadas.", icon="👍")
        st.divider()

        # ✅ Infraestrutura
        ip = results.get("geoip", {}).get("ip") or results.get("page", {}).get("ip") or results.get("shodan", {}).get("ip_str")
        asn = results.get("geoip", {}).get("asn") or results.get("shodan", {}).get("asn") or "Desconhecido"
        server = results.get("ssl", {}).get("issuer", {}).get("CN") or results.get("urlscan", {}).get("server")

        st.markdown("### 🌐 Infraestrutura Detectada")
        st.write(f"- **IP público detectado:** `{ip or 'Não identificado'}`")
        st.write(f"- **ASN / Operadora:** `{asn}`")
        st.write(f"- **Servidor web:** `{server or 'Não identificado'}`")
        
        st.markdown("---")

        
        with st.spinner("Coletando informações básicas..."):
            if ioc_type in ["ip", "domain"]:
                whois_info = get_whois_info(normalized_ioc, ioc_type)
                results["whois"] = whois_info
                
                if "error" not in whois_info:
                    st.subheader("Informações Whois")
                    if ioc_type == "ip" and "OrgName" in whois_info:
                        whois_df = pd.DataFrame({
                            "Atributo": [
                                "Nome Organização", "ID Organização", "Endereço", "Cidade", "Estado", "CEP", "País",
                                "Alcance IP", "CIDR", "Nome da Rede", "Organização", "Data de Registro"
                            ],
                            "Valor": [
                                str(whois_info.get("Nome Organização", "N/A")),
                                str(whois_info.get("ID Organização", "N/A")),
                                str(whois_info.get("Endereço", "N/A")),
                                str(whois_info.get("Cidade", "N/A")),
                                str(whois_info.get("Estado", "N/A")),
                                str(whois_info.get("CEP", "N/A")),
                                str(whois_info.get("País", "N/A")),
                                str(whois_info.get("Alcance IP", "N/A")),
                                str(whois_info.get("CIDR", "N/A")),
                                str(whois_info.get("Nome da Rede", "N/A")),
                                str(whois_info.get("Organização", "N/A")),
                                str(whois_info.get("Data de Registro", "N/A")),
                            ]
                        })
                    else:
                        whois_df = pd.DataFrame({
                            "Atributo": ["Registrar", "Organização", "Data de Criação", "Data de Expiração", "Data de Atualização", "Status", "Servidores de Nome", "Emails", "País", "Cidade"],
                            "Valor": [
                                str(whois_info.get("registrar", "N/A")),
                                str(whois_info.get("org", "N/A")),
                                str(whois_info.get("creation_date", "N/A")),
                                str(whois_info.get("expiration_date", "N/A")),
                                str(whois_info.get("updated_date", "N/A")),
                                str(whois_info.get("status", "N/A")),
                                str(whois_info.get("name_servers", "N/A")),
                                str(whois_info.get("emails", "N/A")),
                                str(whois_info.get("country", "N/A")),
                                str(whois_info.get("city", "N/A"))
                            ]
                        })
                    st.dataframe(whois_df, use_container_width=True)
        
        st.info("ℹ️ Para mais detalhes técnicos, navegue pelas abas laterais.")
        # Atualizar session state
        st.session_state.analyzed_results = results

    with tab_technical:
        st.session_state.active_tab = 1
        st.header("Detalhes Técnicos")
        
        if ioc_type == "domain":
            # DNS para domínios
            with st.spinner("Consultando registros DNS..."):
                dns_info = get_dns_info(normalized_ioc)
                results["dns"] = dns_info
                
                st.subheader("Registros DNS")
                for record_type, records in dns_info.items():
                    if records:
                        st.write(f"**{record_type}:**")
                        for record in records:
                            st.code(record)
            
            # SSL para domínios
            with st.spinner("Verificando certificado SSL..."):
                ssl_info = get_ssl_cert_info(normalized_ioc)
                results["ssl"] = ssl_info
                
                st.subheader("Certificado SSL")
                if "error" in ssl_info:
                    st.error(ssl_info["error"])
                else:
                    ssl_df = pd.DataFrame({
                        "Atributo": ["Emissor", "Válido Até", "Expirado", "Versão"],
                        "Valor": [
                            str(ssl_info.get("issuer", {}).get("CN", "N/A")),
                            str(ssl_info.get("not_after", "N/A")),
                            "Sim" if ssl_info.get("has_expired") else "Não",
                            str(ssl_info.get("version", "N/A"))
                        ]
                    })
                    st.dataframe(ssl_df, use_container_width=True)
        
        elif ioc_type == "ip":
            # Informações técnicas para IPs
            st.subheader("Informações de Rede")
            
            try:
                hostname = socket.gethostbyaddr(normalized_ioc)[0]
                st.write(f"**Hostname:** {hostname}")
            except:
                st.write("**Hostname:** Não disponível")
            
            # Verificar se é IP privado
            try:
                is_private = ipaddress.ip_address(normalized_ioc).is_private
                st.write(f"**IP Privado:** {'Sim' if is_private else 'Não'}")
            except:
                pass
        
        elif ioc_type == "hash":
            st.subheader("Informações do Hash")
            hash_len = len(normalized_ioc)
            hash_type = "Desconhecido"
            if hash_len == 32: hash_type = "MD5"
            elif hash_len == 40: hash_type = "SHA1"
            elif hash_len == 64: hash_type = "SHA256"
            st.write(f"**Tipo de Hash Detectado:** {hash_type}")
            st.write("Informações adicionais sobre arquivos associados a este hash geralmente são encontradas em fontes como VirusTotal.")
            st.caption("Verifique a aba 'Fontes Externas (APIs)'.")
            st.divider()
        
        elif ioc_type == "url":
            st.write("Analisando componentes da URL:")
            
            try:
                parsed_url = urlparse(normalized_ioc)
                
                url_df = pd.DataFrame({
                    "Componente": ["Esquema", "Domínio", "Caminho", "Parâmetros", "Fragmento"],
                    "Valor": [
                        str(parsed_url.scheme),
                        str(parsed_url.netloc),
                        str(parsed_url.path),
                        str(parsed_url.query),
                        str(parsed_url.fragment)
                    ]
                })
                st.dataframe(url_df, use_container_width=True)
                
                # Tentar obter informações do domínio
                domain = parsed_url.netloc
                st.write(f"**Verificando domínio:** {domain}")
                
                # DNS para o domínio da URL
                with st.spinner("Consultando registros DNS do domínio..."):
                    dns_info = get_dns_info(domain)
                    results["dns"] = dns_info
                    
                    st.subheader("Registros DNS")
                    for record_type, records in dns_info.items():
                        if records:
                            st.write(f"**{record_type}:**")
                            for record in records:
                                st.code(record)
            except:
                st.error("Erro ao analisar componentes da URL")
        
        # Atualizar session state
        st.session_state.analyzed_results = results

    with tab_geo:
        st.session_state.active_tab = 2
        st.header("Geolocalização")
        
        if ioc_type == "ip":
            with st.spinner("Obtendo informações de geolocalização..."):
                geo_info = get_geoip_info(normalized_ioc)
                results["geoip"] = geo_info
                
                if "error" in geo_info:
                    st.error(geo_info["error"])
                else:
                    st.subheader("Localização do IP")
                    
                    # Exibir informações de localização
                    geo_df = pd.DataFrame({
                        "Atributo": ["País", "Região", "Cidade", "ISP/Organização", "Timezone"],
                        "Valor": [
                            str(geo_info.get("country", "N/A")),
                            str(geo_info.get("region", "N/A")),
                            str(geo_info.get("city", "N/A")),
                            str(geo_info.get("org", "N/A")),
                            str(geo_info.get("timezone", "N/A"))
                        ]
                    })
                    st.dataframe(geo_df, use_container_width=True)
                    
                    # Criar mapa interativo com Plotly
                    if geo_info.get("latitude") and geo_info.get("longitude"):
                        st.subheader("Mapa de Localização")
                        
                        df_map = pd.DataFrame({
                            "lat": [geo_info["latitude"]],
                            "lon": [geo_info["longitude"]],
                            "name": [normalized_ioc],
                            "info": [f"{geo_info.get('city', 'N/A')}, {geo_info.get('country', 'N/A')}"]
                        })
                        
                        fig = px.scatter_map(
                            df_map, 
                            lat="lat", 
                            lon="lon", 
                            hover_name="name",
                            hover_data=["info"],
                            zoom=5,
                            height=500
                        )
                        
                        fig.update_layout(
                            mapbox_style="open-street-map",
                            margin={"r": 0, "t": 0, "l": 0, "b": 0}
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
        else:
            st.info(f"Geolocalização não é aplicável diretamente para o tipo {ioc_type.upper()}.")
            
            if ioc_type == "domain":
                st.write("Para obter a geolocalização de um domínio, primeiro resolva-o para um endereço IP.")
                
                # Tentar resolver o domínio para IP
                try:
                    with st.spinner("Resolvendo domínio para IP..."):
                        dns_info = get_dns_info(normalized_ioc)
                        if dns_info.get("A"):
                            ip = dns_info["A"][0]
                            st.success(f"Domínio resolvido para IP: {ip}")
                            
                            # Obter geolocalização do IP
                            geo_info = get_geoip_info(ip)
                            results["geoip"] = geo_info
                            
                            if "error" in geo_info:
                                st.error(geo_info["error"])
                            else:
                                # Exibir informações de localização
                                geo_df = pd.DataFrame({
                                    "Atributo": ["IP", "País", "Região", "Cidade", "ISP/Organização"],
                                    "Valor": [
                                        str(ip),
                                        str(geo_info.get("country", "N/A")),
                                        str(geo_info.get("region", "N/A")),
                                        str(geo_info.get("city", "N/A")),
                                        str(geo_info.get("org", "N/A"))
                                    ]
                                })
                                st.dataframe(geo_df, use_container_width=True)
                                
                                # Criar mapa interativo com Plotly
                                if geo_info.get("latitude") and geo_info.get("longitude"):
                                    st.subheader("Mapa de Localização")
                                    
                                    df_map = pd.DataFrame({
                                        "lat": [geo_info["latitude"]],
                                        "lon": [geo_info["longitude"]],
                                        "name": [f"{normalized_ioc} ({ip})"],
                                        "info": [f"{geo_info.get('city', 'N/A')}, {geo_info.get('country', 'N/A')}"]
                                    })
                                    
                                    fig = px.scatter_map(
                                        df_map, 
                                        lat="lat", 
                                        lon="lon", 
                                        hover_name="name",
                                        hover_data=["info"],
                                        zoom=5,
                                        height=500
                                    )
                                    
                                    fig.update_layout(
                                        mapbox_style="open-street-map",
                                        margin={"r": 0, "t": 0, "l": 0, "b": 0}
                                    )
                                    
                                    st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.warning("Não foi possível resolver o domínio para um endereço IP.")
                except Exception as e:
                    st.error(f"Erro ao resolver domínio: {str(e)}")
            
            elif ioc_type == "url":
                st.write("Para obter a geolocalização de uma URL, primeiro extraia o domínio e resolva-o para um endereço IP.")
                
                # Tentar extrair o domínio da URL
                try:
                    parsed_url = urlparse(normalized_ioc)
                    domain = parsed_url.netloc
                    
                    st.write(f"Domínio extraído: {domain}")
                    
                    # Tentar resolver o domínio para IP
                    with st.spinner("Resolvendo domínio para IP..."):
                        dns_info = get_dns_info(domain)
                        if dns_info.get("A"):
                            ip = dns_info["A"][0]
                            st.success(f"Domínio resolvido para IP: {ip}")
                            
                            # Obter geolocalização do IP
                            geo_info = get_geoip_info(ip)
                            results["geoip"] = geo_info
                            
                            if "error" in geo_info:
                                st.error(geo_info["error"])
                            else:
                                # Exibir informações de localização
                                geo_df = pd.DataFrame({
                                    "Atributo": ["IP", "País", "Região", "Cidade", "ISP/Organização"],
                                    "Valor": [
                                        str(ip),
                                        str(geo_info.get("country", "N/A")),
                                        str(geo_info.get("region", "N/A")),
                                        str(geo_info.get("city", "N/A")),
                                        str(geo_info.get("org", "N/A"))
                                    ]
                                })
                                st.dataframe(geo_df, use_container_width=True)
                                
                                # Criar mapa interativo com Plotly
                                if geo_info.get("latitude") and geo_info.get("longitude"):
                                    st.subheader("Mapa de Localização")
                                    
                                    df_map = pd.DataFrame({
                                        "lat": [geo_info["latitude"]],
                                        "lon": [geo_info["longitude"]],
                                        "name": [f"{domain} ({ip})"],
                                        "info": [f"{geo_info.get('city', 'N/A')}, {geo_info.get('country', 'N/A')}"]
                                    })
                                    
                                    fig = px.scatter_map(
                                        df_map, 
                                        lat="lat", 
                                        lon="lon", 
                                        hover_name="name",
                                        hover_data=["info"],
                                        zoom=5,
                                        height=500
                                    )
                                    
                                    fig.update_layout(
                                        mapbox_style="open-street-map",
                                        margin={"r": 0, "t": 0, "l": 0, "b": 0}
                                    )
                                    
                                    st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.warning("Não foi possível resolver o domínio para um endereço IP.")
                except Exception as e:
                    st.error(f"Erro ao processar URL: {str(e)}")
        
        # Atualizar session state
        st.session_state.analyzed_results = results

    with tab_apis:
        st.session_state.active_tab = 3
        st.header("Resultados de APIs Externas")
        
        # Verificar se as chaves de API estão configuradas
        virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        threatfox_api_key = os.getenv("THREATFOX_API_KEY", "")
        
        # Criar abas para cada API
        api_tabs = st.tabs(["VirusTotal", "Shodan", "AbuseIPDB", "ThreatFox", "DNSDumpster", "ASN e Vizinhança"])
        
        # VirusTotal
        with api_tabs[0]:
            st.subheader("VirusTotal")

            if not virustotal_api_key:
                st.warning("Chave de API do VirusTotal não configurada. Configure a variável de ambiente VIRUSTOTAL_API_KEY.")
                st.info("Para fins de demonstração, os resultados serão simulados.")
            else:
                with st.spinner("Consultando VirusTotal..."):
                    vt_results = query_virustotal(normalized_ioc, ioc_type, virustotal_api_key)
                    results["virustotal"] = vt_results

                    if "error" in vt_results:
                        st.error(vt_results["error"])
                    else:
                        st.success("Consulta ao VirusTotal concluída com sucesso")
                        st.markdown("### Resposta completa da API VirusTotal")
                        with st.expander(f"Ver resposta completa da API Virus Total (JSON)"):
                            st.json(vt_results)
                        
                        vt_data = vt_results.get("data", {})
                        vt_attrs = vt_data.get("attributes", {})
                        vt_stats = vt_attrs.get("last_analysis_stats", {})
                        st.write(f"**Detecções:** Maliciosas: {vt_stats.get('malicious', 0)}, Suspeitas: {vt_stats.get('suspicious', 0)}, Inofensivas: {vt_stats.get('harmless', 0)}, Não Detectadas: {vt_stats.get('undetected', 0)}")
                        st.write(f"**Reputação VT:** {vt_attrs.get('reputation', 'N/A')}")

        
        # Shodan
        with api_tabs[1]:
            st.subheader("Shodan")
            
            if ioc_type not in ["ip", "domain"]:
                st.info(f"Shodan não é aplicável diretamente para o tipo {ioc_type.upper()}")
            else:
                if not shodan_api_key:
                    st.warning("Chave de API do Shodan não configurada. Configure a variável de ambiente SHODAN_API_KEY.")
                    st.info("Para fins de demonstração, os resultados serão simulados.")
                    
                    # Simulação de resultados
                    st.write("**Resultados simulados:**")
                    
                    if ioc_type == "ip":
                        st.write("**Portas abertas:** 80, 443")
                        st.write("**Organização:** Simulação Inc.")
                        st.write("**País:** Brasil")
                    elif ioc_type == "domain":
                        st.write("**Subdomínios encontrados:** 3")
                        st.write("**IPs associados:** 2")
                else:
                    with st.spinner("Consultando Shodan..."):
                        shodan_results = query_shodan(normalized_ioc, ioc_type, shodan_api_key)
                        with st.expander(f"Ver resposta completa do Shodan (JSON)"):
                            st.json(shodan_results)

                        if ioc_type == 'ip':
                                st.write(f"**País:** {shodan_results.get('country_name', 'N/A')}")
                                st.write(f"**Organização:** {shodan_results.get('org', 'N/A')}")
                                st.write(f"**Portas Abertas:** {shodan_results.get('ports', [])}")
                                st.write(f"**Hostnames:** {shodan_results.get('hostnames', [])}")
                                st.write(f"**Vulnerabilidades (CVEs):** {shodan_results.get('vulns', [])}")
                        elif ioc_type == 'domain':
                            st.write(f"**Subdomínios:** {shodan_results.get('subdomains', [])}")
                            st.link_button("Ver no Shodan", f"https://www.shodan.io/search?query={normalized_ioc}")
                        
                        if "error" in shodan_results:
                            st.error(shodan_results["error"])
                        else:
                            st.success("Consulta ao Shodan concluída com sucesso")

        
        # AbuseIPDB
        with api_tabs[2]:
            st.subheader("AbuseIPDB")
            
            if ioc_type != "ip":
                st.info(f"AbuseIPDB é aplicável apenas para endereços IP, não para {ioc_type.upper()}")
            else:
                if not abuseipdb_api_key:
                    st.warning("Chave de API do AbuseIPDB não configurada. Configure a variável de ambiente ABUSEIPDB_API_KEY.")
                    st.info("Para fins de demonstração, os resultados serão simulados.")
                    
                    # Simulação de resultados
                    st.write("**Resultados simulados:**")
                    
                    # Gerar um score aleatório para demonstração
                    score = random.randint(0, 100)
                    
                    # Destacar com base no score
                    if score > 90:
                        st.error(f"**Score de Abuso:** {score}/100 (Alto)")
                    elif score > 50:
                        st.warning(f"**Score de Abuso:** {score}/100 (Médio)")
                    else:
                        st.metric(f"**Score de Abuso:** {score}/100 (Baixo)")
                    
                    st.write("**Relatórios:** 0")
                    st.write("**Última Denúncia:** N/A")
                else:
                    with st.spinner("Consultando AbuseIPDB..."):
                        abuse_results = query_abuseipdb(normalized_ioc, abuseipdb_api_key)
                        results["abuseipdb"] = abuse_results
                        
                        if "error" in abuse_results:
                            st.error(abuse_results["error"])
                        else:
                            st.success("Consulta ao AbuseIPDB concluída com sucesso")

                            # Exibir JSON completo
                            with st.expander("Ver resposta completa"):
                                st.json(abuse_results)
                            
                            # Extrair e exibir o score
                            data = abuse_results.get("data", {})
                            score = data.get("abuseConfidenceScore", 0)
                            color = "red" if score > 75 else "orange" if score > 25 else "green"
                            st.metric("Score de Abuso", f"{score}%")
                            
                            # Exibir detalhes adicionais
                            st.write(f"**Relatórios:** {data.get('totalReports', 0)}")
                            st.write(f"**País:** {abuse_data.get('countryCode', 'N/A')}, **ISP:** {abuse_data.get('isp', 'N/A')}")
                            st.write(f"**Última Denúncia:** {data.get('lastReportedAt', 'N/A')}")
                            st.link_button("Ver no AbuseIPDB", f"https://www.abuseipdb.com/check/{normalized_ioc}")
        
        # ThreatFox
        with api_tabs[3]:
            st.subheader("ThreatFox")
            
            if not threatfox_api_key:
                st.info("ThreatFox pode ser usado sem chave de API, mas com limitações.")
            
            with st.spinner("Consultando ThreatFox..."):
                threatfox_results = query_threatfox(normalized_ioc, ioc_type, threatfox_api_key)
                results["threatfox"] = threatfox_results
                
                if "error" in threatfox_results:
                    st.error(threatfox_results["error"])
                else:
                    st.success("Consulta ao ThreatFox concluída com sucesso")
                    st.json(threatfox_results)
        
        # DNSDumpster
        with api_tabs[4]:
            st.subheader("DNSDumpster")
            
            if ioc_type != "domain":
                st.info(f"DNSDumpster é aplicável apenas para domínios, não para {ioc_type.upper()}")
                
                if ioc_type == "url":
                    # Tentar extrair o domínio da URL
                    try:
                        parsed_url = urlparse(normalized_ioc)
                        domain = parsed_url.netloc
                        
                        st.write(f"Domínio extraído da URL: {domain}")
                        
                        with st.spinner(f"Consultando DNSDumpster para {domain}..."):
                            dns_results = query_dnsdumpster(domain)
                            results["dnsdumpster"] = dns_results
                            
                            if "error" in dns_results:
                                st.error(dns_results["error"])
                            elif "warning" in dns_results:
                                st.warning(dns_results["warning"])
                                st.write(f"**Domínio:** {dns_results['domain']}")
                                
                                # Exibir registros DNS
                                dns_records = dns_results.get("dns_records", {})
                                for record_type, records in dns_records.items():
                                    if records:
                                        st.write(f"**{record_type}:**")
                                        for record in records:
                                            st.code(record)
                    except Exception as e:
                        st.error(f"Erro ao processar URL: {str(e)}")
            else:
                with st.spinner(f"Consultando DNSDumpster para {normalized_ioc}..."):
                    dns_results = query_dnsdumpster(normalized_ioc)
                    results["dnsdumpster"] = dns_results
                    
                    if "error" in dns_results:
                        st.error(dns_results["error"])
                    elif "warning" in dns_results:
                        st.warning(dns_results["warning"])
                        st.write(f"**Domínio:** {dns_results['domain']}")
                        
                        # Exibir registros DNS
                        dns_records = dns_results.get("dns_records", {})
                        for record_type, records in dns_records.items():
                            if records:
                                st.write(f"**{record_type}:**")
                                for record in records:
                                    st.code(record)
        
        with api_tabs[5]:
            st.subheader("ASN e Vizinhança")
            if ioc_type == "ip":
                st.subheader("Informações de ASN e Vizinhança IP")
                st.success("Consulta concluída com sucesso")
                with st.spinner("Consultando dados RDAP..."):
                    asn_result = get_asn_info(normalized_ioc)
                    if "error" in asn_result:
                        st.error(asn_result["error"])
                    else:
                        results["asn_info"] = asn_result  # envia ao RAG

                        st.markdown(f"**ASN:** `{asn_result.get('asn')}`")
                        st.markdown(f"**Descrição ASN:** {asn_result.get('asn_description')}")
                        st.markdown(f"**Organização:** {asn_result.get('org_name')}")
                        st.markdown(f"**País:** {asn_result.get('country')}")
                        st.markdown(f"**Faixa CIDR:** `{asn_result.get('cidr')}`")
                        st.markdown(f"**IP Inicial:** `{asn_result.get('start_address')}`")
                        st.markdown(f"**IP Final:** `{asn_result.get('end_address')}`")
            else:
                st.info("Esta análise é aplicável apenas a IOCs do tipo **IP**.")

        # Atualizar session state
        st.session_state.analyzed_results = results

    with tab_webcontent:
        st.session_state.active_tab = 4.5
        st.header("Análise de Conteúdo Web (Passiva)")

        # 🔽 Criar sub-abas internas
        sub_html, sub_subdomains, sub_fingerprinting, sub_history, sub_osint, sub_headers, sub_engines = st.tabs([
            "🧾 Conteúdo HTML", 
            "🌐 Enumeração Subdomínios",
            "🧬 Fingerprinting Tecnologias",
            "🕓 Histórico Domínios",
            "🔍 OSINT: E-mails e Vazamentos",
            "🛡️ Headers de Segurança",
            "🔎 Motores OSINT"
        ])


        # 🧾 Subaba: Conteúdo HTML
        with sub_html:
            if ioc_type == "url":
                st.subheader("Resumo da Página")
                with st.spinner("Fazendo requisição HTTP..."):
                    content_data = analyze_web_content(normalized_ioc)

                    if "error" in content_data:
                        st.error(content_data["error"])
                    else:
                        results["web_content"] = content_data  # adiciona ao contexto do RAG

                        st.write(f"**Código de status:** {content_data['status_code']}")
                        st.write(f"**URL final após redirecionamentos:** {content_data['final_url']}")
                        st.write(f"**Título da página:** {content_data['title']}")

                        st.subheader("Headers HTTP")
                        st.json(content_data["headers"])

                        st.subheader("Formulários detectados (actions):")
                        if content_data["forms"]:
                            for action in content_data["forms"]:
                                st.code(action)
                        else:
                            st.info("Nenhum formulário encontrado.")

                        st.subheader("Scripts externos detectados:")
                        if content_data["scripts"]:
                            for src in content_data["scripts"]:
                                st.code(src)
                        else:
                            st.info("Nenhum script externo encontrado.")

                        st.subheader("Iframes detectados:")
                        if content_data["iframes"]:
                            for iframe in content_data["iframes"]:
                                st.code(iframe)
                        else:
                            st.info("Nenhum iframe encontrado.")

                        st.subheader("HTML (primeiros 3000 caracteres)")
                        with st.expander("Ver HTML (parcial)"):
                            st.code(content_data["html_snippet"])
            else:
                st.info("Esta análise é aplicável apenas a IOCs do tipo **URL**.")

        # 🌐 Subaba: Enumeração Subdomínios
        with sub_subdomains:
            if ioc_type in ["url", "domain"]:
                st.subheader("Subdomínios Detectados (via crt.sh)")

                ext = tldextract.extract(normalized_ioc)
                if not ext.domain or not ext.suffix:
                    st.error("Domínio inválido.")
                else:
                    domain = f"{ext.domain}.{ext.suffix}"
                    st.write(f"**Domínio analisado:** {domain}")

                subdomain_result = get_subdomains_crtsh(domain)

                if isinstance(subdomain_result, dict) and "error" in subdomain_result:
                    st.error(subdomain_result["error"])
                elif isinstance(subdomain_result, list) and subdomain_result:
                    st.success(f"{len(subdomain_result)} subdomínios encontrados.")
                    results["subdomains"] = subdomain_result  # envia para RAG

                    for sub in subdomain_result:
                        st.code(sub)

                    # Exportar wordlist
                    wordlist_content = "\n".join(subdomain_result)
                    wordlist_bytes = wordlist_content.encode("utf-8")
                    st.download_button(
                        label="📥 Baixar Wordlist de Subdomínios",
                        data=wordlist_bytes,
                        file_name=f"{domain}_subdomains.txt",
                        mime="text/plain"
                    )
                else:
                    st.info("Nenhum subdomínio encontrado.")
            else:
                st.info("Enumeração de subdomínios só é aplicável para IOCs do tipo **domínio** ou **URL**.")

        with sub_fingerprinting:
            if ioc_type == "url":
                st.subheader("Tecnologias Detectadas com Fingerprinting Passivo")

                with st.spinner("Analisando tecnologias da página..."):
                    tech_result = detect_technologies(normalized_ioc)

                    if "error" in tech_result:
                        st.error(tech_result["error"])
                    else:
                        results["tech_fingerprint"] = tech_result  # envia ao RAG

                        if tech_result:
                            st.success(f"{len(tech_result)} tecnologias detectadas:")
                            for category, items in tech_result.items():
                                st.markdown(f"**{category}:**")
                                for tech in items:
                                    st.code(tech)
                        else:
                            st.info("Nenhuma tecnologia identificada.")

                        if "server" in tech_result:
                            st.write(f"**Servidor Web:** {tech_result['server']}")
            else:
                st.info("Fingerprinting de tecnologias só é aplicável para IOCs do tipo **URL**.")
        
        with sub_history:
            if ioc_type in ["domain", "url"]:
                st.subheader("Snapshots Arquivados do Domínio (Wayback Machine)")
                
                ext = tldextract.extract(normalized_ioc)
                if not ext.domain or not ext.suffix:
                    st.error("Domínio inválido.")
                else:
                    domain = f"{ext.domain}.{ext.suffix}"
                    st.write(f"**Domínio analisado:** {domain}")

                with st.spinner("Consultando Wayback Machine..."):
                    history_result = get_wayback_history(domain)

                    if isinstance(history_result, dict) and "error" in history_result:
                        st.error(history_result["error"])
                    elif isinstance(history_result, list) and history_result:
                        st.success(f"{len(history_result)} snapshots encontrados.")
                        results["domain_history"] = history_result  # envia para o RAG

                        for item in history_result:
                            st.markdown(f"- {item['date']} — [📎 Ver snapshot]({item['url']})")

                        # 🔽 Extração e wordlist passiva de caminhos

                        paths = set()
                        for item in history_result:
                            try:
                                path = urlparse(item["url"]).path
                                if path and path != "/":
                                    paths.add(path.strip())
                            except Exception:
                                pass

                        if paths:
                            st.subheader("📁 Wordlist de Caminhos Históricos")
                            st.write(f"{len(paths)} caminhos únicos extraídos das URLs arquivadas:")

                            for p in sorted(paths):
                                st.code(p)

                            wordlist_content = "\n".join(sorted(paths))
                            wordlist_bytes = wordlist_content.encode("utf-8")

                            st.download_button(
                                label="📥 Baixar Wordlist de Caminhos",
                                data=wordlist_bytes,
                                file_name=f"{domain}_paths.txt",
                                mime="text/plain"
                            )

                            results["historical_paths"] = sorted(paths)  # envia para o RAG
                        else:
                            st.info("Nenhum caminho válido encontrado para gerar wordlist.")
                    else:
                        st.info("Nenhum histórico encontrado.")
            else:
                st.info("Histórico de domínio só é aplicável para IOCs do tipo **domínio** ou **URL**.")
        
        with sub_osint:
            if ioc_type == "url":

                ext = tldextract.extract(normalized_ioc)
                if not ext.domain or not ext.suffix:
                    st.error("Domínio inválido.")
                else:
                    domain = f"{ext.domain}.{ext.suffix}"
                    st.write(f"**Domínio analisado:** {domain}")

                html_content = results.get("web_content", {}).get("html_snippet", "")
                found_emails = extract_emails_from_html(html_content, domain)

                st.subheader("📧 E-mails encontrados no conteúdo público da página:")
                if found_emails:
                    results["email_osint"] = {"emails": found_emails}  # envia para RAG
                    for email in found_emails:
                        st.code(email)
                else:
                    st.info("Nenhum e-mail detectado no HTML da página.")
            else:
                st.info("Esta análise só é aplicável para IOCs do tipo **URL**.")

        with sub_headers:
            if ioc_type == "url":
                st.subheader("Verificação Passiva de Headers de Segurança")
                raw_headers = results.get("web_content", {}).get("headers", {})
                header_check = analyze_security_headers(raw_headers)
                results["security_headers"] = header_check  # envia para RAG

                for hname, hinfo in header_check.items():
                    icon = "✅" if hinfo["present"] else "❌"
                    st.markdown(
                        f"- {icon} **{hname}** — {hinfo['description']}"
                    )
                    if hinfo["present"] and hinfo["value"]:
                        st.code(hinfo["value"])
                st.info("Caso queira ver informações mais completas, utilize o comando 'curl -I URL' no terminal.")

            else:
                st.info("Esta análise é aplicável apenas a IOCs do tipo **URL**.")
            
        with sub_engines:
            st.subheader("Consultas OSINT Passivas (Multi-Motores)")

            if ioc_type in ["domain", "url", "email"]:

                osint_data = {}

                # DuckDuckGo
                st.markdown("### 🔍 DuckDuckGo")
                duck_results = search_duckduckgo(normalized_ioc)
                if isinstance(duck_results, list):
                    osint_data["duckduckgo"] = duck_results
                    for item in duck_results:
                        st.markdown(f"- [{item['title']}]({item['url']})")
                else:
                    st.warning(duck_results.get("error", "Erro no DuckDuckGo"))

                # URLScan
                st.markdown("### 🌍 URLScan.io (detalhado)")
                scan = search_urlscan(normalized_ioc)

                if isinstance(scan, dict) and "error" not in scan:
                    if "osint_engines" not in results:
                        results["osint_engines"] = {}

                    results["osint_engines"]["urlscan_detailed"] = scan

                    st.markdown(f"**Título:** {scan['title']}")
                    if "url" in scan:
                        st.markdown(f"**URL:** [{scan['url']}]({scan['url']})")
                    else:
                        st.warning("Nenhuma URL disponível para este resultado.")
                    st.markdown(f"**IP:** `{scan['ip']}` — **ASN:** `{scan['asn']}` — **Server:** `{scan['server']}`")

                    if scan["malicious"]:
                        st.error("🚨 Este scan foi marcado como *malicious* no URLScan.")
                    else:
                        st.success("Nenhum comportamento malicioso detectado.")

                    # Verifica se há screenshot válido
                    screenshot_url = scan.get("screenshot")

                    if screenshot_url and isinstance(screenshot_url, str) and "default.gif" not in screenshot_url.lower():
                        st.image(screenshot_url, caption="Screenshot da página")
                    else:
                        st.info("Nenhum screenshot útil disponível para esta análise.")


                    if scan["resources"]:
                        st.markdown("**Recursos Sensíveis Carregados:**")
                        for r in scan["resources"]:
                            st.code(r)

                    if scan["external_domains"]:
                        st.markdown("**Domínios Externos Carregados:**")
                        for d in scan["external_domains"]:
                            st.markdown(f"- `{d}`")
                else:
                    st.warning(scan.get("error", "Erro desconhecido no URLScan"))


                # GitHub
                st.markdown("### 📂 GitHub Code Search")
                github = search_github_code(normalized_ioc)
                if isinstance(github, list):
                    osint_data["github"] = github
                    for g in github:
                        repo_name = g.get("name", "Repositório sem nome")
                        repo_url = g.get("html_url", "#")
                        language = g.get("language", "não especificada")
                        st.markdown(f"- [{repo_name}]({repo_url}) — linguagem: `{language}`")
                else:
                    st.warning(github.get("error", "Erro no GitHub"))

                # Hunter.io
                st.markdown("### 🔎 Hunter.io (E-mails Públicos)")
                hunter = search_hunter_emails(domain)
                if isinstance(hunter, list):
                    osint_data["hunter"] = hunter
                    hunter = pd.DataFrame(hunter)
                    st.dataframe(hunter, hide_index=True, use_container_width=True)
                else:
                    st.warning(hunter.get("error", "Erro no Hunter.io"))


                # ✅ Armazenar todos os dados no results para IA
                results["osint_engines"] = results.get("osint_engines", {})
                results["osint_engines"].update(osint_data)

                # 🔽 Exportar relatório
                if osint_data:
                    def generate_osint_markdown(data):
                        md = f"# Relatório OSINT para: {normalized_ioc}\n\n"

                        if "duckduckgo" in data:
                            md += "## 🔍 DuckDuckGo\n"
                            for item in data["duckduckgo"]:
                                md += f"- [{item['title']}]({item['url']})\n"
                            md += "\n"

                        if "urlscan" in data:
                            md += "## 🌍 URLScan.io\n"
                            for item in data["urlscan"]:
                                md += f"- {item['page_title']} → {item['url']}\n"
                            md += "\n"

                        if "github" in data:
                            md += "## 📂 GitHub Code Search\n"
                            for item in data["github"]:
                                name = item.get("name", "Sem nome")
                                lang = item.get("language", "Não especificada")
                                url = item.get("html_url", "#")
                                md += f"- [{name}]({url}) — linguagem: `{lang}`\n"
                            md += "\n"

                        if "hunter" in data:
                            md += "## 🔎 Hunter.io\n"
                            for item in data["hunter"]:
                                md += f"- {item['value']} ({item['type']}) — Fonte: {item['source']}\n"
                            md += "\n"

                        return md

                    osint_md = generate_osint_markdown(osint_data)
                    osint_txt = osint_md.replace("#", "").strip()

                    st.download_button(
                        label="📥 Baixar Relatório OSINT (.md)",
                        data=osint_md,
                        file_name=f"osint_{normalized_ioc}.md",
                        mime="text/markdown"
                    )

                    st.download_button(
                        label="📥 Baixar Relatório OSINT (.txt)",
                        data=osint_txt,
                        file_name=f"osint_{normalized_ioc}.txt",
                        mime="text/plain"
                    )

            else:
                st.info("Esta análise é aplicável apenas a IOCs do tipo **domínio** ou **URL**.")

        

    with tab_ai:
        st.session_state.active_tab = 4
        st.header("🤖 Análise Contextual com IA (RAG)")
        st.caption("Faça perguntas em linguagem natural sobre o IOC analisado.")
        openai_api_key = os.getenv("OPENAI_API_KEY", "")

        # Atualize o vectorstore SEMPRE que entrar na aba IA
        if st.session_state.analyzed_results:
            rag_system.add_ioc_data(
                st.session_state.analyzed_ioc,
                st.session_state.analyzed_type,
                st.session_state.analyzed_results
            )

        if not openai_api_key:
            st.warning("Chave de API OpenAI não configurada.")
        else:
            if "chat_history" not in st.session_state:
                st.session_state.chat_history = []

            def render_chat_messages():
                for msg in st.session_state.chat_history:
                    text = msg["text"].strip()
                    if not text:
                        continue
                    time_tag = f"<span style='font-size:12px;float:right;'>{msg.get('time', '')}</span>"
                    if msg["role"] == "user":
                        st.markdown(
                            f"""<div style='background-color:#263238;color:#fff;padding:12px 18px;border-radius:10px;margin:10px 0 10px 40px;text-align:left;'>
                                <b>🤔 Você:</b> {time_tag}<br>{text}
                            </div>""", unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f"""<div style='background-color:#37474f;color:#fff;padding:12px 18px;border-radius:10px;margin:10px 40px 10px 0;text-align:left;'>
                                <b>🤖 IA:</b> {time_tag}<br>{text}
                            </div>""", unsafe_allow_html=True
                        )

            st.button("🧹 Limpar Chat", key="clear_chat", on_click=lambda: st.session_state.chat_history.clear())
            st.info("Para melhores respostas reinicie o streamlit após cada análise de IOC. Além disso forneça o máximo de contexto possível e faça perguntas com clareza.")

            st.markdown("---")
            st.subheader("Chat")
            with st.container():
                render_chat_messages()

            user_input = st.chat_input("Digite sua pergunta sobre o IOC")

            def ask_ai(user_question):
                if user_question and "analyzed_results" in st.session_state:
                    with st.spinner("💬 A IA está pensando..."):
                        answer = rag_system.query(user_question)
                    st.session_state.chat_history.append({"role": "ai", "text": answer, "time": datetime.now().strftime("%H:%M")})

            if user_input:
                st.session_state.chat_history.append({"role": "user", "text": user_input, "time": datetime.now().strftime("%H:%M")})
                ask_ai(user_input.strip())
                st.session_state.active_tab = 4  # Manter na aba IA após enviar mensagem
                st.rerun()

            # Sugestões de perguntas
            st.markdown("---")
            st.subheader("Sugestões de perguntas")
            if ioc_type == "ip":
                suggestions = [
                    "Este IP é malicioso?",
                    "Em qual país este IP está localizado?",
                    "Quais portas estão abertas neste IP?",
                    "Qual é a reputação deste IP?",
                    "Este IP está associado a alguma atividade maliciosa conhecida?"
                ]
            elif ioc_type == "domain":
                suggestions = [
                    "Este domínio é malicioso?",
                    "Quando este domínio foi registrado?",
                    "Quais são os servidores de nome deste domínio?",
                    "Este domínio está associado a alguma atividade maliciosa conhecida?",
                    "Qual é a reputação deste domínio?"
                ]
            elif ioc_type == "hash":
                suggestions = [
                    "Este hash está associado a malware?",
                    "Qual é o tipo de arquivo associado a este hash?",
                    "Quais antivírus detectam este hash como malicioso?",
                    "Este hash está associado a alguma campanha de malware conhecida?",
                    "Qual é a classificação deste arquivo?"
                ]
            elif ioc_type == "url":
                suggestions = [
                    "Esta URL é maliciosa?",
                    "Qual é o domínio desta URL?",
                    "Esta URL está associada a phishing?",
                    "Qual é a reputação desta URL?",
                    "Esta URL está associada a alguma campanha maliciosa conhecida?"
                ]
            else:
                suggestions = []

            # Estilo para os botões sugestivos desabilitados
            st.markdown("""
            <style>
            .suggestion-btn {
                display: block;
                width: 100%;
                background-color: #263238;
                color: #fff;
                border: none;
                border-radius: 8px;
                padding: 10px 0;
                margin-bottom: 8px;
                font-size: 16px;
                cursor: not-allowed;
                opacity: 0.7;
                text-align: center;
                pointer-events: none;
            }
            </style>
            """, unsafe_allow_html=True)

            for suggestion in suggestions:
                st.markdown(f"<div class='suggestion-btn'>{suggestion}</div>", unsafe_allow_html=True)

            # Exportar conversa
            st.markdown("---")
            st.subheader("📥 Exportar Conversa")
            if st.button("Baixar Conversa como Markdown"):
                chat_md = "\n\n".join([
                    f"**Você:** {msg['text']}" if msg["role"] == "user" else f"**IA:** {msg['text']}"
                    for msg in st.session_state.chat_history
                ])
                st.download_button("Download .md", chat_md, file_name="conversa_ioc.md", mime="text/markdown")

            if st.button("Baixar Conversa como JSON"):
                chat_json = json.dumps(st.session_state.chat_history, indent=2, ensure_ascii=False)
                st.download_button("Download .json", chat_json, file_name="conversa_ioc.json", mime="application/json")

    with tab_history:
        st.session_state.active_tab = 5
        st.header("Histórico de Buscas")
        
        # Adicionar a busca atual ao histórico da sessão
        current_search = {
            "timestamp": datetime.now().isoformat(),
            "ioc": normalized_ioc,
            "ioc_type": ioc_type,
            "summary": {
                "whois": "success" if "whois" in results and "error" not in results["whois"] else "error" if "whois" in results else "n/a",
                "dns": "success" if "dns" in results and "error" not in results["dns"] else "error" if "dns" in results else "n/a",
                "ssl": "success" if "ssl" in results and "error" not in results["ssl"] else "error" if "ssl" in results else "n/a",
                "geoip": "success" if "geoip" in results and "error" not in results["geoip"] else "error" if "geoip" in results else "n/a",
                "virustotal": "success" if "virustotal" in results and "error" not in results["virustotal"] else "error" if "virustotal" in results else "n/a",
                "shodan": "success" if "shodan" in results and "error" not in results["shodan"] else "error" if "shodan" in results else "n/a",
                "abuseipdb": "success" if "abuseipdb" in results and "error" not in results["abuseipdb"] else "error" if "abuseipdb" in results else "n/a",
                "threatfox": "success" if "threatfox" in results and "error" not in results["threatfox"] else "error" if "threatfox" in results else "n/a",
                "dnsdumpster": "success" if "dnsdumpster" in results and "error" not in results["dnsdumpster"] else "error" if "dnsdumpster" in results else "n/a"
            }
        }

        if st.button("Limpar Histórico", type="secondary"):
            try:
                os.remove(history_file)
                st.session_state.history = []
                st.success("Histórico limpo com sucesso!")
                st.rerun() # Recarrega para atualizar a exibição
            except Exception as e:
                st.error(f"Erro ao limpar histórico: {e}")
        else:
            pass
        
        # Adicionar ao início da lista (mais recente primeiro)
        st.session_state.history.insert(0, current_search)
        
        # Limitar o histórico a 50 entradas
        if len(st.session_state.history) > 50:
            st.session_state.history = st.session_state.history[:50]
        
        # Exibir histórico
        if st.session_state.history:
            for i, entry in enumerate(st.session_state.history):
                with st.expander(f"{entry['ioc']} ({entry['ioc_type'].upper()}) - {datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"):
                    # Criar colunas para exibir o status de cada fonte
                    cols = st.columns(3)
                    
                    for j, (source, status) in enumerate(entry["summary"].items()):
                        col_idx = j % 3
                        with cols[col_idx]:
                            if status == "success":
                                st.success(source.upper())
                            elif status == "error":
                                st.error(source.upper())
                            else:
                                st.info(source.upper())
                    

        else:
            st.info("Nenhum histórico de busca disponível.")
    
    with tab_export:
        st.subheader("📤 Exportação Completa do Reconhecimento")

        # Mostrar dados brutos (útil para debug ou análise manual)
        with st.expander("📦 Ver dados brutos (JSON)", expanded=False):
            st.json(results)

        try:
            # Gerar relatórios em diferentes formatos
            report_md = generate_full_report(results, format="md")
            report_txt = generate_full_report(results, format="txt")

            st.success("Relatórios gerados com sucesso!")

            # Botões de download
            st.download_button(
                label="📥 Baixar relatório (.md)",
                data=report_md,
                file_name=f"recon_{normalized_ioc}.md",
                mime="text/markdown"
            )

            st.download_button(
                label="📥 Baixar relatório (.txt)",
                data=report_txt,
                file_name=f"recon_{normalized_ioc}.txt",
                mime="text/plain"
            )

        except Exception as e:
            st.error(f"Erro ao gerar os relatórios: {str(e)}")

    
    # Salvar histórico em arquivo (chame aqui, dentro do bloco das abas)
    save_history(normalized_ioc, ioc_type, results)

# --- Instruções e Informações ---
with st.sidebar:
    st.header("📘 Instruções de Uso")
    st.write("""
Este projeto realiza **reconhecimento passivo** de IOCs (Indicadores de Comprometimento), utilizando fontes externas e motores OSINT.

Para usar:
1. Informe um IOC válido no campo de busca (IP, domínio, URL ou hash).
2. A análise será feita automaticamente em diversas fontes passivas.
3. Os resultados são organizados em abas temáticas e podem ser exportados.

🔒 *Este projeto evita técnicas de ataque ativo para não gerar tráfego suspeito ao alvo.*
    """)

    st.subheader("📌 Tipos de IOC Suportados")
    st.write("- **IP:** Endereços IPv4 ou IPv6")
    st.write("- **Domínio:** Ex: `empresa.com`")
    st.write("- **URL:** Ex: `https://app.empresa.com/login`")
    st.write("- **Hash:** MD5, SHA1 ou SHA256")

    st.subheader("🧠 Funcionalidades e Fontes de Dados")
    st.write("""
**Análises Gerais:**
- Whois (IP e Domínio)
- DNS (nslookup passivo)
- Geolocalização (GeoIP)
- Certificados SSL
- ASN e Vizinhança de IP

**Verificações de Segurança:**
- Headers HTTP de segurança
- Fingerprinting de tecnologias (Wappalyzer)
- Análise de conteúdo HTML
- Detectores de CSP e Server

**Consulta em Fontes de Reputação:**
- VirusTotal (com suporte para URL, IP, domínio e hash)
- Shodan
- AbuseIPDB
- ThreatFox

**Reconhecimento Passivo e OSINT:**
- Subdomínios via crt.sh 
- Histórico de Domínios (Wayback Machine)
- Motores OSINT: DuckDuckGo, GitHub, Hunter.io, URLScan.io
- Extração de e-mails públicos e vazamentos relacionados

**Exportação:**
- Relatórios em `.md`, `.txt` e `.json`
- Wordlists de subdomínios e caminhos históricos

""")

    st.info("⚠️ Para acesso total, configure suas chaves de API no arquivo `.env`.\nSem elas, os dados podem ser limitados.")

