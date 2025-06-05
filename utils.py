import re
import socket
import ipaddress
import requests
import whois
import dns.resolver
import ssl
import OpenSSL
import json
import os
from datetime import datetime
from geoip2 import database
from bs4 import BeautifulSoup
from ipwhois import IPWhois
import base64
import builtwith
import tldextract

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"


# Função para detectar o tipo de IOC
def detect_ioc_type(ioc):
    """
    Detecta o tipo de IOC: IP, domínio, hash ou URL
    Retorna uma tupla (tipo, valor_normalizado)
    """
    ioc = ioc.strip()
    
    # Verificar se é um endereço IP
    try:
        ipaddress.ip_address(ioc)
        return ("ip", ioc)
    except ValueError:
        pass
    
    # Verificar se é um hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):  # MD5
        return ("hash", ioc.lower())
    elif re.match(r'^[a-fA-F0-9]{40}$', ioc):  # SHA1
        return ("hash", ioc.lower())
    elif re.match(r'^[a-fA-F0-9]{64}$', ioc):  # SHA256
        return ("hash", ioc.lower())
    
    # Verificar se é uma URL
    if re.match(r'^https?://', ioc):
        return ("url", ioc)
    
    # Se não for nenhum dos anteriores, considerar como domínio
    # Verificação básica de formato de domínio
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc):
        return ("domain", ioc.lower())
    
    # Se não corresponder a nenhum formato conhecido
    return ("unknown", ioc)

# Função para obter informações Whois
def get_whois_info(ioc, ioc_type):
    """
    Obtém informações Whois para IPs e domínios
    """
    if ioc_type == "ip":
        try:
            obj = IPWhois(ioc)
            res = obj.lookup_rdap()
            network = res.get("network", {})
            org_ref = network.get("handle") or network.get("org_ref") 
            org_info = res.get("objects", {}).get(org_ref, {})
            org_name = org_info.get("contact", {}).get("name") or network.get("name")
            address_info = org_info.get("contact", {}).get("address", [{}])[0]
            address_str = ', '.join(filter(None, address_info.get("value", "").split('\n')))
            return {
                "OrgName": org_name or "N/A",
                "OrgId": org_ref or "N/A",
                "Address": address_str or "N/A",
                "Country": network.get("country", "N/A"),
                "NetRange": f'{network.get("start_address", "N/A")} - {network.get("end_address", "N/A")}',
                "CIDR": network.get("cidr", "N/A"),
                "NetName": network.get("name", "N/A"),
                "RegDate": network.get("registrationDate") or network.get("created", "N/A"), 
                "Updated": network.get("lastChangedDate") or network.get("updated", "N/A"),
                "Source": "RDAP"
            }
        except Exception as e:
            return {"error": f"Erro ao obter WHOIS do IP: {str(e)}"}
        
    elif ioc_type == "domain":
        try:
            result = whois.whois(ioc)
            if not result or not result.domain_name:
                return {"error": f"Nenhuma informação Whois encontrada para o domínio '{ioc}'."}
            
            def format_date(d):
                if isinstance(d, list): # Às vezes retorna lista de datas
                    d = d[0]
                return d.isoformat() if isinstance(d, datetime) else str(d) if d else "N/A"


            return {
                "registrar": result.registrar or "N/A",
                "org": result.org or "N/A",
                "creation_date": format_date(result.creation_date),
                "expiration_date": format_date(result.expiration_date),
                "updated_date": format_date(result.updated_date),
                "status": ' '.join(result.status) if isinstance(result.status, list) else result.status or "N/A",
                "name_servers": sorted(list(set(result.name_servers))) if result.name_servers else [], # Garante lista única e ordenada
                "emails": sorted(list(set(result.emails))) if result.emails else [], # Garante lista única e ordenada
                "country": getattr(result, "country", "N/A"),
                "city": getattr(result, "city", "N/A"),
                "address": getattr(result, "address", "N/A"),
                "zipcode": getattr(result, "zipcode", "N/A"),
                "state": getattr(result, "state", "N/A"),
                "Source": "Whois"
            }
        except Exception as e:
            return {"error": f"Erro ao obter informações Whois: {str(e)}"}
    else:
        return {"error": f"Whois não aplicável para o tipo {ioc_type}"}

# Função para obter informações DNS
def get_dns_info(domain):
    """
    Obtém registros DNS para um domínio
    """
    if not domain:
        return {"error": "Domínio não fornecido"}
    
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception:
            results[record_type] = []
    
    return results

# Função para obter informações de certificado SSL
def get_ssl_cert_info(host):
    """
    Obtém informações do certificado SSL para um host
    """
    if not host:
        return {"error": "Host não fornecido"}
    
    try:
        # Tentar conectar na porta 443 (HTTPS)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                
                # Extrair informações do certificado
                cert_info = {
                    "subject": dict(x509.get_subject().get_components()),
                    "issuer": dict(x509.get_issuer().get_components()),
                    "version": x509.get_version(),
                    "serial_number": x509.get_serial_number(),
                    "not_before": x509.get_notBefore().decode(),
                    "not_after": x509.get_notAfter().decode(),
                    "has_expired": x509.has_expired()
                }
                
                # Converter bytes para strings nos dicionários
                for key in ["subject", "issuer"]:
                    cert_info[key] = {k.decode(): v.decode() for k, v in cert_info[key].items()}
                
                return cert_info
    except Exception as e:
        return {"error": f"Erro ao obter certificado SSL: {str(e)}"}

# Função para obter informações de geolocalização de IP
def get_geoip_info(ip):
    """
    Obtém informações de geolocalização para um endereço IP usando o banco local MaxMind
    """
    if not ip:
        return {"error": "IP não fornecido"}
    
    try:
        # Verificar se é um IP privado
        if ipaddress.ip_address(ip).is_private:
            return {"error": "IP privado, geolocalização não disponível"}
        
        db_path = os.getenv("GEOLITE2_DB_PATH", "./db/GeoLite2-City.mmdb")
        if not os.path.exists(db_path):
            return {"error": f"Banco de dados GeoLite2 não encontrado em {db_path}"}
        
        with database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone
            }
    except ValueError:
        return {"error": "Endereço IP inválido"}
    except Exception as e:
        return {"error": f"Erro ao obter geolocalização: {str(e)}"}

# Função para consultar VirusTotal
def query_virustotal(ioc, ioc_type, api_key=None):
    """
    Consulta a API do VirusTotal para IPs, domínios, hashes e URLs.
    Para URLs, realiza POST (submit) + GET /analyses/{id} + GET /urls/{url_base64_id}.
    """
    api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "Chave de API do VirusTotal não fornecida (nem via argumento nem via variável de ambiente VIRUSTOTAL_API_KEY)."}

    base_url = "https://www.virustotal.com/api/v3/"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": DEFAULT_USER_AGENT # Boa prática incluir User-Agent
    }

    try:
        if ioc_type == "ip":
            response = requests.get(base_url + f"ip_addresses/{ioc}", headers=headers)
            return response.json() if response.status_code == 200 else {"error": f"Erro (IP): {response.status_code}"}

        elif ioc_type == "domain":
            response = requests.get(base_url + f"domains/{ioc}", headers=headers)
            return response.json() if response.status_code == 200 else {"error": f"Erro (Domínio): {response.status_code}"}

        elif ioc_type == "hash":
            response = requests.get(base_url + f"files/{ioc}", headers=headers)
            return response.json() if response.status_code == 200 else {"error": f"Erro (Hash): {response.status_code}"}

        elif ioc_type == "url":
            # Etapa 1: Enviar a URL via POST
            response_post = requests.post(base_url + "urls", headers=headers, data={"url": ioc})
            if response_post.status_code != 200:
                return {
                    "error": f"Erro ao enviar URL: {response_post.status_code}",
                    "detalhes": response_post.text
                }

            analysis_id = response_post.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "ID da análise não retornado pela API (etapa 1)"}

            # Etapa 2: Obter resultado da análise
            analysis_resp = requests.get(base_url + f"analyses/{analysis_id}", headers=headers)
            analysis_data = analysis_resp.json() if analysis_resp.status_code == 200 else {}

            # Etapa 3: Codificar a URL no formato exigido pelo VirusTotal
            url_base64 = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            details_resp = requests.get(base_url + f"urls/{url_base64}", headers=headers)

            if details_resp.status_code == 200:
                full_data = details_resp.json()
                full_data["analysis_result"] = analysis_data  # anexa resultado bruto da análise também
                return full_data
            else:
                return {
                    "error": f"Erro ao obter detalhes completos da URL: {details_resp.status_code}",
                    "detalhes": details_resp.text,
                    "analysis_result": analysis_data
                }

        else:
            return {"error": f"Tipo de IOC não suportado: {ioc_type}"}

    except Exception as e:
        return {"error": f"Exceção na consulta ao VirusTotal: {str(e)}"}


# Função para consultar Shodan
def query_shodan(ioc, ioc_type, api_key=None):
    """
    Consulta a API do Shodan para obter informações sobre o IOC
    """
    api_key = api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "Chave de API do Shodan não fornecida (SHODAN_API_KEY)."}
    
    if ioc_type not in ["ip", "domain"]:
        return {"error": f"Shodan não suporta o tipo de IOC: {ioc_type}"}
    
    try:
        if ioc_type == "ip":
            url = f"https://api.shodan.io/shodan/host/{ioc}?key={api_key}"
        else:  # domain
            url = f"https://api.shodan.io/dns/domain/{ioc}?key={api_key}&history=true"
        
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Nada encontrado no Shodan! Caso queira testar, consulte no site em https://www.shodan.io/"}
    except Exception as e:
        return {"error": f"Erro ao consultar Shodan: {str(e)}"}

# Função para consultar AbuseIPDB
def query_abuseipdb(ip, api_key=None):
    """
    Consulta a API do AbuseIPDB para verificar a reputação de um IP
    """
    api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "Chave de API do AbuseIPDB não fornecida (ABUSEIPDB_API_KEY)."}
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key,
            "User-Agent": DEFAULT_USER_AGENT
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Erro na consulta ao AbuseIPDB: {response.status_code}"}
    except Exception as e:
        return {"error": f"Erro ao consultar AbuseIPDB: {str(e)}"}

# Função para consultar ThreatFox
def query_threatfox(ioc, ioc_type, api_key=None):
    """
    Consulta a API do ThreatFox para obter informações sobre o IOC
    """
    api_key = api_key or os.getenv("THREATFOX_API_KEY")
    
    url = "https://threatfox-api.abuse.ch/api/v1/"

    if ioc_type not in ["ip", "domain", "url", "hash"]:
        return {"error": f"Tipo de IOC '{ioc_type}' não suportado pela consulta ThreatFox."}
    
    data = {
        "query": "search_ioc",
        "search_term": ioc,
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_USER_AGENT
    }

    if api_key:
        headers["API-KEY"] = api_key

    try:
        response = requests.post(url, json=data, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "no_result":
                result["info"] = f"IOC '{ioc}' não encontrado no ThreatFox."
            return result
        else:
            error_message = f"Erro na consulta ao ThreatFox: Status {response.status_code}"
            try:
                # Tenta extrair a mensagem de erro do JSON da resposta
                error_detail = response.json().get("query_status", response.text)
                error_message += f" - {error_detail}"
            except json.JSONDecodeError:
                error_message += f" - {response.text}"
            return {"error": error_message}

    # Trata exceções de rede ou outras
    except requests.exceptions.RequestException as e:
        return {"error": f"Erro de rede ao consultar ThreatFox: {str(e)}"}
    except Exception as e:
        return {"error": f"Erro inesperado na consulta ao ThreatFox: {str(e)}"}

# Função para consultar DNSDumpster (via scraping, já que não tem API oficial)
def query_dnsdumpster(domain):
    """
    Obtém informações do DNSDumpster para um domínio
    Nota: Esta é uma implementação simplificada, já que DNSDumpster não tem API oficial
    """
    try:
        # Aviso: DNSDumpster não tem API oficial, então retornamos um aviso
        return {
            "warning": "DNSDumpster não possui API oficial. Para resultados completos, visite https://dnsdumpster.com/",
            "domain": domain,
            "dns_records": get_dns_info(domain)  # Usamos nossa própria função de DNS como alternativa
        }
    except Exception as e:
        return {"error": f"Erro ao consultar DNSDumpster: {str(e)}"}

# Função para salvar histórico de buscas
def save_history(ioc, ioc_type, results):
    """
    Salva o histórico de buscas em um arquivo JSON
    """
    history_file = "history.json"
    history = []
    
    # Carregar histórico existente, se houver
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
        except:
            history = []
    
    # Adicionar nova entrada ao histórico
    history_entry = {
        "timestamp": datetime.now().isoformat(),
        "ioc": ioc,
        "ioc_type": ioc_type,
        "summary": {
            "whois": "success" if "error" not in results.get("whois", {"error": ""}) else "error",
            "dns": "success" if "error" not in results.get("dns", {"error": ""}) else "error",
            "ssl": "success" if "error" not in results.get("ssl", {"error": ""}) else "error",
            "geoip": "success" if "error" not in results.get("geoip", {"error": ""}) else "error",
            "virustotal": "success" if "error" not in results.get("virustotal", {"error": ""}) else "error",
            "shodan": "success" if "error" not in results.get("shodan", {"error": ""}) else "error",
            "abuseipdb": "success" if "error" not in results.get("abuseipdb", {"error": ""}) else "error",
            "threatfox": "success" if "error" not in results.get("threatfox", {"error": ""}) else "error"
        }
    }
    
    # Adicionar ao início da lista (mais recente primeiro)
    history.insert(0, history_entry)
    
    # Limitar o histórico a 50 entradas
    if len(history) > 50:
        history = history[:50]
    
    # Salvar histórico atualizado
    try:
        with open(history_file, "w") as f:
            json.dump(history, f, indent=2)
        return True
    except Exception as e:
        print(f"Erro ao salvar histórico: {str(e)}")
        return False

# Função para gerar relatório em diferentes formatos
def generate_report(data, format="json"):
    """
    Gera um relatório nos formatos JSON ou Markdown
    """
    if format == "json":
        return json.dumps(data, indent=2)
    
    elif format == "markdown":
        md = "# Relatório de Análise de IOC\n\n"
        md += f"**IOC:** {data.get('ioc', 'N/A')}\n"
        md += f"**Tipo:** {data.get('ioc_type', 'N/A')}\n"
        md += f"**Data da Análise:** {data.get('timestamp', datetime.now().isoformat())}\n\n"
        
        # Adicionar seções para cada tipo de análise
        for section, section_data in data.items():
            if section in ["ioc", "ioc_type", "timestamp"]:
                continue
                
            md += f"## {section.upper()}\n\n"
            
            if isinstance(section_data, dict):
                if "error" in section_data:
                    md += f"**Erro:** {section_data['error']}\n\n"
                else:
                    for key, value in section_data.items():
                        md += f"**{key}:** {value}\n\n"
            elif isinstance(section_data, list):
                for item in section_data:
                    md += f"- {item}\n"
                md += "\n"
            else:
                md += f"{section_data}\n\n"
        
        return md
    
    else:
        return {"error": f"Formato de relatório não suportado: {format}"}

# Função para analisar conteúdo de uma página web
def analyze_web_content(url):
    """
    Faz uma requisição GET passiva ao site e extrai título, headers e conteúdo básico do HTML.
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=10)

        result = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "final_url": response.url,
            "html_snippet": response.text[:3000]  # Limita para evitar sobrecarga
        }

        soup = BeautifulSoup(response.text, "html.parser")
        result["title"] = soup.title.string.strip() if soup.title else "Sem título"
        result["scripts"] = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        result["forms"] = [f.get("action") for f in soup.find_all("form") if f.get("action")]
        result["iframes"] = [i.get("src") for i in soup.find_all("iframe") if i.get("src")]

        return result

    except Exception as e:
        return {"error": f"Erro ao analisar o conteúdo do site: {str(e)}"}
    
# Função para enumerar subdomínios passivamente usando crt.sh
def get_subdomains_crtsh(domain):
    """
    Consulta o site crt.sh para obter subdomínios passivamente através de certificados SSL públicos.
    """

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=30)
        if response.status_code != 200:
            return {"error": f"Erro ao consultar crt.sh: {response.status_code}"}

        data = response.json()
        subdomains = set()

        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        subdomains.add(sub)

        return sorted(subdomains)

    except Exception as e:
        return {"error": f"Falha ao buscar subdomínios: {str(e)}"}
    
# Fingerprinting passivo de tecnologias usando webtech
def detect_technologies(url):
    """
    Detecta tecnologias web usando o builtwith (fingerprinting passivo).
    """

    if not url or not url.startswith(("http://", "https://")):
        return {"error": "URL inválida ou não fornecida para detecção de tecnologias."}

    try:
        result = builtwith.parse(url)
        return result
    except Exception as e:
        return {"error": f"Erro ao detectar tecnologias: {str(e)}"}

def get_wayback_history(domain, limit=20):
    """
    Consulta a Wayback Machine para obter histórico de snapshots de um domínio.
    """
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&limit={limit}&fl=timestamp,original&filter=statuscode:200"

    try:
        response = requests.get(url, timeout=20)
        if response.status_code != 200:
            return {"error": f"Erro ao consultar Wayback Machine: {response.status_code}"}

        data = response.json()
        entries = []

        for row in data[1:]:  # pula cabeçalho
            timestamp, original = row
            date_fmt = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[8:10]}:{timestamp[10:12]}"
            archive_url = f"https://web.archive.org/web/{timestamp}/{original}"
            entries.append({"date": date_fmt, "url": archive_url})

        return entries

    except Exception as e:
        return {"error": f"Erro ao buscar histórico do domínio: {str(e)}"}
    
def extract_emails_from_html(html, target_domain=None):
    """
    Extrai e-mails do conteúdo HTML. Se 'target_domain' for fornecido, filtra apenas e-mails daquele domínio.
    """
    email_pattern = r"[a-zA-Z0-9._%+-]+@" + (re.escape(target_domain) if target_domain else r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    return list(set(re.findall(email_pattern, html)))

def analyze_security_headers(headers):
    """
    Verifica a presença e valor dos principais headers de segurança.
    Ignora diferenças de maiúsculas/minúsculas.
    """
    expected_headers = {
        "server": "Identifica o servidor web (pode ser útil ou prejudicial)",
        "x-powered-by": "Indica tecnologias usadas (pode ser útil ou prejudicial)",
        "content-security-policy": "Protege contra XSS e content injection",
        "strict-transport-security": "Força uso de HTTPS (HSTS)",
        "x-content-type-options": "Previne MIME sniffing",
        "x-frame-options": "Previne clickjacking",
        "x-xss-protection": "Proteção contra XSS (obsoleto, mas ainda verificado)",
        "referrer-policy": "Controla envio de referenciadores",
        "permissions-policy": "Restringe APIs sensíveis no navegador",
        "access-control-allow-methods": "Controla métodos HTTP permitidos",
        "access-control-allow-origin": "Controla origens permitidas para CORS"
    }

    # Normaliza os headers recebidos (tudo minúsculo)
    normalized = {k.lower(): v for k, v in headers.items()}
    analysis = {}

    for hname, description in expected_headers.items():
        present = hname in normalized
        value = normalized.get(hname)
        analysis[hname.title()] = {  # exibe com formatação normal
            "present": present,
            "value": value,
            "description": description
        }

    return analysis

def get_asn_info(ip):
    """
    Usa IPWhois para obter ASN, organização, faixa CIDR e vizinhança IP.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()

        network = res.get("network", {})
        return {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "org_name": res.get("network", {}).get("name"),
            "cidr": network.get("cidr"),
            "start_address": network.get("start_address"),
            "end_address": network.get("end_address"),
            "country": res.get("asn_country_code"),
            "raw": res
        }

    except Exception as e:
        return {"error": f"Erro ao buscar ASN/RDAP: {str(e)}"}
    
def search_duckduckgo(query):
    url = f"https://html.duckduckgo.com/html/?q={query}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, "html.parser")

        results = []
        for a in soup.select(".result__a"):
            title = a.text.strip()
            link = a.get("href")
            if link:
                results.append({"title": title, "url": link})

        return results[:20]

    except Exception as e:
        return {"error": f"Erro na busca DuckDuckGo: {str(e)}"}
    
def search_urlscan(ioc):
    """
    Consulta URLScan.io e retorna dados úteis para reconhecimento passivo:
    - URL, título da página
    - Screenshot
    - IP, ASN, servidor web
    - Recursos carregados (.js, .json, .php etc.)
    - Domínios externos
    - Indicação de 'malicious'
    """

    ext = tldextract.extract(ioc)
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ioc

    api_key = os.getenv("URLSCAN_API_KEY")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    try:
        # Buscar os scans mais recentes do domínio
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        search_res = requests.get(search_url, headers=headers, timeout=10)
        if search_res.status_code != 200:
            return {"error": f"Erro URLScan.io (busca): {search_res.status_code}"}

        results = search_res.json().get("results", [])[:1]  # Pega o mais recente
        if not results:
            return {"error": "Nenhum resultado encontrado no URLScan.io"}

        uuid = results[0].get("task", {}).get("uuid")
        if not uuid:
            return {"error": "UUID não encontrado no resultado"}

        # Buscar dados detalhados do scan
        result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
        res = requests.get(result_url, headers=headers, timeout=10)
        if res.status_code != 200:
            return {"error": f"Erro URLScan.io (detalhes): {res.status_code}"}

        data = res.json()
        output = {
            "url": data.get("page", {}).get("url"),
            "title": data.get("page", {}).get("title", "Sem título"),
            "ip": data.get("page", {}).get("ip"),
            "asn": data.get("page", {}).get("asn"),
            "server": data.get("page", {}).get("server"),
            "screenshot": data.get("screenshot") or data.get("task", {}).get("screenshotURL"),
            "resources": [],     # arquivos carregados
            "external_domains": [],  # domínios terceiros
            "malicious": False
        }

        # Filtrar recursos úteis (.js, .json, .php, .xml, etc.)
        extensions = (".js", ".json", ".php", ".xml", ".env", ".config", ".bak", ".log")
        all_resources = data.get("lists", {}).get("resources", [])
        output["resources"] = sorted([
            r for r in all_resources
            if isinstance(r, str) and any(r.lower().endswith(ext) for ext in extensions)
        ])

        # Domínios externos carregados
        all_domains = data.get("lists", {}).get("domains", [])
        output["external_domains"] = [d for d in all_domains if not domain in d]

        # Verificar se é considerado malicioso
        verdict = data.get("verdicts", {}).get("overall")
        output["malicious"] = verdict == "malicious"

        return output

    except Exception as e:
        return {"error": f"Erro ao consultar URLScan detalhado: {str(e)}"}
    
def search_hunter_emails(domain):
    """
    Usa a API do Hunter.io para buscar e-mails públicos do domínio.
    """

    api_key = os.getenv("HUNTER_API_KEY")
    if not api_key:
        return {"error": "Chave da API do Hunter.io não configurada."}

    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"error": f"Erro Hunter.io: {response.status_code}"}

        data = response.json().get("data", {})
        emails = data.get("emails", [])[:30]

        results = []
        for e in emails:
            results.append({
                "value": e.get("value"),
                "type": e.get("type"),
                "source": e.get("sources", [{}])[0].get("uri", "N/A"),
                "confidence": e.get("confidence"), # Score de confiança
                "first_name": e.get("first_name"),
                "last_name": e.get("last_name"),
                "position": e.get("position")
            })

        return results

    except Exception as e:
        return {"error": f"Erro ao consultar Hunter.io: {str(e)}"}

    # Trata exceções de rede ou outras
    except requests.exceptions.RequestException as e:
        return {"error": f"Erro de rede ao consultar Hunter.io: {str(e)}"}
    except Exception as e:
        return {"error": f"Erro inesperado ao consultar Hunter.io: {str(e)}"}

def search_github_code(ioc):
    token = os.getenv("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}" if token else None
    }

    url = f"https://api.github.com/search/code?q={ioc}+in:file&per_page=10"

    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code != 200:
            return {"error": f"Erro na API do GitHub: {response.status_code}"}

        items = response.json().get("items", [])
        results = []

        for item in items:
            results.append({
                "name": item.get("name"),
                "html_url": item.get("html_url"),
                "language": item.get("repository", {}).get("language", "N/A")
            })

        return results

    except Exception as e:
        return {"error": f"Erro ao consultar GitHub: {str(e)}"}

def generate_full_report(results, format="md"):
    """
    Gera um relatório completo com todas as seções relevantes de reconhecimento passivo.
    Suporta os formatos: Markdown (.md) e Texto puro (.txt)
    """

    ioc = results.get("ioc", "N/A")
    ioc_type = results.get("ioc_type", "N/A")
    timestamp = results.get("timestamp", datetime.now().isoformat())

    def format_line(text):
        return text if format == "md" else text.replace("#", "").strip()

    lines = []
    lines.append(format_line(f"# Relatório de Reconhecimento Passivo"))
    lines.append("")
    lines.append(format_line(f"**IOC:** `{ioc}`"))
    lines.append(format_line(f"**Tipo:** `{ioc_type}`"))
    lines.append(format_line(f"**Data da Análise:** {timestamp}"))
    lines.append("")

    def section(title):
        return format_line(f"## {title}\n")

    # Whois
    if "whois" in results and isinstance(results["whois"], dict):
        lines.append(section("Whois"))
        for k, v in results["whois"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # DNS
    if "dns" in results and isinstance(results["dns"], dict):
        lines.append(section("Registros DNS"))
        for k, v in results["dns"].items():
            if v:
                lines.append(f"- **{k}:** {', '.join(v)}")
        lines.append("")

    # SSL
    if "ssl" in results and isinstance(results["ssl"], dict):
        lines.append(section("Certificado SSL"))
        for k, v in results["ssl"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # GeoIP
    if "geoip" in results and isinstance(results["geoip"], dict):
        lines.append(section("Geolocalização"))
        for k, v in results["geoip"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # Shodan
    if "shodan" in results and isinstance(results["shodan"], dict):
        lines.append(section("Dados do Shodan"))
        for k, v in results["shodan"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # AbuseIPDB
    if "abuseipdb" in results and isinstance(results["abuseipdb"], dict):
        lines.append(section("Reputação (AbuseIPDB)"))
        for k, v in results["abuseipdb"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # ThreatFox
    if "threatfox" in results and isinstance(results["threatfox"], dict):
        lines.append(section("Dados do ThreatFox"))
        for k, v in results["threatfox"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    # ASN
    if "asn_info" in results and isinstance(results["asn_info"], dict):
        lines.append(section("ASN e Vizinhança"))
        for k, v in results["asn_info"].items():
            if k != "raw":
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    # OSINT Engines
    engines = results.get("osint_engines", {})
    if engines:
        lines.append(section("OSINT - Motores Externos"))

        if "duckduckgo" in engines:
            lines.append("### DuckDuckGo")
            for r in engines["duckduckgo"]:
                lines.append(f"- {r.get('title')}: {r.get('url')}")

        if "github" in engines:
            lines.append("### GitHub")
            for r in engines["github"]:
                lines.append(f"- {r.get('name')} ({r.get('language')}): {r.get('html_url')}")

        if "hunter" in engines:
            lines.append("### Hunter.io")
            for r in engines["hunter"]:
                lines.append(f"- {r.get('value')} ({r.get('type')}), fonte: {r.get('source')}")

        if "urlscan_detailed" in engines:
            scan = engines["urlscan_detailed"]
            lines.append("### URLScan Detalhado")
            lines.append(f"- URL: {scan.get('url')}")
            lines.append(f"- IP: {scan.get('ip')}")
            lines.append(f"- ASN: {scan.get('asn')}")
            lines.append(f"- Servidor: {scan.get('server')}")
            lines.append(f"- Título: {scan.get('title')}")
            lines.append(f"- Malicioso? {'SIM' if scan.get('malicious') else 'NÃO'}")
            if scan.get("resources"):
                lines.append("- Recursos carregados:")
                for r in scan["resources"]:
                    lines.append(f"  • {r}")
            if scan.get("external_domains"):
                lines.append("- Domínios externos:")
                for d in scan["external_domains"]:
                    lines.append(f"  • {d}")

        lines.append("")

    return "\n".join(lines)