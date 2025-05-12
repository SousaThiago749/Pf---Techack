import re
import urllib.parse

import whois
from datetime import datetime
from dateutil import parser as date_parser

import ssl
import socket

import requests
from urllib.parse import urlparse

import Levenshtein

from bs4 import BeautifulSoup



phishing_list = [
    "phishing-example.com",
    "fake-login.bank.com",
    "malicious-site.xyz"
]

def verificar_url(url):
    resultado = {
        "phishing_list": False,
        "numeros_no_dominio": False,
        "subdominios_excessivos": False,
        "caracteres_especiais": False
    }

    if not url.startswith("http"):
        url = "http://" + url

    url_parse = urllib.parse.urlparse(url)
    dominio = url_parse.netloc.lower()

    if dominio in phishing_list:
        resultado["phishing_list"] = True

    if re.search(r'[a-zA-Z]\d+[a-zA-Z]', dominio):
        resultado["numeros_no_dominio"] = True

    subdominios = dominio.split('.')
    if len(subdominios) > 3:
        resultado["subdominios_excessivos"] = True

    if re.search(r'[@%$!]', url):
        resultado["caracteres_especiais"] = True

    resultado["dns_dinamico"] = verificar_dns_dinamico(dominio)

    idade = verificar_idade_dominio(dominio)
    resultado["idade_dominio"] = f"{idade} dias" if idade is not None else "Não identificado"

    ssl_resultado = verificar_ssl(url)
    resultado["ssl_valido"] = ssl_resultado["ssl_valido"]
    resultado["ssl_correspondente"] = ssl_resultado["ssl_correspondente"]

    redir = verificar_redirecionamento(url)
    resultado["redireciona_para_outro_dominio"] = redir["redireciona_para_outro_dominio"]
    resultado["redirecionamentos_multiplos"] = redir["redirecionamentos_multiplos"]

    resultado["similar_a_marca_conhecida"] = verificar_similaridade_marca(dominio)

    conteudo = verificar_conteudo_html(url)
    resultado["formulario_detectado"] = conteudo["tem_formulario"]
    resultado["campo_sensivel_detectado"] = conteudo["tem_campo_sensivel"]
    resultado["palavras_sensiveis_detectadas"] = ", ".join(conteudo["palavras_chave_detectadas"]) or "Nenhuma"

    return resultado

dns_dinamico = [
    "no-ip.com", "no-ip.org", "dyndns.org", "duckdns.org",
    "zapto.org", "myftp.biz", "myvnc.com", "servehttp.com"
]

def verificar_idade_dominio(dominio):
    try:
        info = whois.whois(dominio)
        criacao = info.creation_date

        # Em alguns casos vem como lista
        if isinstance(criacao, list):
            criacao = criacao[0]

        if criacao:
            idade_dias = (datetime.now() - criacao).days
            return idade_dias
    except Exception as e:
        print(f"[ERRO WHOIS] {dominio}: {e}")
    return None  # Não foi possível obter idade

def verificar_dns_dinamico(dominio):
    for dd in dns_dinamico:
        if dominio.endswith(dd):
            return True
    return False


def verificar_ssl(url):
    try:
        # Se a URL começa com http e não https, já marcamos como inválido
        if url.startswith("http://"):
            return {
                "ssl_valido": False,
                "ssl_correspondente": False
            }

        # Extrai domínio
        dominio = url.replace("https://", "").split("/")[0]
        if dominio.startswith("www."):
            dominio = dominio[4:]

        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                ssl_valido = True

                nomes = cert.get("subject", [])
                cn = ""
                for tup in nomes:
                    if tup[0][0] == "commonName":
                        cn = tup[0][1]

                nome_bate = dominio in cn or cn in dominio
                return {
                            "ssl_valido": bool(ssl_valido),
                            "ssl_correspondente": bool(nome_bate)
                        }

    except Exception as e:
        print(f"[SSL ERRO] {url}: {e}")
        return {
            "ssl_valido": False,
            "ssl_correspondente": False
        }

def verificar_redirecionamento(url):
    try:
        resposta = requests.get(url, timeout=5, allow_redirects=True)

        # Extrai domínios
        dominio_original = urlparse(url).netloc.replace("www.", "")
        dominio_final = urlparse(resposta.url).netloc.replace("www.", "")

        redireciona = dominio_original != dominio_final
        multiplos = len(resposta.history) > 1

        return {
            "redireciona_para_outro_dominio": redireciona,
            "redirecionamentos_multiplos": multiplos
        }

    except Exception as e:
        print(f"[REDIRECIONAMENTO ERRO] {url}: {e}")
        return {
            "redireciona_para_outro_dominio": False,
            "redirecionamentos_multiplos": False
        }
    

marcas_conhecidas = [
    "google", "facebook", "paypal", "apple", "microsoft",
    "amazon", "bank", "instagram", "twitter", "outlook"
]

def verificar_similaridade_marca(dominio):
    dominio_principal = dominio.split('.')[-2] if '.' in dominio else dominio

    for marca in marcas_conhecidas:
        distancia = Levenshtein.distance(dominio_principal.lower(), marca)
        if 0 < distancia <= 2:
            return True  # Suspeito: muito parecido com marca conhecida
    return False


from bs4 import BeautifulSoup

palavras_sensiveis = [
    "senha", "password", "login", "cartão", "credit card",
    "informações pessoais", "cpf", "ssn", "security number"
]

def verificar_conteudo_html(url):
    try:
        resposta = requests.get(url, timeout=5)
        html = resposta.text
        soup = BeautifulSoup(html, "html.parser")

        # Verifica se há <form>
        tem_form = bool(soup.find("form"))

        # Verifica se há campos tipo password ou email
        campos_sensiveis = soup.find_all("input", {"type": ["password", "email", "tel", "text"]})
        tem_campo_sensivel = any("password" in field.get("type", "") for field in campos_sensiveis)

        # Busca por palavras-chave no texto visível da página
        texto = soup.get_text().lower()
        palavras_detectadas = [p for p in palavras_sensiveis if p in texto]

        return {
            "tem_formulario": tem_form,
            "tem_campo_sensivel": tem_campo_sensivel,
            "palavras_chave_detectadas": palavras_detectadas
        }

    except Exception as e:
        print(f"[HTML ERRO] {url}: {e}")
        return {
            "tem_formulario": False,
            "tem_campo_sensivel": False,
            "palavras_chave_detectadas": []
        }
