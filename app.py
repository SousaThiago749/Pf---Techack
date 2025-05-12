from flask import Flask, render_template, request
from verificacao import verificar_url

import csv
from flask import Flask, render_template, request, redirect, url_for, send_file
from io import StringIO
from verificacao import verificar_url

from collections import Counter

from io import BytesIO

app = Flask(__name__)

historico_resultados = []

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = None
    if request.method == 'POST':
        url = request.form.get('url')
        resultado = verificar_url(url)
        resultado["url_analisada"] = url
        historico_resultados.append(resultado)
    return render_template('index.html', resultado=resultado)

@app.route('/historico')
@app.route('/historico')
def historico():
    contadores = Counter()
    for r in historico_resultados:
        for chave in [
            "phishing_list", "numeros_no_dominio", "subdominios_excessivos",
            "caracteres_especiais", "dns_dinamico", "ssl_valido", "ssl_correspondente",
            "redireciona_para_outro_dominio", "redirecionamentos_multiplos",
            "similar_a_marca_conhecida", "formulario_detectado", "campo_sensivel_detectado"
        ]:
            if chave in r and (
                (chave in ["ssl_valido", "ssl_correspondente"] and r[chave] == False) or
                (chave not in ["ssl_valido", "ssl_correspondente"] and r[chave] == True)
            ):
                contadores[chave] += 1

    labels = list(contadores.keys())
    valores = list(contadores.values())

    return render_template(
        'historico.html',
        historico=historico_resultados,
        labels=labels,
        valores=valores
    )

@app.route('/exportar')
def exportar():
    if not historico_resultados:
        return "Nenhuma URL verificada ainda.", 400

    # Escreve CSV em texto com StringIO
    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=historico_resultados[0].keys())
    writer.writeheader()
    writer.writerows(historico_resultados)

    # Converte texto para binário e prepara para download
    output = BytesIO(si.getvalue().encode('utf-8'))
    output.seek(0)

    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='historico.csv'
    )

if __name__ == '__main__':
    app.run(debug=True)
