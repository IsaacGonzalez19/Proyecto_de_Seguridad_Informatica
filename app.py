from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from detector import PhishingDetector
from utils import format_analysis_report

app = Flask(__name__)
CORS(app)

# Inicializar el detector
detector = PhishingDetector()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_email():
    try:
        data = request.get_json()
        email_content = data.get('email_content', '')

        if not email_content.strip():
            return jsonify({
                "error": "Por favor, ingresa el contenido del correo electrónico"
            }), 400

        # Analizar usando el detector modular
        result = detector.analyze_email(email_content)

        return jsonify({
            "success": True,
            "analysis": result
        })

    except Exception as e:
        return jsonify({
            "error": f"Error al analizar el correo: {str(e)}"
        }), 500


@app.route('/api/keywords', methods=['GET'])
def get_keywords():
    """Endpoint para obtener estadísticas de palabras clave"""
    try:
        stats = detector.keyword_manager.get_statistics()
        return jsonify({
            "success": True,
            "statistics": stats
        })
    except Exception as e:
        return jsonify({
            "error": f"Error obteniendo estadísticas: {str(e)}"
        }), 500


if __name__ == '__main__':
    # Crear carpetas necesarias
    os.makedirs('data', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)

    app.run(debug=True, host='0.0.0.0', port=5000)