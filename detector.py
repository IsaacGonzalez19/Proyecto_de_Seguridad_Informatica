"""
Motor principal de análisis de phishing
Contiene la lógica central para detectar correos sospechosos
"""

import re
from keywords import KeywordManager
from utils import clean_text, calculate_risk_level, extract_urls


class PhishingDetector:
    def __init__(self):
        self.keyword_manager = KeywordManager()

    def analyze_email(self, email_content):
        """
        Función principal para analizar un correo electrónico

        Args:
            email_content (str): Contenido del correo a analizar

        Returns:
            dict: Resultado del análisis con nivel de riesgo y detalles
        """
        if not email_content or not email_content.strip():
            raise ValueError("El contenido del correo no puede estar vacío")

        # Limpiar el texto
        cleaned_text = clean_text(email_content)

        # Análisis de palabras clave
        keyword_analysis = self.check_keywords(cleaned_text)

        # Análisis de URLs
        url_analysis = self.analyze_urls(email_content)

        # Calcular puntuación total
        total_score = keyword_analysis['score'] + url_analysis['score']

        # Determinar nivel de riesgo
        risk_info = calculate_risk_level(total_score)

        return {
            'risk_level': risk_info['level'],
            'risk_color': risk_info['color'],
            'score': total_score,
            'detected_keywords': keyword_analysis['detected'],
            'suspicious_urls': url_analysis['suspicious'],
            'total_urls': url_analysis['total'],
            'recommendations': self.get_recommendations(risk_info['level'])
        }

    def check_keywords(self, text):
        """
        Analiza las palabras clave sospechosas en el texto

        Args:
            text (str): Texto limpio a analizar

        Returns:
            dict: Score y palabras detectadas
        """
        keywords = self.keyword_manager.get_all_keywords()
        text_lower = text.lower()

        detected_keywords = []
        score = 0

        for category, words in keywords.items():
            for word in words:
                if word.lower() in text_lower:
                    score += self.keyword_manager.get_keyword_weight(category)
                    detected_keywords.append(f"{word} ({category})")

        return {
            'score': score,
            'detected': detected_keywords
        }

    def analyze_urls(self, text):
        """
        Analiza las URLs encontradas en el texto

        Args:
            text (str): Texto original con URLs

        Returns:
            dict: Información sobre URLs analizadas
        """
        urls = extract_urls(text)
        suspicious_urls = []
        url_score = 0

        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co',
            'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'
        ]

        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IPs
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]{2,}',  # Dominios sospechosos
            r'[a-z]{20,}\.[a-z]{2,}'  # Dominios muy largos
        ]

        for url in urls:
            url_lower = url.lower()
            is_suspicious = False

            # Verificar dominios conocidos de acortamiento
            if any(domain in url_lower for domain in suspicious_domains):
                suspicious_urls.append(url)
                url_score += 2
                is_suspicious = True

            # Verificar patrones sospechosos
            if not is_suspicious:
                for pattern in suspicious_patterns:
                    if re.search(pattern, url_lower):
                        suspicious_urls.append(url)
                        url_score += 1
                        break

        return {
            'score': url_score,
            'suspicious': suspicious_urls,
            'total': len(urls)
        }

    def get_recommendations(self, risk_level):
        """
        Obtiene recomendaciones basadas en el nivel de riesgo

        Args:
            risk_level (str): Nivel de riesgo (ALTO, MEDIO, BAJO)

        Returns:
            list: Lista de recomendaciones
        """
        recommendations = {
            'ALTO': [
                'NO hagas clic en ningún enlace del correo',
                'NO descargues archivos adjuntos',
                'NO proporciones información personal',
                'Elimina el correo inmediatamente',
                'Reporta el correo como spam/phishing'
            ],
            'MEDIO': [
                'Verifica la dirección del remitente cuidadosamente',
                'No hagas clic en enlaces sospechosos',
                'Contacta directamente a la organización por teléfono',
                'Busca errores ortográficos o gramaticales',
                'Desconfía si pide información urgente'
            ],
            'BAJO': [
                'El correo parece legítimo, pero mantén precaución',
                'Siempre verifica enlaces antes de hacer clic',
                'No compartas información sensible por correo',
                'Mantén actualizado tu antivirus'
            ]
        }

        return recommendations.get(risk_level, recommendations['BAJO'])