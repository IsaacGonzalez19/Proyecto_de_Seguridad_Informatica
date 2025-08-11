"""
Utilidades y funciones de apoyo para el detector de phishing
Contiene funciones auxiliares para limpieza de texto, cálculos y extracción
"""

import re
import string
from typing import List, Dict


def clean_text(text: str) -> str:
    """
    Limpia y normaliza el texto para análisis

    Args:
        text (str): Texto original

    Returns:
        str: Texto limpio y normalizado
    """
    if not text:
        return ""

    # Convertir a minúsculas
    text = text.lower()

    # Eliminar caracteres de control y tabulaciones extra
    text = re.sub(r'[\t\n\r\f\v]+', ' ', text)

    # Normalizar espacios múltiples
    text = re.sub(r'\s+', ' ', text)

    # Eliminar espacios al inicio y final
    text = text.strip()

    return text


def extract_urls(text: str) -> List[str]:
    """
    Extrae todas las URLs del texto

    Args:
        text (str): Texto del que extraer URLs

    Returns:
        list: Lista de URLs encontradas
    """
    # Patrón para detectar URLs
    url_patterns = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    ]

    urls = []
    for pattern in url_patterns:
        found_urls = re.findall(pattern, text, re.IGNORECASE)
        urls.extend(found_urls)

    # Eliminar duplicados manteniendo el orden
    unique_urls = []
    for url in urls:
        if url not in unique_urls:
            unique_urls.append(url)

    return unique_urls


def calculate_risk_level(score: int) -> Dict[str, str]:
    """
    Calcula el nivel de riesgo basado en la puntuación

    Args:
        score (int): Puntuación total del análisis

    Returns:
        dict: Información del nivel de riesgo
    """
    if score >= 8:
        return {
            'level': 'ALTO',
            'color': 'danger',
            'icon': '🚨',
            'description': 'Muy probable que sea phishing'
        }
    elif score >= 4:
        return {
            'level': 'MEDIO',
            'color': 'warning',
            'icon': '⚠️',
            'description': 'Posible intento de phishing'
        }
    else:
        return {
            'level': 'BAJO',
            'color': 'success',
            'icon': '✅',
            'description': 'El correo parece seguro'
        }


def validate_email_format(email: str) -> bool:
    """
    Valida si un email tiene formato correcto

    Args:
        email (str): Dirección de email a validar

    Returns:
        bool: True si el formato es válido
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def extract_email_addresses(text: str) -> List[str]:
    """
    Extrae direcciones de email del texto

    Args:
        text (str): Texto del que extraer emails

    Returns:
        list: Lista de emails encontrados
    """
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(pattern, text)

    # Validar y filtrar emails
    valid_emails = [email for email in emails if validate_email_format(email)]

    return list(set(valid_emails))  # Eliminar duplicados


def count_suspicious_chars(text: str) -> Dict[str, int]:
    """
    Cuenta caracteres sospechosos en el texto

    Args:
        text (str): Texto a analizar

    Returns:
        dict: Conteo de caracteres sospechosos
    """
    suspicious_chars = {
        'exclamations': text.count('!'),
        'question_marks': text.count('?'),
        'dollar_signs': text.count('$'),
        'uppercase_words': len(re.findall(r'\b[A-Z]{3,}\b', text)),
        'numbers': len(re.findall(r'\d+', text))
    }

    return suspicious_chars


def format_analysis_report(analysis_result: Dict) -> str:
    """
    Formatea el resultado del análisis en un reporte legible

    Args:
        analysis_result (dict): Resultado del análisis

    Returns:
        str: Reporte formateado
    """
    report_lines = []
    report_lines.append("=== REPORTE DE ANÁLISIS DE PHISHING ===")
    report_lines.append(f"Nivel de Riesgo: {analysis_result['risk_level']}")
    report_lines.append(f"Puntuación: {analysis_result['score']} puntos")
    report_lines.append("")

    if analysis_result['detected_keywords']:
        report_lines.append("Palabras clave detectadas:")
        for keyword in analysis_result['detected_keywords']:
            report_lines.append(f"  - {keyword}")
        report_lines.append("")

    if analysis_result['suspicious_urls']:
        report_lines.append("URLs sospechosas:")
        for url in analysis_result['suspicious_urls']:
            report_lines.append(f"  - {url}")
        report_lines.append("")

    report_lines.append("Recomendaciones:")
    for rec in analysis_result['recommendations']:
        report_lines.append(f"  • {rec}")

    return "\n".join(report_lines)


def get_severity_color(risk_level: str) -> str:
    """
    Obtiene el color CSS correspondiente al nivel de riesgo

    Args:
        risk_level (str): Nivel de riesgo

    Returns:
        str: Clase CSS de color
    """
    colors = {
        'ALTO': 'text-danger',
        'MEDIO': 'text-warning',
        'BAJO': 'text-success'
    }
    return colors.get(risk_level, 'text-secondary')