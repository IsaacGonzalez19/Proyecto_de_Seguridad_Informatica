"""
Gestor de palabras clave para detección de phishing
Maneja la carga, actualización y categorización de términos sospechosos
"""

import json
import os
from typing import Dict, List


class KeywordManager:
    def __init__(self, keywords_file='data/phishing_keywords.json'):
        self.keywords_file = keywords_file
        self.keywords = self.load_keywords()
        self.category_weights = {
            'urgentes': 2,
            'amenazas': 3,
            'dinero': 2,
            'personales': 3,
            'sospechosas': 1
        }

    def load_keywords(self) -> Dict[str, List[str]]:
        """
        Carga las palabras clave desde el archivo JSON

        Returns:
            dict: Diccionario con categorías y palabras clave
        """
        try:
            if os.path.exists(self.keywords_file):
                with open(self.keywords_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return self.get_default_keywords()
        except Exception as e:
            print(f"Error cargando keywords: {e}")
            return self.get_default_keywords()

    def get_default_keywords(self) -> Dict[str, List[str]]:
        """
        Retorna las palabras clave por defecto si no existe el archivo

        Returns:
            dict: Diccionario con palabras clave básicas
        """
        return {
            "urgentes": [
                "urgente", "inmediatamente", "ahora mismo", "expire hoy",
                "última oportunidad", "tiempo limitado", "actúa ahora",
                "vence pronto", "solo por hoy", "oferta limitada"
            ],
            "amenazas": [
                "suspender", "bloquear", "cerrar cuenta", "eliminar",
                "cancelar", "desactivar", "penalización", "multa",
                "consecuencias legales", "demanda", "investigación"
            ],
            "dinero": [
                "premio", "ganador", "millones", "transferencia", "banco",
                "dinero gratis", "inversión garantizada", "lotería",
                "herencia", "reembolso", "compensación", "beneficio"
            ],
            "personales": [
                "verificar", "actualizar datos", "confirmar", "validar",
                "información personal", "datos bancarios", "contraseña",
                "número de cuenta", "tarjeta de crédito", "pin", "cvv"
            ],
            "sospechosas": [
                "hacer clic aquí", "enlace", "descarga inmediata",
                "adjunto importante", "no responder", "reenviar",
                "confidencial", "secreto", "oportunidad única"
            ]
        }

    def get_all_keywords(self) -> Dict[str, List[str]]:
        """
        Obtiene todas las palabras clave

        Returns:
            dict: Todas las categorías y palabras clave
        """
        return self.keywords

    def get_keywords_by_category(self, category: str) -> List[str]:
        """
        Obtiene palabras clave de una categoría específica

        Args:
            category (str): Nombre de la categoría

        Returns:
            list: Lista de palabras clave de la categoría
        """
        return self.keywords.get(category, [])

    def get_keyword_weight(self, category: str) -> int:
        """
        Obtiene el peso de una categoría de palabras clave

        Args:
            category (str): Nombre de la categoría

        Returns:
            int: Peso de la categoría
        """
        return self.category_weights.get(category, 1)

    def add_keyword(self, category: str, keyword: str) -> bool:
        """
        Añade una nueva palabra clave a una categoría

        Args:
            category (str): Categoría donde añadir
            keyword (str): Palabra clave a añadir

        Returns:
            bool: True si se añadió correctamente
        """
        try:
            if category not in self.keywords:
                self.keywords[category] = []

            if keyword.lower() not in [k.lower() for k in self.keywords[category]]:
                self.keywords[category].append(keyword.lower())
                self.save_keywords()
                return True
            return False
        except Exception as e:
            print(f"Error añadiendo keyword: {e}")
            return False

    def remove_keyword(self, category: str, keyword: str) -> bool:
        """
        Elimina una palabra clave de una categoría

        Args:
            category (str): Categoría de donde eliminar
            keyword (str): Palabra clave a eliminar

        Returns:
            bool: True si se eliminó correctamente
        """
        try:
            if category in self.keywords and keyword.lower() in self.keywords[category]:
                self.keywords[category].remove(keyword.lower())
                self.save_keywords()
                return True
            return False
        except Exception as e:
            print(f"Error eliminando keyword: {e}")
            return False

    def save_keywords(self) -> bool:
        """
        Guarda las palabras clave en el archivo JSON

        Returns:
            bool: True si se guardó correctamente
        """
        try:
            os.makedirs(os.path.dirname(self.keywords_file), exist_ok=True)
            with open(self.keywords_file, 'w', encoding='utf-8') as f:
                json.dump(self.keywords, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Error guardando keywords: {e}")
            return False

    def get_statistics(self) -> Dict[str, int]:
        """
        Obtiene estadísticas de las palabras clave

        Returns:
            dict: Estadísticas por categoría
        """
        stats = {}
        total = 0

        for category, words in self.keywords.items():
            count = len(words)
            stats[category] = count
            total += count

        stats['total'] = total
        return stats