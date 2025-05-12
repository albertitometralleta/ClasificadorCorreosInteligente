
from bs4 import BeautifulSoup
import re
import string
import nltk
from nltk.corpus import stopwords
from langdetect import detect
from deep_translator import GoogleTranslator


# FUNCIONES DE PREPROCESAMIENTO DE TEXTO

nltk.download('stopwords')
stop_words = set(stopwords.words('english')) 


phishing_keywords = [
    # Seguridad y cuenta
    "account", "password", "verify", "login", "update", "security",
    "credentials", "unauthorized", "suspended", "compromised", "alert", "reset",

    # Urgencia o amenaza
    "urgent", "immediately", "action required", "important", "now",
    "verify immediately", "failure", "final warning", "attention", "limited time", "response needed",

    # Recompensas, dinero o premios
    "winner", "congratulations", "free", "bonus", "refund", "claim",
    "reward", "lottery", "prize", "gift card", "cash",

    # Enlaces o descargas
    "click here", "download", "open attachment", "access", "view",
    "see details", "login link", "check now", "follow the link",

    # Entidades suplantadas
    "paypal", "apple", "amazon", "bank", "netflix", "support",
    "help desk", "it department", "administrator", "system", "cnn"
]

def limpiar_html(texto):
    # 1
    texto_sin_html = BeautifulSoup(texto, "html.parser").get_text()
    # 2
    texto_limpio = re.sub(r'[^a-zA-Z\s]', '', texto_sin_html)
    return texto_limpio


def eliminar_stopwords(texto):
    # 1
    tokens = texto.split()
    # 2
    tokens_filtrados = [word for word in tokens if word not in stop_words]
    # 3
    return " ".join(tokens_filtrados)


def preprocess_text(text):
    #1
    text = limpiar_html(text) 
    #2
    text = text.lower()
    #3
    text = re.sub(r"http\S+", "", text)                
    text = re.sub(r"\S+@\S+", "", text) 
    #4                   
    text = re.sub(r"\d+", "", text)                         
    text = text.translate(str.maketrans('', '', string.punctuation))  
    #5
    text = text.strip()
    #6
    text = eliminar_stopwords(text) 
    return text

def light_clean(text):
    # 1
    if isinstance(text, str):
        # 2
        return re.sub(r'\s+', ' ', text).strip().lower()
    # 3
    return ''  # Si no es una cadena, devolver una cadena vacía 

def extract_features(text):
    text_lower = text.lower()
    return {
        # 1
        'num_links': len(re.findall(r'http[s]?://|www\.|bit\.ly|tinyurl|chk\.me', text_lower)),
        # 2
        'has_form': int(bool(re.search(r'<form|input type=', text_lower))),
        # 3
        'has_attachment': int('.zip' in text_lower or '.exe' in text_lower or 'attachment' in text_lower),
        # 4
        'text_length': len(text),
        # 5
        'num_phishing_keywords': sum(1 for kw in phishing_keywords if kw in text_lower),
    }

def traducir_a_ingles(texto):
    try:
        idioma = detect(texto)
        if idioma != 'en':
            return GoogleTranslator(source='auto', target='en').translate(texto)
        return texto
    except Exception as e:
        print(f"Error traduciendo: {e}")
        return texto