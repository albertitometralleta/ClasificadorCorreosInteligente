import pandas as pd
from bs4 import BeautifulSoup
import re
import nltk
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
import string
import joblib
import os
from xgboost import XGBClassifier


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
phishing_path = os.path.join(BASE_DIR, 'datasets', 'CEAS_08.csv')
spam_path = os.path.join(BASE_DIR, 'datasets', 'combined_data.csv')
model1_path = os.path.join(BASE_DIR, 'modelos', 'model1.pkl')
model2_path = os.path.join(BASE_DIR, 'modelos', 'model2.pkl')
vectorizer_path = os.path.join(BASE_DIR, 'modelos', 'vectorizer.pkl')
vectorizer2_path = os.path.join(BASE_DIR, 'modelos', 'vectorizer2.pkl')


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


#https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset/data
phishing_data = pd.read_csv(phishing_path)
#https://www.kaggle.com/datasets/purusinghvi/email-spam-classification-dataset
spam_data = pd.read_csv(spam_path)


phishing_data['text'] = phishing_data['subject'] + ' ' + phishing_data['body']
phishing_data = phishing_data.drop(columns=['sender', 'receiver', 'date', 'subject', 'body', 'urls'])
spam_data = spam_data[['label', 'text' ]]
spam_data = spam_data.sample(frac=0.5, random_state=42)
spam_data['label'] = spam_data['label'].replace(1,2)


mail_data = pd.concat([phishing_data, spam_data], ignore_index=True)
mail_data['label'] = mail_data['label'].replace(2, 1)


malicious_data = pd.concat([spam_data, phishing_data], ignore_index=True)
malicious_data = malicious_data[malicious_data['label'] != 0]
malicious_data['label'] = malicious_data['label'].replace(2, 0)


mail_data['clean_text'] = mail_data['text'].astype(str).apply(preprocess_text)

malicious_data['text'] = malicious_data['text'].apply(light_clean)
feature_data = malicious_data['text'].apply(extract_features).apply(pd.Series)


vectorizer = TfidfVectorizer(max_features=7500)  
X = vectorizer.fit_transform(mail_data['clean_text'])
y = mail_data['label']  

vectorizer2 = TfidfVectorizer(max_features=5000, stop_words='english')
X_malicious_text = vectorizer2.fit_transform(malicious_data['text'])
y_malicious = malicious_data['label'] 
X_malicious_combined = hstack([X_malicious_text, feature_data])

# Como ahora no necesitamos comprobar el buen funcionamiento del modelo, no es necesario dividir el conjunto de datos en train y test.
#X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
#X_malicious_train, X_malicious_test, y_malicious_train, y_malicious_test = train_test_split(X_malicious_combined, y_malicious, test_size=0.2, random_state=42, stratify=y_malicious)

# Entrenamos el modelo con el conjunto de datos completo
model = XGBClassifier(eval_metric='mlogloss')
model.fit(X, y)

malicious_model = XGBClassifier(eval_metric='mlogloss')
malicious_model.fit(X_malicious_combined, y_malicious)

# Guardar el modelo
joblib.dump(model, model1_path)
joblib.dump(malicious_model, model2_path)

# Guardae el vectorizador
joblib.dump(vectorizer, vectorizer_path)
joblib.dump(vectorizer2, vectorizer2_path)