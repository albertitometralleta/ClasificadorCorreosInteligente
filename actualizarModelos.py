import utils
from utils import preprocess_text, extract_features, light_clean
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
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


#https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset/data
phishing_data = pd.read_csv(phishing_path)
#https://www.kaggle.com/datasets/purusinghvi/email-spam-classification-dataset
spam_data = pd.read_csv(spam_path)


phishing_data['text'] = phishing_data['subject'].fillna('') + ' ' + phishing_data['body'].fillna('')
phishing_data = phishing_data.drop(columns=['sender', 'receiver', 'date', 'subject', 'body', 'urls'])
spam_data = spam_data[['label', 'text' ]]
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

print("Modelos y vectorizadores guardados correctamente.")