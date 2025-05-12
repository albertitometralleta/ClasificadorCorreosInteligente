import tkinter as tk
from tkinter import filedialog
import email
from email import policy
import joblib
import re
import string
import nltk
from nltk.corpus import stopwords
from bs4 import BeautifulSoup
from scipy.sparse import hstack
from langdetect import detect
from deep_translator import GoogleTranslator
import os
import pandas as pd
import subprocess
from tkinter import messagebox

# Cargar stopwords
nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

# Rutas de los modelos y vectorizadores
ruta_modelo1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo1.pkl")
ruta_modelo2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo2.pkl")
ruta_vectorizer = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectorizer.pkl")
ruta_vectorizer2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectorizer2.pkl")

phishing_keywords = [
    "account", "password", "verify", "login", "update", "security",
    "credentials", "unauthorized", "suspended", "compromised", "alert", "reset",
    "urgent", "immediately", "action required", "important", "now",
    "verify immediately", "failure", "final warning", "attention", "limited time",
    "response needed", "winner", "congratulations", "free", "bonus", "refund",
    "claim", "reward", "lottery", "prize", "gift card", "cash", "click here",
    "download", "open attachment", "access", "view", "see details", "login link",
    "check now", "follow the link", "paypal", "apple", "amazon", "bank",
    "netflix", "support", "help desk", "it department", "administrator", "system", "cnn"
]

def traducir_a_ingles(texto):
    idioma = detect(texto)
    return GoogleTranslator(source='auto', target='en').translate(texto) if idioma != 'en' else texto

def limpiar_html(texto):
    return re.sub(r'[^a-zA-Z\s]', '', BeautifulSoup(texto, "html.parser").get_text())

def eliminar_stopwords(texto):
    return " ".join([word for word in texto.split() if word not in stop_words])

def preprocess_text(text):
    text = limpiar_html(text).lower()
    text = re.sub(r"http\S+|\S+@\S+|\d+", "", text)
    text = text.translate(str.maketrans('', '', string.punctuation)).strip()
    return eliminar_stopwords(text)

def light_clean(text):
    return re.sub(r'\s+', ' ', text).strip().lower() if isinstance(text, str) else ''

def extract_features(text):
    text_lower = text.lower()
    return {
        'num_links': len(re.findall(r'http[s]?://|www\\.|bit\\.ly|tinyurl|chk\\.me', text_lower)),
        'has_form': int(bool(re.search(r'<form|input type=', text_lower))),
        'has_attachment': int('.zip' in text_lower or '.exe' in text_lower or 'attachment' in text_lower),
        'text_length': len(text),
        'num_phishing_keywords': sum(1 for kw in phishing_keywords if kw in text_lower),
    }

def extract_body(msg):
    def get_charset(part):
        charset = part.get_content_charset()
        if charset is None:
            charset = part.get_charset()
        return charset or 'utf-8'

    def extract_text_from_part(part):
        try:
            charset = get_charset(part)
            return part.get_payload(decode=True).decode(charset, errors='ignore')
        except Exception:
            return ''

    if msg.is_multipart():
        text = ''
        html = ''
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                text += extract_text_from_part(part)
            elif content_type == "text/html":
                html += extract_text_from_part(part)

        return text.strip() if text.strip() else BeautifulSoup(html, "html.parser").get_text()
    else:
        content_type = msg.get_content_type()
        payload = extract_text_from_part(msg)

        if content_type == "text/plain":
            return payload
        elif content_type == "text/html":
            return BeautifulSoup(payload, "html.parser").get_text()
        else:
            return ""

def cargar_archivo_eml():
    archivo_eml = filedialog.askopenfilename(filetypes=[("Archivos EML", "*.eml")])
    if archivo_eml:
        with open(archivo_eml, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f, policy=policy.default)
        subject = msg['subject']
        from_ = msg['from']
        body = extract_body(msg)
        label_subject.config(text="Asunto: " + subject)
        label_from.config(text="De: " + from_)
        text_body.delete(1.0, tk.END)
        text_body.insert(tk.END, str(body))
        classify_email(body)

def classify_email(text):
    text = traducir_a_ingles(text)
    clean = preprocess_text(text)
    model = joblib.load(ruta_modelo1)
    malicious_model = joblib.load(ruta_modelo2)
    vectorizer = joblib.load(ruta_vectorizer)
    vectorizer2 = joblib.load(ruta_vectorizer2)

    X = vectorizer.transform([clean])
    probabilities = model.predict_proba(X)[0]
    spam_prob = probabilities[1]
    ham_prob = probabilities[0]

    draw_bar(canvas_main, ham_prob, spam_prob, ["Ham", "Spam"], show_secondary=False)

    if spam_prob > 0.5:
        clean2 = light_clean(text)
        features = list(extract_features(clean2).values())
        X_mal = vectorizer2.transform([clean2])
        full_features = hstack([X_mal, features])
        phishing_probs = malicious_model.predict_proba(full_features)[0]
        draw_bar(canvas_secondary, phishing_probs[0], phishing_probs[1], ["Spam inofensivo", "Phishing"], show_secondary=True)

    if spam_prob < 0.5:
        mostrar_confirmacion("Ham")
    elif spam_prob > 0.5 and phishing_probs[1] < 0.5:
        mostrar_confirmacion("Spam")
    else:
        mostrar_confirmacion("Phishing")

def draw_bar(canvas, left_prob, right_prob, labels, show_secondary=True):
    canvas.delete("all")
    width = int(canvas['width'])
    height = int(canvas['height'])
    center = width // 2

    left_len = int(center * left_prob)
    right_len = int(center * right_prob)

    canvas.create_rectangle(center - left_len, 5, center, height - 5, fill="green", outline="")
    canvas.create_rectangle(center, 5, center + right_len, height - 5, fill="red", outline="")

    canvas.create_text(center, height // 2, text=f" {left_prob*100:.1f}% / {right_prob*100:.1f}%", font=("Arial", 10))

    if show_secondary:
        frame_secondary_bar.pack(pady=(0, 10))
    else:
        frame_secondary_bar.pack_forget()

# Crear la ventana principal
window = tk.Tk()
window.title("Clasificador de Correos Inteligente")
window.geometry("650x700")

tk.Button(window, text="Cargar Archivo EML", command=cargar_archivo_eml).pack(pady=10)
label_subject = tk.Label(window, text="Asunto:", font=("Arial", 12))
label_subject.pack()
label_from = tk.Label(window, text="De:", font=("Arial", 12))
label_from.pack()

text_body = tk.Text(window, height=10, width=70)
text_body.pack(pady=10)

# Frame de la barra principal
frame_main_bar = tk.Frame(window)
frame_main_bar.pack(pady=(10, 5))

label_left_main = tk.Label(frame_main_bar, text="Ham", fg="green", font=("Arial", 10, "bold"))
label_left_main.pack(side="left", padx=(0, 5))

canvas_main = tk.Canvas(frame_main_bar, width=400, height=30, bg="white", highlightthickness=1, highlightbackground="gray")
canvas_main.pack(side="left")

label_right_main = tk.Label(frame_main_bar, text="No Ham", fg="red", font=("Arial", 10, "bold"))
label_right_main.pack(side="left", padx=(5, 0))

# Frame de la barra secundaria (oculta por defecto)
frame_secondary_bar = tk.Frame(window)

label_left_secondary = tk.Label(frame_secondary_bar, text="Spam", fg="green", font=("Arial", 10, "bold"))
label_left_secondary.pack(side="left", padx=(0, 5))

canvas_secondary = tk.Canvas(frame_secondary_bar, width=400, height=30, bg="white", highlightthickness=1, highlightbackground="gray")
canvas_secondary.pack(side="left")

label_right_secondary = tk.Label(frame_secondary_bar, text="Phishing", fg="red", font=("Arial", 10, "bold"))
label_right_secondary.pack(side="left", padx=(5, 0))

# Frame general de feedback (MOVIDO DEBAJO DE TODO)
frame_feedback_total = tk.Frame(window)
frame_feedback_total.pack(side="bottom", pady=(10, 5))

resultado_label = tk.Label(frame_feedback_total, text="", font=("Arial", 12, "italic"))
resultado_label.pack()

frame_feedback = tk.Frame(frame_feedback_total)
frame_feedback.pack(pady=5)

btn_si = tk.Button(frame_feedback, text="Sí", width=10, command=lambda: respuesta_correcta())
btn_no = tk.Button(frame_feedback, text="No", width=10, command=lambda: mostrar_correccion())

# Frame para corrección
frame_correccion = tk.Frame(frame_feedback_total)
btn_ham = tk.Button(frame_correccion, text="Ham", width=10, command=lambda: corregir("Ham"))
btn_spam = tk.Button(frame_correccion, text="Spam", width=10, command=lambda: corregir("Spam"))
btn_phishing = tk.Button(frame_correccion, text="Phishing", width=10, command=lambda: corregir("Phishing"))

for btn in (btn_ham, btn_spam, btn_phishing):
    btn.pack(side="left", padx=5)

def mostrar_confirmacion(pred):
    resultado_label.config(text=f"Resultado de la predicción: {pred}")
    frame_feedback.pack()
    btn_si.pack(side="left", padx=10)
    btn_no.pack(side="left", padx=10)
    frame_correccion.pack_forget()

def respuesta_correcta():
    btn_si.pack_forget()
    btn_no.pack_forget()
    frame_feedback.pack_forget()
    frame_correccion.pack_forget()
    resultado_label.config(text="¡Gracias por su confirmación!")

def mostrar_correccion():
    btn_si.pack_forget()
    btn_no.pack_forget()
    frame_feedback.pack_forget()
    resultado_label.config(text="¿Qué tipo de mail es realmente?")
    frame_correccion.pack()

def corregir(tipo):
    body = text_body.get("1.0", tk.END).strip()
    if tipo == "Ham":
        guardar_correo(body, 0, 'combined_data.csv')
    elif tipo == "Spam":
        guardar_correo(body, 1, 'combined_data.csv')
    elif tipo == "Phishing":
        guardar_correo(body, 1, 'CEAS_08.csv')
    frame_correccion.pack_forget()
    resultado_label.config(text=f"Gracias por su colaboración.")

def guardar_correo(body, label, dataset):
    body_traducido = traducir_a_ingles(body)
    texto_limpio = light_clean(body_traducido)

    if dataset == 'combined_data.csv':
        nuevo_dato = pd.DataFrame({'text': [texto_limpio], 'label': [label]})
    elif dataset == 'CEAS_08.csv':
        nuevo_dato = pd.DataFrame({'text': [texto_limpio], 'label': [1]})
    else:
        return
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), dataset)
    if os.path.exists(ruta):
        df = pd.read_csv(ruta)
        df = pd.concat([df, nuevo_dato], ignore_index=True)
    else:
        df = nuevo_dato
    df.to_csv(ruta, index=False)

def al_cerrar():
    # Muestra la ventana emergente de espera
    popup = tk.Toplevel()
    popup.title("Actualizando")
    popup.geometry("300x100")
    tk.Label(popup, text="Espere un momento, actualizando las bases de datos...").pack(pady=20)
    popup.update()

    # Ejecuta el script externo y espera a que termine
    try:
        
        subprocess.run(["python", "actualizarModelos.py"], check=True)
    except Exception as e:
        messagebox.showerror("Error", f"Hubo un problema al actualizar:\n{e}")
    finally:
        popup.destroy()
        window.destroy()

# Asociar la función al evento de cierre de ventana
window.protocol("WM_DELETE_WINDOW", al_cerrar)

window.mainloop()