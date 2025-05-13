# Clasificador Inteligente de Correos (Spam / Phishing / Ham)

Proyecto realizado y presentado para formar parte del concurso **Desafío Tecnológico en Ciberseguridad CiberUGR, 2025**

---

Este proyecto es una aplicación de escritorio en Python con interfaz gráfica (Tkinter) que permite **clasificar correos electrónicos** `.eml` en tres categorías:
- 🟢 **Ham** (mails legítimos)
- 🟡 **Spam** (publicidad/mails molestos)
- 🔴 **Phishing** (mails con contenido/intencion maliciosa)

La clasificación se realiza en dos etapas usando modelos de Machine Learning entrenados previamente.

---

## Características
- Clasificación automática de correos usando modelos `XGBClassifier`.
- Traducción automática si el correo está en otro idioma diferente a nuestra BBDD.
- Visualización de resultados en la interfaz mediante barras gráficas.
- Detección de patrones phishing basados en palabras clave y características estructurales.
- Feedback del usuario con opción de corrección y aprendizaje continuo.

---

## Requisitos
- Windows 10/11
- Python 3.12 o superior
- Requiere conexión a internet para traducción y actualización  (deep-translator y nltk.downloader stopwords)

---

## Instalación
1. Clonar repositorio 
2. Comprobar los `requisitos`previos
3. SI ES LA PRIMERA VEZ --> Ejecutar: `configureAndStart.bat`
	SI NO LO ES         --> Ejecutar: `start.bat`
