import os
import pickle

# Global variables so that the model and vectorizer are initialized ONCE
model = None
vectorizer = None

def load_ml_model():
    """Loads the model and vectorizer into memory."""
    global model, vectorizer
    
    # Define absolute paths based on this file's location
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'model.pkl')
    vec_path = os.path.join(base_dir, 'vectorizer.pkl')

    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        with open(vec_path, 'rb') as f:
            vectorizer = pickle.load(f)
        print("✅ ML Model and Vectorizer loaded successfully.")
    except FileNotFoundError:
        print("⚠️ Warning: model.pkl or vectorizer.pkl not found. Please run train_model.py.")
        model = None
        vectorizer = None

# Initialize immediately when this file is imported by app.py
load_ml_model()

def predict_phishing(text: str) -> float:
    """
    Takes input text and predicts phishing probability using the trained ML model.
    Returns:
        probability (float): 0.0 to 1.0 score.
    """
    # Error handling: Empty input
    if not text:
        return 0.0

    # Error handling: Model not loaded
    if model is None or vectorizer is None:
        return 0.0
    
    try:
        # Transform the single text input into TF-IDF vector format
        # vectorizer.transform expects a list/iterable
        text_vec = vectorizer.transform([text])
        
        # predict_proba returns an array, e.g. [[safe_prob, phishing_prob]]
        # We index [0][1] to get the phishing_prob
        probability = model.predict_proba(text_vec)[0][1]
        
        return round(float(probability), 2)
    except Exception as e:
        print(f"Error during ML prediction: {e}")
        return 0.0
