import csv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle
import os

def train_phishing_model(csv_path="dataset.csv"):
    print("Loading dataset...")
    X = []
    y = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('text') and row.get('label'):
                    X.append(row['text'])
                    y.append(int(row['label']))
    except FileNotFoundError:
        print(f"Error: Could not find {csv_path}")
        return

    if not X:
        print("Dataset is empty or incorrectly formatted.")
        return

    # 1. Split the dataset into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 2. Convert text to features (TF-IDF)
    print("Converting text to TF-IDF features...")
    vectorizer = TfidfVectorizer(max_features=1000) # Use top 1000 words
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 3. Train model (Logistic Regression)
    print("Training Logistic Regression model...")
    model = LogisticRegression()
    model.fit(X_train_vec, y_train)

    # 4. Evaluate accuracy
    print("Evaluating model...")
    y_pred = model.predict(X_test_vec)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

    # 5. Save model and vectorizer using pickle
    print("Saving model and vectorizer...")
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
    
    with open('vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)

    print("✅ Model successfully saved as 'model.pkl' and 'vectorizer.pkl'")

    # -- BONUS: Retraining documentation --
    print("\n💡 Tip: To retrain this model later, just add more rows to 'dataset.csv'")
    print("and run this script again: python train_model.py")

if __name__ == "__main__":
    # Ensure dataset exists before training
    if not os.path.exists("dataset.csv"):
        print("Please create 'dataset.csv' first with 'text' and 'label' columns.")
    else:
        train_phishing_model()
