import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import GridSearchCV

def load_dataset():
    data = np.load('attack_dataset.npz')
    return data['X_train'], data['X_test'], data['y_train'], data['y_test']

def train_model(X_train, y_train):

    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'bootstrap': [True, False]
    }
    

    rf = RandomForestClassifier(random_state=42, class_weight='balanced')
    
    grid_search = GridSearchCV(
        estimator=rf,
        param_grid=param_grid,
        cv=3,
        n_jobs=-1,
        verbose=2
    )
    
    print("Starting grid search...")
    grid_search.fit(X_train, y_train)
    
    print("Best parameters found:")
    print(grid_search.best_params_)
    
    return grid_search.best_estimator_

def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    
    print("Model Evaluation:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

def save_model(model):
    joblib.dump(model, 'eboli.pkl')
    print("Model saved as eboli.pkl")

def main():
    print("Loading dataset...")
    X_train, X_test, y_train, y_test = load_dataset()
    
    print("Training model...")
    model = train_model(X_train, y_train)
    
    print("Evaluating model...")
    evaluate_model(model, X_test, y_test)
    
    print("Saving model...")
    save_model(model)

if __name__ == "__main__":
    main()
