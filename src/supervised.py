import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

from src.config import MODELS_DIR


class SupervisedIntrusionClassifiers:
    """
    Supervised Intrusion Detection Models:
    1. Random Forest (Binary & Multi-class)
    2. XGBoost (Binary & Multi-class)
    Features feature importance ranking, probability estimation, and persistence.
    """
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.label_encoder = LabelEncoder()
        
        # Binary Classifiers
        self.rf_binary = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            random_state=random_state,
            n_jobs=-1
        )
        self.xgb_binary = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=random_state,
            n_jobs=-1,
            eval_metric='logloss'
        )
        
        # Multi-class Classifiers (5 classes: Normal, DoS, Probe, R2L, U2R)
        self.rf_multiclass = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            random_state=random_state,
            n_jobs=-1
        )
        self.xgb_multiclass = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=random_state,
            n_jobs=-1,
            eval_metric='mlogloss'
        )
        
        self.feature_names = []
        self.is_fitted = False

    def fit(self, X_train, y_train_cat, y_train_bin, feature_names=None):
        """
        Fits both binary and multi-class supervised models.
        """
        print("[SupervisedClassifiers] Fitting Supervised Models...")
        self.feature_names = feature_names or [f"feat_{i}" for i in range(X_train.shape[1])]
        
        # Fit LabelEncoder on 5 categories
        y_train_cat_enc = self.label_encoder.fit_transform(y_train_cat)
        print(f"  Categories encoded: {list(self.label_encoder.classes_)}")
        
        # 1. Fit Random Forest Binary
        print("  Fitting Random Forest (Binary: Normal vs Attack)...")
        self.rf_binary.fit(X_train, y_train_bin)
        
        # 2. Fit XGBoost Binary
        print("  Fitting XGBoost (Binary: Normal vs Attack)...")
        self.xgb_binary.fit(X_train, y_train_bin)
        
        # 3. Fit Random Forest Multi-class
        print("  Fitting Random Forest (5-Class Attack Categorization)...")
        self.rf_multiclass.fit(X_train, y_train_cat_enc)
        
        # 4. Fit XGBoost Multi-class
        print("  Fitting XGBoost (5-Class Attack Categorization)...")
        self.xgb_multiclass.fit(X_train, y_train_cat_enc)
        
        self.is_fitted = True
        print("[SupervisedClassifiers] All supervised models fitted successfully.")
        return self

    def predict_binary(self, X, model_name='xgboost'):
        """Returns binary predictions (0 = Normal, 1 = Attack) and attack probabilities."""
        if not self.is_fitted:
            raise ValueError("Supervised models must be fitted before prediction.")
            
        model = self.xgb_binary if model_name.lower() == 'xgboost' else self.rf_binary
        preds = model.predict(X)
        probs = model.predict_proba(X)[:, 1]
        return preds, probs

    def predict_multiclass(self, X, model_name='xgboost'):
        """Returns predicted category string (Normal, DoS, Probe, R2L, U2R) and class probabilities."""
        if not self.is_fitted:
            raise ValueError("Supervised models must be fitted before prediction.")
            
        model = self.xgb_multiclass if model_name.lower() == 'xgboost' else self.rf_multiclass
        pred_enc = model.predict(X)
        probs = model.predict_proba(X)
        pred_labels = self.label_encoder.inverse_transform(pred_enc)
        return pred_labels, probs

    def get_feature_importances(self, model_name='rf_binary', top_n=20):
        """Returns a sorted dictionary of top N feature importances."""
        if model_name == 'rf_binary':
            importances = self.rf_binary.feature_importances_
        elif model_name == 'xgb_binary':
            importances = self.xgb_binary.feature_importances_
        else:
            importances = self.rf_multiclass.feature_importances_
            
        indices = np.argsort(importances)[::-1][:top_n]
        return [(self.feature_names[i], float(importances[i])) for i in indices]

    def save(self, filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "supervised_classifiers.joblib"
        joblib.dump(self, filepath)
        print(f"[SupervisedClassifiers] Saved models to {filepath}")

    @staticmethod
    def load(filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "supervised_classifiers.joblib"
        return joblib.load(filepath)
