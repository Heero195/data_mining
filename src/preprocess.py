import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler
import joblib
from pathlib import Path

from src.config import (
    TRAIN_DATA_PATH,
    TEST_DATA_PATH,
    TEST21_DATA_PATH,
    COLUMN_NAMES,
    CATEGORICAL_FEATURES,
    BINARY_FEATURES,
    CONTINUOUS_FEATURES,
    SKEWED_FEATURES,
    ATTACK_CATEGORIES,
    NOVEL_ATTACKS,
    MODELS_DIR
)


class NetworkDataPreprocessor:
    """
    Handles preprocessing of network traffic connections:
    - Log transformation on skewed flow stats (duration, src_bytes, dst_bytes)
    - One-hot encoding of protocol, service, and connection flags
    - Standard scaling for continuous packet stats
    - Attack category and novel-attack label extraction
    """
    def __init__(self, scaler_type='standard'):
        self.scaler_type = scaler_type
        self.encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        self.scaler = StandardScaler()
        self.feature_names = []
        self.num_cols = CONTINUOUS_FEATURES + BINARY_FEATURES
        self.cat_cols = CATEGORICAL_FEATURES
        self.is_fitted = False

    def load_dataset(self, file_path):
        """Loads NSL-KDD raw txt file into DataFrame with correct schema."""
        df = pd.read_csv(file_path, names=COLUMN_NAMES, header=None)
        
        # Strip potential whitespaces
        for col in self.cat_cols:
            df[col] = df[col].astype(str).str.strip()
        df['label'] = df['label'].astype(str).str.strip().str.lower()
        
        # Add 5-class category
        df['attack_cat'] = df['label'].map(lambda x: ATTACK_CATEGORIES.get(x, 'Unknown'))
        
        # Add Binary label (0 = Normal, 1 = Attack)
        df['is_attack'] = (df['label'] != 'normal').astype(int)
        
        # Add Novel attack flag
        df['is_novel'] = df['label'].isin(NOVEL_ATTACKS).astype(int)
        
        return df

    def _transform_skewed(self, df):
        """Applies log1p transform to heavy-tailed byte and duration features."""
        df_copy = df.copy()
        for col in SKEWED_FEATURES:
            if col in df_copy.columns:
                df_copy[col] = np.log1p(np.maximum(0, df_copy[col].astype(float)))
        return df_copy

    def fit(self, df_train):
        """Fits encoders and scalers on the training set."""
        df_skewed = self._transform_skewed(df_train)
        
        # Fit OneHotEncoder on categorical features
        self.encoder.fit(df_skewed[self.cat_cols])
        encoded_cat_names = list(self.encoder.get_feature_names_out(self.cat_cols))
        
        # Fit Scaler on numeric features
        self.scaler.fit(df_skewed[self.num_cols])
        
        self.feature_names = self.num_cols + encoded_cat_names
        self.is_fitted = True
        return self

    def transform(self, df):
        """Transforms input network data into feature matrix X."""
        if not self.is_fitted:
            raise ValueError("Preprocessor has not been fitted yet!")
            
        df_skewed = self._transform_skewed(df)
        
        # Scale numeric features
        num_scaled = self.scaler.transform(df_skewed[self.num_cols])
        
        # Encode categorical features
        cat_encoded = self.encoder.transform(df_skewed[self.cat_cols])
        
        # Concatenate
        X = np.hstack([num_scaled, cat_encoded])
        return X

    def fit_transform(self, df_train):
        self.fit(df_train)
        return self.transform(df_train)

    def save(self, filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "preprocessor.joblib"
        joblib.dump(self, filepath)
        print(f"[Preprocessor] Saved to {filepath}")

    @staticmethod
    def load(filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "preprocessor.joblib"
        return joblib.load(filepath)


def get_preprocessed_data(use_test21=False):
    """
    Convenience function to load and preprocess train and test sets.
    Returns:
        X_train, y_train_cat, y_train_bin, df_train,
        X_test, y_test_cat, y_test_bin, df_test,
        preprocessor
    """
    preprocessor = NetworkDataPreprocessor()
    
    print(f"Loading training data from {TRAIN_DATA_PATH}...")
    df_train = preprocessor.load_dataset(TRAIN_DATA_PATH)
    
    test_file = TEST21_DATA_PATH if use_test21 else TEST_DATA_PATH
    print(f"Loading test data from {test_file}...")
    df_test = preprocessor.load_dataset(test_file)
    
    print("Fitting preprocessor and transforming data...")
    X_train = preprocessor.fit_transform(df_train)
    X_test = preprocessor.transform(df_test)
    
    y_train_cat = df_train['attack_cat'].values
    y_train_bin = df_train['is_attack'].values
    
    y_test_cat = df_test['attack_cat'].values
    y_test_bin = df_test['is_attack'].values
    
    print(f"Dataset summary:")
    print(f"  X_train shape: {X_train.shape} | Attack ratio: {y_train_bin.mean():.2%}")
    print(f"  X_test shape:  {X_test.shape}  | Attack ratio: {y_test_bin.mean():.2%}")
    print(f"  Novel attack samples in test: {df_test['is_novel'].sum()} ({df_test['is_novel'].mean():.2%})")
    
    preprocessor.save()
    return X_train, y_train_cat, y_train_bin, df_train, X_test, y_test_cat, y_test_bin, df_test, preprocessor


if __name__ == "__main__":
    X_tr, y_tr_c, y_tr_b, df_tr, X_te, y_te_c, y_te_b, df_te, prep = get_preprocessed_data()
    print("Preprocessor test passed successfully.")
