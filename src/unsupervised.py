import numpy as np
import joblib
from pathlib import Path
from sklearn.cluster import MiniBatchKMeans, DBSCAN
from sklearn.decomposition import PCA
from sklearn.covariance import LedoitWolf
from sklearn.neighbors import NearestNeighbors
from scipy.spatial.distance import cdist

from src.config import MODELS_DIR


from typing import Optional

class UnsupervisedAnomalyDetector:
    """
    Hybrid Unsupervised Intrusion Detection System combining:
    1. K-Means clustering to model normal traffic centroids
    2. Mahalanobis distance metric (covariance-aware) via PCA + Ledoit-Wolf
    3. Euclidean distance metric (geometric distance to normal clusters)
    4. DBSCAN topological density estimation for boundary/noise isolation
    5. Calibrated Anomaly Score (0 - 100) and threshold-based classification
    """
    def __init__(self, n_clusters=12, pca_variance=0.95, dbscan_eps=2.0, dbscan_min_samples=10, random_state=42):
        self.n_clusters = n_clusters
        self.pca_variance = pca_variance
        self.dbscan_eps = dbscan_eps
        self.dbscan_min_samples = dbscan_min_samples
        self.random_state = random_state
        
        self.pca = PCA(n_components=pca_variance, random_state=random_state)
        self.kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=random_state, batch_size=2048, n_init='auto')
        self.cov_estimator = LedoitWolf()
        self.nn_core: Optional[NearestNeighbors] = None
        
        self.centroids_: Optional[np.ndarray] = None
        self.inv_cov_: Optional[np.ndarray] = None
        self.core_samples_: Optional[np.ndarray] = None
        
        # Normalization scale factors
        self.norm_scale_euc = 1.0
        self.norm_scale_mah = 1.0
        
        # Calibrated threshold percentiles from normal baseline
        self.thresh_euc_95: Optional[float] = None
        self.thresh_mah_95: Optional[float] = None
        self.thresh_hybrid_95: Optional[float] = None
        
        self.is_fitted = False

    def fit(self, X_normal, dbscan_sample_size=8000):
        """
        Fits baseline normal profile on normal traffic connections.
        Args:
            X_normal: feature matrix of known normal connections
            dbscan_sample_size: subsample size for fitting DBSCAN core points
        """
        print(f"[UnsupervisedDetector] Fitting baseline on {len(X_normal)} normal samples...")
        
        # 1. Fit PCA for dimensionality reduction and covariance regularization
        X_pca = self.pca.fit_transform(X_normal)
        n_comps = self.pca.n_components_
        print(f"  PCA reduced features to {n_comps} components (variance: {self.pca_variance:.0%})")
        
        # 2. Fit K-Means on normal clusters
        self.kmeans.fit(X_pca)
        self.centroids_ = self.kmeans.cluster_centers_
        print(f"  K-Means fitted with {self.n_clusters} clusters")
        
        # 3. Fit regularized covariance matrix for Mahalanobis metric
        self.cov_estimator.fit(X_pca)
        self.inv_cov_ = np.linalg.pinv(self.cov_estimator.covariance_)
        print(f"  Ledoit-Wolf covariance inverted successfully")
        
        # 4. Fit DBSCAN on representative sample to extract dense core prototypes
        if len(X_pca) > dbscan_sample_size:
            rng = np.random.RandomState(self.random_state)
            sample_idx = rng.choice(len(X_pca), size=dbscan_sample_size, replace=False)
            X_db_sample = X_pca[sample_idx]
        else:
            X_db_sample = X_pca
            
        db = DBSCAN(eps=self.dbscan_eps, min_samples=self.dbscan_min_samples).fit(X_db_sample)
        if len(db.core_sample_indices_) > 0:
            self.core_samples_ = X_db_sample[db.core_sample_indices_]
            self.nn_core = NearestNeighbors(n_neighbors=1, algorithm='ball_tree').fit(self.core_samples_)
            print(f"  DBSCAN fitted: {len(self.core_samples_)} core normal prototypes found")
        else:
            # Fallback to centroids if no core samples found
            self.core_samples_ = self.centroids_
            self.nn_core = NearestNeighbors(n_neighbors=1, algorithm='ball_tree').fit(self.core_samples_)
            print(f"  DBSCAN fallback: using {len(self.core_samples_)} centroids as core prototypes")
            
        # 5. Calibrate baseline distance percentiles on normal training data
        dist_euc_norm = cdist(X_pca, self.centroids_, metric='euclidean').min(axis=1)
        dist_mah_norm = cdist(X_pca, self.centroids_, metric='mahalanobis', VI=self.inv_cov_).min(axis=1)
        
        self.thresh_euc_95 = float(np.percentile(dist_euc_norm, 95))
        self.thresh_mah_95 = float(np.percentile(dist_mah_norm, 95))
        
        # Normalization scale factors (using 99th percentile to cap scaling)
        self.norm_scale_euc = float(np.percentile(dist_euc_norm, 99))
        self.norm_scale_mah = float(np.percentile(dist_mah_norm, 99))
        
        scores_norm = self._compute_scores_from_dists(dist_euc_norm, dist_mah_norm, np.zeros_like(dist_euc_norm))
        self.thresh_hybrid_95 = float(np.percentile(scores_norm, 95))
        
        print(f"  Calibrated 95th percentile thresholds (Normal FPR ~ 5%):")
        print(f"    Euclidean threshold:   {self.thresh_euc_95:.3f}")
        print(f"    Mahalanobis threshold: {self.thresh_mah_95:.3f}")
        print(f"    Hybrid score threshold: {self.thresh_hybrid_95:.2f} / 100")
        
        self.is_fitted = True
        return self

    def _compute_scores_from_dists(self, dist_euc, dist_mah, db_outlier):
        """Converts raw distance metrics into a calibrated 0-100 Anomaly Score."""
        # Scaled relative distances
        s_euc = np.clip((dist_euc / (self.norm_scale_euc + 1e-6)) * 40.0, 0, 50.0)
        s_mah = np.clip((dist_mah / (self.norm_scale_mah + 1e-6)) * 40.0, 0, 50.0)
        s_db = db_outlier * 10.0
        
        # Weighted combination: 45% Mahalanobis, 45% Euclidean, 10% DBSCAN density
        anomaly_score = s_mah * 0.45 + s_euc * 0.45 + s_db
        return np.clip(anomaly_score, 0.0, 100.0)

    def predict_distances(self, X):
        """
        Computes all unsupervised distance metrics for incoming traffic:
        - Euclidean distance to closest normal centroid
        - Mahalanobis distance to closest normal centroid
        - DBSCAN core neighbor distance & density outlier flag
        """
        if (
            not self.is_fitted 
            or self.centroids_ is None 
            or self.inv_cov_ is None 
            or self.nn_core is None
        ):
            raise ValueError("Detector must be fitted before computing distances.")
            
        X_pca = self.pca.transform(X)
        
        # 1. Euclidean distance
        dist_euc = cdist(X_pca, self.centroids_, metric='euclidean').min(axis=1)
        
        # 2. Mahalanobis distance
        dist_mah = cdist(X_pca, self.centroids_, metric='mahalanobis', VI=self.inv_cov_).min(axis=1)
        
        # 3. DBSCAN core distance and outlier
        core_dists, _ = self.nn_core.kneighbors(X_pca)
        core_dists = core_dists.ravel()
        db_outlier = (core_dists > self.dbscan_eps).astype(int)
        
        # 4. Unified Anomaly Score (0 - 100)
        anomaly_scores = self._compute_scores_from_dists(dist_euc, dist_mah, db_outlier)
        
        return {
            'dist_euclidean': dist_euc,
            'dist_mahalanobis': dist_mah,
            'dist_dbscan_core': core_dists,
            'dbscan_outlier': db_outlier,
            'anomaly_score': anomaly_scores
        }

    def predict(self, X, metric: str = 'hybrid', threshold: Optional[float] = None) -> np.ndarray:
        """
        Predicts whether connections are Normal (0) or Anomalous (1).
        metric options: 'hybrid', 'mahalanobis', 'euclidean', 'dbscan'
        """
        dists = self.predict_distances(X)
        
        if metric == 'hybrid':
            th = self.thresh_hybrid_95 if threshold is None else threshold
            if th is None:
                raise ValueError("Hybrid threshold is not calibrated. Fit the detector first or provide a threshold.")
            return (dists['anomaly_score'] >= float(th)).astype(int)
        elif metric == 'mahalanobis':
            th = self.thresh_mah_95 if threshold is None else threshold
            if th is None:
                raise ValueError("Mahalanobis threshold is not calibrated. Fit the detector first or provide a threshold.")
            return (dists['dist_mahalanobis'] >= float(th)).astype(int)
        elif metric == 'euclidean':
            th = self.thresh_euc_95 if threshold is None else threshold
            if th is None:
                raise ValueError("Euclidean threshold is not calibrated. Fit the detector first or provide a threshold.")
            return (dists['dist_euclidean'] >= float(th)).astype(int)
        elif metric == 'dbscan':
            return dists['dbscan_outlier']
        else:
            raise ValueError(f"Unknown metric: {metric}")

    def save(self, filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "unsupervised_detector.joblib"
        joblib.dump(self, filepath)
        print(f"[UnsupervisedDetector] Saved model to {filepath}")

    @staticmethod
    def load(filepath=None):
        if filepath is None:
            filepath = MODELS_DIR / "unsupervised_detector.joblib"
        return joblib.load(filepath)
