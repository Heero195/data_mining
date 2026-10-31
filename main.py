import argparse
import sys
import numpy as np
import pandas as pd

from src.preprocess import get_preprocessed_data, NetworkDataPreprocessor
from src.unsupervised import UnsupervisedAnomalyDetector
from src.supervised import SupervisedIntrusionClassifiers
from src.evaluate import Evaluator
from src.visualize import Visualizer
from src.wazuh_integration.replay_to_wazuh import run_traffic_replay
from src.config import MODELS_DIR, PLOTS_DIR, REPORTS_DIR


def train_pipeline():
    """Trains both unsupervised and supervised intrusion detection models."""
    print("\n=======================================================")
    print("      STAGE 1: PREPROCESSING & TRAINING PIPELINE      ")
    print("=======================================================")
    
    # 1. Preprocessing
    X_train, y_train_cat, y_train_bin, df_train, X_test, y_test_cat, y_test_bin, df_test, preprocessor = get_preprocessed_data()
    
    # 2. Train Unsupervised Anomaly Detector (fit baseline normal profile)
    print("\n[Step 2/3] Training Unsupervised Anomaly Detector (K-Means + Mahalanobis + DBSCAN)...")
    mask_normal = (y_train_bin == 0)
    X_normal_train = X_train[mask_normal]
    
    unsup_detector = UnsupervisedAnomalyDetector(
        n_clusters=12,
        pca_variance=0.95,
        dbscan_eps=2.0,
        dbscan_min_samples=10,
        random_state=42
    )
    unsup_detector.fit(X_normal_train)
    unsup_detector.save()
    
    # 3. Train Supervised Classifiers (Random Forest & XGBoost)
    print("\n[Step 3/3] Training Supervised Classifiers (Random Forest & XGBoost)...")
    sup_classifiers = SupervisedIntrusionClassifiers(random_state=42)
    sup_classifiers.fit(X_train, y_train_cat, y_train_bin, feature_names=preprocessor.feature_names)
    sup_classifiers.save()
    
    print("\n>>> All models trained and saved to:", MODELS_DIR)
    return preprocessor, unsup_detector, sup_classifiers


def eval_pipeline():
    """Evaluates all models, compares performance, tests novel attacks, and produces plots."""
    print("\n=======================================================")
    print("      STAGE 2: EVALUATION & VISUALIZATION PIPELINE    ")
    print("=======================================================")
    
    # Load components
    preprocessor = NetworkDataPreprocessor.load()
    unsup_detector = UnsupervisedAnomalyDetector.load()
    sup_classifiers = SupervisedIntrusionClassifiers.load()
    
    # Load test data
    from src.config import TEST_DATA_PATH
    df_test = preprocessor.load_dataset(TEST_DATA_PATH)
    X_test = preprocessor.transform(df_test)
    y_test_bin = df_test['is_attack'].values
    y_test_cat = df_test['attack_cat'].values
    
    # Evaluation
    evaluator = Evaluator(unsup_detector, sup_classifiers, preprocessor)
    df_binary, df_novel_sum, df_novel_detail, multiclass_res, models_data = evaluator.generate_full_report(X_test, df_test)
    
    print("\n" + "="*60)
    print("1. OVERALL BINARY COMPARISON:")
    print("="*60)
    print(df_binary.to_string(index=False))
    
    print("\n" + "="*60)
    print("2. NOVEL ATTACK SIGNATURE (ZERO-DAY) RECALL:")
    print("="*60)
    print(df_novel_sum.to_string(index=False))
    
    # Visualization
    print("\nGenerating evaluation charts and plots...")
    viz = Visualizer(output_dir=PLOTS_DIR)
    
    # 1. ROC Curves
    viz.plot_roc_curves(y_test_bin, models_data)
    
    # 2. Novel Attack Detection Bar Chart
    viz.plot_novel_attack_detection(df_novel_detail)
    
    # 3. Distance & Anomaly Score Distributions
    dists = unsup_detector.predict_distances(X_test)
    viz.plot_distance_distributions(df_test, dists)
    
    # 4. Feature Importance
    feat_imps = sup_classifiers.get_feature_importances(model_name='rf_binary', top_n=15)
    viz.plot_feature_importance(feat_imps)
    
    # 5. Confusion Matrices
    viz.plot_confusion_matrices(
        multiclass_res['rf_cm'],
        multiclass_res['xgb_cm'],
        multiclass_res['categories']
    )
    
    print("\n>>> All plots saved to:", PLOTS_DIR)
    print(">>> All reports saved to:", REPORTS_DIR)


def main():
    parser = argparse.ArgumentParser(description="Network Intrusion & Cyber Attack Detection Pipeline")
    parser.add_argument("--train", action="store_true", help="Train unsupervised and supervised models")
    parser.add_argument("--eval", action="store_true", help="Run comparative evaluation and generate visualizations")
    parser.add_argument("--novel-eval", action="store_true", help="Run dedicated novel attack signature evaluation")
    parser.add_argument("--wazuh-demo", action="store_true", help="Run simulated traffic replay to Wazuh Homelab")
    parser.add_argument("--all", action="store_true", help="Execute complete pipeline (train, eval, wazuh demo)")
    
    args = parser.parse_args()
    
    # If no flags provided, default to --all
    if not (args.train or args.eval or args.novel_eval or args.wazuh_demo or args.all):
        args.all = True
        
    if args.train or args.all:
        train_pipeline()
        
    if args.eval or args.all:
        eval_pipeline()
        
    if args.wazuh_demo or args.all:
        run_traffic_replay(count=12, delay=0.1)


if __name__ == "__main__":
    main()
