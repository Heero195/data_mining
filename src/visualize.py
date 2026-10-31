import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, auc, confusion_matrix
from pathlib import Path

from src.config import PLOTS_DIR

# Set aesthetic styling
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams.update({'font.sans-serif': 'DejaVu Sans', 'font.size': 11})


class Visualizer:
    """
    Generates publication-quality charts for Intrusion Detection:
    - ROC Curves (Unsupervised vs Supervised)
    - Novel Attack Detection Rates per signature
    - Distance Metric Distributions (Normal vs Known vs Novel)
    - Supervised Feature Importance
    - Confusion Matrices
    """
    def __init__(self, output_dir=PLOTS_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def plot_roc_curves(self, y_true, models_data, filename="roc_curves.png"):
        """Plots ROC curves comparing unsupervised distance metrics and supervised models."""
        plt.figure(figsize=(9, 7))
        
        palette = {
            'Unsupervised (Euclidean)': '#e67e22',
            'Unsupervised (Mahalanobis)': '#9b59b6',
            'Unsupervised (Hybrid)': '#e74c3c',
            'Supervised (Random Forest)': '#2980b9',
            'Supervised (XGBoost)': '#27ae60'
        }
        
        for name, data in models_data.items():
            if name == 'Unsupervised (DBSCAN)':
                continue  # DBSCAN produces binary core flag, skip in continuous ROC
            score = data['score']
            fpr, tpr, _ = roc_curve(y_true, score)
            roc_auc = auc(fpr, tpr)
            color = palette.get(name, '#34495e')
            ls = '--' if 'Unsupervised' in name else '-'
            plt.plot(fpr, tpr, color=color, linestyle=ls, linewidth=2.2, label=f"{name} (AUC = {roc_auc:.3f})")

        plt.plot([0, 1], [0, 1], color='#7f8c8d', linestyle=':', label='Random Guess (AUC = 0.50)')
        plt.xlim(-0.01, 1.0)
        plt.ylim(0.0, 1.02)
        plt.xlabel("False Positive Rate (False Alarm Rate)", fontweight='bold')
        plt.ylabel("True Positive Rate (Detection Recall)", fontweight='bold')
        plt.title("ROC Curve: Unsupervised Anomaly Metrics vs Supervised Models", fontsize=13, fontweight='bold', pad=15)
        plt.legend(loc="lower right", frameon=True, facecolor='white', framealpha=0.9)
        plt.tight_layout()
        
        out_path = self.output_dir / filename
        plt.savefig(out_path, dpi=300)
        plt.close()
        print(f"[Visualizer] Saved ROC curves to {out_path}")

    def plot_novel_attack_detection(self, df_novel_detail, filename="novel_attacks_detection_rate.png"):
        """Plots a grouped bar chart of detection rate per novel attack type."""
        df_melt = pd.melt(
            df_novel_detail,
            id_vars=['Attack Name', 'Category', 'Samples'],
            value_vars=['Hybrid (K-Means+Maha+DB) Det %', 'XGBoost Det %', 'Random Forest Det %'],
            var_name='Model',
            value_name='Detection Rate (%)'
        )
        df_melt['Model'] = df_melt['Model'].str.replace(' Det %', '')

        plt.figure(figsize=(14, 7))
        ax = sns.barplot(
            data=df_melt,
            x='Attack Name',
            y='Detection Rate (%)',
            hue='Model',
            palette={'Hybrid (K-Means+Maha+DB)': '#e74c3c', 'XGBoost': '#27ae60', 'Random Forest': '#2980b9'}
        )
        
        plt.title("Detection Recall on 17 Novel Attack Signatures (Zero-Day Benchmark)", fontsize=14, fontweight='bold', pad=15)
        plt.xlabel("Novel Attack Signature (Unseen in Training Data)", fontweight='bold')
        plt.ylabel("Detection Rate / Recall (%)", fontweight='bold')
        plt.ylim(0, 105)
        plt.xticks(rotation=45, ha='right')
        plt.axhline(100, color='gray', linestyle=':', alpha=0.6)
        plt.legend(title="Detection Engine", frameon=True, facecolor='white')
        plt.tight_layout()
        
        out_path = self.output_dir / filename
        plt.savefig(out_path, dpi=300)
        plt.close()
        print(f"[Visualizer] Saved novel attack detection rates to {out_path}")

    def plot_distance_distributions(self, df_test, dists, filename="distance_distribution.png"):
        """Plots Mahalanobis and Euclidean distance distributions across traffic types."""
        fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
        
        types = []
        for _, row in df_test.iterrows():
            if row['is_attack'] == 0:
                types.append('Normal')
            elif row['is_novel'] == 1:
                types.append('Novel Attack (Zero-Day)')
            else:
                types.append('Known Attack')
                
        plot_df = pd.DataFrame({
            'Traffic Type': types,
            'Euclidean Distance': dists['dist_euclidean'],
            'Mahalanobis Distance': dists['dist_mahalanobis'],
            'Anomaly Score': dists['anomaly_score']
        })
        
        colors = {'Normal': '#2ecc71', 'Known Attack': '#e67e22', 'Novel Attack (Zero-Day)': '#e74c3c'}
        
        # 1. Mahalanobis distance distribution
        sns.kdeplot(
            data=plot_df,
            x='Mahalanobis Distance',
            hue='Traffic Type',
            palette=colors,
            common_norm=False,
            fill=True,
            alpha=0.3,
            ax=axes[0],
            clip=(0, 20)
        )
        axes[0].set_title("Mahalanobis Distance Distribution to Normal Centroids", fontweight='bold')
        axes[0].set_xlim(0, 15)
        
        # 2. Unified Anomaly Score
        sns.kdeplot(
            data=plot_df,
            x='Anomaly Score',
            hue='Traffic Type',
            palette=colors,
            common_norm=False,
            fill=True,
            alpha=0.3,
            ax=axes[1],
            clip=(0, 100)
        )
        axes[1].set_title("Calibrated Anomaly Score Distribution (0 - 100)", fontweight='bold')
        axes[1].set_xlim(0, 100)
        
        plt.tight_layout()
        out_path = self.output_dir / filename
        plt.savefig(out_path, dpi=300)
        plt.close()
        print(f"[Visualizer] Saved distance distributions to {out_path}")

    def plot_feature_importance(self, feature_importances, filename="feature_importance.png"):
        """Plots top feature importances for intrusion detection."""
        feats, scores = zip(*feature_importances)
        df_imp = pd.DataFrame({'Feature': feats, 'Importance': scores})
        
        plt.figure(figsize=(10, 6))
        ax = sns.barplot(data=df_imp, y='Feature', x='Importance', hue='Feature', palette='crest')
        if ax.get_legend() is not None:
            ax.get_legend().remove()
        plt.title("Top 15 Most Important Features for Network Intrusion Detection", fontsize=13, fontweight='bold', pad=15)
        plt.xlabel("Feature Importance Score (Random Forest)", fontweight='bold')
        plt.ylabel("Traffic Feature", fontweight='bold')
        plt.tight_layout()
        
        out_path = self.output_dir / filename
        plt.savefig(out_path, dpi=300)
        plt.close()
        print(f"[Visualizer] Saved feature importances to {out_path}")

    def plot_confusion_matrices(self, cm_rf, cm_xgb, categories, filename="confusion_matrices.png"):
        """Plots multi-class confusion matrices for Random Forest and XGBoost."""
        fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
        
        sns.heatmap(cm_rf, annot=True, fmt='d', cmap='Blues', xticklabels=categories, yticklabels=categories, ax=axes[0])
        axes[0].set_title("Random Forest - 5-Class Confusion Matrix", fontweight='bold')
        axes[0].set_xlabel("Predicted Category")
        axes[0].set_ylabel("True Category")
        
        sns.heatmap(cm_xgb, annot=True, fmt='d', cmap='Greens', xticklabels=categories, yticklabels=categories, ax=axes[1])
        axes[1].set_title("XGBoost - 5-Class Confusion Matrix", fontweight='bold')
        axes[1].set_xlabel("Predicted Category")
        axes[1].set_ylabel("True Category")
        
        plt.tight_layout()
        out_path = self.output_dir / filename
        plt.savefig(out_path, dpi=300)
        plt.close()
        print(f"[Visualizer] Saved confusion matrices to {out_path}")
