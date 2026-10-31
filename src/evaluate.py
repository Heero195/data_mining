import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from src.config import REPORTS_DIR, NOVEL_ATTACKS


class Evaluator:
    """
    Evaluation Engine for Network Intrusion Detection:
    1. Comprehensive binary comparison (Unsupervised vs Supervised)
    2. Multi-class attack categorization performance
    3. Deep-dive evaluation on Novel Attack Signatures (Zero-Day attacks)
    4. Generates structured Markdown and JSON reports
    """
    def __init__(self, unsupervised_detector, supervised_classifiers, preprocessor):
        self.unsup = unsupervised_detector
        self.sup = supervised_classifiers
        self.prep = preprocessor

    def evaluate_binary_all(self, X_test, y_test_bin):
        """
        Evaluates and compares:
        - Euclidean Distance
        - Mahalanobis Distance
        - DBSCAN Core Outlier
        - Hybrid Unsupervised Detector
        - Random Forest (Binary)
        - XGBoost (Binary)
        """
        print("[Evaluator] Computing binary anomaly detection metrics...")
        
        # Unsupervised predictions & raw scores
        dists = self.unsup.predict_distances(X_test)
        pred_euc = self.unsup.predict(X_test, metric='euclidean')
        pred_mah = self.unsup.predict(X_test, metric='mahalanobis')
        pred_db = self.unsup.predict(X_test, metric='dbscan')
        pred_hybrid = self.unsup.predict(X_test, metric='hybrid')
        
        score_euc = dists['dist_euclidean']
        score_mah = dists['dist_mahalanobis']
        score_hybrid = dists['anomaly_score'] / 100.0
        
        # Supervised predictions & probabilities
        pred_rf, prob_rf = self.sup.predict_binary(X_test, model_name='rf')
        pred_xgb, prob_xgb = self.sup.predict_binary(X_test, model_name='xgboost')
        
        models = {
            'Unsupervised (Euclidean)': {'pred': pred_euc, 'score': score_euc},
            'Unsupervised (Mahalanobis)': {'pred': pred_mah, 'score': score_mah},
            'Unsupervised (DBSCAN)': {'pred': pred_db, 'score': dists['dist_dbscan_core']},
            'Unsupervised (Hybrid)': {'pred': pred_hybrid, 'score': score_hybrid},
            'Supervised (Random Forest)': {'pred': pred_rf, 'score': prob_rf},
            'Supervised (XGBoost)': {'pred': pred_xgb, 'score': prob_xgb}
        }
        
        results = []
        for name, data in models.items():
            pred = data['pred']
            score = data['score']
            
            acc = accuracy_score(y_test_bin, pred)
            prec = precision_score(y_test_bin, pred, zero_division=0)
            rec = recall_score(y_test_bin, pred, zero_division=0)
            f1 = f1_score(y_test_bin, pred, zero_division=0)
            
            try:
                auc = roc_auc_score(y_test_bin, score)
            except Exception:
                auc = float('nan')
                
            tn, fp, fn, tp = confusion_matrix(y_test_bin, pred).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            
            results.append({
                'Model': name,
                'Accuracy': round(acc * 100, 2),
                'Precision': round(prec * 100, 2),
                'Recall (Detection Rate)': round(rec * 100, 2),
                'F1-Score': round(f1 * 100, 2),
                'ROC-AUC': round(auc, 4),
                'False Alarm Rate (FPR)': round(fpr * 100, 2),
                'True Positives': int(tp),
                'False Positives': int(fp),
                'True Negatives': int(tn),
                'False Negatives': int(fn)
            })
            
        df_results = pd.DataFrame(results)
        return df_results, models

    def evaluate_novel_attacks(self, X_test, df_test):
        """
        Critical Evaluation: Evaluates detection capability specifically on:
        1. Known Attacks (in training set)
        2. Novel Attacks (unseen attack types in training set)
        3. Breakdown across every individual novel attack signature
        """
        print("[Evaluator] Evaluating detection capability on novel attack signatures...")
        
        y_test_bin = df_test['is_attack'].values
        is_novel = df_test['is_novel'].values
        labels = df_test['label'].values
        
        # Predictions
        pred_euc = self.unsup.predict(X_test, metric='euclidean')
        pred_mah = self.unsup.predict(X_test, metric='mahalanobis')
        pred_hybrid = self.unsup.predict(X_test, metric='hybrid')
        pred_rf, _ = self.sup.predict_binary(X_test, model_name='rf')
        pred_xgb, _ = self.sup.predict_binary(X_test, model_name='xgboost')
        
        preds_dict = {
            'Euclidean': pred_euc,
            'Mahalanobis': pred_mah,
            'Hybrid (K-Means+Maha+DB)': pred_hybrid,
            'Random Forest': pred_rf,
            'XGBoost': pred_xgb
        }
        
        # 1. Summary comparison: Known vs Novel
        mask_known = (y_test_bin == 1) & (is_novel == 0)
        mask_novel = (y_test_bin == 1) & (is_novel == 1)
        
        summary_rows = []
        for name, p in preds_dict.items():
            known_recall = recall_score(y_test_bin[mask_known], p[mask_known], zero_division=0)
            novel_recall = recall_score(y_test_bin[mask_novel], p[mask_novel], zero_division=0)
            overall_recall = recall_score(y_test_bin[y_test_bin == 1], p[y_test_bin == 1], zero_division=0)
            
            summary_rows.append({
                'Model': name,
                'Known Attack Recall': round(known_recall * 100, 2),
                'Novel Attack Recall (Zero-Day)': round(novel_recall * 100, 2),
                'Overall Attack Recall': round(overall_recall * 100, 2)
            })
            
        df_summary = pd.DataFrame(summary_rows)
        
        # 2. Detailed Breakdown per Novel Attack Type
        novel_breakdown = []
        novel_names = sorted(list(NOVEL_ATTACKS))
        
        for att in novel_names:
            mask_att = (labels == att)
            count = mask_att.sum()
            if count == 0:
                continue
                
            row = {'Attack Name': att, 'Category': df_test[mask_att]['attack_cat'].iloc[0], 'Samples': int(count)}
            for name, p in preds_dict.items():
                detected = p[mask_att].sum()
                rate = (detected / count) * 100.0
                row[f"{name} Det %"] = round(rate, 1)
            novel_breakdown.append(row)
            
        df_breakdown = pd.DataFrame(novel_breakdown)
        return df_summary, df_breakdown

    def evaluate_multiclass(self, X_test, y_test_cat):
        """Evaluates supervised 5-class attack classification (Normal, DoS, Probe, R2L, U2R)."""
        print("[Evaluator] Evaluating supervised 5-class classification...")
        
        rf_preds, _ = self.sup.predict_multiclass(X_test, model_name='rf')
        xgb_preds, _ = self.sup.predict_multiclass(X_test, model_name='xgboost')
        
        cats = sorted(list(set(y_test_cat)))
        
        rep_rf = classification_report(y_test_cat, rf_preds, labels=cats, output_dict=True, zero_division=0)
        rep_xgb = classification_report(y_test_cat, xgb_preds, labels=cats, output_dict=True, zero_division=0)
        
        cm_rf = confusion_matrix(y_test_cat, rf_preds, labels=cats)
        cm_xgb = confusion_matrix(y_test_cat, xgb_preds, labels=cats)
        
        return {
            'categories': cats,
            'rf_report': rep_rf,
            'xgb_report': rep_xgb,
            'rf_cm': cm_rf.tolist(),
            'xgb_cm': cm_xgb.tolist()
        }

    def generate_full_report(self, X_test, df_test):
        """Runs all evaluations and writes markdown and JSON reports to disk."""
        y_test_bin = df_test['is_attack'].values
        y_test_cat = df_test['attack_cat'].values
        
        df_binary, models_data = self.evaluate_binary_all(X_test, y_test_bin)
        df_novel_sum, df_novel_detail = self.evaluate_novel_attacks(X_test, df_test)
        multiclass_res = self.evaluate_multiclass(X_test, y_test_cat)
        
        # Save JSON
        json_path = REPORTS_DIR / "evaluation_metrics.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'binary_comparison': df_binary.to_dict(orient='records'),
                'novel_attack_summary': df_novel_sum.to_dict(orient='records'),
                'novel_attack_breakdown': df_novel_detail.to_dict(orient='records'),
                'multiclass': multiclass_res
            }, f, indent=2)
            
        def df_to_md(df, index=False):
            try:
                return df.to_markdown(index=index)
            except Exception:
                return df.to_string(index=index)

        # Save Markdown Report
        md_path = REPORTS_DIR / "evaluation_report.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# Network Intrusion & Cyber Attack Detection - Evaluation Report\n\n")
            f.write("## 1. Overall Binary Detection Comparison\n\n")
            f.write(df_to_md(df_binary, index=False))
            f.write("\n\n## 2. Detection Capability on Novel Attack Signatures (Zero-Day Attacks)\n\n")
            f.write("Comparison of detection recall between Known Attacks (seen during training) and Novel Attacks (unseen attack types in NSL-KDD test set):\n\n")
            f.write(df_to_md(df_novel_sum, index=False))
            f.write("\n\n### Detailed Breakdown Per Novel Attack Signature\n\n")
            f.write(df_to_md(df_novel_detail, index=False))
            f.write("\n\n## 3. Supervised 5-Class Categorization (XGBoost)\n\n")
            xgb_rep_df = pd.DataFrame(multiclass_res['xgb_report']).transpose()
            f.write(df_to_md(xgb_rep_df, index=True))
            f.write("\n")
            
        print(f"[Evaluator] Reports saved to:\n  - {json_path}\n  - {md_path}")
        return df_binary, df_novel_sum, df_novel_detail, multiclass_res, models_data
