# Network Intrusion & Cyber Attack Detection - Evaluation Report

## 1. Overall Binary Detection Comparison

| Model                      |   Accuracy |   Precision |   Recall (Detection Rate) |   F1-Score |   ROC-AUC |   False Alarm Rate (FPR) |   True Positives |   False Positives |   True Negatives |   False Negatives |
|:---------------------------|-----------:|------------:|--------------------------:|-----------:|----------:|-------------------------:|-----------------:|------------------:|-----------------:|------------------:|
| Unsupervised (Euclidean)   |      69.64 |       90.7  |                     51.99 |      66.1  |    0.8995 |                     7.04 |             6672 |               684 |             9027 |              6161 |
| Unsupervised (Mahalanobis) |      68.73 |       90.48 |                     50.37 |      64.71 |    0.8964 |                     7    |             6464 |               680 |             9031 |              6369 |
| Unsupervised (DBSCAN)      |      76.34 |       90.94 |                     64.9  |      75.74 |    0.9179 |                     8.55 |             8328 |               830 |             8881 |              4505 |
| Unsupervised (Hybrid)      |      76.88 |       90.36 |                     66.48 |      76.6  |    0.9004 |                     9.37 |             8531 |               910 |             8801 |              4302 |
| Supervised (Random Forest) |      76.14 |       96.72 |                     60.13 |      74.16 |    0.9632 |                     2.7  |             7717 |               262 |             9449 |              5116 |

## 2. Detection Capability on Novel Attack Signatures (Zero-Day Attacks)

Comparison of detection recall between Known Attacks (seen during training) and Novel Attacks (unseen attack types in NSL-KDD test set):

| Model                    |   Known Attack Recall |   Novel Attack Recall (Zero-Day) |   Overall Attack Recall |
|:-------------------------|----------------------:|---------------------------------:|------------------------:|
| Euclidean                |                 53.79 |                            47.63 |                   51.99 |
| Mahalanobis              |                 52.86 |                            44.35 |                   50.37 |
| Hybrid (K-Means+Maha+DB) |                 66.88 |                            65.49 |                   66.48 |
| Random Forest            |                 75.37 |                            23.23 |                   60.13 |

### Detailed Breakdown Per Novel Attack Signature

| Attack Name   | Category   |   Samples |   Euclidean Det % |   Mahalanobis Det % |   Hybrid (K-Means+Maha+DB) Det % |   Random Forest Det % |
|:--------------|:-----------|----------:|------------------:|--------------------:|---------------------------------:|----------------------:|
| apache2       | DoS        |       737 |              69.9 |                66.2 |                             87.9 |                  20.5 |
| httptunnel    | R2L        |       133 |              21.1 |                18   |                             72.9 |                  10.5 |
| mailbomb      | DoS        |       293 |               1   |                 7.2 |                             14.3 |                   0   |
| mscan         | Probe      |       996 |              69.1 |                69   |                             82.8 |                  38.3 |
| named         | R2L        |        17 |              41.2 |                41.2 |                             52.9 |                   5.9 |
| processtable  | DoS        |       685 |              28.6 |                12.6 |                             69.3 |                   1.3 |
| ps            | U2R        |        15 |              40   |                40   |                             66.7 |                   6.7 |
| saint         | Probe      |       319 |              93.7 |                93.7 |                             95.3 |                  97.5 |
| sendmail      | R2L        |        14 |              78.6 |                78.6 |                             78.6 |                   0   |
| snmpgetattack | R2L        |       178 |               5.1 |                 5.1 |                              5.6 |                   0   |
| snmpguess     | R2L        |       331 |               0.3 |                 0.6 |                              0.3 |                   0   |
| sqlattack     | U2R        |         2 |             100   |               100   |                            100   |                   0   |
| udpstorm      | DoS        |         2 |               0   |                 0   |                              0   |                 100   |
| worm          | R2L        |         2 |               0   |                 0   |                              0   |                   0   |
| xlock         | R2L        |         9 |              88.9 |                88.9 |                            100   |                   0   |
| xsnoop        | R2L        |         4 |              75   |                75   |                             75   |                   0   |
| xterm         | U2R        |        13 |              76.9 |                76.9 |                             76.9 |                   7.7 |

## 3. Supervised 5-Class Categorization (Random Forest)

|              |   precision |     recall |   f1-score |      support |
|:-------------|------------:|-----------:|-----------:|-------------:|
| DoS          |    0.961628 | 0.776213   | 0.85903    |  7458        |
| Normal       |    0.643756 | 0.974153   | 0.775219   |  9711        |
| Probe        |    0.821625 | 0.61834    | 0.705633   |  2421        |
| R2L          |    1        | 0.00207828 | 0.00414794 |  2887        |
| U2R          |    1        | 0.0149254  | 0.0294118  |    67        |
| accuracy     |    0.743125 | 0.743125   | 0.743125   |     0.743125 |
| macro avg    |    0.885402 | 0.477142   | 0.474688   | 22544        |
| weighted avg |    0.814695 | 0.743125   | 0.694512   | 22544        |
