# Network Intrusion & Cyber Attack Detection - Evaluation Report

## 1. Overall Binary Detection Comparison

| Model                      |   Accuracy |   Precision |   Recall (Detection Rate) |   F1-Score |   ROC-AUC |   False Alarm Rate (FPR) |   True Positives |   False Positives |   True Negatives |   False Negatives |
|:---------------------------|-----------:|------------:|--------------------------:|-----------:|----------:|-------------------------:|-----------------:|------------------:|-----------------:|------------------:|
| Unsupervised (Euclidean)   |      69.59 |       90.69 |                     51.91 |      66.03 |    0.8995 |                     7.04 |             6662 |               684 |             9027 |              6171 |
| Unsupervised (Mahalanobis) |      68.68 |       90.47 |                     50.28 |      64.63 |    0.8964 |                     7    |             6452 |               680 |             9031 |              6381 |
| Unsupervised (DBSCAN)      |      68.03 |       97.34 |                     45.07 |      61.61 |    0.9476 |                     1.63 |             5784 |               158 |             9553 |              7049 |
| Unsupervised (Hybrid)      |      71.79 |       91.03 |                     55.97 |      69.31 |    0.9099 |                     7.29 |             7182 |               708 |             9003 |              5651 |
| Supervised (Random Forest) |      79.05 |       97.02 |                     65.19 |      77.98 |    0.9669 |                     2.65 |             8366 |               257 |             9454 |              4467 |
| Supervised (XGBoost)       |      79.86 |       96.95 |                     66.72 |      79.04 |    0.9656 |                     2.77 |             8562 |               269 |             9442 |              4271 |

## 2. Detection Capability on Novel Attack Signatures (Zero-Day Attacks)

Comparison of detection recall between Known Attacks (seen during training) and Novel Attacks (unseen attack types in NSL-KDD test set):

| Model                    |   Known Attack Recall |   Novel Attack Recall (Zero-Day) |   Overall Attack Recall |
|:-------------------------|----------------------:|---------------------------------:|------------------------:|
| Euclidean                |                 53.66 |                            47.68 |                   51.91 |
| Mahalanobis              |                 52.72 |                            44.35 |                   50.28 |
| Hybrid (K-Means+Maha+DB) |                 55.19 |                            57.84 |                   55.97 |
| Random Forest            |                 76.47 |                            37.87 |                   65.19 |
| XGBoost                  |                 78.27 |                            38.75 |                   66.72 |

### Detailed Breakdown Per Novel Attack Signature

| Attack Name   | Category   |   Samples |   Euclidean Det % |   Mahalanobis Det % |   Hybrid (K-Means+Maha+DB) Det % |   Random Forest Det % |   XGBoost Det % |
|:--------------|:-----------|----------:|------------------:|--------------------:|---------------------------------:|----------------------:|----------------:|
| apache2       | DoS        |       737 |              69.9 |                66.2 |                             70.4 |                  72.2 |            75.7 |
| httptunnel    | R2L        |       133 |              21.1 |                18   |                             20.3 |                   7.5 |             5.3 |
| mailbomb      | DoS        |       293 |               1   |                 7.2 |                              8.9 |                   0   |             0   |
| mscan         | Probe      |       996 |              69.2 |                69   |                             76.5 |                  54.4 |            39.3 |
| named         | R2L        |        17 |              41.2 |                41.2 |                             47.1 |                  11.8 |            17.6 |
| processtable  | DoS        |       685 |              28.8 |                12.6 |                             69.3 |                   1.9 |            24.4 |
| ps            | U2R        |        15 |              40   |                40   |                             60   |                  13.3 |            20   |
| saint         | Probe      |       319 |              93.7 |                93.7 |                             93.7 |                  98.4 |            99.7 |
| sendmail      | R2L        |        14 |              78.6 |                78.6 |                             78.6 |                   0   |             0   |
| snmpgetattack | R2L        |       178 |               5.1 |                 5.1 |                              5.1 |                   0   |             0   |
| snmpguess     | R2L        |       331 |               0.3 |                 0.6 |                              0.3 |                   0   |             0   |
| sqlattack     | U2R        |         2 |             100   |               100   |                            100   |                   0   |             0   |
| udpstorm      | DoS        |         2 |               0   |                 0   |                              0   |                 100   |           100   |
| worm          | R2L        |         2 |               0   |                 0   |                              0   |                   0   |             0   |
| xlock         | R2L        |         9 |              88.9 |                88.9 |                             88.9 |                   0   |             0   |
| xsnoop        | R2L        |         4 |              75   |                75   |                             75   |                  25   |            25   |
| xterm         | U2R        |        13 |              76.9 |                76.9 |                             76.9 |                  15.4 |            23.1 |

## 3. Supervised 5-Class Categorization (XGBoost)

|              |   precision |    recall |   f1-score |      support |
|:-------------|------------:|----------:|-----------:|-------------:|
| DoS          |    0.963872 | 0.837088  |  0.896017  |  7458        |
| Normal       |    0.678947 | 0.971682  |  0.799356  |  9711        |
| Probe        |    0.804078 | 0.667906  |  0.729693  |  2421        |
| R2L          |    0.993243 | 0.0509179 |  0.0968699 |  2887        |
| U2R          |    0.7      | 0.104478  |  0.181818  |    67        |
| accuracy     |    0.774042 | 0.774042  |  0.774042  |     0.774042 |
| macro avg    |    0.828028 | 0.526414  |  0.540751  | 22544        |
| weighted avg |    0.826955 | 0.774042  |  0.732056  | 22544        |
