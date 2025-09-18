"""Train a simple RandomForest model from a CSV of features.

CSV must contain feature columns (matching detector.domain_features keys) and a 'label' column (0/1).
"""
from __future__ import annotations

import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('csv')
    parser.add_argument('--out', default='model.joblib')
    args = parser.parse_args(argv)

    df = pd.read_csv(args.csv)
    if 'label' not in df.columns:
        raise SystemExit('CSV must include a label column')

    X = df.drop(columns=['label'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    print(classification_report(y_test, preds))
    joblib.dump(clf, args.out)
    print('Saved model to', args.out)


if __name__ == '__main__':
    main()
