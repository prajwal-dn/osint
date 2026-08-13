"""
Entity Resolution Engine
=========================
Resolves whether two digital-footprint records (e.g. "raj_kumar_92" on
Platform A and "R. Kumar" on Platform B) belong to the SAME real person.

Outputs a MATCH CONFIDENCE SCORE (0-1) -- this is intentionally NOT a
"risk score" on the individual. It only measures identity-match certainty,
which keeps the tool's ML output legally/ethically defensible under India's
DPDP Act framing (see project notes).

Training/validation uses the FEBRL4 benchmark dataset (Christen, 2008) --
a real, peer-reviewed, publicly licensed record-linkage benchmark with
ground-truth duplicate labels. This gives us a genuine, reportable
accuracy number instead of a self-graded synthetic test.
"""

import pandas as pd
import numpy as np
import recordlinkage
from recordlinkage.datasets import load_febrl4
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score
import xgboost as xgb
import joblib
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "entity_resolution_model.joblib")


def build_feature_vectors(dfA, dfB, candidate_pairs):
    """
    Turn a pair of candidate records into a numeric feature vector describing
    how similar they are. This is the core signal the classifier learns from.
    """
    compare = recordlinkage.Compare()

    # String similarity on identity fields
    compare.string("given_name", "given_name", method="jarowinkler", label="given_name_sim")
    compare.string("surname", "surname", method="jarowinkler", label="surname_sim")
    compare.string("street_number", "street_number", method="jarowinkler", label="street_sim")
    compare.string("suburb", "suburb", method="jarowinkler", label="suburb_sim")
    compare.string("state", "state", method="jarowinkler", label="state_sim")
    compare.exact("date_of_birth", "date_of_birth", label="dob_exact")
    compare.exact("postcode", "postcode", label="postcode_exact")
    compare.string("soc_sec_id", "soc_sec_id", method="jarowinkler", label="id_sim")

    features = compare.compute(candidate_pairs, dfA, dfB)
    return features


def train():
    print("[1/5] Loading FEBRL4 benchmark dataset (real, public, ground-truth labeled)...")
    dfA, dfB, true_links = load_febrl4(return_links=True)

    print("[2/5] Generating candidate pairs (blocking on surname to keep this tractable)...")
    indexer = recordlinkage.Index()
    indexer.block("surname")
    candidate_pairs = indexer.index(dfA, dfB)
    print(f"      {len(candidate_pairs):,} candidate pairs generated")

    print("[3/5] Computing similarity feature vectors...")
    X = build_feature_vectors(dfA, dfB, candidate_pairs)
    y = X.index.isin(true_links).astype(int)
    print(f"      {y.sum():,} true matches / {len(y):,} total pairs")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    print("[4/5] Training XGBoost classifier...")
    clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    precision = precision_score(y_test, preds)
    recall = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)

    print("[5/5] Validation results (on held-out FEBRL test split):")
    print(f"      Precision: {precision:.4f}")
    print(f"      Recall:    {recall:.4f}")
    print(f"      F1 score:  {f1:.4f}")

    joblib.dump({"model": clf, "feature_columns": list(X.columns)}, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

    return {"precision": precision, "recall": recall, "f1": f1, "n_train": len(X_train), "n_test": len(X_test)}


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not trained yet. Run train() first.")
    return joblib.load(MODEL_PATH)


def score_pair(record_a: dict, record_b: dict) -> float:
    """
    Given two persona records (dicts with keys matching FEBRL schema:
    given_name, surname, street_number, suburb, state, date_of_birth,
    postcode, soc_sec_id), return a match-confidence score between 0 and 1.

    This is what the backend API calls when comparing two profiles found
    across different data sources for the same investigation.
    """
    bundle = load_model()
    clf, feature_columns = bundle["model"], bundle["feature_columns"]

    dfA = pd.DataFrame([record_a]).set_index(pd.Index(["a"]))
    dfB = pd.DataFrame([record_b]).set_index(pd.Index(["b"]))

    compare = recordlinkage.Compare()
    compare.string("given_name", "given_name", method="jarowinkler", label="given_name_sim")
    compare.string("surname", "surname", method="jarowinkler", label="surname_sim")
    compare.string("street_number", "street_number", method="jarowinkler", label="street_sim")
    compare.string("suburb", "suburb", method="jarowinkler", label="suburb_sim")
    compare.string("state", "state", method="jarowinkler", label="state_sim")
    compare.exact("date_of_birth", "date_of_birth", label="dob_exact")
    compare.exact("postcode", "postcode", label="postcode_exact")
    compare.string("soc_sec_id", "soc_sec_id", method="jarowinkler", label="id_sim")

    pairs = pd.MultiIndex.from_tuples([("a", "b")])
    X = compare.compute(pairs, dfA, dfB)
    X = X[feature_columns]

    proba = clf.predict_proba(X)[0][1]
    features_dict = X.iloc[0].to_dict()
    return float(proba), features_dict


if __name__ == "__main__":
    metrics = train()
    print("\n--- Summary for your hackathon slide ---")
    print(f"Entity resolution model validated on FEBRL public benchmark: "
          f"F1={metrics['f1']:.3f}, Precision={metrics['precision']:.3f}, Recall={metrics['recall']:.3f}")
