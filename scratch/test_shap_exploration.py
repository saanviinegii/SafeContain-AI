import os
import joblib
import numpy as np
import pandas as pd
import shap
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.feature_engineering import FeatureEngineer

reg = ModelRegistry()
pipeline, meta = reg.load_model()
prep = pipeline.named_steps["prep"]
clf = pipeline.named_steps["clf"]

fe = FeatureEngineer()
raw_df = fe.extract_raw_features()
features = meta["features"]
X = raw_df[features]

print("X shape:", X.shape)
X_trans = prep.transform(X)
feature_names = prep.get_feature_names_out()
print("X_trans shape:", X_trans.shape)
print("Transformed feature names:", len(feature_names), feature_names[:5])

# Test LinearExplainer
explainer = shap.LinearExplainer(clf, X_trans)
shap_values = explainer(X_trans)
print("SHAP values shape:", shap_values.shape)
print("Base values:", explainer.expected_value)
print("First row SHAP values sum + base:", shap_values.values[0].sum() + explainer.expected_value)
print("First row margin:", clf.decision_function(X_trans[:1]))
