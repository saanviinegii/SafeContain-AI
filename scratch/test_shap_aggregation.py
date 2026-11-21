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

X_trans = prep.transform(X)
feature_names = list(prep.get_feature_names_out())

explainer = shap.LinearExplainer(clf, X_trans)
sv = explainer(X_trans)

# Let's inspect first row (node)
row_0_shap = sv.values[0]
raw_row_0 = X.iloc[0]

# Mapping transformed feature to original feature
mapping = {}
for i, fn in enumerate(feature_names):
    # e.g. 'num__criticality' -> 'criticality', 'cat__node_type_Host' -> 'node_type'
    if fn.startswith("num__"):
        orig = fn.replace("num__", "")
    elif fn.startswith("cat__"):
        parts = fn.replace("cat__", "").split("_")
        # reconstruct original feature name from known features
        orig = None
        for f in features:
            if fn.replace("cat__", "").startswith(f):
                orig = f
                break
        if not orig:
            orig = fn
    else:
        orig = fn
    mapping[i] = (fn, orig)

# Aggregate SHAP by original feature
orig_shap = {f: 0.0 for f in features}
for i, val in enumerate(row_0_shap):
    fn, orig = mapping[i]
    if orig in orig_shap:
        orig_shap[orig] += float(val)

print("Original features SHAP for row 0:")
sorted_orig = sorted(orig_shap.items(), key=lambda x: abs(x[1]), reverse=True)
for feat, sval in sorted_orig[:5]:
    direction = "increases_risk" if sval > 0 else "decreases_risk"
    print(f"  {feat}: raw_val={raw_row_0[feat]}, shap={sval:.4f}, dir={direction}")
