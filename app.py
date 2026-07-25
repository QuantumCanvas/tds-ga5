"""
Proration calculator endpoint.

Supports two versioned business rules, selected by the `spec` field:

  spec == "v1" (legacy):
      charge = (new_price - old_price) * (days_remaining / 30)
      The divisor is ALWAYS 30, regardless of the real month length.
      This is the historical rule and must be preserved for old
      invoices / audit / reconciliation.

  spec == "v2" (corrected):
      charge = (new_price - old_price) * (days_remaining / days_in_actual_month)
      Uses the true number of days in the billing month (28/29/30/31).

POST /prorate
Request body:
  {
    "old_price": number,
    "new_price": number,
    "days_remaining": number,
    "days_in_actual_month": number,
    "spec": "v1" | "v2"
  }

Response body:
  { "charge": number }
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_SPECS = {"v1", "v2"}


def compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec):
    price_delta = new_price - old_price

    if spec == "v1":
        # Legacy rule: fixed 30-day divisor, no matter the real month length.
        divisor = 30
    elif spec == "v2":
        # Corrected rule: use the actual number of days in the billing month.
        divisor = days_in_actual_month
    else:
        raise ValueError(f"Unknown spec '{spec}', expected one of {sorted(VALID_SPECS)}")

    if divisor == 0:
        raise ValueError("divisor (days in month) cannot be zero")

    return price_delta * (days_remaining / divisor)


@app.route("/prorate", methods=["POST"])
def prorate():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    required_fields = ["old_price", "new_price", "days_remaining", "days_in_actual_month", "spec"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        return jsonify({"error": f"Missing field(s): {', '.join(missing)}"}), 400

    spec = body["spec"]
    if spec not in VALID_SPECS:
        return jsonify({"error": f"spec must be one of {sorted(VALID_SPECS)}"}), 400

    try:
        old_price = float(body["old_price"])
        new_price = float(body["new_price"])
        days_remaining = float(body["days_remaining"])
        days_in_actual_month = float(body["days_in_actual_month"])
    except (TypeError, ValueError):
        return jsonify({"error": "old_price, new_price, days_remaining, days_in_actual_month must be numbers"}), 400

    try:
        charge = compute_charge(old_price, new_price, days_remaining, days_in_actual_month, spec)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"charge": charge})


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Bind to 0.0.0.0 so it's reachable when deployed behind a host/port mapping.
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
