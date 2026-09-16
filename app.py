import os
import libsql_client
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

TURSO_URL = "https://darksearch-irakliw.aws-eu-west-1.turso.io"
TURSO_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODk2MDExNDUsImlkIjoiMDFhMGFjODQtZWYwMS03YTdiLWI4N2UtNzhlZDlkNDY0Zjc3Iiwia2lkIjoiblJES3oyYllzeWJ4bjNMUXRDdmVlVkdCSldDVEVvbkNubjBJMHNkUEhfRSIsInJpZCI6IjBkODY4MjNlLTIwZmQtNGJhZS1iOGEwLWZjNDhkNDFmZTRiZCJ9.y_Oo4fMmp5sWEDvLvx4hFckwgEByLt0xkdE-sASHkhFSiKAYOWVgbkG1y7U1Z1X574JvVHJcYoEV8OK_sk5mDg"


@app.route("/")
def index():
  return render_template("index.html")


@app.route("/search", methods=["GET"])
def search():
  saxeli = request.args.get("saxeli", "").strip().lower()
  gvari = request.args.get("gvari", "").strip().lower()
  mamis = request.args.get("mamis", "").strip().lower()
  piadi = request.args.get("piadi", "").strip()
  sqesi = request.args.get("sqesi", "").strip()
  dabWeli = request.args.get("dabWeli", "").strip()
  quca = request.args.get("quca", "").strip().lower()

  conditions = []
  params = []

  if saxeli:
    conditions.append("LOWER(data) LIKE ?")
    params.append(f"%saxeli:{saxeli}%")
  if gvari:
    conditions.append("LOWER(data) LIKE ?")
    params.append(f"%gvari:{gvari}%")
  if mamis:
    conditions.append("LOWER(data) LIKE ?")
    params.append(f"%mamis saxeli:{mamis}%")
  if piadi:
    conditions.append("data LIKE ?")
    params.append(f"%piadi:#{piadi}%")
  if sqesi:
    conditions.append("data LIKE ?")
    params.append(f"%sqesi:{sqesi}%")
  if dabWeli:
    conditions.append("data LIKE ?")
    params.append(f"%dab weli:{dabWeli}%")
  if quca:
    conditions.append("LOWER(data) LIKE ?")
    params.append(f"%quca:{quca}%")

  if not conditions:
    return jsonify({"error": "გთხოვთ მიუთითოთ მინიმუმ ერთი საძიებო ველი!"})

  query = (
      "SELECT id, data FROM records WHERE "
      + " AND ".join(conditions)
      + " LIMIT 30"
  )

  try:
    client = libsql_client.create_client_sync(
        url=TURSO_URL, auth_token=TURSO_TOKEN
    )
    result = client.execute(query, params)
    client.close()

    formatted_results = []
    for row in result.rows:
      formatted_results.append({"id": row[0], "info": row[1]})

    return jsonify(formatted_results)
  except Exception as e:
    return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
