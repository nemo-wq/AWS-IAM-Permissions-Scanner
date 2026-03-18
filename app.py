from flask import Flask, render_template, request

from scanner import IAMScanner

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    profile = ""

    if request.method == "POST":
        profile = request.form.get("profile", "").strip()
        try:
            scanner = IAMScanner(profile=profile or None)
            report = scanner.scan()
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

    return render_template("index.html", report=report, error=error, profile=profile)


if __name__ == "__main__":
    app.run(debug=True)
