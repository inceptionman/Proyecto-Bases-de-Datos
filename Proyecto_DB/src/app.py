from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")

def hola_mundo():
    return "Hola Mundo!!"

@app.route("/about")
def hola_mundo_elegante():
    return """
        <html>
            <body>
                <h1>Saludos!!<h1>
                <p>Hola Mundo!!</p>
            </body>
        </html>
        """
@app.route("/elegante")
def template_elegante():
    return render_template("elegante.html")

if __name__ == "__main__":
    app.run()