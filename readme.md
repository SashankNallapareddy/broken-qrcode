Install

Clone
Make virtual environment: python3 -m venv venv
Activate virtual environment: source venv/bin/activate
Install requirements: pip install -r requirements.txt
IMPORTANT run: mkdir qr_codes to create a qr codes directory to save in, permissions will be messed up and the docker container won't be able to write to the qr_codes directory if you don't.
Note: make sure docker is started
run pytest locally to check that it works locally
Start the app with docker compose up --build
Goto http://localhost/docs to view openapi spec documentation
Click "authorize" input username: admin password: secret
Test making, retrieving, and deleting QR codes on the spec page.
