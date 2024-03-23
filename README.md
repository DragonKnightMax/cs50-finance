# CS50-Finance

CS50 Finance is a web application that allows users to trade stocks developed for CS50 Final Project. 


## Technology

- Flask
- SQLAlchemy
- IEX Stock API
- Bootstrap


## Features

- Register and login and logout
- Get stock quotes
- Buy and sell stocks
- View portfolio
- View orders
- Change password


## How to use

1. Get your IEX API key and store it inside `.env` file
2. Create virtual environment with `python -m venv .venv`
3. Activate virtual environment with `source .venv/bin/activate`
4. Run `python app.py` and visit `http://127.0.0.1:5000`


## Notes

- Removed CS50 dependency, replace with Flask SQLAlchemy ORM


## Links

- [https://cs50.harvard.edu/x/2020/tracks/web/finance/](https://cs50.harvard.edu/x/2020/tracks/web/finance/)
