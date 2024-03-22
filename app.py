from decimal import Decimal
import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func
import sshtunnel
from helpers import apology, login_required, lookup, usd

from dotenv import load_dotenv
load_dotenv()

# Configure application
app = Flask(__name__)

# SSH Tunnel to PythonAnywhere
# sshtunnel.SSH_TIMEOUT = 5.0
# sshtunnel.TUNNEL_TIMEOUT = 5.0
# tunnel = sshtunnel.SSHTunnelForwarder(
#     ("ssh.pythonanywhere.com", 22), 
#     ssh_username=os.getenv("SSH_USERNAME"),
#     ssh_password=os.getenv("SSH_PASSWORD"),
#     remote_bind_address=(os.getenv("DB_HOST"), 3306),
# )
# tunnel.start()

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Make sure API key is set
if not os.environ.get("IEX_API_KEY"):
    raise RuntimeError("IEX_API_KEY not set")

# Configure dataabse
db_uri = "sqlite:///finance.db"

# TODO: using MySQL database instead of sqlite3
# db_username = os.environ.get("DB_USERNAME")
# db_password = os.environ.get("DB_PASSWORD")
# db_host = os.environ.get("DB_HOST")
# db_name = os.environ.get("DB_NAME")
# db_uri = f"mysql://{db_username}:{db_password}@127.0.0.1:{tunnel.local_bind_port}/{db_name}"

app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299 
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Create new table, and index (for efficient search later on) to keep track of stock orders, by each user
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    hash = db.Column(db.Text, nullable=False)
    cash = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default=10000.00)

    def __getitem__(self, field):
        return self.__dict__[field]
    

class Order(db.Model):
    __tablename__ = "orders"
    __table_args__ = (db.Index('orders_by_user_id_index', "user_id"),)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    symbol = db.Column(db.String(5), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(precision=10, scale=2), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    def __getitem__(self, field):
        return self.__dict__[field]
    

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # query rows that match the user id
    stocks = db.session.query(
        Order.symbol, 
        func.sum(Order.shares).label('num_shares')
    ).filter(
        Order.user_id == session["user_id"]
    ).group_by(
        Order.symbol
    ).all()

    portfolio = []
    subtotal = 0
    for stock in stocks:
        # calculate the total holdings of each stock
        stock_info = lookup(stock.symbol)
        temp = {
            "symbol": stock.symbol,
            "name": stock_info["name"],
            "shares": stock.num_shares,
            "price": usd(stock_info["price"]),
            "total": usd(stock_info["price"] * stock.num_shares)
        }

        # calculate subtotal of assets
        subtotal += Decimal(stock_info["price"]) * stock.num_shares

        # create a row for each stock
        portfolio.append(temp)

    # query for user current cash balance in account
    cash = db.session.query(User.cash).filter(User.id == session["user_id"]).scalar()
    subtotal += cash

    return render_template("index.html", portfolio=portfolio, cash=usd(cash), subtotal=usd(subtotal))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # ensure symbol was.submitted
        if not request.form.get("symbol"):
            return apology("must provide a symbol", 403)

        # ensure no of shares was submitted
        elif not request.form.get("shares"):
            return apology("must provide no. of shares", 403)

        elif not request.form.get("shares").isdigit():
            return apology("must provide an integer", 403)

        # ensure positive integer for shares
        elif int(request.form.get("shares")) < 1:
            return apology("must provide positive integer for shares", 403)

        # ensure valid symbol was submitted
        stock_to_buy = lookup(request.form.get("symbol"))
        if stock_to_buy is None:
            return apology("Symbol not found", 404)

        # calculate total price of shares
        shares = int(request.form.get("shares"))
        price_per_share = float(stock_to_buy["price"])
        total = price_per_share * shares

        # identify user info
        user = db.session.query(User).filter(User.id == session["user_id"]).first()

        # determine if user can afford the stock shares
        if user.cash < total:
            return apology("not enough cash to buy", 403)

        # calculate cash balance after purchasing stock shares
        else:
            user.cash -= Decimal(total)
            db.session.commit()

        # insert record into orders table
        symbol = stock_to_buy["symbol"]
        order = Order(user_id=session["user_id"], symbol=symbol, price=price_per_share, shares=shares)
        db.session.add(order)
        db.session.commit()

        # redirect user to homepage after buying stocks
        flash("Bought")
        return redirect("/")

    # display buy page when request via GET method
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # query each transaction in history for particular user
    rows = db.session.query(
        Order
    ).filter(
        Order.user_id == session["user_id"]
    ).order_by(
        Order.timestamp.desc()
    ).all()

    records = []
    for record in rows:
        print(record)
        # store table data in dictionaries
        temp = {
            "symbol": record["symbol"],
            "shares": record["shares"],
            "price": usd(record["price"]),
            "total": usd(record["shares"] * record["price"]),
            "timestamp": record["timestamp"]
        }

        records.append(temp)

    return render_template("history.html", records=records)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = request.form.get("username")
        rows = db.session.query(User).filter(User.username == username).all()
        
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0].hash, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0].id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # lookup return a dictionary
        stock_info = lookup(request.form.get("symbol"))

        # handle stock not found
        if stock_info is None:
            return apology("Symbol not found", 404)

        # return search result for the stock symbol
        else:
            name = stock_info["name"]
            price = usd(stock_info["price"])
            symbol = stock_info["symbol"]

            flash("Success")
            return render_template("quoted.html", name=name, price=price, symbol=symbol)

    # display quote page if request via GET method
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # ensure confirmed password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm your password", 403)

        # ensure confirmed password is the same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("confirmed password must match the password", 403)

        # ensure no duplicate username :username is a placeholder
        username = request.form.get("username")
        user_name = db.session.query(User).filter(User.username == username).all()
        if len(user_name) != 0:
            return apology("username already exists", 403)

        # store hash generated instead of password in database
        hashed_password = generate_password_hash(request.form.get("password"))

        # register user in database
        user = User(username=username, hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        # redirect user to home page
        flash("Registration success")
        return redirect("/")

    # display the register page when user request via GET method
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        
        # ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # ensure no. of shares was submitted
        elif not request.form.get("shares"):
            return apology("must provide no. of shares", 403)

        elif not request.form.get("shares").isdigit():
            return apology("must provide an integer", 403)

        # ensure positive integer for no. of share
        elif int(request.form.get("shares")) < 1:
            return apology("must provide positive integer", 403)

        # ensure user own the stock or has enough shares to sell
        symbol = request.form.get("symbol")
        stock_to_sell = db.session.query(
            Order.symbol, 
            db.func.sum(Order.shares).label('holdings')
        ).filter(
            Order.user_id == session["user_id"], 
            Order.symbol == symbol
        ).group_by(
            Order.symbol
        ).first()
        
        holdings = stock_to_sell[1]
        if stock_to_sell is None or holdings == 0:
            return apology("Must provide stock you own", 403)

        elif int(request.form.get("shares")) > holdings:
            return apology("you dont have enough shares to sell", 403)

        # get the info of the share on IEX
        stock_info = lookup(request.form.get("symbol"))

        # calculate the total selling price of stock
        shares = int(request.form.get("shares"))
        price_per_share = float(stock_info["price"])
        total = price_per_share * abs(shares)

        # update balance cash after selling stock
        user = db.session.query(User).filter(User.id == session["user_id"]).first()
        user.cash += Decimal(total)
        db.session.commit()

        # insert transaction into orders table
        symbol = stock_info["symbol"]
        order = Order(user_id=session["user_id"], symbol=symbol, price=price_per_share, shares=-shares)
        db.session.add(order)
        db.session.commit()

        # redirect user to homepage
        flash("Sold")
        return redirect("/")

    # display sell page when user request via GET method
    else:
        return render_template("sell.html")

# Extra features
@app.route("/reload", methods=["GET", "POST"])
@login_required
def reload():
    """ reload user cash in account """
    if request.method == "POST":

        if not request.form.get("cash"):
            return apology("must provide amount of cash", 403)

        elif float(request.form.get("cash")) <= 0:
            return apology("must provide positive number", 403)

        # rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        # before = rows[0]["cash"]
        user = db.session.query(User).filter(User.id == session["user_id"]).first()
        user.cash += Decimal(request.form.get("cash"))

        # update user cash after reloading
        db.session.commit()

        flash("Reloaded successfully")
        return redirect("/")

    else:
        return render_template("reload.html")
    

@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change uaer password"""
    if request.method == "POST":

        if not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("new"):
            return apology("must provide new password", 403)

        elif not request.form.get("confirmed"):
            return apology("must confirmed new password", 403)

        old_password = request.form.get("password")
        user = db.session.query(User).filter(User.id == session["user_id"]).first()
        hash_password = user.hash

        # ensure user enter old password
        if not check_password_hash(hash_password, old_password):
            return apology("must provide current password", 403)

        # ensure new password is different
        new_password = request.form.get("new")
        if old_password == new_password:
            return apology("new password must be different", 403)

        # ensure new password is confirmed
        confirmed_password = request.form.get("confirmed")
        if new_password != confirmed_password:
            return apology("must confirmed new password", 403)

        # update hash password
        hash_password = generate_password_hash(new_password)
        user.hash = hash_password
        db.session.commit()

        flash("Password changed")
        return redirect("/")

    else:
        return render_template("password.html")
    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
