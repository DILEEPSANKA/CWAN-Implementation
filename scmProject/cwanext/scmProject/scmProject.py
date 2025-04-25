import os
from flask import Blueprint, Flask, request, render_template, abort,jsonify,redirect,url_for
from flask import current_app as app
from cwan.extensions.base_extension import BaseExtension
from .config.config import User_details,Shipments,Home,signup,Dashboard,Account
from .model.model import Signup
from .routers.Authentication import create_access_token,decode_token
import re
from passlib.context import CryptContext

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

class Extension(BaseExtension):

    def __init__(self, app):
        super().__init__(app)
        self.bp = Blueprint(
            "scmProject",
            __name__,
            template_folder=os.path.join(os.path.dirname(__file__), "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "static"),
            static_url_path="/scmProject/static",
        )

    def register_routes(self):
        pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

        @self.bp.route("/", methods=["GET"])
        def home():
            Home_Template = Home.find_one({"section": "home_page"}, {"_id": 0})
            return render_template(
                "Home.html",
                home_template = Home_Template
            )
        @self.bp.route("/signup", methods=["GET"])
        def sign():
            signup_template = signup.find_one({"template_name": "signup"})
            return render_template("sign_up.html", signup_template=signup_template, 
                                   error_message=None)

        @self.bp.route("/signup", methods=["POST"])
        def sign_post():
            try:
                signup_template = signup.find_one({"template_name": "signup"})

                username = request.form.get("username", "").strip()
                email = request.form.get("email", "").strip()
                role = request.form.get("role", "user").strip()
                password = request.form.get("password", "").strip()
                confirm = request.form.get("confirm", "").strip()

                existing_user = User_details.find_one({"user": username})
                existing_email = User_details.find_one({"email": email})

                if existing_user:
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Username already used", username=username, email=email, role=role)

                if existing_email:
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Email already used", username=username, email=email, role=role)

                if len(username) < 3 or len(username) > 20:
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Username must be between 3 and 20 characters.", username=username, email=email, role=role)

                if password != confirm:
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Passwords do not match", username=username, email=email, role=role)

                if not any(char.isdigit() for char in password):
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Password should contain at least one digit", username=username, email=email, role=role)

                if not re.search(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Invalid email format", username=username, email=email, role=role)

                if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Password should contain at least one special character", username=username, email=email, role=role)

                if len(password) < 8:
                    return render_template("sign_up.html", signup_template=signup_template,
                                        error_message="Password should be at least 8 characters long", username=username, email=email, role=role)

                pw = pwd_cxt.hash(password)
                signupData = Signup(user=username, email=email, role=role, password=pw)
                User_details.insert_one(dict(signupData))

                return redirect(url_for("scmProject.login"))

            except Exception as e:
                signup_template = signup.find_one({"template_name": "signup"})
                return render_template("sign_up.html", signup_template=signup_template,
                                    error_message=f"Internal Server Error: {str(e)}", username="", email="", role="")

        
        @self.bp.route("/login", methods=["GET"])
        def login():
            return render_template("Login.html", error_message=None)

        @self.bp.route("/login", methods=["POST"])  
        def login_post():
            try:
                username = request.form.get("username")
                password = request.form.get("password")

                user_data = User_details.find_one({"user": username})
                if not user_data:
                    return jsonify({"detail": "Username not found."}), 404

                if not pwd_cxt.verify(password, user_data["password"]):
                    return jsonify({"detail": "Incorrect password."}), 401

                token = create_access_token(data={
                    "username": user_data["user"],
                    "email": user_data["email"],
                    "role": user_data["role"]
                })

                response = jsonify({
                    "access_token": token,
                    "username": user_data["user"],
                    "email": user_data["email"],
                    "role": user_data["role"],
                    "redirect_url": "/dashboard"
                })
                response.set_cookie("access_token", f"Bearer {token}", httponly=True, samesite="Strict")
                return response

            except Exception as e:
                return jsonify({"detail": str(e)}), 500

        @self.bp.route("/reset-password", methods=["POST"])
        def reset_password():
            data = request.json
            username = data.get("username")
            email = data.get("email")
            new_password = data.get("new_password")

            if len(new_password) < 8:
                return jsonify({"detail": "Password must be at least 8 characters long."}), 400

            user_data = User_details.find_one({"user": username, "email": email})
            if not user_data:
                return jsonify({"detail": "Invalid username or email."}), 404

            hashed_password = pwd_cxt.hash(new_password)
            User_details.update_one({"user": username}, {"$set": {"password": hashed_password}})
            return jsonify({"detail": "Password updated successfully."}), 200 
        
        def fetch_user_from_cookie():
            try:
                token = request.cookies.get("access_token")
                if not token:
                    return None
                user = decode_token(token)
                if not user:
                    raise ValueError("Failed to retrieve user data from token")
                return user
            except Exception as e:
                print(f"Error decoding token: {e}")
                return None
            
        @self.bp.route("/dashboard", methods=["GET"])
        def dashboard():
            try:
                current_user = fetch_user_from_cookie()
                if current_user is None:
                    return redirect(url_for("scmProject.login") + "?alert=true")

                role = current_user.get("role", "user")
                username = current_user.get("username", "User")

                dashboard_template = Dashboard.find_one({"section": "dashboard_page"}, {"_id": 0})

                if dashboard_template is None:
                    return "Dashboard template not found", 404

                return render_template(
                    "Dashboard.html",
                    role=role,
                    username=username,
                    dashboard_template=dashboard_template
                )

            except Exception as e:
                print(f"Error rendering dashboard: {e}")
                return jsonify({"detail": f"An unexpected error occurred: {str(e)}"}), 500

        @self.bp.route("/account", methods=["GET"])
        def account():
            try:
                current_user = fetch_user_from_cookie()
                if current_user is None:
                    return redirect(url_for("scmProject.login") + "?alert=true")

                role = current_user.get("role", "user")
                username = current_user.get("user", "User")  
                email = current_user.get("email", "N/A")

                account_template = Account.find_one({"template_name": "account"}, {"_id": 0})

                if account_template is None:
                    return "Account template not found", 404

                return render_template(
                    "account.html",
                    role=role,
                    username=username,
                    email=email,
                    template=account_template
                )

            except Exception as e:
                print(f"Error rendering account page: {e}")
                return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500


        @self.bp.route("/newshipment", methods=["GET"])
        def newship():
            token = request.cookies.get("access_token")
            current_user = decode_token(token)
            if current_user is None:
                return redirect(url_for("/login") + "?alert=true")

            try:
                role = current_user.get("role", "user")
                username = current_user.get("username", "User")

                return render_template("Newshipment.html", role=role, username=username)
            except Exception as e:
                return jsonify({"detail": f"Error loading template: {str(e)}"}), 500

        @self.bp.route("/newshipment", methods=["POST"])
        def newshipment_user():
            token = request.cookies.get("access_token")
            current_user = decode_token(token)
            if current_user is None:
                return jsonify({"detail": "User not logged in."}), 400

            try:
                shipment_details = request.json

                if any(
                    value == ""
                    for value in [
                        shipment_details.get("shipment_number"),
                        shipment_details.get("container_number"),
                        shipment_details.get("goods_number"),
                        shipment_details.get("route_details"),
                        shipment_details.get("goods_type"),
                        shipment_details.get("device_id"),
                        shipment_details.get("expected_delivery_date"),
                        shipment_details.get("po_number"),
                        shipment_details.get("delivery_number"),
                        shipment_details.get("ndc_number"),
                        shipment_details.get("batch_id"),
                        shipment_details.get("shipment_description"),
                    ]
                ):
                    return jsonify({"detail": "All fields must be filled"}), 400

                existing_data = Shipments.find_one({"shipment_number": shipment_details["shipment_number"]}, {"_id": 0})
                if existing_data:
                    return jsonify({"detail": "Shipment number already exists"}), 400

                shipment_data = {
                    "user": current_user["user"],
                    "email": current_user["email"],
                    "shipment_number": shipment_details["shipment_number"],
                    "container_number": shipment_details["container_number"],
                    "route_details": shipment_details["route_details"],
                    "goods_type": shipment_details["goods_type"],
                    "device": shipment_details["device_id"],
                    "expected_delivery": shipment_details["expected_delivery_date"],
                    "po_number": shipment_details["po_number"],
                    "delivery_number": shipment_details["delivery_number"],
                    "ndc_number": shipment_details["ndc_number"],
                    "batch_id": shipment_details["batch_id"],
                    "serial_number": shipment_details["goods_number"],
                    "shipment_description": shipment_details["shipment_description"],
                }

                Shipments.insert_one(shipment_data)

                return jsonify({"message": "Shipment Created Successfully"}), 200

            except Exception as e:
                return jsonify({"detail": str(e)}), 500
            
        @self.bp.route("/myshipment", methods=["GET"])
        def my_shipments():
            try:
                current_user = fetch_user_from_cookie()
                if current_user is None:
                    return redirect(url_for("/login") + "?alert=true")

                role = current_user.get("role", "user")
                email = current_user.get("email")

                if role == "admin":
                    shipments = list(Shipments.find({}, {"_id": 0}))
                else:
                    if not email:
                        return jsonify({"detail": "User email not found."}), 400
                    shipments = list(Shipments.find({"email": email}, {"_id": 0}))

                return render_template("Myshipment.html", shipments=shipments, role=role)
            except Exception as e:
                print(f"Error fetching shipments: {e}")
                return render_template(
                    "Myshipment.html",
                    shipments=[],
                    role=current_user.get("role", "user"),
                    error_message="An error occurred while fetching shipments.",
                )

        @self.bp.route("/logout", methods=["POST"])
        def logout():
            try:
                response = jsonify({"message": "Logged out"})
                response.delete_cookie("access_token")
                return response
            except Exception as e:
                return jsonify({"detail": str(e)}), 500
       
        app.register_blueprint(self.bp)
