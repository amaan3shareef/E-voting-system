import tkinter as tk
from tkinter import messagebox
import datetime
import hashlib
import json
import os
import random
import base64
from cryptography.fernet import Fernet

# Files to store data
USER_FILE = "users.json"
CANDIDATE_FILE = "candidates.json"
VOTES_FILE = "votes.json"
VOTER_FILE = "voters.json"
RECEIPT_FILE = "vote_receipts.json"
OFFICER_FILE = "officers.json"

# Ensure JSON files exist
for file in [USER_FILE, CANDIDATE_FILE, VOTES_FILE, VOTER_FILE, RECEIPT_FILE, OFFICER_FILE]:
    if not os.path.exists(file):
        with open(file, "w") as f:
            json.dump([] if file != RECEIPT_FILE else {}, f)

# Global variables
current_voter_id = None
key = Fernet.generate_key()
cipher = Fernet(key)

# ### Receipt Functions
def generate_receipt_id():
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))

def generate_digital_receipt(voter_id, candidate_name):
    receipt_id = generate_receipt_id()
    timestamp = datetime.datetime.now().isoformat()
    vote_data = {
        "candidate": candidate_name,
        "timestamp": timestamp,
        "receipt_id": receipt_id
    }
    
    encrypted_data = cipher.encrypt(json.dumps(vote_data).encode())
    encoded_receipt = base64.b64encode(encrypted_data).decode('utf-8')
    
    with open(RECEIPT_FILE, "r") as rf:
        receipts = json.load(rf)
    
    receipts[receipt_id] = encoded_receipt
    with open(RECEIPT_FILE, "w") as rf:
        json.dump(receipts, rf, indent=4)
    
    return receipt_id, vote_data

def verify_receipt(receipt_id):
    try:
        with open(RECEIPT_FILE, "r") as rf:
            receipts = json.load(rf)
        
        if receipt_id not in receipts:
            return None
            
        encoded_receipt = receipts[receipt_id]
        encrypted_data = base64.b64decode(encoded_receipt)
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        return json.loads(decrypted_data)
    except:
        return None

# ### Main Window
def main_auth_window():
    global root, frame
    root = tk.Tk()
    root.title("E-Voting System")
    root.geometry("400x400")
    frame = tk.Frame(root)
    frame.pack(fill="both", expand=True)
    show_main_menu()
    root.mainloop()

def show_main_menu():
    clear_frame()
    tk.Label(frame, text="E-Voting System", font=("Arial", 14)).pack(pady=10)
    tk.Button(frame, text="Voter Register/Login", command=show_user_menu).pack(pady=5)
    tk.Button(frame, text="Candidate Nomination", command=show_candidate_menu).pack(pady=5)
    tk.Button(frame, text="Officer Register/Login", command=show_officer_menu).pack(pady=5)
    tk.Button(frame, text="Verify Vote Receipt", command=show_verify_receipt).pack(pady=5)

def show_user_menu():
    clear_frame()
    tk.Button(frame, text="Voter Register", command=show_registration).pack(pady=5)
    tk.Button(frame, text="Voter Login", command=show_login).pack(pady=5)
    tk.Button(frame, text="Back", command=show_main_menu).pack(pady=5)

def show_officer_menu():
    clear_frame()
    tk.Label(frame, text="Officer Portal", font=("Arial", 14)).pack(pady=10)
    tk.Button(frame, text="Officer Register", command=show_officer_registration).pack(pady=5)
    tk.Button(frame, text="Officer Login", command=show_officer_login).pack(pady=5)
    tk.Button(frame, text="Back", command=show_main_menu).pack(pady=5)

def show_candidate_menu():
    clear_frame()
    tk.Label(frame, text="Candidate Nomination", font=("Arial", 12)).pack(pady=10)
    tk.Button(frame, text="Register as Candidate", command=show_candidate_registration).pack(pady=5)
    tk.Button(frame, text="Login as Candidate", command=show_candidate_login).pack(pady=5)
    tk.Button(frame, text="Back", command=show_main_menu).pack(pady=5)

# ### Voter Registration and Login
def show_registration():
    clear_frame()
    tk.Label(frame, text="Enter Date of Birth (YYYY-MM-DD):").pack()
    dob_entry = tk.Entry(frame)
    dob_entry.pack(pady=5)

    def check_age():
        dob = dob_entry.get()
        try:
            birth_year = int(dob.split("-")[0])
            current_year = datetime.datetime.now().year
            age = current_year - birth_year
            if age < 18:
                messagebox.showerror("Eligibility", "You are not eligible to vote (Age < 18).")
                show_main_menu()
            else:
                messagebox.showinfo("Eligibility", "You are eligible to vote!")
                show_registration_details()
        except ValueError:
            messagebox.showerror("Error", "Invalid Date Format. Use YYYY-MM-DD")
    
    tk.Button(frame, text="Next", command=check_age).pack(pady=10)

def show_registration_details():
    clear_frame()
    tk.Label(frame, text="Enter Name:").pack()
    name_entry = tk.Entry(frame)
    name_entry.pack()
    tk.Label(frame, text="Enter User ID:").pack()
    user_id_entry = tk.Entry(frame)
    user_id_entry.pack()
    tk.Label(frame, text="Enter Password:").pack()
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack()

    def save_user():
        user_id = user_id_entry.get()
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open(USER_FILE, "r") as file:
            try:
                users = json.load(file)
            except json.JSONDecodeError:
                users = []
        if any(user["user_id"] == user_id for user in users):
            messagebox.showerror("Error", "User ID already exists!")
            return
        user_data = {"name": name_entry.get(), "user_id": user_id, "password": hashed_password, "voted": False}
        users.append(user_data)
        with open(USER_FILE, "w") as file:
            json.dump(users, file, indent=4)
        messagebox.showinfo("Success", "Registration Successful!")
        show_main_menu()

    tk.Button(frame, text="Register", command=save_user).pack(pady=10)

def show_login():
    clear_frame()
    tk.Label(frame, text="User ID:").pack()
    user_id_entry = tk.Entry(frame)
    user_id_entry.pack()
    tk.Label(frame, text="Password:").pack()
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack()

    def validate_login():
        global current_voter_id
        user_id = user_id_entry.get()
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open(USER_FILE, "r") as file:
            try:
                users = json.load(file)
            except json.JSONDecodeError:
                users = []
        for user in users:
            if user["user_id"] == user_id and user["password"] == hashed_password:
                current_voter_id = user_id
                messagebox.showinfo("Login Success", f"Welcome {user['name']}!")
                show_voting_page()
                return
        messagebox.showerror("Login Failed", "Invalid User ID or Password")

    tk.Button(frame, text="Login", command=validate_login).pack(pady=10)
    tk.Button(frame, text="Back to Main Menu", command=show_main_menu).pack(pady=10)

# ### Voting Interface
def show_voting_page():
    clear_frame()
    tk.Label(frame, text="Cast Your Vote", font=("Arial", 14)).pack(pady=10)

    try:
        with open(CANDIDATE_FILE, "r") as file:
            candidates = json.load(file)
        with open(VOTES_FILE, "r") as vf:
            try:
                votes = json.load(vf)
            except json.JSONDecodeError:
                votes = {}
        with open(VOTER_FILE, "r") as vf:
            try:
                voted_users = json.load(vf)
            except json.JSONDecodeError:
                voted_users = {}
    except (FileNotFoundError, json.JSONDecodeError):
        candidates = []
        votes = {}
        voted_users = {}

    if not candidates or all(c["symbol"] is None for c in candidates):
        tk.Label(frame, text="No registered candidates yet.", font=("Arial", 10)).pack(pady=10)
        tk.Button(frame, text="Logout", command=show_main_menu).pack(pady=10)
        return

    canvas = tk.Canvas(frame)
    scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    vote_labels = {}

    def cast_vote(candidate_name):
        global current_voter_id
        if not current_voter_id:
            messagebox.showerror("Error", "Please login first!")
            show_main_menu()
            return
        if current_voter_id in voted_users:
            messagebox.showerror("Error", "You have already voted!")
            return

        votes[candidate_name] = votes.get(candidate_name, 0) + 1
        with open(VOTES_FILE, "w") as vf:
            json.dump(votes, vf, indent=4)

        voted_users[current_voter_id] = True
        with open(VOTER_FILE, "w") as vf:
            json.dump(voted_users, vf, indent=4)

        with open(USER_FILE, "r") as uf:
            users = json.load(uf)
        for user in users:
            if user["user_id"] == current_voter_id:
                user["voted"] = True
                break
        with open(USER_FILE, "w") as uf:
            json.dump(users, uf, indent=4)

        receipt_id, vote_data = generate_digital_receipt(current_voter_id, candidate_name)
        vote_labels[candidate_name].config(text=f"Votes: {votes[candidate_name]}")
        
        receipt_text = (
            f"Vote Receipt\n"
            f"Receipt ID: {receipt_id}\n"
            f"Voted for: {vote_data['candidate']}\n"
            f"Timestamp: {vote_data['timestamp']}\n"
            f"Keep this Receipt ID to verify your vote!"
        )
        messagebox.showinfo("Vote Recorded", receipt_text)
        show_main_menu()

    for candidate in candidates:
        if candidate["symbol"]:
            candidate_frame = tk.Frame(scrollable_frame, bd=2, relief="solid", padx=10, pady=5)
            candidate_frame.pack(pady=5, fill="x", padx=10)
            tk.Label(candidate_frame, text=f"Name: {candidate['name']}", font=("Arial", 10)).pack(anchor="w")
            tk.Label(candidate_frame, text=f"Symbol: {candidate['symbol']}", font=("Arial", 10, "bold")).pack(anchor="w")
            tk.Label(candidate_frame, text=f"Qualification: {candidate['qualification']}", font=("Arial", 10)).pack(anchor="w")
            vote_count = votes.get(candidate["name"], 0)
            vote_label = tk.Label(candidate_frame, text=f"Votes: {vote_count}", font=("Arial", 10))
            vote_label.pack(anchor="w")
            vote_labels[candidate["name"]] = vote_label
            if current_voter_id not in voted_users:
                tk.Button(candidate_frame, text="Cast Vote", 
                         command=lambda name=candidate["name"]: cast_vote(name)).pack(pady=5)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    tk.Button(frame, text="Logout", command=show_main_menu).pack(pady=10)

# ### Receipt Verification
def show_verify_receipt():
    clear_frame()
    tk.Label(frame, text="Verify Your Vote Receipt", font=("Arial", 14)).pack(pady=10)
    tk.Label(frame, text="Enter Receipt ID:").pack()
    receipt_id_entry = tk.Entry(frame)
    receipt_id_entry.pack(pady=5)

    def verify():
        receipt_id = receipt_id_entry.get()
        vote_data = verify_receipt(receipt_id)
        if vote_data:
            verify_text = (
                f"Vote Verification\n"
                f"Receipt ID: {vote_data['receipt_id']}\n"
                f"Voted for: {vote_data['candidate']}\n"
                f"Timestamp: {vote_data['timestamp']}"
            )
            messagebox.showinfo("Verification Successful", verify_text)
        else:
            messagebox.showerror("Verification Failed", "Invalid Receipt ID!")
    
    tk.Button(frame, text="Verify", command=verify).pack(pady=5)
    tk.Button(frame, text="Back", command=show_main_menu).pack(pady=5)

# ### Candidate Registration and Login
def show_candidate_registration():
    clear_frame()
    tk.Label(frame, text="Enter Date of Birth (YYYY-MM-DD):").pack()
    dob_entry = tk.Entry(frame)
    dob_entry.pack(pady=10)

    def check_candidate_age():
        dob = dob_entry.get()
        try:
            birth_year = int(dob.split("-")[0])
            age = datetime.datetime.now().year - birth_year
            if age < 40:
                messagebox.showerror("Eligibility", "You are not eligible for nomination (Age < 40).")
                show_main_menu()
            else:
                messagebox.showinfo("Eligibility", "You are eligible for nomination!")
                show_candidate_details()
        except ValueError:
            messagebox.showerror("Error", "Invalid Date Format. Use YYYY-MM-DD")
    
    tk.Button(frame, text="Next", command=check_candidate_age).pack(pady=10)

def show_candidate_details():
    clear_frame()
    tk.Label(frame, text="Enter Name:").pack()
    name_entry = tk.Entry(frame)
    name_entry.pack()
    tk.Label(frame, text="Enter Qualification:").pack()
    qualification_entry = tk.Entry(frame)
    qualification_entry.pack()
    tk.Label(frame, text="Enter User ID:").pack()
    user_id_entry = tk.Entry(frame)
    user_id_entry.pack()
    random_password = str(random.randint(100000, 999999))
    tk.Label(frame, text=f"Generated Password: {random_password}").pack()

    def save_candidate():
        user_id = user_id_entry.get()
        hashed_password = hashlib.sha256(random_password.encode()).hexdigest()
        try:
            with open(CANDIDATE_FILE, "r") as file:
                candidates = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            candidates = []
        if len(candidates) >= 10:  # Updated to allow up to 10 candidates
            messagebox.showerror("Error", "Candidate limit reached (10 candidates only).")
            return
        candidate_data = {"name": name_entry.get(), "user_id": user_id, "password": hashed_password, 
                         "qualification": qualification_entry.get(), "symbol": None}
        candidates.append(candidate_data)
        with open(CANDIDATE_FILE, "w") as file:
            json.dump(candidates, file, indent=4)
        messagebox.showinfo("Success", "Registration Successful!")
        show_main_menu()

    tk.Button(frame, text="Register", command=save_candidate).pack(pady=10)

def show_candidate_login():
    clear_frame()
    tk.Label(frame, text="User ID:").pack()
    user_id_entry = tk.Entry(frame)
    user_id_entry.pack()
    tk.Label(frame, text="Password:").pack()
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack()

    def validate_candidate_login():
        user_id = user_id_entry.get()
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            with open(CANDIDATE_FILE, "r") as file:
                candidates = json.load(file)
            for candidate in candidates:
                if candidate["user_id"] == user_id and candidate["password"] == hashed_password:
                    messagebox.showinfo("Login Success", f"Welcome {candidate['name']}!")
                    choose_symbol_interface(user_id)
                    return
            messagebox.showerror("Login Failed", "Invalid User ID or Password")
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror("Error", "Candidate database error!")

    tk.Button(frame, text="Login", command=validate_candidate_login).pack(pady=10)

def choose_symbol_interface(user_id):
    clear_frame()
    tk.Label(frame, text="Choose Your Party Symbol").pack(pady=10)
    available_symbols = ["Lion", "Eagle", "Tiger", "Horse", "Elephant", "Bear", "Wolf", "Fox", "Deer", "Owl"]  # Expanded to 10 symbols
    symbol_var = tk.StringVar()
    for symbol in available_symbols:
        tk.Radiobutton(frame, text=symbol, variable=symbol_var, value=symbol).pack()

    def save_symbol():
        symbol = symbol_var.get()
        if not symbol:
            messagebox.showerror("Error", "Please select a symbol.")
            return
        try:
            with open(CANDIDATE_FILE, "r") as file:
                candidates = json.load(file)
            for candidate in candidates:
                if candidate["user_id"] == user_id:
                    candidate["symbol"] = symbol
                    break
            with open(CANDIDATE_FILE, "w") as file:
                json.dump(candidates, file, indent=4)
            messagebox.showinfo("Success", f"Symbol '{symbol}' assigned successfully!")
            show_registered_symbols()
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror("Error", "Database error!")

    tk.Button(frame, text="Confirm Symbol", command=save_symbol).pack(pady=10)

def show_registered_symbols():
    clear_frame()
    tk.Label(frame, text="Registered Candidates", font=("Arial", 12)).pack(pady=10)
    try:
        with open(CANDIDATE_FILE, "r") as file:
            candidates = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        candidates = []
    if not candidates or all(c["symbol"] is None for c in candidates):
        tk.Label(frame, text="No registered candidates yet.", font=("Arial", 10)).pack(pady=10)
        return
    container = tk.Frame(frame)
    container.pack(fill="both", expand=True)
    canvas = tk.Canvas(container)
    scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    for candidate in candidates:
        if candidate["symbol"]:
            candidate_frame = tk.Frame(scrollable_frame, bd=2, relief="solid", padx=10, pady=5)
            candidate_frame.pack(pady=5, fill="x", padx=10)
            tk.Label(candidate_frame, text=f"Name: {candidate['name']}", font=("Arial", 10)).pack(anchor="w")
            tk.Label(candidate_frame, text=f"Symbol: {candidate['symbol']}", font=("Arial", 10, "bold")).pack(anchor="w")
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    button_frame = tk.Frame(frame)
    button_frame.pack(side="bottom", fill="x", pady=10)
    tk.Button(button_frame, text="Back to Main Menu", command=show_main_menu).pack()

# ### Officer Functions
def show_officer_registration():
    clear_frame()
    tk.Label(frame, text="Officer Registration", font=("Arial", 14)).pack(pady=10)
    tk.Label(frame, text="Enter Name:").pack()
    name_entry = tk.Entry(frame)
    name_entry.pack()
    tk.Label(frame, text="Enter Officer ID:").pack()
    officer_id_entry = tk.Entry(frame)
    officer_id_entry.pack()
    tk.Label(frame, text="Enter Password:").pack()
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack()

    def save_officer():
        officer_id = officer_id_entry.get()
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        with open(OFFICER_FILE, "r") as file:
            try:
                officers = json.load(file)
            except json.JSONDecodeError:
                officers = []
        
        if any(officer["officer_id"] == officer_id for officer in officers):
            messagebox.showerror("Error", "Officer ID already exists!")
            return
        
        officer_data = {
            "name": name_entry.get(),
            "officer_id": officer_id,
            "password": hashed_password
        }
        officers.append(officer_data)
        
        with open(OFFICER_FILE, "w") as file:
            json.dump(officers, file, indent=4)
        
        messagebox.showinfo("Success", "Officer Registration Successful!")
        show_officer_menu()

    tk.Button(frame, text="Register", command=save_officer).pack(pady=10)
    tk.Button(frame, text="Back", command=show_officer_menu).pack(pady=5)

def show_officer_login():
    clear_frame()
    tk.Label(frame, text="Officer Login", font=("Arial", 14)).pack(pady=10)
    tk.Label(frame, text="Officer ID:").pack()
    officer_id_entry = tk.Entry(frame)
    officer_id_entry.pack()
    tk.Label(frame, text="Password:").pack()
    password_entry = tk.Entry(frame, show="*")
    password_entry.pack()

    def validate_officer_login():
        officer_id = officer_id_entry.get()
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        with open(OFFICER_FILE, "r") as file:
            try:
                officers = json.load(file)
            except json.JSONDecodeError:
                officers = []
        
        for officer in officers:
            if officer["officer_id"] == officer_id and officer["password"] == hashed_password:
                messagebox.showinfo("Login Success", f"Welcome {officer['name']}!")
                show_officer_dashboard(officer_id)
                return
        
        messagebox.showerror("Login Failed", "Invalid Officer ID or Password")

    tk.Button(frame, text="Login", command=validate_officer_login).pack(pady=10)
    tk.Button(frame, text="Back", command=show_officer_menu).pack(pady=5)

def show_officer_dashboard(officer_id):
    clear_frame()
    tk.Label(frame, text="Election Officer Dashboard", font=("Arial", 14)).pack(pady=10)

    try:
        with open(CANDIDATE_FILE, "r") as cf:
            candidates = json.load(cf)
        with open(VOTES_FILE, "r") as vf:
            votes = json.load(vf)
        with open(VOTER_FILE, "r") as vtf:
            voters = json.load(vtf)
    except (FileNotFoundError, json.JSONDecodeError):
        candidates = []
        votes = {}
        voters = {}

    total_votes = len(voters)
    tk.Label(frame, text=f"Total Votes Cast: {total_votes}", font=("Arial", 12)).pack(pady=5)

    container = tk.Frame(frame)
    container.pack(fill="both", expand=True)
    canvas = tk.Canvas(container)
    scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    tk.Label(scrollable_frame, text="Election Results:", font=("Arial", 12, "bold")).pack(pady=5)
    
    for candidate in candidates:
        vote_count = votes.get(candidate["name"], 0)
        result_frame = tk.Frame(scrollable_frame, bd=2, relief="solid", padx=10, pady=5)
        result_frame.pack(pady=5, fill="x", padx=10)
        tk.Label(result_frame, 
                text=f"Candidate: {candidate['name']} | Symbol: {candidate['symbol']}", 
                font=("Arial", 10)).pack(anchor="w")
        tk.Label(result_frame, 
                text=f"Votes: {vote_count} | Percentage: {(vote_count/total_votes*100):.2f}%" if total_votes > 0 else "Votes: 0 | Percentage: 0%", 
                font=("Arial", 10)).pack(anchor="w")

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def announce_winner():
        if not votes:
            messagebox.showinfo("Election Results", "No votes have been cast yet!")
            return
        
        winner = max(votes.items(), key=lambda x: x[1])
        winner_name, winner_votes = winner
        winner_symbol = next((c["symbol"] for c in candidates if c["name"] == winner_name), "N/A")
        
        tied_candidates = [name for name, count in votes.items() if count == winner_votes and name != winner_name]
        
        if tied_candidates:
            tied_message = f"Election Tie!\nMultiple candidates have {winner_votes} votes:\n- {winner_name} (Symbol: {winner_symbol})\n"
            for tied_name in tied_candidates:
                tied_symbol = next((c["symbol"] for c in candidates if c["name"] == tied_name), "N/A")
                tied_message += f"- {tied_name} (Symbol: {tied_symbol})\n"
            messagebox.showinfo("Election Results", tied_message)
        else:
            winner_message = (
                f"Election Winner Announced!\n"
                f"Winner: {winner_name}\n"
                f"Symbol: {winner_symbol}\n"
                f"Votes: {winner_votes}\n"
                f"Percentage: {(winner_votes/total_votes*100):.2f}%"
            )
            messagebox.showinfo("Election Results", winner_message)

    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)
    tk.Button(button_frame, text="Announce Winner", command=announce_winner).pack(side="left", padx=5)
    tk.Button(button_frame, text="Logout", command=show_main_menu).pack(side="left", padx=5)

# ### Utility Function
def clear_frame():
    for widget in frame.winfo_children():
        widget.destroy()

# ### Run Application
main_auth_window()
