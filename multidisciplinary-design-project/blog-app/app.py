
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import json
import time
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'a_very_secret_key_that_is_not_secure'

# --- MongoDB Setup ---
client = MongoClient('mongodb://localhost:27017/')
db = client['blog_db']
users_collection = db['users']
blogs_collection = db['blogs']

# --- Routes ---


def get_all_posts():
    """Helper function to fetch all posts with author usernames."""
    posts = list(blogs_collection.find().sort('publication_date', -1))
    # Attach author username
    for post in posts:
        author = users_collection.find_one({'_id': post['author_id']})
        post['author_username'] = author['username'] if author else 'Unknown'
    return posts

@app.route('/')
def home():
    """Home Page - Requires login, displays all blog posts."""
    if 'username' not in session:
        return redirect(url_for('login'))
    posts = get_all_posts()
    return render_template('home.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User Registration Page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if users_collection.find_one({'username': username}):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        if users_collection.find_one({'email': email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        
        # Store password as MD5 hash (for demo, still insecure)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        # Hash security answer for consistency (though simple MD5)
        security_answer_hash = hashlib.md5(security_answer.lower().strip().encode()).hexdigest()

        users_collection.insert_one({
            'username': username,
            'email': email,
            'passwordHash': password_hash,
            'security_question': security_question,
            'security_answer': security_answer_hash,
            'is_admin': False,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User Login - VULNERABLE to NoSQL Injection via password field."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        query = {'username': username, 'passwordHash': None}
        
        if password.startswith('{') and password.endswith('}'):
            if "$where" in password:
                flash('Illegal characters detected in password.', 'danger')
                return render_template('login.html'), 400
            try:
                query['passwordHash'] = json.loads(password)
            except Exception:
                query['passwordHash'] = hashlib.md5(password.encode()).hexdigest()
        else:
            query['passwordHash'] = hashlib.md5(password.encode()).hexdigest()

        user = users_collection.find_one(query)
        if user:
            session['username'] = user['username']
            session['user_id'] = str(user['_id'])
            session['is_admin'] = user.get('is_admin', False)
            flash('Login successful!', 'success')
            posts = get_all_posts()
            return render_template('home.html', posts=posts), 200
        else:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html'), 401
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """User Dashboard - Requires login."""
    if 'username' not in session:
        flash('You must be logged in to view the dashboard.', 'warning')
        return redirect(url_for('login'))
    user_id = ObjectId(session['user_id'])
    posts = list(blogs_collection.find({'author_id': user_id}).sort('publication_date', -1))
    return render_template('dashboard.html', posts=posts)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User Profile Page - Edit details."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    user = users_collection.find_one({'_id': user_id})
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('new_password')
        new_security_question = request.form.get('security_question')
        new_security_answer = request.form.get('security_answer')
        
        # Verify current password
        current_password_hash = hashlib.md5(current_password.encode()).hexdigest()
        if current_password_hash != user['passwordHash']:
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('profile'))

        update_data = {}
        updated_fields = []

        # Check Username
        if new_username != user['username']:
            if users_collection.find_one({'username': new_username}):
                flash('Username already exists.', 'danger')
                return redirect(url_for('profile'))
            update_data['username'] = new_username
            updated_fields.append('Username')

        # Check Email
        if new_email != user.get('email'):
            if users_collection.find_one({'email': new_email}):
                flash('Email already in use by another account.', 'danger')
                return redirect(url_for('profile'))
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                flash('Invalid email format.', 'danger')
                return redirect(url_for('profile'))
            update_data['email'] = new_email
            updated_fields.append('Email')

        # Check Password
        if new_password:
             update_data['passwordHash'] = hashlib.md5(new_password.encode()).hexdigest()
             updated_fields.append('Password')

        # Check Security Question
        if new_security_question and new_security_question != user.get('security_question'):
            update_data['security_question'] = new_security_question
            updated_fields.append('Security Question')

        # Check Security Answer
        if new_security_answer:
            update_data['security_answer'] = hashlib.md5(new_security_answer.lower().strip().encode()).hexdigest()
            updated_fields.append('Security Answer')
        
        if update_data:
            update_data['updated_at'] = datetime.utcnow()
            users_collection.update_one({'_id': user_id}, {'$set': update_data})
            
            # Update session if username changed
            if 'username' in update_data:
                session['username'] = update_data['username']
            
            for field in updated_fields:
                flash(f'{field} is updated.', 'success')
        else:
            flash('No changes made.', 'info')

        return redirect(url_for('profile'))
        
    return render_template('profile.html', user=user)


@app.route('/delete_account', methods=['POST'])
def delete_account():
    """Delete User Account - Requires Password Verification."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    password = request.form.get('password')
    
    user = users_collection.find_one({'_id': user_id})
    if not user:
         flash('User not found.', 'danger')
         return redirect(url_for('login'))
         
    # Verify password
    password_hash = hashlib.md5(password.encode()).hexdigest()
    if password_hash != user['passwordHash']:
        flash('Incorrect password. Account deletion cancelled.', 'danger')
        return redirect(url_for('profile'))
        
    # Delete User and Posts
    users_collection.delete_one({'_id': user_id})
    blogs_collection.delete_many({'author_id': user_id})
    
    session.clear()
    flash('Your account has been permanently deleted.', 'info')
    return redirect(url_for('login'))


@app.route('/post/<post_id>')
def view_post(post_id):
    """View a single post."""
    post = blogs_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return "Post not found", 404
    author = users_collection.find_one({'_id': post['author_id']})
    post['author_username'] = author['username'] if author else 'Unknown'
    return render_template('view_post.html', post=post)



def get_blacklist():
    """Reads the blacklist file and returns a list of forbidden words."""
    try:
        with open('blacklist.txt', 'r') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def contains_forbidden_words(text):
    """Checks if the text contains any forbidden words."""
    blacklist = get_blacklist()
    text_lower = text.lower()
    for word in blacklist:
        if word in text_lower:
            return True
    return False

@app.route('/create', methods=['GET', 'POST'])
def create_post():
    """Create a new blog post."""
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category', 'General')
        
        # Check for forbidden words
        if contains_forbidden_words(title) or contains_forbidden_words(content) or contains_forbidden_words(category):
            flash('User policy violation: Content contains prohibited words.', 'danger')
            return render_template('create_post.html', title=title, content=content, category=category)

        blogs_collection.insert_one({
            'title': title,
            'content': content,
            'author_id': ObjectId(session['user_id']),
            'category': category,
            'publication_date': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
        flash('Post created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_post.html')


@app.route('/edit/<post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    """Edit an existing blog post."""
    if 'username' not in session:
        return redirect(url_for('login'))
    post = blogs_collection.find_one({'_id': ObjectId(post_id)})
    if not post or post['author_id'] != ObjectId(session['user_id']):
        flash('You do not have permission to edit this post.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category', post.get('category', 'General'))
        
        # Check for forbidden words
        if contains_forbidden_words(title) or contains_forbidden_words(content) or contains_forbidden_words(category):
            flash('User policy violation: Content contains prohibited words.', 'danger')
            return render_template('edit_post.html', post=post)

        blogs_collection.update_one({'_id': ObjectId(post_id)}, {'$set': {
            'title': title,
            'content': content,
            'category': category,
            'publication_date': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }})
        flash('Post updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_post.html', post=post)


@app.route('/delete/<post_id>')
def delete_post(post_id):
    """Delete a blog post."""
    if 'username' not in session:
        return redirect(url_for('login'))
    post = blogs_collection.find_one({'_id': ObjectId(post_id)})
    if not post or post['author_id'] != ObjectId(session['user_id']):
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('dashboard'))
    blogs_collection.delete_one({'_id': ObjectId(post_id)})
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/search')
def search():
    """Search - VULNERABLE to Blind NoSQL Injection via $where in JSON query."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    query_str = request.args.get('q', '').strip()
    results = []
    is_json_query = False
    query_obj = {}

    if query_str.startswith('{') and query_str.endswith('}'):
        try:
            DANGEROUS_OPERATORS = ['"$ne"', '"$gt"', '"$lt"', '"$gte"', '"$lte"', '"$in"', '"$nin"', '"$regex"']
            for op in DANGEROUS_OPERATORS:
                if op in query_str:
                    flash(f'Operator {op} is not allowed.', 'danger')
                    return render_template('search_results.html', results=[], query=query_str)
            query_obj = json.loads(query_str)
            is_json_query = True
        except json.JSONDecodeError:
            is_json_query = False

    if is_json_query:
        try:
            blog_results = list(blogs_collection.find(query_obj))
            user_results = list(users_collection.find(query_obj))
            results = blog_results
        except Exception as e:
            flash(f'Database error: {e}', 'danger')
            results = []
    else:
        if query_str:
            blog_matches = list(blogs_collection.find({
                '$or': [
                    {'title': {'$regex': query_str, '$options': 'i'}},
                    {'content': {'$regex': query_str, '$options': 'i'}},
                    {'category': {'$regex': query_str, '$options': 'i'}}
                ]
            }))
            matching_users = list(users_collection.find({
                'username': {'$regex': query_str, '$options': 'i'}
            }))
            if matching_users:
                user_ids = [user['_id'] for user in matching_users]
                user_blogs = list(blogs_collection.find({'author_id': {'$in': user_ids}}))
                existing_ids = {post['_id'] for post in blog_matches}
                for blog in user_blogs:
                    if blog['_id'] not in existing_ids:
                        blog_matches.append(blog)
            results = blog_matches

    for post in results:
        if 'author_id' in post:
            author = users_collection.find_one({'_id': post['author_id']})
            post['author_username'] = author['username'] if author else 'Unknown'
    
    return render_template('search_results.html', results=results, query=query_str)



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Password Reset - Step 1: Enter Username."""
    if request.method == 'POST':
        username = request.form.get('username')
        user = users_collection.find_one({'username': username})
        if user:
            # If user has a security question set, proceed
            if 'security_question' in user and user['security_question']:
                return render_template('reset_password_verify.html', username=username, question=user['security_question'])
            else:
                flash('This account does not have a security question set. Please contact support.', 'warning')
                return redirect(url_for('login'))
        else:
            # Generic message to avoid username enumeration (though app is vulnerable elsewhere)
            flash('If the username exists, you will be redirected.', 'info')
            return redirect(url_for('reset_password'))
    return render_template('reset_password.html')


@app.route('/reset_password_verify', methods=['POST'])
def reset_password_verify():
    """Password Reset - Step 2: Verify Answer and Reset."""
    username = request.form.get('username')
    security_answer = request.form.get('security_answer')
    new_password = request.form.get('new_password')
    
    user = users_collection.find_one({'username': username})
    if not user:
        flash('Error: User not found.', 'danger')
        return redirect(url_for('login'))

    # Verify Answer
    input_hash = hashlib.md5(security_answer.lower().strip().encode()).hexdigest()
    if input_hash == user.get('security_answer'):
        # Reset Password
        new_password_hash = hashlib.md5(new_password.encode()).hexdigest()
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {
                'passwordHash': new_password_hash,
                'updated_at': datetime.utcnow()
            }}
        )
        flash('Password reset successful! Please log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Incorrect security answer.', 'danger')
        return render_template('reset_password_verify.html', username=username, question=user['security_question'])


# --- Admin Routes ---

@app.route('/admin')
def admin_dashboard():
    """Admin Dashboard - Manage users and posts."""
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('home'))
    
    users = list(users_collection.find())
    posts = list(blogs_collection.find().sort('publication_date', -1))
    
    # Attach author names to posts
    for post in posts:
        author = users_collection.find_one({'_id': post['author_id']})
        post['author_username'] = author['username'] if author else 'Unknown'
        
    return render_template('admin_dashboard.html', users=users, posts=posts)


@app.route('/admin/delete_all_users', methods=['POST'])
def admin_delete_all_users():
    """Admin - Delete ALL non-admin users."""
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('home'))
        
    # Delete all users EXCEPT the current admin (to prevent lockout)
    current_admin_id = ObjectId(session['user_id'])
    
    # Logic: Delete everyone where _id is NOT current_admin_id
    # You might want to keep other admins too, but request said "delete all users". 
    # Safest is to keep at least the current one.
    
    result = users_collection.delete_many({'_id': {'$ne': current_admin_id}})
    
    # Also clean up their posts? Implicitly yes, usually "delete users" implies cleaning up their data.
    # But if we delete users, posts with author_ids pointing to nowhere will crash 'get_all_posts' 
    # unless we handle missing authors (which we do: "Unknown").
    # Let's delete orphan posts to be clean.
    
    # Get all remaining user IDs (which is just the admin)
    remaining_user_ids = [user['_id'] for user in users_collection.find({}, {'_id': 1})]
    
    # Delete posts where author_id is NOT in remaining_user_ids
    blogs_collection.delete_many({'author_id': {'$nin': remaining_user_ids}})

    flash(f'Deleted {result.deleted_count} users and their posts.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<user_id>')
def admin_delete_user(user_id):
    """Admin - Delete a user and their posts."""
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('home'))
        
    # Prevent deleting self
    if str(user_id) == session['user_id']:
        flash('You cannot delete your own admin account.', 'warning')
        return redirect(url_for('admin_dashboard'))

    users_collection.delete_one({'_id': ObjectId(user_id)})
    blogs_collection.delete_many({'author_id': ObjectId(user_id)})
    
    flash('User and their posts deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_post/<post_id>')
def admin_delete_post(post_id):
    """Admin - Delete any post."""
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('home'))
        
    blogs_collection.delete_one({'_id': ObjectId(post_id)})
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
